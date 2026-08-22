import json
import os
import sys
import logging
import secrets
import subprocess
from datetime import datetime
from flask import Flask, abort, jsonify, render_template, request

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'src'))
from model_catalog import ALLOWED_MODELS, inventory, missing_artifacts, train_hint  # noqa: E402
from mitigation_policy import DEFAULT_ALERT_THRESHOLD  # noqa: E402
sys.path.insert(0, BASE_DIR)
from controller.openflow_bind import any_realtime_controller_running, pid_file_alive  # noqa: E402

# Tắt spam log HTTP 200 trên terminal
log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

ALERT_LOG = os.path.join(BASE_DIR, 'dataset', 'alerts.json')
LIVE_STATS_LOG = os.path.join(BASE_DIR, 'dataset', 'live_stats.json')
CONFIG_PATH = os.path.join(BASE_DIR, 'dataset', 'controller_config.json')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
UPTIME_START = datetime.now()

# Loopback is the safe default. Non-loopback binding requires an API token.
DASHBOARD_HOST = os.environ.get('DASHBOARD_HOST', '127.0.0.1')
DASHBOARD_PORT = int(os.environ.get('DASHBOARD_PORT', '5000'))
DASHBOARD_API_TOKEN = os.environ.get('DASHBOARD_API_TOKEN', '')
CSRF_TOKEN = secrets.token_urlsafe(32)
ALLOWED_TARGETS = {f'10.0.0.{host}' for host in range(1, 7)}

DEFAULT_CONFIG = {
    'polling_interval': 5.0,
    'alert_threshold': DEFAULT_ALERT_THRESHOLD,
    'block_timeout': 120,
    'mitigation_enabled': True,
    'selected_model': 'random_forest_binary'
}


@app.before_request
def protect_dashboard():
    if DASHBOARD_HOST not in {'127.0.0.1', 'localhost', '::1'}:
        supplied = request.headers.get('Authorization', '')
        expected = f'Bearer {DASHBOARD_API_TOKEN}'
        if not DASHBOARD_API_TOKEN or not secrets.compare_digest(supplied, expected):
            abort(401)
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        supplied = request.headers.get('X-CSRF-Token', '')
        if not secrets.compare_digest(supplied, CSRF_TOKEN):
            abort(403)


@app.after_request
def harden_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Cache-Control'] = 'no-store'
    return resp


def load_json(filepath, default):
    if not os.path.exists(filepath):
        return default
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except (json.JSONDecodeError, OSError):
        return default


def _controller_telemetry_fresh(live, max_age_sec=20):
    """live_stats.json is leftover after python controller/... Terminated."""
    raw = str((live or {}).get('updated_at') or '').strip()
    if not raw:
        return False
    try:
        ts = datetime.strptime(raw, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return False
    return (datetime.now() - ts).total_seconds() <= max_age_sec


def get_live_state():
    alerts = load_json(ALERT_LOG, [])
    live = load_json(LIVE_STATS_LOG, {})
    cfg = load_json(CONFIG_PATH, DEFAULT_CONFIG)
    pid_path = os.path.join(BASE_DIR, 'dataset', 'controller.pid')
    if os.path.exists(pid_path):
        # PID file is source of truth: leftover live_stats.json must not look "CONNECTED".
        controller_alive = pid_file_alive()
    else:
        controller_alive = (
            any_realtime_controller_running() and _controller_telemetry_fresh(live)
        )

    flows_analyzed = live.get('flows_analyzed', 0)
    if not flows_analyzed and alerts:
        flows_analyzed = max(int(a.get('flows_analyzed', 0) or 0) for a in alerts)

    blocked_from_alerts = {
        a.get('ip_src', '')
        for a in alerts
        if a.get('blocked') and a.get('ip_src')
    }
    blocked_from_live = set(live.get('blocked_ips', []))
    all_blocked = sorted(list(blocked_from_alerts | blocked_from_live))

    uptime_sec = int((datetime.now() - UPTIME_START).total_seconds())
    last_alert_at = alerts[-1].get('timestamp') if alerts else None

    # Host status matrix
    hosts = [
        {'id': 'h1', 'ip': '10.0.0.1', 'role': 'Normal User (s1)', 'switch': 's1'},
        {'id': 'h2', 'ip': '10.0.0.2', 'role': 'Normal User (s1)', 'switch': 's1'},
        {'id': 'h3', 'ip': '10.0.0.3', 'role': 'Normal User (s1)', 'switch': 's1'},
        {'id': 'h4', 'ip': '10.0.0.4', 'role': 'Attacker Host (s2)', 'switch': 's2'},
        {'id': 'h5', 'ip': '10.0.0.5', 'role': 'Attacker Host (s2)', 'switch': 's2'},
        {'id': 'h6', 'ip': '10.0.0.6', 'role': 'Attacker Host (s2)', 'switch': 's2'},
    ]

    recent_alerts = alerts[-30:] if isinstance(alerts, list) else []
    recent_attacker_ips = {a.get('ip_src') for a in recent_alerts[-5:]}

    for h in hosts:
        if h['ip'] in all_blocked:
            h['status'] = 'BLOCKED'
        elif h['ip'] in recent_attacker_ips:
            h['status'] = 'ATTACKING'
        else:
            h['status'] = 'NORMAL'

    # Traffic distribution — controller counters only. Do not remap ANOMALY → DDoS/Portscan.
    normal_cnt = int(live.get('normal_count', 0) or 0)
    ddos_cnt = int(live.get('ddos_count', 0) or 0)
    portscan_cnt = int(live.get('portscan_count', 0) or 0)
    anomaly_cnt = int(live.get('anomaly_count', 0) or 0)

    if not (normal_cnt or ddos_cnt or portscan_cnt or anomaly_cnt):
        for a in alerts:
            pred = str(a.get('prediction', '')).upper()
            if pred == 'DDOS':
                ddos_cnt += 1
            elif pred == 'PORTSCAN':
                portscan_cnt += 1
            elif pred == 'ANOMALY':
                anomaly_cnt += 1
            elif pred == 'NORMAL':
                normal_cnt += 1

    requested = str(cfg.get('selected_model', 'xgboost')).lower()
    runtime_model = str((live.get('config') or {}).get('selected_model') or requested).lower()
    models_on_disk = inventory(MODELS_DIR)
    active = str(live.get('active_model') or '').strip().lower()
    load_st = str(live.get('model_load_status') or 'idle')
    if active:
        shown_model = active
    elif load_st == 'loading':
        shown_model = ''
    else:
        shown_model = runtime_model

    return {
        'stats': {
            'total_flows_analyzed': flows_analyzed,
            'total_attacks_detected': len(alerts),
            'total_ips_blocked': len(all_blocked),
            'uptime_seconds': uptime_sec,
            'model_loaded': not missing_artifacts(MODELS_DIR, runtime_model),
            'runtime_model': shown_model or live.get('active_model') or '',
            'requested_model': requested,
            'model_artifact': live.get('model_artifact') or '',
            'model_task': live.get('model_task') or models_on_disk.get(runtime_model, {}).get('task'),
            'model_load_status': live.get('model_load_status') or 'idle',
            'model_load_target': live.get('model_load_target') or '',
            'model_load_elapsed_sec': live.get('model_load_elapsed_sec') or 0,
            'model_load_timeout_sec': live.get('model_load_timeout_sec') or 0,
            'model_load_message': live.get('model_load_message') or '',
            'last_latency_ms': live.get('last_latency_ms', 0),
            'last_alert_at': last_alert_at,
            'controller_alive': controller_alive,
            'switches_count': 0 if not controller_alive else len(live.get('active_switches', [])),
        },
        'traffic_distribution': {
            'NORMAL': normal_cnt,
            'DDOS': ddos_cnt,
            'PORTSCAN': portscan_cnt,
            'ANOMALY': anomaly_cnt,
        },
        'hosts': hosts,
        'blocked_ips': all_blocked,
        'recent_flows': live.get('recent_flows', []),
        'recent_alerts': recent_alerts,
        'config': cfg,
        'available_models': models_on_disk,
    }


@app.route('/')
def index():
    return render_template('index.html', csrf_token=CSRF_TOKEN)


@app.route('/api/live_data')
def get_live_data():
    return jsonify(get_live_state())


@app.route('/api/stats')
def get_stats():
    data = get_live_state()
    return jsonify(data['stats'])


@app.route('/api/alerts')
def get_alerts():
    data = get_live_state()
    return jsonify(data['recent_alerts'])


@app.route('/api/blocked')
def get_blocked():
    data = get_live_state()
    alerts = data['recent_alerts']
    blocked = [a for a in alerts if a.get('blocked')]
    return jsonify(blocked[-20:])


@app.route('/api/traffic_stats')
def get_traffic_stats():
    data = get_live_state()
    return jsonify(data['traffic_distribution'])


@app.route('/api/settings', methods=['GET', 'POST'])
def handle_settings():
    if request.method == 'POST':
        try:
            body = request.get_json(silent=True) or {}
            cfg = load_json(CONFIG_PATH, dict(DEFAULT_CONFIG))
            
            if 'polling_interval' in body:
                cfg['polling_interval'] = max(1.0, min(30.0, float(body['polling_interval'])))
            if 'alert_threshold' in body:
                cfg['alert_threshold'] = max(1, min(20, int(body['alert_threshold'])))
            if 'block_timeout' in body:
                cfg['block_timeout'] = max(10, min(1200, int(body['block_timeout'])))
            if 'mitigation_enabled' in body:
                cfg['mitigation_enabled'] = bool(body['mitigation_enabled'])
            if 'selected_model' in body:
                model_name = str(body['selected_model']).lower()
                if model_name not in ALLOWED_MODELS:
                    return jsonify({
                        'status': 'error',
                        'message': (
                            f"Model '{model_name}' không hỗ trợ. "
                            f"Chỉ nhận: {', '.join(ALLOWED_MODELS)}."
                        ),
                    }), 400
                miss = missing_artifacts(MODELS_DIR, model_name)
                if miss:
                    return jsonify({
                        'status': 'error',
                        'message': (
                            f"Thiếu artifact cho {model_name}: "
                            + ', '.join(os.path.basename(p) for p in miss)
                            + f". Chạy `{train_hint(model_name)}`. Không dùng model giả."
                        ),
                        'missing': [os.path.basename(p) for p in miss],
                    }), 400
                cfg['selected_model'] = model_name

            with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                json.dump(cfg, f, indent=2)

            return jsonify({
                'status': 'ok',
                'config': cfg,
                'available_models': inventory(MODELS_DIR),
                'message': (
                    'Đã ghi cấu hình. Header hiện ĐANG NẠP; Autoencoder lần đầu '
                    'có thể 30–180s (TensorFlow). Timeout thì giữ model cũ, không bịa.'
                ),
            })
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 400

    cfg = load_json(CONFIG_PATH, dict(DEFAULT_CONFIG))
    return jsonify({
        **cfg,
        'available_models': inventory(MODELS_DIR),
    })


@app.route('/api/simulate', methods=['POST'])
def handle_simulation():
    """Kích hoạt traffic generator script trong Mininet."""
    try:
        body = request.get_json(silent=True) or {}
        action_type = str(body.get('type', 'normal')).lower()
        if action_type not in {'normal', 'ddos', 'portscan', 'stop'}:
            return jsonify({'status': 'error', 'message': 'Loại traffic không hợp lệ.'}), 400
        duration = max(1, min(60, int(body.get('duration', 8))))
        target = str(body.get('target', '10.0.0.1'))
        if target not in ALLOWED_TARGETS:
            return jsonify({
                'status': 'error',
                'message': 'Target chỉ được là host Mininet 10.0.0.1–10.0.0.6.',
            }), 400

        if os.name == 'nt':
            return jsonify({
                'status': 'error',
                'type': action_type,
                'message': (
                    'Nút Bắn chỉ chạy khi dashboard nằm trong WSL (mnexec). '
                    'Quay thesis: gõ trong mininet>  h1 ping -c 8 10.0.0.2'
                ),
            }), 409

        live = load_json(LIVE_STATS_LOG, {})
        switches = live.get('active_switches') or []
        if action_type != 'stop' and not switches:
            return jsonify({
                'status': 'error',
                'type': action_type,
                'message': (
                    'Controller realtime chưa có switch (header đang NO SWITCH). '
                    'Ping/iperf vẫn có thể chạy trên OVS nhưng dashboard không thấy flow. '
                    'Thường do run_fault_monitor.py còn giữ cổng 6633. '
                    'Kill process cũ, để đúng một python run_realtime.py, '
                    'rồi restart Mininet. Video: gõ lệnh trong mininet>.'
                ),
            }), 409

        script_path = os.path.join(BASE_DIR, 'scripts', 'trigger_traffic.py')
        if not os.path.isfile(script_path):
            return jsonify({
                'status': 'error',
                'type': action_type,
                'message': (
                    'Thiếu scripts/trigger_traffic.py. '
                    'Chạy traffic trong mininet>: '
                    'h1 ping / h4 hping3 --flood / h6 nmap.'
                )
            }), 400

        cmd = [
            sys.executable, script_path,
            '--type', action_type,
            '--duration', str(duration),
            '--target', target
        ]
        if action_type == 'stop':
            try:
                completed = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=20,
                )
            except subprocess.TimeoutExpired:
                return jsonify({
                    'status': 'error',
                    'type': action_type,
                    'message': 'Dừng traffic quá 20s — kiểm tra Mininet/mnexec.',
                }), 500
            detail = (completed.stdout or completed.stderr or '').strip()
            return jsonify({
                'status': 'ok' if completed.returncode == 0 else 'error',
                'type': action_type,
                'message': detail or 'Đã gửi SIGKILL ping/iperf/hping3/nmap trong host Mininet.',
            })
        subprocess.Popen(cmd)
        return jsonify({
            'status': 'ok',
            'type': action_type,
            'message': (
                f"Đã gọi trigger_traffic.py [{action_type.upper()}] ({duration}s). "
                "Nếu Mininet chưa chạy thì không có traffic — "
                "thesis/video nên gõ lệnh trong mininet>."
            )
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/reset', methods=['POST'])
def handle_reset():
    """Reset alerts log và unblock IPs."""
    try:
        with open(ALERT_LOG, 'w', encoding='utf-8') as f:
            json.dump([], f)
        
        live = load_json(LIVE_STATS_LOG, {})
        live['flows_analyzed'] = 0
        live['normal_count'] = 0
        live['ddos_count'] = 0
        live['portscan_count'] = 0
        live['anomaly_count'] = 0
        live['blocked_ips'] = []
        live['recent_flows'] = []
        
        with open(LIVE_STATS_LOG, 'w', encoding='utf-8') as f:
            json.dump(live, f, indent=2)

        # Stop any background traffic
        subprocess.run(["killall", "-9", "hping3", "nmap", "iperf"], capture_output=True)

        return jsonify({'status': 'ok', 'message': 'Đã reset toàn bộ số liệu thống kê và alert logs!'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/health')
def health():
    cfg = load_json(CONFIG_PATH, DEFAULT_CONFIG)
    return jsonify({
        'status': 'ok',
        'time': datetime.now().isoformat(timespec='seconds'),
        'bind': f'{DASHBOARD_HOST}:{DASHBOARD_PORT}',
        'model_loaded': not missing_artifacts(MODELS_DIR, cfg.get('selected_model', 'xgboost')),
        'active_model': cfg.get('selected_model', 'xgboost'),
        'available_models': inventory(MODELS_DIR),
    })


def _reachable_ips():
    ips = []
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True, timeout=2)
        ips = [x for x in out.split() if x and not x.startswith("127.")]
    except (OSError, subprocess.SubprocessError):
        pass
    return ips


if __name__ == '__main__':
    if DASHBOARD_HOST not in {'127.0.0.1', 'localhost', '::1'} and not DASHBOARD_API_TOKEN:
        raise RuntimeError(
            'Non-loopback DASHBOARD_HOST requires DASHBOARD_API_TOKEN. '
            'Prefer 127.0.0.1 for the thesis demo.'
        )
    print("=" * 60)
    print("  SDN Anomaly Detection & SOC Monitoring Dashboard")
    print(f"  Bind: {DASHBOARD_HOST}:{DASHBOARD_PORT}")
    print(f"  Thu WSL:           http://127.0.0.1:{DASHBOARD_PORT}")
    print(f"  Chrome (Windows):  http://127.0.0.1:{DASHBOARD_PORT}")
    for ip in _reachable_ips():
        print(f"  Neu localhost loi: http://{ip}:{DASHBOARD_PORT}")
    print("  (Terminal spam disabled for clean console output)")
    print("=" * 60)
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False)

