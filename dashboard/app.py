import json
import os
import sys
import logging
import subprocess
from datetime import datetime
from flask import Flask, jsonify, render_template, request

# Tắt spam log HTTP 200 trên terminal
log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_LOG = os.path.join(BASE_DIR, 'dataset', 'alerts.json')
LIVE_STATS_LOG = os.path.join(BASE_DIR, 'dataset', 'live_stats.json')
CONFIG_PATH = os.path.join(BASE_DIR, 'dataset', 'controller_config.json')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
UPTIME_START = datetime.now()

# 0.0.0.0: Chrome trên Windows mới vào được khi Flask chạy trong WSL.
DASHBOARD_HOST = os.environ.get('DASHBOARD_HOST', '0.0.0.0')
DASHBOARD_PORT = int(os.environ.get('DASHBOARD_PORT', '5000'))

DEFAULT_CONFIG = {
    'polling_interval': 5.0,
    'alert_threshold': 3,
    'block_timeout': 120,
    'mitigation_enabled': True,
    'selected_model': 'xgboost'
}


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


def get_live_state():
    alerts = load_json(ALERT_LOG, [])
    live = load_json(LIVE_STATS_LOG, {})
    cfg = load_json(CONFIG_PATH, DEFAULT_CONFIG)

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

    # Traffic distribution
    normal_cnt = live.get('normal_count', 0)
    ddos_cnt = live.get('ddos_count', 0)
    portscan_cnt = live.get('portscan_count', 0)

    if not (normal_cnt or ddos_cnt or portscan_cnt):
        for a in alerts:
            pred = str(a.get('prediction', '')).upper()
            if pred == 'DDOS':
                ddos_cnt += 1
            elif pred == 'PORTSCAN':
                portscan_cnt += 1

    return {
        'stats': {
            'total_flows_analyzed': flows_analyzed,
            'total_attacks_detected': len(alerts),
            'total_ips_blocked': len(all_blocked),
            'uptime_seconds': uptime_sec,
            'model_loaded': os.path.exists(os.path.join(MODELS_DIR, f"{cfg.get('selected_model', 'xgboost')}_model.pkl")),
            'last_latency_ms': live.get('last_latency_ms', 0.33),
            'last_alert_at': last_alert_at,
            'switches_count': len(live.get('active_switches', [1, 2]))
        },
        'traffic_distribution': {
            'NORMAL': normal_cnt,
            'DDOS': ddos_cnt,
            'PORTSCAN': portscan_cnt
        },
        'hosts': hosts,
        'blocked_ips': all_blocked,
        'recent_flows': live.get('recent_flows', []),
        'recent_alerts': recent_alerts,
        'config': cfg
    }


@app.route('/')
def index():
    return render_template('index.html')


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
                if model_name in ['xgboost', 'random_forest']:
                    cfg['selected_model'] = model_name

            with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                json.dump(cfg, f, indent=2)
            
            return jsonify({'status': 'ok', 'config': cfg, 'message': 'Đã cập nhật cấu hình SOC thành công!'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 400

    cfg = load_json(CONFIG_PATH, dict(DEFAULT_CONFIG))
    return jsonify(cfg)


@app.route('/api/simulate', methods=['POST'])
def handle_simulation():
    """Kích hoạt traffic generator script trong Mininet."""
    try:
        body = request.get_json(silent=True) or {}
        action_type = body.get('type', 'normal')
        duration = int(body.get('duration', 8))
        target = body.get('target', '10.0.0.1')

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
        'model_loaded': os.path.exists(os.path.join(MODELS_DIR, 'xgboost_model.pkl')),
        'active_model': cfg.get('selected_model', 'xgboost')
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

