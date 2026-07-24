"""
Real-time SDN Anomaly Detection Dashboard.
Hiển thị trạng thái hệ thống, alerts, và blocked IPs qua web interface.

Chạy: python dashboard/app.py
Mở: http://localhost:5000

Dashboard đọc alert log từ controller (dataset/alerts.json).
"""

import json
import os
from datetime import datetime

from flask import Flask, jsonify, render_template

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_LOG = os.path.join(BASE_DIR, 'dataset', 'alerts.json')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
UPTIME_START = datetime.now()

# Chỉ bind localhost mặc định (an toàn hơn khi demo trên máy cá nhân).
# Muốn mở LAN: set env DASHBOARD_HOST=0.0.0.0
DASHBOARD_HOST = os.environ.get('DASHBOARD_HOST', '127.0.0.1')
DASHBOARD_PORT = int(os.environ.get('DASHBOARD_PORT', '5000'))


@app.after_request
def harden_headers(resp):
    """Header cứng nhẹ cho demo local (không thay thế reverse-proxy prod)."""
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Cache-Control'] = 'no-store'
    return resp


def load_alerts():
    """Load alerts từ file JSON (controller ghi vào)."""
    if not os.path.exists(ALERT_LOG):
        return []
    try:
        with open(ALERT_LOG, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def build_stats(alerts):
    flows = 0
    if alerts:
        flows = max(int(a.get('flows_analyzed', 0) or 0) for a in alerts)
    blocked_ips = sorted({
        a.get('ip_src', '')
        for a in alerts
        if a.get('blocked') and a.get('ip_src')
    })
    uptime_sec = int((datetime.now() - UPTIME_START).total_seconds())
    return {
        'total_flows_analyzed': flows,
        'total_attacks_detected': len(alerts),
        'total_ips_blocked': len(blocked_ips),
        'uptime_start': UPTIME_START.strftime('%Y-%m-%d %H:%M:%S'),
        'uptime_seconds': uptime_sec,
        'model_loaded': os.path.exists(os.path.join(MODELS_DIR, 'xgboost_model.pkl')),
        'alert_log_exists': os.path.exists(ALERT_LOG),
    }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/stats')
def get_stats():
    return jsonify(build_stats(load_alerts()))


@app.route('/api/alerts')
def get_alerts():
    return jsonify(load_alerts()[-50:])


@app.route('/api/blocked')
def get_blocked():
    alerts = load_alerts()
    blocked = [a for a in alerts if a.get('blocked')]
    return jsonify(blocked[-20:])


@app.route('/api/traffic_stats')
def get_traffic_stats():
    traffic = {'NORMAL': 0, 'DDOS': 0, 'PORTSCAN': 0}
    for a in load_alerts():
        label = str(a.get('prediction', 'NORMAL')).upper()
        traffic[label] = traffic.get(label, 0) + 1
    return jsonify(traffic)


@app.route('/api/health')
def health():
    return jsonify({
        'status': 'ok',
        'time': datetime.now().isoformat(timespec='seconds'),
        'bind': f'{DASHBOARD_HOST}:{DASHBOARD_PORT}',
        'model_loaded': os.path.exists(os.path.join(MODELS_DIR, 'xgboost_model.pkl')),
    })


if __name__ == '__main__':
    print("=" * 60)
    print("  SDN Anomaly Detection Dashboard")
    print(f"  URL: http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    print(f"  Alert log: {ALERT_LOG}")
    print("=" * 60)
    # debug=False để tránh double-reload khi demo bảo vệ
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False)
