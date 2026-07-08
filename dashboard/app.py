"""
Real-time SDN Anomaly Detection Dashboard.
Hiển thị trạng thái hệ thống, alerts, và blocked IPs qua web interface.

Chạy: python dashboard/app.py
Mở: http://localhost:5000

Dashboard đọc alert log từ controller và hiển thị real-time.
"""

import os
import json
import time
from datetime import datetime
from flask import Flask, render_template, jsonify

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_LOG = os.path.join(BASE_DIR, 'dataset', 'alerts.json')
MODELS_DIR = os.path.join(BASE_DIR, 'models')

# In-memory alert storage (simulated from log file)
alerts = []
blocked_ips = []
stats = {
    'total_flows_analyzed': 0,
    'total_attacks_detected': 0,
    'total_ips_blocked': 0,
    'uptime_start': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'model_loaded': os.path.exists(os.path.join(MODELS_DIR, 'xgboost_model.pkl')),
}


def load_alerts():
    """Load alerts từ file JSON (controller ghi vào)."""
    if os.path.exists(ALERT_LOG):
        try:
            with open(ALERT_LOG, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    return []


@app.route('/')
def index():
    """Trang chính dashboard."""
    return render_template('index.html')


@app.route('/api/stats')
def get_stats():
    """API trả về thống kê tổng quan."""
    current_alerts = load_alerts()
    stats['total_attacks_detected'] = len(current_alerts)
    stats['total_ips_blocked'] = len(set(a.get('ip_src', '') for a in current_alerts if a.get('blocked')))
    stats['total_flows_analyzed'] = len(current_alerts) * 50  # Estimate

    return jsonify(stats)


@app.route('/api/alerts')
def get_alerts():
    """API trả về danh sách alerts gần nhất."""
    current_alerts = load_alerts()
    # Trả 50 alerts gần nhất
    return jsonify(current_alerts[-50:])


@app.route('/api/blocked')
def get_blocked():
    """API trả về danh sách IP đang bị block."""
    current_alerts = load_alerts()
    blocked = [a for a in current_alerts if a.get('blocked')]
    return jsonify(blocked[-20:])


@app.route('/api/traffic_stats')
def get_traffic_stats():
    """API trả về thống kê traffic theo loại."""
    current_alerts = load_alerts()
    traffic = {'NORMAL': 0, 'DDOS': 0, 'PORTSCAN': 0}
    for a in current_alerts:
        label = a.get('prediction', 'NORMAL')
        traffic[label] = traffic.get(label, 0) + 1

    return jsonify(traffic)


if __name__ == '__main__':
    print("=" * 60)
    print("  SDN Anomaly Detection Dashboard")
    print("  URL: http://localhost:5000")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)
