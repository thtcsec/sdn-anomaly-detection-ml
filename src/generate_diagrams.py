"""Sinh sơ đồ method cho khóa luận (topology, kiến trúc, thu CSV, xử lý input)."""

import os

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.unicode_minus": False,
})


def _box(ax, x, y, w, h, text, fc, fs=8.2, ec="#212121", lw=1.4):
    p = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.012,rounding_size=0.02",
        facecolor=fc, edgecolor=ec, linewidth=lw, zorder=2,
    )
    ax.add_patch(p)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fs, fontweight="bold", zorder=3, wrap=True)
    return p


def _arrow(ax, x1, y1, x2, y2, color="#212121", style="-|>"):
    ax.add_patch(FancyArrowPatch(
        (x1, y1), (x2, y2),
        arrowstyle=style, mutation_scale=12, lw=1.6,
        color=color, zorder=1,
    ))


def generate_topology_diagram():
    fig, ax = plt.subplots(figsize=(11.2, 7.2))
    nodes = {
        "c0": {"pos": (0.50, 0.88), "r": 0.055, "fc": "#1565c0",
               "cap": "c0  os-ken :6633\nOpenFlow 1.3"},
        "s1": {"pos": (0.28, 0.58), "r": 0.048, "fc": "#ef6c00",
               "cap": "s1  OVS\nOpenFlow13"},
        "s2": {"pos": (0.72, 0.58), "r": 0.048, "fc": "#ef6c00",
               "cap": "s2  OVS\nOpenFlow13"},
        "h1": {"pos": (0.10, 0.28), "r": 0.038, "fc": "#2e7d32", "cap": "h1  10.0.0.1"},
        "h2": {"pos": (0.28, 0.28), "r": 0.038, "fc": "#2e7d32", "cap": "h2  10.0.0.2"},
        "h3": {"pos": (0.46, 0.28), "r": 0.038, "fc": "#2e7d32", "cap": "h3  10.0.0.3"},
        "h4": {"pos": (0.54, 0.10), "r": 0.038, "fc": "#c62828", "cap": "h4  10.0.0.4"},
        "h5": {"pos": (0.72, 0.10), "r": 0.038, "fc": "#c62828", "cap": "h5  10.0.0.5"},
        "h6": {"pos": (0.90, 0.10), "r": 0.038, "fc": "#c62828", "cap": "h6  10.0.0.6"},
    }
    edges = [
        ("c0", "s1", "#1565c0", 1.6),
        ("c0", "s2", "#1565c0", 1.6),
        ("s1", "s2", "#616161", 2.4),
        ("s1", "h1", "#616161", 1.6),
        ("s1", "h2", "#616161", 1.6),
        ("s1", "h3", "#616161", 1.6),
        ("s2", "h4", "#616161", 1.6),
        ("s2", "h5", "#616161", 1.6),
        ("s2", "h6", "#616161", 1.6),
    ]
    for u, v, c, lw in edges:
        p1, p2 = nodes[u]["pos"], nodes[v]["pos"]
        ax.plot([p1[0], p2[0]], [p1[1], p2[1]], color=c, lw=lw, zorder=1)
    for name, n in nodes.items():
        x, y = n["pos"]
        circ = plt.Circle((x, y), n["r"], facecolor=n["fc"], edgecolor="black",
                          lw=1.3, zorder=2)
        ax.add_patch(circ)
        ax.text(x, y, name, color="white", ha="center", va="center",
                fontsize=10, fontweight="bold", zorder=3)
        dy = 0.075 if name == "c0" else (-0.075 if name in ("s1", "s2") else -0.062)
        ax.text(x, y + dy, n["cap"], ha="center", va="center", fontsize=8)

    ax.annotate(
        "", xy=(0.12, 0.30), xytext=(0.52, 0.12),
        arrowprops=dict(arrowstyle="-|>", color="#c62828", lw=2.0),
    )
    ax.text(0.36, 0.18, "VD DDoS: h4 SYN flood → h1:80",
            color="#b71c1c", fontsize=8.5, fontweight="bold")
    ax.text(0.28, 0.40, "LAN nội bộ (thường là victim / Normal)",
            color="#1b5e20", fontsize=9, fontweight="bold", ha="center")
    ax.text(0.78, 0.40, "Cạnh ngoài (thường là attacker)",
            color="#b71c1c", fontsize=9, fontweight="bold", ha="center")
    ax.text(0.50, 0.72, "Kênh điều khiển OpenFlow (không phải data plane)",
            color="#0d47a1", fontsize=8.5, ha="center")

    ax.set_title(
        "Topology testbed Mininet: 2 switch Open vSwitch, 6 host, controller os-ken",
        fontsize=12.5, fontweight="bold", pad=12,
    )
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.02)
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(os.path.join(REPORTS_DIR, "network_topology_method.png"), dpi=180,
                bbox_inches="tight", facecolor="white")
    plt.close(fig)


def generate_architecture_diagram():
    fig, ax = plt.subplots(figsize=(12.4, 8.0))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    _box(ax, 0.03, 0.86, 0.94, 0.11,
         "Application plane    ·    Flask dashboard (live_stats.json, alerts.json)    ·    không sinh traffic thesis",
         "#e3f2fd", 9)
    _box(ax, 0.03, 0.62, 0.45, 0.20,
         "Control plane — thu thập (offline)\n"
         "os-ken app: controller/monitor.py\n"
         "OFPFlowStatsRequest mỗi 5s → ghi CSV",
         "#fff3e0", 8.6)
    _box(ax, 0.52, 0.62, 0.45, 0.20,
         "Control plane — prototype realtime\n"
         "os-ken app: controller/realtime_detector.py\n"
         "XGB 10 feature → Alert ×3 → DROP 120s",
         "#ffe0b2", 8.6)
    _box(ax, 0.03, 0.46, 0.94, 0.12,
         "Southbound: OpenFlow 1.3  ·  cổng 6633  ·  Flow Statistics (không DPI payload)",
         "#e8eaf6", 9)
    _box(ax, 0.03, 0.26, 0.94, 0.16,
         "Data plane — Mininet + Open vSwitch\n"
         "s1 (h1–h3)  —  s2 (h4–h6)  ·  IP 10.0.0.1–10.0.0.6  ·  ping / iperf / HTTP / hping3 / nmap",
         "#e8f5e9", 8.8)
    _box(ax, 0.03, 0.04, 0.30, 0.18,
         "Gộp run độc lập\nflow_stats_grouped.csv\n79.114 snapshot · 32 run · 19 scenario",
         "#f3e5f5", 8)
    _box(ax, 0.35, 0.04, 0.30, 0.18,
         "Đánh giá chính (nhận xét lab)\nLOSO 19 scenario · 8 feature\nbỏ cổng thô · không SMOTE",
         "#fce4ec", 8)
    _box(ax, 0.67, 0.04, 0.30, 0.18,
         "4 mô hình baseline\nXGB · RF  (có giám sát)\nAE · IF  (không giám sát)",
         "#eceff1", 8)

    _arrow(ax, 0.25, 0.62, 0.25, 0.58)
    _arrow(ax, 0.75, 0.62, 0.75, 0.58)
    _arrow(ax, 0.50, 0.46, 0.50, 0.42)
    _arrow(ax, 0.18, 0.26, 0.18, 0.22)
    ax.set_title(
        "Kiến trúc hệ thống: hai đường Control (thu CSV / realtime) trên cùng testbed",
        fontsize=13, fontweight="bold", pad=8,
    )
    fig.tight_layout()
    fig.savefig(os.path.join(REPORTS_DIR, "system_architecture_method.png"), dpi=180,
                bbox_inches="tight", facecolor="white")
    plt.close(fig)


def generate_collection_pipeline():
    fig, ax = plt.subplots(figsize=(12.6, 7.4))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    steps = [
        (0.03, 0.72, "1. Gắn nhãn cửa sổ\ncurrent_label.txt\n= normal | ddos | portscan"),
        (0.27, 0.72, "2. Sinh traffic trên host\nping / iperf / HTTP\nhping3 / nmap"),
        (0.51, 0.72, "3. OVS cài flow\nPacket-In → FlowMod\nmatch IPv4 + L4"),
        (0.75, 0.72, "4. Poll 5 giây\nOFPFlowStatsRequest\n→ FlowStatsReply"),
        (0.03, 0.38, "5. Trích đặc trưng\npkt, byte, duration\npkt/s, byte/s, size TB"),
        (0.27, 0.38, "6. Append CSV\nflow_stats.csv\n+ cột label cửa sổ"),
        (0.51, 0.38, "7. Cắt theo thời gian run\nindependent_runs/run_*.csv\n+ run_id, scenario_id"),
        (0.75, 0.38, "8. merge_independent_runs\nflow_stats_grouped.csv\nchỉ is_synthetic=0"),
    ]
    for x, y, t in steps:
        _box(ax, x, y, 0.22, 0.22, t, "#e3f2fd", 8.0)
    for x in (0.25, 0.49, 0.73):
        _arrow(ax, x, 0.83, x + 0.02, 0.83)
    _arrow(ax, 0.86, 0.72, 0.86, 0.61)
    ax.text(0.50, 0.64, "↓  mỗi FlowStatsReply thành nhiều dòng quan sát  ↓",
            ha="center", fontsize=8.5, color="#37474f")
    for x in (0.25, 0.49, 0.73):
        _arrow(ax, x, 0.49, x + 0.02, 0.49)

    _box(ax, 0.08, 0.06, 0.84, 0.24,
         "Input của mô hình không phải pcap. Mỗi dòng CSV = một lần quan sát Flow Statistics\n"
         "của một 5-tuple tại một lần poll. Cùng một phiên TCP có thể sinh nhiều dòng (mỗi 5s).\n"
         "Nhãn = kịch bản đang chạy trong cửa sổ thời gian, không phải ground-truth từng gói.\n"
         "Tập chính khóa luận: 79.114 snapshot · 32 run_id · 19 scenario_id. Không dùng dump thô 155k.",
         "#fff8e1", 8.4)

    ax.set_title(
        "Quy trình sinh CSV: từ OpenFlow Flow Statistics đến tập lab có provenance",
        fontsize=13, fontweight="bold", pad=8,
    )
    fig.tight_layout()
    fig.savefig(os.path.join(REPORTS_DIR, "data_collection_pipeline_method.png"), dpi=180,
                bbox_inches="tight", facecolor="white")
    plt.close(fig)


def generate_input_method_diagram():
    fig, ax = plt.subplots(figsize=(12.4, 7.6))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    _box(ax, 0.04, 0.78, 0.92, 0.16,
         "Bản tin OpenFlow OFPFlowStatsReply  →  chỉ giữ flow có ipv4_src / ipv4_dst\n"
         "Bỏ table-miss, ARP. Lấy match: ip_proto, tcp/udp src-dst, packet_count, byte_count, duration",
         "#e8eaf6", 8.6)
    _box(ax, 0.04, 0.52, 0.44, 0.22,
         "Đặc trưng tính thêm\n"
         "pkt/s = packet_count / duration\n"
         "byte/s = byte_count / duration\n"
         "packet_size_avg = byte_count / packet_count",
         "#e0f2f1", 8.4)
    _box(ax, 0.52, 0.52, 0.44, 0.22,
         "Hai cấu hình đặc trưng (không trộn)\n"
         "Realtime / random-split: 10 cột (có cổng thô)\n"
         "LOSO chính: 8 cột — BỎ tp_src, tp_dst",
         "#fce4ec", 8.4)
    _box(ax, 0.04, 0.24, 0.44, 0.22,
         "Tiền xử lý offline\n"
         "Lọc is_synthetic=0, run_id hợp lệ\n"
         "Bỏ NA trên cột ML, không DPI\n"
         "SMOTE chỉ phụ lục train 80/20 — không dùng LOSO",
         "#fff3e0", 8.2)
    _box(ax, 0.52, 0.24, 0.44, 0.22,
         "Đánh giá / quyền khẳng định\n"
         "Chính: LOSO 19 scenario, 3 poll đầu\n"
         "Trung gian: GroupKFold theo run_id\n"
         "Kết quả = nhận xét trên testbed này",
         "#f3e5f5", 8.2)
    _box(ax, 0.04, 0.04, 0.92, 0.16,
         "Method: không đề xuất thuật toán mới. So sánh 4 baseline đã công bố trên cùng dữ liệu tự thu,\n"
         "cùng protocol hold-out kịch bản, rồi gắn một prototype XGB vào controller.",
         "#eceff1", 8.5)

    ax.set_title(
        "Xử lý input và method đánh giá: từ Flow Statistics đến LOSO",
        fontsize=13, fontweight="bold", pad=8,
    )
    fig.tight_layout()
    fig.savefig(os.path.join(REPORTS_DIR, "input_method_pipeline_method.png"), dpi=180,
                bbox_inches="tight", facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    generate_topology_diagram()
    generate_architecture_diagram()
    generate_collection_pipeline()
    generate_input_method_diagram()
    print("Wrote 4 figures to reports/")
