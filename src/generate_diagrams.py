import os
import matplotlib.pyplot as plt

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_topology_diagram():
    print("Generating network topology diagram using Matplotlib...")
    fig, ax = plt.subplots(figsize=(8, 6))
    
    # Define node coordinates and parameters
    nodes = {
        "Controller": {"pos": (0.5, 0.9), "color": "#1f77b4", "label": "SDN Controller\n(os-ken)"},
        "s1": {"pos": (0.3, 0.6), "color": "#ff7f0e", "label": "Switch s1\n(OpenFlow)"},
        "s2": {"pos": (0.7, 0.6), "color": "#ff7f0e", "label": "Switch s2\n(OpenFlow)"},
        "h1": {"pos": (0.1, 0.3), "color": "#2ca02c", "label": "Host h1\n10.0.0.1"},
        "h2": {"pos": (0.3, 0.3), "color": "#2ca02c", "label": "Host h2\n10.0.0.2"},
        "h3": {"pos": (0.5, 0.3), "color": "#2ca02c", "label": "Host h3\n10.0.0.3"},
        "h4": {"pos": (0.5, 0.1), "color": "#d62728", "label": "Host h4\n10.0.0.4"},
        "h5": {"pos": (0.7, 0.1), "color": "#d62728", "label": "Host h5\n10.0.0.5"},
        "h6": {"pos": (0.9, 0.1), "color": "#d62728", "label": "Host h6\n10.0.0.6"},
    }
    
    edges = [
        ("Controller", "s1"),
        ("Controller", "s2"),
        ("s1", "s2"),
        ("s1", "h1"),
        ("s1", "h2"),
        ("s1", "h3"),
        ("s2", "h4"),
        ("s2", "h5"),
        ("s2", "h6"),
    ]
    
    # Draw edges
    for u, v in edges:
        p1 = nodes[u]["pos"]
        p2 = nodes[v]["pos"]
        # Draw line
        ax.plot([p1[0], p2[0]], [p1[1], p2[1]], color='#9e9e9e', lw=2.5, zorder=1)
        
    # Draw nodes as circles
    for name, info in nodes.items():
        x, y = info["pos"]
        color = info["color"]
        # Adjust radius for controller and switches
        radius = 0.055 if name in ["Controller", "s1", "s2"] else 0.045
        circle = plt.Circle((x, y), radius, facecolor=color, edgecolor='black', linewidth=1.5, zorder=2)
        ax.add_patch(circle)
        
        # Add inside label
        ax.text(x, y, name, color='white', ha='center', va='center', fontsize=10, fontweight='bold', zorder=3)
        
        # Add descriptive label text outside node
        offset_y = 0.07 if name == "Controller" else -0.07
        ax.text(x, y + offset_y, info["label"], color='black', ha='center', va='center', fontsize=8.5, fontweight='bold', zorder=3)

    # Label groups
    ax.text(0.18, 0.42, "Mạng Nội bộ (Normal Traffic)", color='#1b5e20', fontsize=11, fontweight='bold', ha='center')
    ax.text(0.82, 0.22, "Mạng Ngoài (Attacker Traffic)", color='#b71c1c', fontsize=11, fontweight='bold', ha='center')

    ax.set_title("Sơ đồ Topology Mạng SDN Giả Lập Trong Mininet", fontsize=13, fontweight='bold', pad=20)
    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.05, 1.05)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'network_topology.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("Saved network topology to reports/network_topology.png")

def generate_architecture_diagram():
    print("Generating system architecture diagram...")
    fig, ax = plt.subplots(figsize=(10, 7))
    
    boxes = [
        {"name": "Mô phỏng Mạng SDN (Mininet)\n- 2 Switches (s1, s2)\n- 6 Hosts (h1-h6)\n- Sinh lưu lượng (ping, iperf, hping3, nmap)", "pos": (0.05, 0.7), "size": (0.26, 0.15), "color": "#e1f5fe"},
        {"name": "Bộ điều khiển os-ken SDN\n- monitor.py (Ghi lưu lượng)\n- realtime_detector.py\n  (Phát hiện thời gian thực)", "pos": (0.37, 0.7), "size": (0.26, 0.15), "color": "#ffe0b2"},
        {"name": "Cơ sở dữ liệu CSV\n- flow_stats.csv (Lưu lượng thô)\n- label_log.csv (Thời gian nhãn)\n- label_data.py (Gán nhãn)", "pos": (0.69, 0.7), "size": (0.26, 0.15), "color": "#e8f5e9"},
        
        {"name": "Tiền xử lý Dữ liệu\n- preprocess.py (Lọc trùng, bỏ trống)\n- Trích xuất 10 đặc trưng mạng số học\n- Scale dữ liệu (StandardScaler)\n- Cân bằng dữ liệu (SMOTE)", "pos": (0.69, 0.4), "size": (0.26, 0.18), "color": "#f3e5f5"},
        {"name": "Huấn luyện Mô hình\n- train_model.py (Supervised: XGBoost)\n- train_autoencoder.py\n  (Unsupervised: Autoencoder)", "pos": (0.37, 0.42), "size": (0.26, 0.15), "color": "#e0f2f1"},
        
        {"name": "Mô hình & Scaler (models/)\n- xgboost_model.pkl (Phân loại)\n- scaler.pkl (Bộ chuẩn hóa)\n- autoencoder_model.keras", "pos": (0.37, 0.15), "size": (0.26, 0.16), "color": "#eceff1"},
        {"name": "Ghi nhận Cảnh báo\n- Ghi log cảnh báo xâm nhập\n- Hiển thị IP nguồn, IP đích,\ngiao thức & loại tấn công", "pos": (0.05, 0.42), "size": (0.26, 0.15), "color": "#ffebee"}
    ]
    
    for box in boxes:
        # Draw box
        rect = plt.Rectangle(box["pos"], box["size"][0], box["size"][1], 
                             facecolor=box["color"], edgecolor="black", linewidth=1.5, zorder=2)
        ax.add_patch(rect)
        # Text in center of box
        cx = box["pos"][0] + box["size"][0] / 2
        cy = box["pos"][1] + box["size"][1] / 2
        ax.text(cx, cy, box["name"], ha="center", va="center", fontsize=8.5, fontweight='bold', color='black', zorder=3)

    # Add arrows
    # Arrow 1: Mininet <-> Controller
    ax.annotate('', xy=(0.37, 0.77), xytext=(0.31, 0.77), arrowprops=dict(arrowstyle="<->", lw=2, color="blue"))
    # Arrow 2: Controller -> Database
    ax.annotate('', xy=(0.69, 0.77), xytext=(0.63, 0.77), arrowprops=dict(arrowstyle="->", lw=2, color="black"))
    # Arrow 3: Database -> Preprocessing
    ax.annotate('', xy=(0.82, 0.58), xytext=(0.82, 0.7), arrowprops=dict(arrowstyle="->", lw=2, color="black"))
    # Arrow 4: Preprocessing -> Model Training
    ax.annotate('', xy=(0.63, 0.49), xytext=(0.69, 0.49), arrowprops=dict(arrowstyle="->", lw=2, color="black"))
    # Arrow 5: Model Training -> ML Models
    ax.annotate('', xy=(0.50, 0.31), xytext=(0.50, 0.42), arrowprops=dict(arrowstyle="->", lw=2, color="black"))
    # Arrow 6: ML Models -> Controller
    ax.annotate('', xy=(0.50, 0.7), xytext=(0.50, 0.31), arrowprops=dict(arrowstyle="->", lw=2, color="green", linestyle="dashed"))
    # Arrow 7: Controller -> Alert Log
    ax.annotate('', xy=(0.18, 0.57), xytext=(0.37, 0.7), arrowprops=dict(arrowstyle="->", lw=2, color="red"))
    
    # Arrow labels
    ax.text(0.34, 0.79, "OpenFlow", fontsize=8, color="blue", fontweight="bold", ha="center")
    ax.text(0.66, 0.79, "Ghi CSV", fontsize=8, color="black", fontweight="bold", ha="center")
    ax.text(0.44, 0.35, "Tích hợp", fontsize=8, color="green", fontweight="bold", ha="center")
    ax.text(0.24, 0.65, "Cảnh báo", fontsize=8, color="red", fontweight="bold", ha="center")

    ax.set_title("Sơ Đồ Kiến Trúc Hệ Thống Phát Hiện Bất Thường SDN Bằng Học Máy", fontsize=13, fontweight='bold', pad=20)
    ax.set_xlim(0, 1)
    ax.set_ylim(0.1, 0.9)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'system_architecture.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("Saved system architecture to reports/system_architecture.png")

if __name__ == "__main__":
    generate_topology_diagram()
    generate_architecture_diagram()
