# SDN Anomaly Detection using Machine Learning

Dự án này tập trung vào việc xây dựng một hệ thống phát hiện bất thường (Anomaly Detection) trong mạng điều khiển bằng phần mềm (Software-Defined Networking - SDN). Hệ thống sử dụng **os-ken Controller** (fork chính thức của Ryu) để quản lý mạng, **Mininet** để giả lập hạ tầng và các mô hình **Machine Learning (XGBoost & Autoencoder)** để phân loại và phát hiện các hành vi bất thường.

> **Lưu ý về os-ken:** Ryu framework đã ngừng phát triển từ 2021. Dự án sử dụng [os-ken](https://pypi.org/project/os-ken/) - fork chính thức được OpenStack maintain, tương thích Python 3.10+ và có API gần như giống hệt Ryu. Mọi tutorial/tài liệu Ryu đều áp dụng được, chỉ cần đổi `import ryu` → `import os_ken`.

## 👥 Thành viên thực hiện
| STT | Họ và Tên | MSSV | Vai trò |
|---|---|---|---|
| 1 | **Trịnh Hoàng Tú** | 23DH113972 | Leader, SDN Lab, Data Extraction |
| 2 | **Trần Minh Thiện** | 23DH113375 | ML Research, Data Processing, Report |

### Phân công công việc chi tiết
| STT | Họ và Tên | Công việc chi tiết |
|---|---|---|
| 1 | **Trịnh Hoàng Tú** | - Dựng Lab trên WSL2 (Ubuntu).<br>- Viết script Python cho os-ken để monitor flow stats.<br>- Giả lập tấn công (DDoS, Port Scan) để lấy data thô (.csv).<br>- Quản lý GitHub (Merge code của Thiện). |
| 2 | **Trần Minh Thiện** | - Làm sạch dữ liệu, xử lý imbalance (SMOTE).<br>- Code & Train model (XGBoost, Autoencoder).<br>- Vẽ biểu đồ, viết nội dung Chương 1, 2, 3 vào file báo cáo.<br>- Format tài liệu tham khảo chuẩn IEEE. |

**GVHD:** Ths. Cao Tiến Thành  
**Chuyên ngành:** An ninh mạng | Khóa 29 – K29 | HUFLIT

## 🚀 Tính năng chính
- Giả lập mạng SDN với các kịch bản tấn công (DDoS, Port Scanning).
- Thu thập dữ liệu OpenFlow flows theo thời gian thực.
- Trích xuất đặc trưng mạng phục vụ cho Machine Learning.
- Phát hiện tấn công sử dụng mô hình lai:
    - **XGBoost**: Phát hiện các kiểu tấn công đã biết (Supervised Learning).
    - **Autoencoder**: Phát hiện các mẫu bất thường mới/chưa xác định (Unsupervised Learning).

## 📁 Cấu trúc thư mục
```text
sdn-anomaly-detection-ml/
├── controller/          # Mã nguồn os-ken Controller (Logic điều khiển, Monitor)
│   └── monitor.py       # Flow stats collector - thu thập dữ liệu từ switches
├── topology/            # Script Python khởi tạo topo mạng trong Mininet
│   └── custom_topo.py   # Topology 2 switches, 6 hosts
├── dataset/             # Dữ liệu lưu trữ (raw/processed CSV files)
├── notebooks/           # Jupyter Notebooks huấn luyện và đánh giá model
├── src/                 # Script xử lý dữ liệu và trích xuất đặc trưng
│   ├── generate_traffic.py  # Hướng dẫn giả lập traffic (normal/ddos/portscan)
│   ├── preprocess.py        # Pipeline tiền xử lý dữ liệu
│   └── train_model.py       # Huấn luyện XGBoost model
├── models/              # Lưu trữ các file model đã huấn luyện (.pkl)
├── reports/             # Biểu đồ kết quả, ma trận nhầm lẫn (Confusion Matrix)
├── requirements.txt     # Danh sách các thư viện cần thiết
└── README.md            # Tài liệu hướng dẫn dự án
```

## 🛠 Yêu cầu hệ thống & Cài đặt (WSL2)

Dự án được tối ưu hóa để chạy trên **Ubuntu (thông qua WSL2 trên Windows)**.

### Yêu cầu
- Windows 10/11 với WSL2
- Ubuntu 20.04+ (trên WSL2)
- Python 3.10
- Open vSwitch (cho Mininet)

### 1. Thiết lập WSL2
```powershell
wsl --install
# Khởi động lại máy và cài đặt Ubuntu từ Microsoft Store
```

### 2. Cài đặt hệ thống
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install mininet openvswitch-switch -y
sudo apt install python3.10 python3.10-venv python3.10-dev -y
sudo apt install hping3 nmap iperf -y
```

### 3. Tạo Virtual Environment
```bash
cd /mnt/d/tu_projects/sdn-anomaly-detection-ml
python3.10 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
```

### 4. Cài đặt dependencies
```bash
pip install -r requirements.txt
```

### 5. Kiểm tra os-ken
```bash
# Kiểm tra os-ken đã cài thành công
python -c "from os_ken.base.app_manager import AppManager; print('os-ken OK')"
```

## 🚀 Hướng dẫn chạy dự án

### Bước 1: Activate venv
```bash
source .venv/bin/activate
```

### Bước 2: Khởi động os-ken Controller
Mở terminal 1:
```bash
python controller/run_controller.py
```

### Bước 3: Chạy Topology Mininet
Mở terminal 2:
```bash
sudo python3 topology/custom_topo.py
```

### Bước 4: Giả lập traffic
Trong Mininet CLI hoặc tham khảo:
```bash
python3 src/generate_traffic.py normal    # Xem lệnh tạo traffic bình thường
python3 src/generate_traffic.py ddos      # Xem lệnh tạo DDoS attack
python3 src/generate_traffic.py portscan  # Xem lệnh tạo Port Scan
```

### Bước 5: Tiền xử lý dữ liệu
```bash
python3 src/preprocess.py
```

### Bước 6: Huấn luyện model
```bash
python3 src/train_model.py
```

## 📊 Workflow tổng quan

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Mininet    │────▶│  os-ken      │────▶│  CSV Data   │
│  Topology   │     │  Controller  │     │  (dataset/) │
└─────────────┘     └──────────────┘     └──────┬──────┘
                                                 │
                                                 ▼
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Reports    │◀────│  ML Model    │◀────│  Preprocess │
│  (reports/) │     │  (XGBoost)   │     │  (src/)     │
└─────────────┘     └──────────────┘     └─────────────┘
```

## 📋 Thư viện chính (Python Libraries)

| Package | Version | Mục đích |
|---------|---------|----------|
| `os-ken` | latest | SDN Controller framework (thay thế Ryu) |
| `xgboost` | latest | Supervised ML - phân loại tấn công |
| `scikit-learn` | latest | Tiền xử lý & đánh giá model |
| `tensorflow` | latest | Autoencoder (Unsupervised) |
| `pandas` | latest | Xử lý dữ liệu tabular |
| `numpy` | latest | Tính toán số học |
| `matplotlib` | latest | Trực quan hóa |
| `seaborn` | latest | Biểu đồ thống kê |
| `joblib` | latest | Lưu/load model |

## ⚠️ Lưu ý quan trọng

### Tại sao dùng os-ken thay vì Ryu?
- **Ryu đã ngừng phát triển** (commit cuối cùng: 2021)
- Ryu không hỗ trợ Python > 3.9
- **os-ken** là fork chính thức từ OpenStack, vẫn được maintain
- API 100% tương thích - chỉ đổi import name
- Hỗ trợ Python 3.10, 3.11, 3.12

### Chuyển đổi code từ Ryu sang os-ken
```python
# Ryu (cũ)
from ryu.base import app_manager
from ryu.controller import ofp_event

# os-ken (mới) - chỉ đổi tên module
from os_ken.base import app_manager
from os_ken.controller import ofp_event
```

### Chạy controller
```bash
# os-ken 4.x (dùng launcher script)
python controller/run_controller.py
```

## 📊 Kết quả & Báo cáo
Các kết quả đánh giá (Accuracy, Precision, Recall, F1-Score) và biểu đồ phân tích được lưu trong thư mục `/reports`.

---
**Khóa luận tốt nghiệp | HUFLIT | Khóa 29**
