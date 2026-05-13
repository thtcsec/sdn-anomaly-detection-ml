# SDN Anomaly Detection using Machine Learning

Dự án này tập trung vào việc xây dựng một hệ thống phát hiện bất thường (Anomaly Detection) trong mạng điều khiển bằng phần mềm (Software-Defined Networking - SDN). Hệ thống sử dụng **Ryu Controller** để quản lý mạng, **Mininet** để giả lập hạ tầng và các mô hình **Machine Learning (XGBoost & Autoencoder)** để phân loại và phát hiện các hành vi bất thường.

## 👥 Thành viên thực hiện
| STT | Họ và Tên | MSSV | Vai trò |
|---|---|---|---|
| 1 | **Trịnh Hoàng Tú** | 23DH113972 | Leader, SDN Lab, Data Extraction |
| 2 | **Trần Minh Thiện** | 23DH113375 | ML Research, Data Processing, Report |

### Phân công công việc chi tiết
| STT | Họ và Tên | Công việc chi tiết |
|---|---|---|
| 1 | **Trịnh Hoàng Tú** | - Dựng Lab trên WSL2 (Ubuntu).<br>- Viết script Python cho Ryu để monitor flow stats.<br>- Giả lập tấn công (DDoS) để lấy data thô (.csv).<br>- Quản lý GitHub (Merge code của Thiện). |
| 2 | **Trần Minh Thiện** | - Làm sạch dữ liệu, xử lý imbalance (SMOTE).<br>- Code & Train model (XGBoost, Autoencoder).<br>- Vẽ biểu đồ, viết nội dung Chương 1, 2, 3 vào file báo cáo.<br>- Format tài liệu tham khảo chuẩn IEEE. |

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
├── controller/          # Mã nguồn Ryu Controller (Logic điều khiển, Monitor)
├── topology/            # Script Python khởi tạo topo mạng trong Mininet
├── dataset/             # Dữ liệu lưu trữ (raw/processed CSV files)
├── notebooks/           # Jupyter Notebooks huấn luyện và đánh giá model
├── src/                 # Script xử lý dữ liệu và trích xuất đặc trưng
├── reports/             # Biểu đồ kết quả, ma trận nhầm lẫn (Confusion Matrix)
├── models/              # Lưu trữ các file model đã huấn luyện (.pkl)
├── requirements.txt     # Danh sách các thư viện cần thiết
└── README.md            # Tài liệu hướng dẫn dự án
```

## 🛠 Yêu cầu hệ thống & Cài đặt (WSL2)

Dự án được tối ưu hóa để chạy trên **Ubuntu (thông qua WSL2 trên Windows)**.

### 1. Thiết lập WSL2
Nếu bạn chưa có WSL2, hãy mở PowerShell với quyền Admin và chạy:
```powershell
wsl --install
# Khởi động lại máy và cài đặt Ubuntu từ Microsoft Store
```

### 2. Cài đặt các thành phần mạng
Trong môi trường Ubuntu (WSL2), thực hiện các lệnh sau:
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install mininet -y
sudo apt install python3-pip python3-dev -y
```

### 3. Cài đặt Ryu Controller
```bash
pip3 install ryu
```

### 4. Cài đặt thư viện Machine Learning
Cài đặt các thư viện cần thiết thông qua file `requirements.txt`:
```bash
pip3 install -r requirements.txt
```

## 📋 Danh sách thư viện (Python Libraries)
Các thư viện chính được sử dụng trong dự án:
- `ryu`: Framework điều khiển SDN.
- `mininet`: Giả lập topo mạng.
- `pandas`, `numpy`: Xử lý dữ liệu.
- `scikit-learn`: Tiền xử lý dữ liệu và đánh giá model.
- `xgboost`: Thuật toán Boosting phát hiện tấn công.
- `tensorflow` hoặc `keras`: Xây dựng mạng nơ-ron Autoencoder.
- `matplotlib`, `seaborn`: Trực quan hóa dữ liệu.

## 🚀 Hướng dẫn chạy dự án

### Bước 1: Khởi động Ryu Controller
Mở một terminal và chạy controller để giám sát mạng:
```bash
ryu-manager controller/monitor.py
```

### Bước 2: Chạy Topo mạng Mininet
Mở terminal thứ hai và khởi tạo topo mạng:
```bash
sudo python3 topology/custom_topo.py
```

### Bước 3: Thu thập dữ liệu & Huấn luyện
1. Chạy các script trong `/src` để ghi lại traffic vào file CSV trong `/dataset`.
2. Sử dụng các notebook trong `/notebooks` để thực hiện EDA và huấn luyện model.

### Bước 4: Kiểm tra (Testing)
Sử dụng model đã lưu trong `/models` để dự đoán traffic trực tiếp từ controller.

## 📊 Kết quả & Báo cáo
Các kết quả đánh giá (Accuracy, Precision, Recall, F1-Score) và biểu đồ phân tích được lưu trong thư mục `/reports`.

---
**Khóa luận tốt nghiệp tại HUFLIT**
