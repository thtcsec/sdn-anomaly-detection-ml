# 🚀 HƯỚNG DẪN CHẠY DEMO HỆ THỐNG SDN ANOMALY DETECTION

---

## ⚡ CÁCH 1: KHỞI ĐỘNG NHANH 1-CLICK (KHUYÊN DÙNG)

Từ thư mục dự án trên Windows, bạn chỉ cần **nhấp đúp chuột vào file `start_demo.bat`** (hoặc gõ trong PowerShell):

```powershell
.\start_demo.bat
```
*Script sẽ tự động dọn sạch mạng cũ (`mn -c`) và mở sẵn 3 tab: Controller, Dashboard, và Mininet CLI.*

---

## 🛠️ CÁCH 2: COPY - PASTE THỦ CÔNG 3 TERMINAL

Mở 3 cửa sổ PowerShell và copy đúng các dòng sau:

### 🖥️ TERMINAL 1: Controller Realtime (Chạy trước tiên)
```bash
wsl -u root
cd /mnt/d/tu_projects/sdn-anomaly-detection-ml
source .venv/bin/activate
python controller/run_realtime.py
```
*(Chờ hiện dòng chữ xanh `[✓] Loaded XGBoost model successfully`)*

---

### 🖥️ TERMINAL 2: Dashboard Web
```bash
wsl -u root
cd /mnt/d/tu_projects/sdn-anomaly-detection-ml
source .venv/bin/activate
python dashboard/app.py
```
* Mở trình duyệt Web: **`http://127.0.0.1:5000`**

---

### 🖥️ TERMINAL 3: Mạng Mininet (Lưu ý dùng `/usr/bin/python3`)
```bash
wsl -u root
cd /mnt/d/tu_projects/sdn-anomaly-detection-ml
mn -c
/usr/bin/python3 topology/custom_topo.py
```
*(Chờ hiện dấu nhắc `mininet>`)*

---

## 🎯 CÁC LỆNH TEST KHI ĐANG Ở DẤU NHẮC `mininet>`:

### 1. Test Dò quét cổng (Portscan):
```bash
h4 nmap -sS -p 1-100 10.0.0.1
```
👉 *Xem Dashboard: Cột Attacks Detected nhảy số, hiện alert PORTSCAN màu cam.*

---

### 2. Test Tấn công DDoS & Auto-Mitigation (Tự động khóa IP):
```bash
h5 hping3 -S --flood -p 80 10.0.0.1
```
*(Để chạy 15-20s rồi bấm `Ctrl + C` để dừng)*

👉 *Xem Dashboard: Cột IPS BLOCKED nhảy lên 1, bảng Blocked IPs hiện `10.0.0.5` bị khóa.*

---

### 3. Kiểm chứng máy tấn công `h5` đã bị cách ly:
```bash
h5 ping -c 3 10.0.0.1
```
👉 *Kết quả: 100% packet loss (h5 không thể gửi gói tin đi đâu).*

```bash
h2 ping -c 3 10.0.0.1
```
👉 *Kết quả: 0% packet loss (người dùng bình thường h2 vẫn hoạt động bình thường).*

---

### 🛑 Thoát Mininet khi dừng demo:
```bash
exit
```
