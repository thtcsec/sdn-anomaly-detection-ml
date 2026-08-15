# 🎬 HƯỚNG DẪN QUAY VIDEO DEMO HỆ THỐNG SDN-ML SOC
*(Dành cho bạn Thiện thực hiện quay video báo cáo & thuyết trình khóa luận)*

---

## 📌 1. CHUẨN BỊ MÔI TRƯỜNG & BỐ CỤC MÀN HÌNH QUAY

### A. Công cụ quay video khuyến nghị:
- Sử dụng **OBS Studio** hoặc **Xbox Game Bar (Win + G)** hoặc **Camtasia / CapCut PC**.
- Độ phân giải: **1080p (1920x1080)**, 30fps hoặc 60fps.

### B. Bố cục màn hình (Split Screen chuyên nghiệp):
- **Bên Trái (50% màn hình):** Cửa sổ Terminal WSL / Mininet CLI (hiển thị controller logs, topology switches `s1`, `s2` và lệnh ping/hping3).
- **Bên Phải (50% màn hình):** Trình duyệt Web mở **Dashboard SOC** tại `http://localhost:5000`.

---

## 🚀 2. CÁCH KHỞI ĐỘNG HỆ THỐNG TRƯỚC KHI BẤM QUAY

1. Mở terminal WSL (hoặc PowerShell chạy `start_demo.bat`):
   ```bash
   # Bước 1: Dọn dẹp Mininet cũ
   sudo mn -c

   # Bước 2: Chạy Controller tích hợp AI Realtime
   cd /mnt/d/tu_projects/sdn-anomaly-detection-ml
   source .venv/bin/activate
   python controller/run_realtime.py

   # Bước 3: Chạy Web Dashboard
   python dashboard/app.py
   ```
2. Mở trình duyệt truy cập: `http://localhost:5000`
3. Kiểm tra thanh **Mininet Traffic Simulation Control** và nút **⚙️ Cấu hình SOC** đã hiển thị đầy đủ.

---

## 🎥 3. KỊCH BẢN QUAY VIDEO CHI TIẾT (STORYBOARD & TEXT CHÈN VÀO VIDEO)

Video dài khoảng **3 đến 4 phút**, chia làm **5 phân cảnh (Scene)** rõ ràng. Dưới đây là hành động và **Text phụ đề bắt buộc chèn vào video**:

---

### 🟢 SCENE 1: GIỚI THIỆU TỔNG QUAN HỆ THỐNG (0:00 - 0:45)
* **Hành động:** 
  - Quay toàn cảnh Dashboard giao diện SOC: 4 KPI Cards (Tổng số flow, Alerts, Tấn công bị chặn, Trạng thái Auto-Mitigation).
  - Rê chuột giới thiệu Topology mạng SDN 2 Switches, 6 Hosts và Biểu đồ Live Network Traffic Rate.
* **Text chèn vào video (Overlay Caption):**
  > **[Text Scene 1]:** *"HỆ THỐNG GIÁM SÁT VÀ PHÁT HIỆN TẤN CÔNG BẤT THƯỜNG TRÊN MẠNG SDN (OPENFLOW 1.3)"*  
  > *"Dashboard SOC tích hợp trí tuệ nhân tạo (XGBoost / Random Forest) giám sát lưu lượng luồng thời gian thực theo chu kỳ Polling.*

---

### 🟢 SCENE 2: THỰC THI LƯU LƯỢNG BÌNH THƯỜNG (NORMAL TRAFFIC) (0:45 - 1:20)
* **Hành động:** 
  - Trên thanh **Simulation Bar**, bấm nút **"🟢 Bắn Normal (iperf/ping)"**.
  - Dashboard hiển thị thông báo Toast xanh: *"Đang phát sinh lưu lượng Normal..."*
  - Biểu đồ **Live Traffic Rate** nhảy vọt lên ~50 - 100 p/s.
  - Cột AI Prediction hiển thị nhãn **NORMAL (Xanh lá)**, không phát sinh bất kỳ cảnh báo đỏ hay lệnh DROP nào.
* **Text chèn vào video (Overlay Caption):**
  > **[Text Scene 2]:** *"TEST 1: MÔ PHỎNG LƯU LƯỢNG BÌNH THƯỜNG (HTTP, DNS, IPERF, PING)"*  
  > *"AI phân loại chính xác nhãn NORMAL. Tỷ lệ cảnh báo giả FPR = 0%. Mạng hoạt động ổn định, không kích hoạt cơ chế chặn.*

---

### 🔴 SCENE 3: PHÁT HIỆN & TỰ ĐỘNG CHẶN TẤN CÔNG DDOS SYN FLOOD (1:20 - 2:15) *(PHÂN CẢNH QUAN TRỌNG NHẤT)*
* **Hành động:** 
  - Bấm nút **"🔴 Bắn DDoS (h4 SYN Flood)"**.
  - Host `h4` (IP `10.0.0.4`) bắt đầu bắn bão gói tin SYN về máy chủ `h1`.
  - Biểu đồ Live Traffic tăng vọt lên hàng nghìn packets/giây.
  - AI phát hiện ngay lập tức nhãn **DDOS (Đỏ)**, cột Alert Violation tăng lên 1 $\rightarrow$ 2 $\rightarrow$ 3.
  - Khi đạt ngưỡng (Alert Threshold = 3), bảng **Threat Alerts Log** kích hoạt còi báo động, xuất hiện nhãn **AUTO-BLOCKED IP 10.0.0.4**.
  - Controller tự động cài đặt luật **OpenFlow DROP Rule (Priority 65535, Timeout 60s)** xuống switch.
  - Lưu lượng tấn công rơi về 0 packets/giây ngay lập tức.
* **Text chèn vào video (Overlay Caption):**
  > **[Text Scene 3]:** *"TEST 2: PHÁT HIỆN & TỰ ĐỘNG NGĂN CHẶN DDOS SYN FLOOD (IP 10.0.0.4)"*  
  > *"Mô hình AI phát hiện luồng tấn công với độ trễ siêu thấp (< 0.4 ms). Kích hoạt cơ chế phòng vệ Auto-Mitigation: Tự động đẩy Flow Rule DROP xuống OpenFlow Switch để cô lập hoàn toàn kẻ tấn công.*

---

### 🟡 SCENE 4: PHÁT HIỆN TẤN CÔNG QUÉT CỔNG (PORTSCAN) (2:15 - 2:50)
* **Hành động:** 
  - Bấm nút **"🟡 Bắn Portscan (h6 Nmap)"**.
  - Host `h6` quét các cổng của toàn bộ dải mạng.
  - AI nhận diện chính xác nhãn **PORTSCAN (Vàng cam)** dựa trên đặc trưng số lượng flow ngắn và đa cổng đích (`tp_dst`).
  - Hệ thống ghi log cảnh báo và cập nhật ma trận tấn công.
* **Text chèn vào video (Overlay Caption):**
  > **[Text Scene 4]:** *"TEST 3: PHÁT HIỆN TẤN CÔNG THU THẬP THÔNG TIN (NMAP PORTSCAN)"*  
  > *"AI nhận diện chính xác hành vi quét cổng đa đích. Toàn bộ thông tin Flow ID, Switch DPID và IP nguồn được ghi nhận vào Threat Intelligence Log.*

---

### ⚙️ SCENE 5: THIẾT LẬP CẤU HÌNH SOC & ĐỔI MÔ HÌNH RUNTIME (2:50 - 3:30)
* **Hành động:** 
  - Bấm nút **"⚙️ Cấu hình SOC"** ở góc phải thanh công cụ.
  - Mở hộp thoại Modal:
    - Kéo thanh trượt **Chu kỳ giám sát (Polling Interval)** từ 5s về 2s.
    - Chỉnh **Ngưỡng vi phạm (Alert Threshold)** từ 3 về 2.
    - Chọn chuyển đổi qua lại giữa mô hình **XGBoost Classifier** và **Random Forest**.
    - Bật/Tắt chế độ **Auto-Mitigation Active Defense**.
  - Bấm **"Lưu cấu hình"** $\rightarrow$ Toast xanh báo *"Cập nhật cấu hình SOC thành công"*.
* **Text chèn vào video (Overlay Caption):**
  > **[Text Scene 5]:** *"QUẢN TRỊ LINH HOẠT: TÙY BIẾN CHU KỲ POLLING, NGƯỠNG BẢO VỆ & SWITCHING MÔ HÌNH AI"*  
  > *"Hệ thống cho phép cấu hình động thời gian giam giữ IP (Hard Timeout), độ nhạy cảnh báo và chuyển đổi mô hình ML trực tiếp mà không cần khởi động lại máy chủ.*

---

## ✂️ 4. XUẤT BẢN VIDEO & KIỂM TRA
- Cắt gọt phần đầu và đuôi video để không bị thừa thao tác chuẩn bị.
- Chèn nhạc nền nhẹ nhàng (nếu có, âm lượng < 10%).
- Xuất file định dạng: `Demo_SDN_Anomaly_Detection_Tu_Thien.mp4` (Full HD 1080p).
