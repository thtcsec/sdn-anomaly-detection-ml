# Hướng dẫn quay video demo (Thiện)

Video **3–4 phút**. Demo là **prototype Mininet + XGBoost đang chạy** (10 feature, model legacy).  
**Không** đọc Acc 0,9999. **Không** nói FPR = 0%. **Không** bật `xgboost_robust` / không đổi model lúc quay.

Số khóa luận (bảng 4 model) nằm trong `HUONG_DAN_CHINH_SUA_KHOA_LUAN_DOCX_VA_SLIDES.md` — nói miệng nếu bị hỏi, **không** chèn lên overlay demo.

---

## 1. Cấm nói trong video

| Cấm | Thay bằng |
|-----|-----------|
| “Accuracy 99,99% / 100%” | “Prototype realtime trên lab Mininet” |
| “FPR = 0%” | Không nhắc FPR. Nếu Normal bị dính alert: cắt cảnh hoặc nói “lab, cần ngưỡng” |
| “Production / mạng trường” | “Testbed 2 switch, 6 host” |
| “Timeout 60 giây” | **120 giây** |
| “HTTP, DNS” khi chỉ bấm Normal | “ping / iperf” |
| Bật model Robust trong Cấu hình SOC | Giữ **XGBoost** mặc định |

---

## 2. Chuẩn bị màn hình

- Quay **1080p 30fps**: OBS / Win+G / CapCut.
- Trái ~50%: terminal (controller log + cửa sổ `mininet>` nếu có).
- Phải ~50%: Chrome `http://127.0.0.1:5000`.
- Trước khi quay: `selected_model` = `xgboost` (không `xgboost_robust`). Poll 5s, ngưỡng 3, timeout 120s, Auto-Mitigation **bật**.

### Khởi động (trước khi bấm Rec)

Cách nhanh: `start_demo.bat` từ thư mục project.

Hoặc 3 terminal WSL root:

```bash
# T1 — controller
cd /mnt/d/tu_projects/sdn-anomaly-detection-ml
source .venv/bin/activate
python controller/run_realtime.py
# Chờ: Active ML Model: XGBOOST

# T2 — dashboard
python dashboard/app.py
# Mở http://127.0.0.1:5000

# T3 — topology (nếu bat chưa mở)
sudo mn -c
/usr/bin/python3 topology/custom_topo.py
```

Kiểm tra: 4 KPI hiện, topology 2SW/6H, **không** alert đỏ sẵn.  
Mở **Cấu hình SOC**: không còn dòng `Accuracy: 99.91%` / `97.80%`. Phải thấy `10-feature multiclass` và latency `~0.33` / `~15.25 ms/flow`.

**Không dùng 3 nút Bắn traffic để quay thesis/video.** Gõ lệnh trong `mininet>` (mục 4). Nút dashboard chỉ gọi `scripts/trigger_traffic.py` khi Mininet đang chạy; toast “đã gửi lệnh” ≠ traffic thật.

---

## 3. Storyboard (5 cảnh)

### Cảnh 1 — Tổng quan (0:00–0:40)

Rê chuột: KPI → topology 2 switch 6 host → biểu đồ live.

**Overlay:**
> Prototype giám sát SDN OpenFlow 1.3 + XGBoost realtime  
> Poll flow stats 5 giây · lab Mininet 2 switch / 6 host

**Lời thoại (thu hoặc thuyết trình):**  
“Em demo hệ thống khép kín: controller os-ken đọc flow, XGBoost gắn nhãn, dashboard SOC. Đây là prototype lab, không phải IDS production.”

---

### Cảnh 2 — Normal (0:40–1:10)

Trong `mininet>`: `h1 ping -c 8 10.0.0.2` (hoặc iperf). **Không** bấm nút Bắn Normal.  
Cột prediction **NORMAL** xanh. Không DROP.

Nếu lỡ có alert đỏ: **cắt cảnh**, quay lại Normal. Đừng để lại rồi gắn chữ “FPR 0%”.

**Overlay:**
> Test 1: lưu lượng bình thường (ping / iperf)  
> Nhãn NORMAL · không kích hoạt DROP

---

### Cảnh 3 — DDoS + auto-block (1:10–2:20) — cảnh chính

Trong `mininet>`: `h4 hping3 -S --flood -p 80 10.0.0.1` (để ~15s rồi Ctrl+C). **Không** bấm nút Bắn DDoS. Host `h4` = `10.0.0.4` → `h1`.

Chờ 3 chu kỳ poll (~15s): alert 1 → 2 → 3 → **AUTO-BLOCKED 10.0.0.4**.  
Log controller: DROP priority cao, `hard_timeout` 120s. Traffic flood hạ.

**Overlay:**
> Test 2: DDoS SYN flood từ 10.0.0.4  
> 3 polling reply liên tiếp / 1 IP nguồn → cài luật DROP 120 giây

**Lời thoại:**  
“Cơ chế mitigation: cùng một IP nguồn bị gắn bất thường 3 lần poll thì controller đẩy rule DROP. Độ trễ suy luận XGBoost trên lab khoảng 0,4 ms; thời gian bắt phụ thuộc chu kỳ poll 5 giây.”

Không nói “phát hiện 100% mọi DDoS”.

---

### Cảnh 4 — Portscan (2:20–2:55)

Trong `mininet>`: `h6 nmap -sS -p 1-64 --max-rate 80 10.0.0.1`. **Không** bấm nút Bắn Portscan.  
Nhãn **PORTSCAN** cam, có log. Không cần block nếu chưa đủ 3 poll — không sao.

**Overlay:**
> Test 3: nmap portscan từ 10.0.0.6  
> Prototype gắn nhãn PORTSCAN trên lab

Không nói “dựa vào tp_dst nên luôn đúng”. Luận văn đã chỉ ra một kịch bản nmap hold-out bị sót.

---

### Cảnh 5 — Cấu hình SOC (2:55–3:30)

Mở **⚙️ Cấu hình SOC**. Chỉ **chỉ** (không lưu nếu làm hỏng demo):

- Polling 5s
- Ngưỡng 3
- Timeout **120s**
- Model **XGBoost - Realtime Prototype** (10-feature, ~0.33 ms/flow). Đừng đổi RF lúc quay. Không được thấy Acc 99.91%.

Có thể tắt/bật Auto-Mitigation một cái rồi bật lại.

**Overlay:**
> Cấu hình: poll 5s · ngưỡng 3 · DROP 120s · XGBoost prototype

---

## 4. Lệnh Mininet (cách chính khi quay / chụp luận văn)

Trong `mininet>`:

```bash
h1 ping -c 4 10.0.0.2
h4 hping3 -S --flood -p 80 10.0.0.1
# để ~15s, Ctrl+C
h6 nmap -sS -p 1-64 --max-rate 80 10.0.0.1
```

Chỉ IP `10.0.0.1`–`10.0.0.6`. Không scan máy thật / mạng trường.

---

## 5. Xuất bản

- Cắt đầu/đuôi chuẩn bị. Nhạc nền (nếu có) < 10%.
- File: `Demo_SDN_Anomaly_Detection_Tu_Thien.mp4` · 1080p.
- Thumbnail/title: “Prototype realtime Mininet” — không “Acc 99,99%”.

Hết video, nếu hội đồng hỏi số: mở bảng mục 2 file sửa Word (XGB F1-anom 0,954 · recall scenario 0,907 min 0,13 · Normal FPR 0,25). Demo và bảng là hai việc khác nhau — nói thẳng.
