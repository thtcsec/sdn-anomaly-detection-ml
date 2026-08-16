# Vá hội đồng — lý thuyết, sơ đồ, câu trả lời

Người dán Word: Trần Minh Thiện. Nói miệng: Trịnh Hoàng Tú.  
**Quyền khẳng định:** dữ liệu do nhóm tự thu trên Mininet. Chỉ nhận xét trên testbed này. Không suy ra SDN production. Không so “hơn bài báo X”.

Chèn 4 hình mới (đã sinh trong `reports/`):

| Chèn vào | File | Caption Word |
|----------|------|----------------|
| Ch.2, trước mô tả dataset | `reports/system_architecture_method.png` | Hình. Kiến trúc hệ thống: hai đường Control (thu CSV / realtime) trên cùng testbed Mininet–os-ken. |
| Ch.2 hoặc Ch.3 môi trường | `reports/network_topology_method.png` | Hình. Topology testbed: 2 Open vSwitch, 6 host `10.0.0.1–6`, controller os-ken cổng 6633. |
| Ch.2 thu thập | `reports/data_collection_pipeline_method.png` | Hình. Quy trình sinh CSV từ OpenFlow Flow Statistics đến `flow_stats_grouped.csv`. |
| Ch.2 method | `reports/input_method_pipeline_method.png` | Hình. Xử lý input và hai cấu hình đặc trưng (10 cột realtime / 8 cột LOSO). |

---

## A. Đoạn dán Chương 1 (lý thuyết nền — có citation)

### A1. SDN và OpenFlow (mở rộng 1.1)

Software-Defined Networking tách mặt phẳng điều khiển khỏi mặt phẳng dữ liệu [1], [8]. Ứng dụng và chính sách nằm ở Application Plane; quyết định định tuyến/cài rule nằm ở Controller; thiết bị chuyển mạch chỉ khớp Flow Table và chuyển tiếp gói. Giao thức southbound được dùng trong khóa luận là **OpenFlow 1.3** [8]: controller và switch trao đổi trên kênh điều khiển (testbed: TCP cổng **6633**).

Hai loại bản tin liên quan trực tiếp đến đề tài:

- **Packet-In / FlowMod:** gói chưa khớp table-miss được gửi lên controller; controller cài flow entry (learning switch lớp 3). Đây là đường *điều khiển chuyển tiếp*, không phải đường *học máy*.
- **Multipart Flow Statistics (`OFPFlowStatsRequest` / `OFPFlowStatsReply`):** controller *hỏi* switch về bộ đếm của từng flow đã cài. Đây là **input duy nhất** của mô hình. Khóa luận **không** bắt payload (không DPI), **không** dùng pcap làm đặc trưng.

Trong SDN, DDoS và quét cổng có thể vừa làm nhiễu Data Plane vừa tạo bão Packet-In / bão hòa Flow Table [6]. Khóa luận quan sát hệ quả đó ở mức **thống kê flow**, không mô hình hóa lỗi vật lý (đứt link, hỏng NIC, sai VLAN).

### A2. Mininet và Open vSwitch (thêm mục 1.x)

**Mininet** là trình giả lập mạng trên nhân Linux: mỗi host là namespace, mỗi switch là Open vSwitch, liên kết là veth. Mininet cho phép tái lập topology và sinh traffic có kiểm soát, nhưng **không đại diện production** (cùng máy, trễ/băng thông giả lập, không có nhiễu campus thật).

Topology khóa luận (`topology/custom_topo.py`):

- 2 switch OVS, protocol `OpenFlow13`: **s1** (h1–h3), **s2** (h4–h6), liên kết s1–s2.
- 6 host cố định: `10.0.0.1` … `10.0.0.6`.
- Controller từ xa: os-ken `127.0.0.1:6633`.

Mọi kịch bản thu thập **chỉ** dùng dải lab này.

### A3. os-ken (thêm mục 1.x)

**os-ken** là fork được duy trì của bộ điều khiển Ryu, viết bằng Python, hỗ trợ OpenFlow 1.3. Khóa luận dùng os-ken **4.2.0** như hai ứng dụng *tách nhau*, không chạy đồng thời một lúc trên cùng cổng:

| Ứng dụng | File | Việc |
|----------|------|------|
| Thu thập dataset | `controller/monitor.py` · `run_controller.py` | Poll 5 s, ghi `dataset/flow_stats.csv` |
| Prototype realtime | `controller/realtime_detector.py` · `run_realtime.py` | Suy luận XGBoost, cảnh báo, minh họa DROP |

Cả hai đều là `OSKenApp`, cài table-miss, học địa chỉ, gửi `OFPFlowStatsRequest` định kỳ. Khác nhau ở *đầu ra*: CSV có nhãn cửa sổ *versus* JSON dashboard + FlowMod DROP.

### A4. Bốn mô hình — baseline đã công bố, không phải đóng góp thuật toán

Khóa luận **không đề xuất** thuật toán mới [0.3]. Bốn mô hình là baseline kinh điển, chọn vì phủ hai họ tiếp cận trên dữ liệu dạng bảng:

**Random Forest** [3]. Tập hợp cây quyết định (bagging): mỗi cây học trên mẫu và tập đặc trưng ngẫu nhiên; dự đoán bằng bỏ phiếu. Ưu: ổn định trên tabular, ít cần chuẩn hóa. Nhược: suy luận chậm hơn boosting trên lab này (~15 ms/flow so với XGB ~0,33 ms).

**XGBoost** [4]. Gradient boosting trên cây: mỗi cây mới xấp xỉ phần dư của các cây trước, có regularize. Dùng cho bài **đa lớp** Normal / DDoS / Port Scan trên prototype, và bài **nhị phân** Normal–Attack trong LOSO. Được chọn gắn controller vì độ trễ suy luận thấp trên CPU lab.

**Isolation Forest** [5]. Không giám sát: cô lập điểm bằng cắt ngẫu nhiên; điểm bất thường có độ dài đường đi ngắn. Huấn luyện chủ yếu trên Normal; đầu ra nhị phân. Trên protocol LOSO của lab này mô hình **thất bại** (Acc ~0,08) và chỉ giữ để đối chứng.

**Autoencoder** (mạng tự mã hóa; cơ sở tái tạo [7]). Học nén–giải nén trên Normal; ngưỡng trên sai số tái tạo (MSE, percentile 95 tập Normal-train). Cũng là baseline nhị phân; trên LOSO lab **thất bại**, không triển khai realtime.

Đóng góp method: (i) tự thu Flow Statistics có `run_id` / `scenario_id`; (ii) đánh giá hold-out theo kịch bản (LOSO) thay vì random-split; (iii) prototype khép kín controller–mô hình–DROP trên testbed.

### A5. “Lỗi mạng” trong đề tài — siết phạm vi (dán đè 0.4)

Trong khóa luận, cụm từ “lỗi mạng” **không** theo nghĩa fault management (mất liên kết, mất gói vật lý, nghẽn hàng đợi, sai cấu hình). Thực nghiệm chỉ gồm **hai nhóm sự kiện an ninh lưu lượng** quan sát được trên Flow Statistics: tấn công từ chối dịch vụ (hping3) và quét cổng (nmap), đối chứng Normal (ping/iperf/HTTP). Đây là bài **phát hiện / phân loại bất thường lưu lượng SDN trên testbed**, không phải chẩn đoán lỗi vận hành mạng.

---

## B. Đoạn dán Chương 2 — thu thập, sinh CSV, xử lý input

### B1. Nguồn dữ liệu (mở 2.1 — bắt buộc)

Tập dữ liệu chính **do nhóm tự sinh** trên testbed Mininet–OVS–os-ken, không lấy nhãn từ CICIDS2017 hay InSDN [2]. InSDN/CICIDS nếu nhắc chỉ là *tài liệu liên quan*, không phải tập huấn luyện controller. Vì vậy mọi số Acc/F1 chỉ là **nhận xét thực nghiệm trên 19 kịch bản lab**, không phải khẳng định tổng quát.

### B2. Cách thu thập và sinh CSV

1. Operator ghi `dataset/current_label.txt` ∈ {`normal`, `ddos`, `portscan`} — nhãn **cửa sổ thời gian**, không phải từng gói.
2. Trên CLI Mininet, host chạy công cụ: ping, iperf, HTTP (Normal); hping3 SYN/UDP/ICMP (DDoS); nmap (Port Scan).
3. Switch OVS cài flow IPv4+L4 qua Packet-In/FlowMod.
4. Mỗi **5 giây**, `monitor.py` gửi `OFPFlowStatsRequest` tới mọi datapath.
5. Với mỗi flow có `ipv4_src` và `ipv4_dst`, controller tính:
   - `packet_count_per_sec = packet_count / duration`
   - `byte_count_per_sec = byte_count / duration`
   - `packet_size_avg = byte_count / packet_count`
   - `flow_duration = duration_sec + duration_nsec/1e9`
6. Một dòng được **append** vào `dataset/flow_stats.csv` kèm `timestamp`, `datapath_id`, 5-tuple, bộ đếm, nhãn cửa sổ.
7. Script `collect_independent_*_runs.py` cắt các dòng theo khoảng thời gian run, gắn `run_id`, `scenario_id`, tool, proto → `dataset/independent_runs/run_*.csv`.
8. `merge_independent_runs.py` hợp nhất (bỏ synthetic / massive) → **`dataset/flow_stats_grouped.csv`**: 79.114 snapshot, 32 run, 19 scenario.

Một phiên TCP sống 30 giây có thể sinh ~6 dòng (mỗi poll 5 s). **79.114 không phải 79.114 phiên độc lập.**

### B3. Xử lý input trước khi vào mô hình

- Lọc `is_synthetic=0`, loại `run_id` rỗng/unknown.
- 10 đặc trưng realtime: `ip_proto, tp_src, tp_dst, packet_count, byte_count, duration_sec, packet_count_per_sec, byte_count_per_sec, packet_size_avg, flow_duration`.
- Protocol chính LOSO **bỏ `tp_src`, `tp_dst`** (8 cột) để giảm việc mô hình học cổng do cách tạo traffic (hping3 `-p 80`, nmap dải cổng).
- StandardScaler fit trên fold/train tương ứng, không fit trên test.
- SMOTE **không** dùng trong LOSO; chỉ phụ lục random-split.

### B4. Method đánh giá (nói rõ trên sơ đồ)

- **Chính:** Leave-One-Scenario-Out, nhị phân Normal–Attack, 19 scenario, tối đa 3 poll đầu mỗi 5-tuple, không SMOTE.
- **Trung gian:** GroupKFold theo `run_id`.
- **Phụ lục:** random 80/20 — Acc ~0,9999 phản ánh rò cùng flow khi poll 5 s, không dùng làm kết luận.

---

## C. Tài liệu tham khảo — thêm vào cuối luận

Giữ [1]–[9]. Thêm:

[10] B. Lantz, B. Heller, and N. McKeown, “A network in a laptop: Rapid prototyping for software-defined networks,” ACM HotNets, 2010. *(Mininet)*  
[11] Open Networking Foundation, “OpenFlow Switch Specification 1.3.0,” 2012.  
[12] os-ken Project, “os-ken SDN framework,” documentation, version 4.2.0.  
[13] G. E. Hinton and R. R. Salakhutdinov, “Reducing the dimensionality of data with neural networks,” Science, vol. 313, pp. 504–507, 2006. *(cơ sở autoencoder)*  
[14] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, “Toward generating a new intrusion detection dataset and intrusion traffic characterization,” ICISSP, 2018. *(CICIDS — chỉ related work, không phải dữ liệu nhóm)*

---

## D. Trả lời miệng (20–40 giây / câu)

**Pipeline / sơ đồ hệ thống?**  
“Ba lớp. Data: Mininet 2 switch 6 host. Control: os-ken OpenFlow 1.3. App: dashboard. Có **hai** app controller: `monitor.py` ghi CSV; `realtime_detector.py` suy luận và DROP. Hình kiến trúc trong chương 2.”

**Input xử lý thế nào?**  
“Không pcap. Mỗi 5 giây hỏi Flow Statistics. Lấy bộ đếm gói/byte/thời gian, tính tốc độ và kích thước gói trung bình. LOSO bỏ cổng thô. Realtime prototype vẫn 10 feature — hai cấu hình này **không** được trộn khi đọc số.”

**Thành phần? Thu thập qua đâu? CSV sinh sao?**  
“Thành phần: Mininet, OVS, os-ken, 4 mô hình offline, Flask. Thu qua OpenFlow Multipart Flow Stats, không qua SPAN/pcap. CSV: mỗi reply → nhiều dòng append `flow_stats.csv` → cắt theo run → gộp `flow_stats_grouped.csv`.”

**Dữ liệu bài báo hay của mình?**  
“Của nhóm, trên Mininet. InSDN/CICIDS không train controller. Nên em **nhận xét** trên 19 kịch bản lab, không khẳng định SDN thật.”

**Độ tin cậy dữ liệu?**  
“Tái lập được: cùng topo, cùng tool, có `run_id`. Yếu: giả lập, nhãn theo cửa sổ không theo gói, chỉ 2 họ tấn công, 6 host cố định.”

**Dataset lỗi mạng? DDoS khác lỗi mạng?**  
“Đúng ạ. Dataset là bất thường lưu lượng (DDoS, Port Scan), không phải fault mất gói/đứt link. Đề tài dùng ‘lỗi mạng’ hẹp — nếu thầy yêu cầu, nhóm chỉnh tiêu đề/phạm vi thành phát hiện bất thường lưu lượng SDN.”

**Model không mới?**  
“Em không nhận là mới. XGB, RF, IF, AE là baseline [3][4][5][7]. Cái nhóm làm là quy trình thu–đánh giá LOSO–prototype trên cùng testbed.”

**Băng thông, gói tin?**  
“Có, nhưng ở mức flow: `byte_count`, `byte_count_per_sec`, `packet_count`, `packet_size_avg`. Không đo BER, không đo loss kernel, không gán nhãn ‘lỗi băng thông’.”

**Sao Acc demo khác 0,92?**  
“0,92 là LOSO offline 8 feature. Demo là prototype 10 feature đa lớp trên live poll. Hai số không thay thế nhau.”
