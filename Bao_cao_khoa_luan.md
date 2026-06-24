# TRƯỜNG ĐẠI HỌC NGOẠI NGỮ - TIN HỌC TP. HỒ CHÍ MINH
## KHOA CÔNG NGHỆ THÔNG TIN

---

# KHÓA LUẬN TỐT NGHIỆP
### NGÀNH: AN NINH MẠNG

## ĐỀ TÀI: PHÁT HIỆN BẤT THƯỜNG VÀ PHÂN LOẠI LỖI MẠNG SDN BẰNG HỌC MÁY

**Sinh viên thực hiện:** 
*   Trịnh Hoàng Tú (MSSV: 23DH113972)
*   Trần Minh Thiện (MSSV: 23DH113375)

**Chuyên ngành:** An ninh mạng
**Khóa:** Khóa 29 – K29
**Giảng viên hướng dẫn:** ThS. Cao Tiến Thành

*TP. Hồ Chí Minh, tháng 05 năm 2026*

---

## MỤC LỤC
1. [Lời Cảm Ơn](#loi-cam-on)
2. [Phần Mở Đầu](#phan-mo-dau)
3. [Chương 1. Cơ Sở Lý Luận Và Thực Tiễn](#chuong-1-co-so-ly-luan-va-thuc-tien)
4. [Chương 2. Phương Pháp Và Dữ Liệu](#chuong-2-phuong-phap-va-du-lieu)
5. [Chương 3. Thực Nghiệm Và Đánh Giá](#chuong-3-thuc-nghiem-va-danh-gia)
6. [Chương 4. Kết Quả Thực Nghiệm](#chuong-4-ket-qua-thuc-nghiem)
7. [Kết Luận](#ket-luan)
8. [Bảng Phân Công Việc](#bang-phan-cong-viec)
9. [Tài Liệu Tham Khảo](#tai-lieu-tham-khao)

---

<a id="loi-cam-on"></a>
## LỜI CẢM ƠN
Lời đầu tiên, chúng em xin bày tỏ lòng biết ơn sâu sắc đến Trường Đại học Ngoại ngữ - Tin học TP. Hồ Chí Minh (HUFLIT) cùng quý thầy cô Khoa Công nghệ Thông tin đã tận tình giảng dạy, truyền đạt những kiến thức chuyên môn quý báu và tạo điều kiện thuận lợi cho chúng em trong suốt quá trình học tập và nghiên cứu tại trường. 

Đặc biệt, chúng em xin gửi lời cảm ơn chân thành nhất đến ThS. Cao Tiến Thành, người đã trực tiếp hướng dẫn, tận tình chỉ bảo và đưa ra nhiều định hướng quan trọng giúp nhóm hoàn thành đề tài này. Những góp ý chuyên môn, sự hỗ trợ và động viên của thầy không chỉ giúp chúng em vượt qua nhiều khó khăn trong quá trình nghiên cứu, xây dựng pipeline thực nghiệm và xử lý dữ liệu, mà còn giúp chúng em hình thành tư duy nghiên cứu khoa học nghiêm túc và có hệ thống hơn. 

Bên cạnh đó, chúng em cũng xin cảm ơn gia đình, bạn bè và các bạn sinh viên đã luôn đồng hành, hỗ trợ và động viên trong suốt quá trình thực hiện đề tài. Mặc dù đã cố gắng hoàn thiện báo cáo với tinh thần nghiêm túc và cầu thị, do kiến thức và kinh nghiệm nghiên cứu khoa học còn hạn chế nên bài báo khó tránh khỏi những thiếu sót. Chúng em rất mong nhận được những ý kiến đóng góp quý báu từ quý thầy cô và các nhà phản biện để có thể tiếp tục hoàn thiện nghiên cứu trong thời gian tới.

*TP. Hồ Chí Minh, ngày 28 tháng 05 năm 2026*
**Sinh viên thực hiện**
Trịnh Hoàng Tú - Trần Minh Thiện

---

<a id="phan-mo-dau"></a>
## PHẦN MỞ ĐẦU

### 0.1. Lý do chọn đề tài
Mạng định nghĩa bằng phần mềm (SDN) đang trở thành xu hướng tất yếu nhờ khả năng quản trị linh hoạt thông qua việc tách biệt tầng điều khiển (Control Plane) và tầng dữ liệu (Data Plane). Tuy nhiên, kiến trúc tập trung hóa này vô tình biến bộ điều khiển (Controller) thành điểm yếu duy nhất (Single Point of Failure). Các cuộc tấn công từ chối dịch vụ phân tán (DDoS) có thể dễ dàng làm tê liệt hệ thống bằng cách gây bão hòa bảng luồng hoặc làm quá tải tài nguyên xử lý. Các phương pháp bảo mật dựa trên ngưỡng tĩnh (Static Threshold) truyền thống tỏ ra kém hiệu quả trước các kỹ thuật tấn công zero-day tinh vi. Do đó, việc ứng dụng học máy (Machine Learning) để phát hiện bất thường và phân loại lỗi một cách tự động là yêu cầu cấp thiết để bảo vệ hạ tầng mạng hiện đại.

### 0.2. Mục đích nghiên cứu
Xây dựng một quy trình (Pipeline) hoàn chỉnh có khả năng phát hiện bất thường và phân loại các loại lỗi/tấn công trong môi trường SDN. Nghiên cứu tập trung vào việc so sánh hiệu năng thực tế giữa các mô hình học máy có giám sát và không giám sát, từ đó đề xuất một kiến trúc phát hiện đa tầng nhằm tối ưu hóa khả năng bảo vệ cho tầng điều khiển với độ trễ thấp nhất.

### 0.3. Lịch sử nghiên cứu vấn đề
Việc ứng dụng học máy trong SDN đã được cộng đồng quốc tế quan tâm từ lâu. Các nghiên cứu điển hình bao gồm việc sử dụng Isolation Forest để giải quyết vấn đề dữ liệu mất cân bằng trong lưu lượng mạng, hay Autoencoder để trích xuất đặc trưng tự động mà không cần dán nhãn. Các thuật toán như Random Forest và XGBoost cũng đã chứng minh được độ chính xác vượt trội trong việc phân loại các biến thể của tấn công DDoS so với các phương pháp học sâu phức tạp nhưng tốn kém tài nguyên.

### 0.4. Đối tượng nghiên cứu và phạm vi nghiên cứu
*   **Đối tượng:** Các dòng lưu lượng mạng (Flow-based) dựa trên giao thức OpenFlow và các thuật toán học máy (XGBoost, Isolation Forest, Autoencoder).
*   **Phạm vi:** Thực nghiệm trên tập dữ liệu mô phỏng trong môi trường mạng giả lập bằng Mininet, sử dụng bộ điều khiển Ryu/os-ken.

### 0.5. Phương pháp nghiên cứu
Nghiên cứu kết hợp giữa lý thuyết và thực nghiệm:
*   **Thu thập dữ liệu:** Sử dụng tập dữ liệu sinh ra từ môi trường thực tế giả lập thông qua các kịch bản bình thường và tấn công.
*   **Tiền xử lý:** Trích xuất các đặc trưng dòng (Flow features) và chuẩn hóa dữ liệu, áp dụng kỹ thuật cân bằng dữ liệu SMOTE.
*   **Huấn luyện:** Áp dụng mô hình học máy có giám sát (XGBoost) cho phân loại đa lớp và học máy không giám sát (Isolation Forest, Autoencoder) cho phát hiện bất thường nhị phân.
*   **Đánh giá:** Sử dụng các chỉ số Accuracy, Precision, Recall, F1-Score, và đường cong ROC/AUC.

### 0.6. Ý nghĩa khoa học và thực tiễn
*   **Khoa học:** Chứng minh giá trị thực tiễn và hiệu suất của các mô hình học máy so với phương pháp Baseline dựa trên luật tĩnh truyền thống.
*   **Thực tiễn:** Cung cấp mô hình khả thi để triển khai trực tiếp trên SDN Controller với chi phí tính toán thấp và độ trễ tối thiểu.

### 0.7. Bố cục của khóa luận
Khóa luận được cấu trúc thành 4 chương chính cùng phần mở đầu, kết luận và phụ lục.

---

<a id="chuong-1-co-so-ly-luan-va-thuc-tien"></a>
## CHƯƠNG 1. CƠ SỞ LÝ LUẬN VÀ THỰC TIỄN

### 1.1. Kiến trúc mạng định nghĩa bằng phần mềm (SDN)
Kiến trúc mạng định nghĩa bằng phần mềm (Software-Defined Networking - SDN) phân tách mạng thành ba lớp độc lập:
*   **Lớp ứng dụng (Application Plane):** Chứa các ứng dụng mạng như tường lửa, cân bằng tải, giám sát.
*   **Lớp điều khiển (Control Plane):** Chứa bộ điều khiển trung tâm (Controller), đóng vai trò bộ não đưa ra quyết định định tuyến.
*   **Lớp dữ liệu (Data Plane):** Gồm các thiết bị phần cứng chuyển mạch (Switches/Routers) chỉ làm nhiệm vụ chuyển tiếp gói tin theo bảng luồng (Flow Table).
*   **Giao thức OpenFlow:** Cung cấp chuẩn giao tiếp chuẩn hóa giữa bộ điều khiển và các thiết bị chuyển mạch ở lớp dữ liệu.

### 1.2. Các thách thức và lỗ hổng bảo mật trong SDN
Kiến trúc SDN tập trung hóa mang lại sự linh hoạt nhưng cũng tạo ra các lỗ hổng bảo mật nghiêm trọng:
*   **Tấn công DDoS vào Control Plane:** Kẻ tấn công gửi số lượng lớn các gói tin mới (chưa có trong bảng luồng) đến Switch. Switch sẽ gửi các yêu cầu Packet-In liên tục về Controller, gây bão hòa băng thông liên kết điều khiển và làm quá tải CPU của Controller.
*   **Bão hòa bảng luồng (Flow Table Saturation) ở Data Plane:** Thiết bị switch có dung lượng bảng luồng (Flow Table) giới hạn. Kẻ tấn công có thể sinh ra hàng triệu luồng giả tạo để lấp đầy bảng luồng, ngăn cản các luồng hợp lệ được xử lý.

### 1.3. Ứng dụng Học máy trong phát hiện bất thường SDN
Học máy đóng vai trò quan trọng trong việc phân tích các mẫu đặc trưng của luồng OpenFlow để phân biệt lưu lượng bình thường và bất thường:
*   **Mô hình có giám sát (XGBoost):** Sử dụng các cây quyết định tăng cường Gradient (Gradient Boosting Trees) để thiết lập ranh giới phân loại chính xác các kiểu tấn công đã biết như DDoS và Port Scan dựa trên dữ liệu dán nhãn.
*   **Mô hình không giám sát (Autoencoder):** Sử dụng mạng nơ-ron sâu tự mã hóa để học cấu trúc dữ liệu Normal, phát hiện bất thường thông qua sai số tái tạo lớn.
*   **Thuật toán Isolation Forest:** Được đề xuất bởi Liu và cộng sự [5] vào năm 2008 là một hướng tiếp cận học máy không giám sát hiệu quả. Khác với các phương pháp phát hiện bất thường truyền thống cố gắng định nghĩa phân phối của dữ liệu bình thường, Isolation Forest cô lập trực tiếp các điểm bất thường bằng cách xây dựng các cây nhị phân ngẫu nhiên (Isolation Trees - iTrees). Do các điểm bất thường (anomalies) chiếm tỷ lệ nhỏ và có các đặc trưng khác biệt đáng kể so với dữ liệu bình thường, chúng sẽ dễ bị cô lập hơn trong quá trình phân hoạch ngẫu nhiên. Hệ quả là, các điểm bất thường này sẽ nằm gần gốc của cây hơn, tương ứng với chiều dài đường đi (path length) từ gốc đến lá ngắn hơn rõ rệt so với các điểm dữ liệu bình thường.

---

<a id="chuong-2-phuong-phap-va-du-lieu"></a>
## CHƯƠNG 2. PHƯƠNG PHÁP VÀ DỮ LIỆU

### 2.1. Mô tả tập dữ liệu
Tập dữ liệu thực nghiệm gồm **10.883 mẫu** lưu lượng mạng được thu thập từ môi trường SDN giả lập bằng Mininet kết hợp với Ryu/os-ken Controller. Dataset bao gồm:
*   **10.565 mẫu Portscan**
*   **312 mẫu Normal**
*   **6 mẫu DDoS**

Các mẫu dữ liệu được trích xuất dưới dạng Flow Statistics từ giao thức OpenFlow và sử dụng cho quá trình huấn luyện và đánh giá mô hình học máy.

### 2.2. Tiền xử lý dữ liệu
Quá trình tiền xử lý dữ liệu (Data Preprocessing) đóng vai trò quyết định đến độ chính xác và khả năng hội tụ của các mô hình học máy. Dữ liệu dòng chảy thô thu thập từ OpenFlow switch (`dataset/flow_stats.csv`) được đưa qua một pipeline tiền xử lý nghiêm ngặt bao gồm các giai đoạn sau:

*   **Làm sạch dữ liệu (Data Cleaning):**
    *   *Xử lý trùng lặp (Handling Duplicates):* Do các switches định kỳ gửi thông số thống kê luồng mạng về Controller, tập dữ liệu thô có thể xuất hiện các bản ghi trùng lặp thông tin đặc trưng khi không có lưu lượng mới phát sinh. Các dòng trùng lặp được loại bỏ hoàn toàn bằng hàm `drop_duplicates()`.
    *   *Xử lý giá trị khuyết thiếu (Handling Missing Values):* Các bản ghi có bất kỳ thuộc tính nào bị khuyết thiếu (NaN) đều bị loại bỏ hoàn toàn qua hàm `dropna()` nhằm đảm bảo tính toàn vẹn của không gian đặc trưng.
*   **Lựa chọn đặc trưng (Feature Selection):** Loại bỏ các thông tin phi số học, không đóng góp trực tiếp vào khả năng phân biệt hành vi mạng như timestamp, địa chỉ IP nguồn/đích dạng chuỗi ký tự, và mã định danh switch (`datapath_id`). Nghiên cứu trích xuất 10 đặc trưng số học cốt lõi phục vụ huấn luyện:
    1.  `ip_proto`: Giao thức tầng mạng (1: ICMP, 6: TCP, 17: UDP).
    2.  `tp_src` & `tp_dst`: Cổng truyền thông nguồn và đích.
    3.  `packet_count`: Tổng số gói tin trong dòng chảy.
    4.  `byte_count`: Tổng số byte dữ liệu trong dòng chảy.
    5.  `duration_sec`: Thời gian sống của dòng chảy (tính bằng giây).
    6.  `packet_count_per_sec`: Tốc độ gói tin trung bình trên giây.
    7.  `byte_count_per_sec`: Tốc độ băng thông truyền tải trung bình trên giây.
    8.  `packet_size_avg`: Kích thước trung bình của một gói tin trong luồng.
    9.  `flow_duration`: Tổng thời gian thực tế dòng chảy tồn tại (kết hợp cả giây và nano giây).
*   **Chuẩn hóa dữ liệu (Feature Scaling):** Do các đặc trưng có biên độ dao động và đơn vị đo khác nhau (ví dụ: `byte_count` có thể lên đến hàng triệu trong khi `ip_proto` chỉ dao động từ 1 đến 17), mô hình có xu hướng bị lấn át bởi các thuộc tính có giá trị lớn. Nghiên cứu sử dụng phương pháp chuẩn hóa `StandardScaler` để đưa dữ liệu về phân phối chuẩn có giá trị trung bình bằng 0 và độ lệch chuẩn bằng 1 theo công thức:
    $$z = \frac{x - \mu}{\sigma}$$
    Trong đó, $\mu$ là giá trị trung bình và $\sigma$ là độ lệch chuẩn của đặc trưng trên tập huấn luyện.
*   **Cân bằng dữ liệu (Oversampling với SMOTE):** Tập dữ liệu thô đối mặt với hiện tượng mất cân bằng phân lớp cực kỳ nghiêm trọng (lớp đa số Portscan chiếm đến 10.565 mẫu, trong khi lớp Normal chỉ có 312 mẫu và lớp DDoS chỉ có 6 mẫu). Nếu huấn luyện trực tiếp, mô hình sẽ bị thiên vị (bias) nặng nề về phía lớp Portscan. Để giải quyết vấn đề này, kỹ thuật SMOTE (Synthetic Minority Over-sampling Technique) được áp dụng. Thay vì sao chép các mẫu có sẵn (dễ gây overfitting), SMOTE tạo ra các mẫu nhân tạo mới bằng cách nội suy tuyến tính giữa các mẫu thuộc lớp thiểu số và các lân cận gần nhất của chúng theo công thức:
    $$x_{new} = x_i + \lambda \times (x_{zi} - x_i)$$
    Với $\lambda \in [0,1]$ là số ngẫu nhiên và $x_{zi}$ là một trong $k$ lân cận gần nhất của mẫu lớp thiểu số $x_i$.
    
    > [!IMPORTANT]
    > **Quy tắc thực nghiệm cốt lõi:** Kỹ thuật SMOTE chỉ được áp dụng duy nhất trên tập huấn luyện (Train set), tuyệt đối không áp dụng trên tập kiểm thử (Test set) để tránh hiện tượng rò rỉ thông tin (Data Leakage) và đảm bảo tính khách quan của kết quả đánh giá.
*   **Phân chia dữ liệu (Train/Test Split):** Dữ liệu được phân chia theo tỷ lệ 80% huấn luyện (Train Set) và 20% kiểm thử (Test Set). Quá trình phân chia sử dụng cơ chế phân tầng (`stratify=y_encoded`) nhằm đảm bảo tỷ lệ phân phối giữa các nhãn ở cả tập train và tập test đồng nhất với tỷ lệ của dataset gốc.

### 2.3. Mô hình XGBoost
Mô hình học máy có giám sát (Supervised Learning) được lựa chọn là XGBoost (eXtreme Gradient Boosting). Đây là một thuật toán tối ưu hóa dựa trên nền tảng cây quyết định tăng cường Gradient (Gradient Boosting Decision Trees - GBDT), nổi bật với tốc độ xử lý nhanh và hiệu năng vượt trội trên dữ liệu dạng bảng (Tabular Data).

*   **Nguyên lý hoạt động:** XGBoost xây dựng mô hình dự đoán theo phương pháp Ensemble Learning (Học kết hợp tuần tự). Thuật toán liên tục thêm các cây quyết định yếu (Weak Learners) mới để dự đoán sai số (Residuals) của các cây trước đó. Hàm mục tiêu tối ưu hóa tại bước thứ $t$ có dạng:
    $$\mathcal{L}^{(t)} = \sum_{i=1}^n l\left(y_i, \hat{y}_i^{(t-1)} + f_t(x_i)\right) + \Omega(f_t)$$
    Trong đó, $l$ là hàm mất mát đo lường sai số giữa nhãn thực tế $y_i$ và giá trị dự đoán $\hat{y}_i^{(t-1)}$. Thành phần thứ hai $\Omega(f_t)$ là hàm phạt chuẩn hóa (Regularization) kiểm soát độ phức tạp của cây quyết định nhằm chống quá khớp (Overfitting):
    $$\Omega(f_t) = \gamma T + \frac{1}{2} \lambda \sum_{j=1}^T w_j^2$$
    Với $T$ là số lượng lá cây và $w_j$ là trọng số tại mỗi lá, $\gamma$ và $\lambda$ là các siêu tham số điều khiển mức độ phạt. XGBoost sử dụng khai triển Taylor bậc hai để xấp xỉ nhanh chóng hàm mục tiêu này trong quá trình tối ưu hóa trọng số lá.
*   **Thiết lập các siêu tham số (Hyperparameters):** Trong nghiên cứu này, các siêu tham số của mô hình được tinh chỉnh thực nghiệm như sau:
    *   `n_estimators = 200`: Xây dựng tối đa 200 cây quyết định tuần tự để học các ranh giới phân loại phức tạp.
    *   `max_depth = 6`: Giới hạn chiều sâu tối đa của mỗi cây bằng 6 lớp để kiểm soát độ phức tạp, tránh việc cây quá sâu dẫn đến overfitting.
    *   `learning_rate = 0.1`: Tốc độ học (hay hệ số co ngót - shrinkage factor) đóng vai trò kiểm soát mức độ đóng góp của từng cây mới vào mô hình tổng thể, giúp quá trình hội tụ diễn ra ổn định.
    *   `subsample = 0.8`: Mỗi cây quyết định chỉ sử dụng ngẫu nhiên 80% số lượng mẫu huấn luyện để tăng tính đa dạng và giảm độ tương quan giữa các cây.
    *   `colsample_bytree = 0.8`: Lựa chọn ngẫu nhiên 80% số lượng đặc trưng khi xây dựng mỗi cây quyết định nhằm nâng cao khả năng tổng quát hóa của mô hình đối với các đặc trưng phụ.
    *   `eval_metric = 'mlogloss'`: Sử dụng hàm mất mát Entropy chéo đa lớp (Multiclass Logarithmic Loss) làm tiêu chí đánh giá và tối ưu hóa chính trong suốt các vòng lặp huấn luyện.

### 2.4. Mô hình Autoencoder
Đối với bài toán phát hiện bất thường không giám sát (Unsupervised Learning) nhằm nhận diện các mẫu tấn công zero-day chưa từng xuất hiện trong tập huấn luyện, nghiên cứu triển khai mạng nơ-ron học sâu Autoencoder.

*   **Kiến trúc mạng:** Mạng Autoencoder được xây dựng với cấu trúc đối xứng bao gồm hai phần chính:
    *   *Encoder (Bộ mã hóa):* Nhận đầu vào là vector đặc trưng dòng chảy OpenFlow có số chiều ban đầu $D_{in}=10$. Mạng nén dữ liệu qua các lớp ẩn dày đặc (Dense Layers) giảm dần số lượng nơ-ron: $10 \rightarrow 8 \rightarrow 6 \rightarrow 4$. Lớp cuối cùng có 4 nơ-ron được gọi là không gian ẩn hoặc nút thắt cổ chai (Bottleneck / Latent Space Representation), nơi lưu giữ các đặc trưng nén cô đọng nhất của luồng dữ liệu hợp lệ.
    *   *Decoder (Bộ giải mã):* Nhận vector nén từ không gian ẩn và tiến hành tái cấu trúc lại dữ liệu qua các lớp ẩn có số nơ-ron tăng dần đối xứng: $4 \rightarrow 6 \rightarrow 8 \rightarrow 10$. Lớp đầu ra có số chiều $D_{out} = 10$ khớp hoàn toàn với đầu vào ban đầu.
*   **Hàm kích hoạt:** Các lớp ẩn sử dụng hàm kích hoạt ReLU để tăng tính phi tuyến tính cho mạng và tránh hiện tượng triệt tiêu đạo hàm (vanishing gradient). Lớp đầu ra giải mã sử dụng hàm kích hoạt tuyến tính (Linear) để khôi phục chính xác các giá trị số học ban đầu của đặc trưng.
*   **Hàm mất mát (Loss Function):** Mô hình được huấn luyện chỉ với dữ liệu lưu lượng bình thường (Normal). Hàm mất mát được sử dụng là sai số bình phương trung bình (Mean Squared Error - MSE) giữa dữ liệu đầu vào $x$ và dữ liệu giải mã tái tạo $\hat{x}$:
    $$MSE = \frac{1}{d} \sum_{i=1}^d (x_i - \hat{x}_i)^2$$
    Với $d = 10$ là số lượng đặc trưng. Khi mô hình đã học tốt cấu trúc phân phối của dữ liệu Normal, nó sẽ tái tạo các luồng dữ liệu bình thường với sai số MSE cực kỳ nhỏ. Ngược lại, khi gặp các lưu lượng tấn công lạ có phân phối khác biệt, mô hình không thể tái tạo tốt và sẽ trả về sai số MSE lớn.
*   **Xác định ngưỡng phát hiện (Threshold Assignment):** Sau khi huấn luyện mô hình Autoencoder trên tập dữ liệu Normal sạch, sai số MSE tái tạo được tính toán trên toàn bộ tập huấn luyện Normal. Ngưỡng phát hiện bất thường (Threshold) được lựa chọn tại phân vị thứ 95 (95th percentile) của phân phối sai số này (đạt giá trị thực nghiệm là $2.355$).
    *   Nếu một luồng dữ liệu mới có $MSE > Threshold$: Hệ thống phân loại là bất thường (Anomaly / Tấn công).
    *   Nếu một luồng dữ liệu mới có $MSE \le Threshold$: Hệ thống phân loại là bình thường (Normal).
*   **Cơ chế dừng sớm (EarlyStopping):** Để tối ưu hóa thời gian huấn luyện và ngăn chặn hiện tượng quá khớp dữ liệu huấn luyện (overfitting), một callback `EarlyStopping` được tích hợp với các thông số:
    *   `monitor = 'val_loss'`: Giám sát hàm mất mát trên tập kiểm định (Validation set).
    *   `patience = 10`: Nếu validation loss không giảm liên tiếp trong vòng 10 epochs, quá trình huấn luyện sẽ dừng lại ngay lập tức.
    *   `restore_best_weights = True`: Khi dừng sớm, mô hình sẽ tự động khôi phục và lưu lại bộ trọng số (weights) tối ưu nhất tại epoch có validation loss thấp nhất thay vì bộ trọng số của epoch cuối cùng.

### 2.5. Mô hình Isolation Forest
Để bổ sung vào tập hợp các phương pháp học không giám sát (Unsupervised Learning) nhằm phát hiện bất thường với độ phức tạp tính toán thấp hơn so với học sâu mạng nơ-ron, nghiên cứu triển khai mô hình Isolation Forest.

*   **Nguyên lý thuật toán:** Isolation Forest hoạt động bằng cách xây dựng một tập hợp các cây cô lập (Isolation Trees - iTrees). Đối với mỗi iTree, dữ liệu được phân hoạch ngẫu nhiên bằng cách chọn ngẫu nhiên một đặc trưng và sau đó chọn ngẫu nhiên một giá trị phân chia giữa giá trị nhỏ nhất và lớn nhất của đặc trưng đó. Quá trình này lặp lại cho đến khi tất cả các điểm dữ liệu được cô lập hoàn toàn. Điểm bất thường (Anomaly) sẽ có chiều dài đường đi trung bình $E(h(x))$ trên các cây ngắn hơn rõ rệt so với các điểm dữ liệu bình thường.
    Điểm bất thường (Anomaly Score) $s$ của một mẫu $x$ trên tập dữ liệu gồm $n$ mẫu được định nghĩa bởi công thức:
    $$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
    Trong đó $h(x)$ là độ dài đường đi của mẫu $x$ trong một cây, $E(h(x))$ là giá trị trung bình của $h(x)$ qua toàn bộ rừng các cây cô lập, và $c(n)$ là độ dài đường đi trung bình của một lần tìm kiếm không thành công trong cây nhị phân tìm kiếm được xây dựng từ $n$ nút:
    $$c(n) = 2 \ln(n - 1) + 0.5772156649 - \frac{2(n - 1)}{n}$$
    Giá trị $s$ nằm trong khoảng $[0, 1]$. Nếu điểm số $s$ gần 1, mẫu dữ liệu có khả năng rất cao là bất thường. Nếu $s$ nhỏ hơn 0.5, mẫu dữ liệu được xem là bình thường.
*   **Thiết lập siêu tham số (Hyperparameters):**
    *   `n_estimators = 200`: Thiết lập số lượng cây cô lập trong rừng bằng 200 để đảm bảo điểm số bất thường hội tụ ổn định và giảm thiểu biến động ngẫu nhiên.
    *   `contamination = 0.05`: Xác định tỷ lệ bất thường dự kiến trong tập dữ liệu huấn luyện là 5%, tương ứng với việc huấn luyện mô hình chủ yếu trên dữ liệu Normal sạch.
*   **So sánh ưu và nhược điểm giữa Isolation Forest và Autoencoder:**
    *   *Isolation Forest:*
        *   *Ưu điểm:* Cấu trúc thuật toán đơn giản, tốc độ huấn luyện và dự đoán cực kỳ nhanh, tiêu thụ ít tài nguyên tính toán (CPU/RAM) và không yêu cầu phần cứng GPU. Rất hiệu quả và ổn định đối với dữ liệu dạng bảng (Tabular) có không gian đặc trưng hẹp, ít bị ảnh hưởng bởi việc tinh chỉnh tham số.
        *   *Nhược điểm:* Khó biểu diễn các mối quan hệ phi tuyến phức tạp trong không gian đa chiều do cơ chế phân hoạch chỉ thực hiện song song với các trục đặc trưng.
    *   *Autoencoder:*
        *   *Ưu điểm:* Có khả năng học sâu và trích xuất các đặc trưng phi tuyến tính phức tạp ở mức độ cao thông qua cấu trúc mạng nơ-ron nhiều lớp ẩn.
        *   *Nhược điểm:* Thời gian huấn luyện lâu hơn nhiều, chi phí tính toán cao, nhạy cảm với việc định cấu hình siêu tham số (số lớp ẩn, số nơ-ron, hàm kích hoạt) và dễ bị lỗi khi không gian đặc trưng OpenFlow quá hẹp.

---

<a id="chuong-3-thuc-nghiem-va-danh-gia"></a>
## CHƯƠNG 3. THỰC NGHIỆM VÀ ĐÁNH GIÁ

### 3.1. Môi trường thực nghiệm
Để đảm bảo tính nhất quán, khả năng tái lập kết quả và khả năng vận hành đồng bộ của toàn bộ hệ thống, nghiên cứu thiết lập môi trường thực nghiệm đồng nhất về cả phần cứng lẫn phần mềm như sau:

*   **Hệ điều hành chủ (Host OS):** Windows 11 Professional (64-bit).
*   **Môi trường giả lập (Simulated Environment):** Windows Subsystem for Linux 2 (WSL2) chạy phân phối Ubuntu 22.04.5 LTS nhằm đảm bảo môi trường Linux thuần cho việc thực thi SDN Controller và Mininet.
*   **Phần cứng thực nghiệm (Hardware Configuration):**
    *   *CPU:* AMD Ryzen 7 5800H (8 nhân, 16 luồng, xung nhịp 3.20 GHz - 4.40 GHz).
    *   *RAM:* 16 GB DDR4 Dual-Channel (tốc độ bus 3200 MHz).
    *   *Lưu trữ:* SSD NVMe M.2 dung lượng 512 GB.
*   **Công cụ và các phiên bản phần mềm hệ thống:**
    *   *Mininet (v2.3.0):* Công cụ giả lập mạng SDN chính, kết hợp với Open vSwitch kernel module để khởi tạo switch ảo hỗ trợ giao thức OpenFlow phiên bản 1.3.
    *   *SDN Controller Framework - os-ken (v4.3.0):* Một fork chính thức của Ryu Controller do OpenStack bảo trì, hỗ trợ Python 3.10+ để định cấu hình định tuyến và thu thập trạng thái mạng từ xa thông qua giao thức OpenFlow.
    *   *Python (v3.12.3):* Ngôn ngữ lập trình chính được chạy độc lập bên trong môi trường ảo hóa Virtual Environment (`.venv`).
*   **Thư viện phân tích dữ liệu và Học máy (Python Packages):**
    *   `xgboost (v2.0.3)`: Thư viện huấn luyện mô hình XGBoost.
    *   `tensorflow / keras (v2.16.1)`: Xây dựng và tối ưu hóa kiến trúc học sâu Autoencoder.
    *   `scikit-learn (v1.4.2)`: Tiền xử lý dữ liệu (`StandardScaler`, `LabelEncoder`, `train_test_split`) và tính toán các chỉ số đánh giá hiệu năng.
    *   `imbalanced-learn (v0.12.2)`: Áp dụng thuật toán SMOTE để cân bằng dữ liệu.
    *   `pandas (v2.2.2)` & `numpy (v1.26.4)`: Đọc, ghi và tính toán ma trận dữ liệu dạng bảng.
    *   `matplotlib (v3.8.4)` & `seaborn (v0.13.2)`: Vẽ biểu đồ trực quan hóa dữ liệu thực nghiệm.
*   **Công cụ sinh traffic và tấn công mạng:**
    *   `ping` & `iperf (v2.0.14)`: Giả lập kết nối mạng thông thường và kiểm tra băng thông truyền tải TCP/UDP hợp lệ.
    *   `hping3 (v3.0.0-alpha-2)`: Công cụ flood gói tin tốc độ cao để giả lập tấn công từ chối dịch vụ DDoS (TCP SYN flood, UDP flood, ICMP flood).
    *   `nmap (v7.92)`: Quét cổng dịch vụ để thực hiện tấn công Portscan thu thập thông tin mạng.

### 3.2. Quy trình thực nghiệm
Quy trình thực nghiệm được tiến hành khép kín theo chu trình 8 bước tuần tự nhằm mô phỏng lưu lượng, thu thập dữ liệu và huấn luyện mô hình học máy:

*   **Bước 1: Khởi động SDN Controller.** Thực thi script launcher `src/run_realtime.py` (hoặc `controller/run_controller.py`) để khởi chạy bộ điều khiển os-ken. Bộ điều khiển mở cổng dịch vụ TCP 6633 lắng nghe các Switch kết nối thông qua giao thức OpenFlow 1.3.
*   **Bước 2: Khởi chạy Topology mạng.** Khởi động môi trường Mininet qua script `topology/custom_topo.py` dưới quyền root (`sudo`). Script sẽ thiết lập topo 2 Switch ảo (`s1`, `s2`) kết nối trực tiếp với nhau và kết nối đồng thời về bộ điều khiển từ xa (Remote Controller) ở localhost. 6 host (`h1` đến `h6`) được cấp phát địa chỉ IP và địa chỉ MAC cố định.
*   **Bước 3: Giả lập lưu lượng và kích hoạt các kịch bản tấn công.** Sử dụng công cụ tự động hóa `auto_traffic.py` (hoặc `collect_data.py`) để chạy tuần tự các kịch bản thực nghiệm:
    *   *Lưu lượng bình thường (Normal):* Kích hoạt dịch vụ Web (HTTP Server) trên `h3`, cho `h1` liên tục gửi các yêu cầu truy cập `curl http://10.0.0.3/` kết hợp chạy dịch vụ đo băng thông `iperf` giữa `h1` và `h2` trong vòng 60 giây.
    *   *Tấn công DDoS:* Chạy `hping3 --flood` từ `h4` và `h5` nhắm thẳng vào `h1` và `h2` trong vòng 30 giây để giả lập bão hòa bảng luồng.
    *   *Tấn công Portscan:* Cho `h6` sử dụng lệnh `nmap -sS` quét toàn bộ dải cổng của `h1` trong 30 giây.
*   **Bước 4: Thu thập số liệu luồng mạng (Flow Stats).** Trong suốt thời gian mạng hoạt động, ứng dụng `monitor.py` chạy trên controller sẽ gửi các bản tin truy vấn trạng thái luồng định kỳ mỗi 5 giây. Khi nhận được bản tin phản hồi từ switches, ứng dụng trích xuất các đặc trưng và ghi trực tiếp vào cơ sở dữ liệu `dataset/flow_stats.csv`. Đồng thời, các mốc thời gian bắt đầu và kết thúc của từng kịch bản được ghi nhận chính xác vào file log `dataset/label_log.csv`.
*   **Bước 5: Đồng bộ hóa dán nhãn dữ liệu.** Chạy script `src/label_data.py`. Chương trình đọc các mốc thời gian thực hiện tấn công trong `label_log.csv` để đối chiếu và tự động cập nhật nhãn chính xác (`normal`, `ddos`, `portscan`) cho từng dòng dữ liệu dòng chảy tương ứng trong `flow_stats.csv`.
*   **Bước 6: Tiền xử lý dữ liệu và phân chia tập mẫu.** Chạy script `src/preprocess.py` để thực thi pipeline làm sạch dữ liệu, lọc bỏ các dòng trùng lặp hoặc khuyết thiếu, áp dụng `StandardScaler` chuẩn hóa các giá trị đặc trưng, chia tập dữ liệu huấn luyện và kiểm thử theo tỷ lệ 80/20 có phân tầng. Đồng thời, kỹ thuật SMOTE được áp dụng trên tập Train để giải quyết bài toán dữ liệu mất cân bằng.
*   **Bước 7: Huấn luyện mô hình.** Kích hoạt tiến trình huấn luyện mô hình XGBoost thông qua `src/train_model.py`, mô hình Isolation Forest thông qua `src/train_isolation_forest.py` và mô hình Autoencoder thông qua `src/train_autoencoder.py`. Các mô hình tối ưu hóa trọng số dựa trên các thuật toán tương ứng và lưu trữ file trạng thái mô hình đã huấn luyện (`.pkl` và `.keras`) vào thư mục `models/`.
*   **Bước 8: Đánh giá hiệu năng.** Mô hình đã huấn luyện được kiểm thử trên tập dữ liệu Test độc lập để tính toán các chỉ số đánh giá định lượng, xuất ra ma trận nhầm lẫn (Confusion Matrix) và biểu đồ đặc trưng quan trọng lưu trữ vào thư mục `reports/`.

### 3.3. Các chỉ số đánh giá
Để đánh giá toàn diện và so sánh chính xác hiệu năng phân loại giữa các mô hình, nghiên cứu sử dụng các chỉ số toán học chuẩn trong đánh giá mô hình phân loại:

*   **Ma trận nhầm lẫn (Confusion Matrix):** Là một bảng biểu diễn mối liên hệ trực tiếp giữa nhãn thực tế (Actual Class) và nhãn do mô hình dự đoán (Predicted Class). Ma trận bao gồm bốn đại lượng cơ bản:
    *   *True Positive (TP):* Số lượng mẫu tấn công thực tế được mô hình dự đoán chính xác là tấn công.
    *   *True Negative (TN):* Số lượng mẫu lưu lượng bình thường thực tế được mô hình dự đoán chính xác là bình thường.
    *   *False Positive (FP - Cảnh báo giả):* Số lượng mẫu bình thường thực tế nhưng bị mô hình phân loại nhầm thành tấn công.
    *   *False Negative (FN - Bỏ sót tấn công):* Số lượng mẫu tấn công thực tế nhưng bị mô hình phân loại nhầm thành bình thường.
*   **Độ chính xác tổng thể (Accuracy):** Tỷ lệ giữa số lượng mẫu dự đoán chính xác trên tổng số lượng mẫu dữ liệu kiểm thử:
    $$Accuracy = \frac{TP + TN}{TP + TN + FP + FN}$$
*   **Độ chính xác phân lớp (Precision):** Tỷ lệ giữa số lượng mẫu thực tế thuộc lớp tấn công được dự đoán đúng trên tổng số mẫu mô hình dự đoán là tấn công:
    $$Precision = \frac{TP}{TP + FP}$$
*   **Độ phủ / Độ nhạy (Recall / Sensitivity):** Tỷ lệ giữa số lượng mẫu tấn công thực tế được dự đoán đúng trên tổng số lượng mẫu tấn công thực tế tồn tại trong tập kiểm thử:
    $$Recall = \frac{TP}{TP + FN}$$
*   **Chỉ số F1-Score:** Trung bình điều hòa (Harmonic Mean) giữa hai chỉ số Precision và Recall, phản ánh sự cân bằng và bền vững của mô hình:
    $$F1\text{-}Score = 2 \times \frac{Precision \times Recall}{Precision + Recall}$$
*   **Đường cong ROC và Chỉ số AUC (Area Under Curve):**
    *   *Đường cong ROC (Receiver Operating Characteristic):* Biểu đồ thể hiện sự tương quan giữa tỷ lệ dự đoán đúng tấn công (True Positive Rate - TPR) và tỷ lệ cảnh báo giả trên tập bình thường (False Positive Rate - FPR) tại các ngưỡng phân loại khác nhau:
        $$FPR = \frac{FP}{FP + TN}$$
    *   *AUC (Area Under the Curve):* Đại diện cho năng lực phân tách tổng thể của mô hình. Giá trị AUC dao động từ 0.5 đến 1.0.

---

<a id="chuong-4-ket-qua-thuc-nghiem"></a>
## CHƯƠNG 4. KẾT QUẢ THỰC NGHIỆM

### 4.1. Kết quả mô hình XGBoost

#### 4.1.1. Phân tích sự chênh lệch hiệu năng định lượng

*Bảng 1. Bảng kết quả tổng quan mô hình XGBoost*

| Metric | Giá trị |
|---|---|
| Accuracy | 1.0000 |
| Precision (macro) | 1.0000 |
| Recall (macro) | 1.0000 |
| F1-Score (macro) | 1.0000 |

*Bảng 2. Bảng Classification Report chi tiết từng lớp của XGBoost*

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| Normal | 1.00 | 1.00 | 1.00 | 63 |
| DDoS | 1.00 | 1.00 | 1.00 | 1 |
| Portscan | 1.00 | 1.00 | 1.00 | 2113 |

![Confusion Matrix XGBoost](file:///d:/KLTNHUFLIT/sdn-anomaly-detection-ml/reports/confusion_matrix_xgboost.png)
*Hình 1. Confusion Matrix XGBoost*

![Feature Importance XGBoost](file:///d:/KLTNHUFLIT/sdn-anomaly-detection-ml/reports/feature_importance_xgboost.png)
*Hình 2. Feature Importance XGBoost*

#### 4.1.2. Nhận xét phân tích kết quả XGBoost
Dựa trên các kết quả định lượng thu được, mô hình học máy có giám sát XGBoost đạt hiệu năng phân loại tuyệt đối với độ chính xác tổng thể (Accuracy) và chỉ số F1-Score đạt 1.0000 trên tập dữ liệu kiểm thử. Cơ chế Gradient Boosting giúp mô hình học hiệu quả các ranh giới phân loại phức tạp giữa các loại lưu lượng mạng khác nhau.

Kết quả Feature Importance cho thấy mô hình phụ thuộc chủ yếu vào các đặc trưng phản ánh mật độ và tốc độ lưu lượng mạng như `packet_count_per_sec`, `byte_count_per_sec`, `packet_count` và `flow_duration`. Các thuộc tính này phản ánh rõ sự khác biệt giữa lưu lượng bình thường và lưu lượng tấn công trong môi trường SDN.

#### 4.1.3. Tại sao mô hình đạt độ chính xác 100%?
Mô hình đạt 100% độ chính xác chủ yếu đến từ đặc điểm dữ liệu được thu thập trong môi trường giả lập Mininet mang tính tiền định (deterministic), không có nhiễu nền phức tạp. Traffic từ `hping3` và `nmap` có đặc trưng thống kê số học hoàn toàn tách biệt so với traffic normal như `ping`, `iperf`, giúp XGBoost dễ dàng học và phân tách lớp hoàn hảo. Trong môi trường thực tế có nhiễu mạng, hiệu năng này dự kiến sẽ giảm nhẹ.

---

### 4.2. Kết quả mô hình Autoencoder

#### 4.2.1. Các bảng chỉ số hiệu năng và hình ảnh thực nghiệm

*Bảng 3. Bảng kết quả tổng quan mô hình Autoencoder (Binary: Normal vs Anomaly)*

| Metric | Giá trị |
|---|---|
| Accuracy | 0.5638 |
| Precision | 0.4850 |
| Recall | 0.4950 |
| F1-Score | 0.4000 |
| AUC | 0.5721 |

*Bảng 4. Bảng Classification Report chi tiết của Autoencoder*

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| Normal | 0.57 | 0.94 | 0.71 | 108 |
| Anomaly | 0.40 | 0.05 | 0.09 | 80 |

![Biểu đồ phân phối lỗi tái tạo Autoencoder](file:///d:/KLTNHUFLIT/sdn-anomaly-detection-ml/reports/autoencoder_error_dist.png)
*Hình 3. Biểu đồ phân phối lỗi tái tạo*

![Đường cong ROC Autoencoder](file:///d:/KLTNHUFLIT/sdn-anomaly-detection-ml/reports/roc_curve_autoencoder.png)
*Hình 4. Đường cong ROC Autoencoder*

![Ma trận nhầm lẫn Autoencoder](file:///d:/KLTNHUFLIT/sdn-anomaly-detection-ml/reports/confusion_matrix_autoencoder.png)
*Hình 5. Ma trận nhầm lẫn Autoencoder*

![Đồ thị hàm mất mát Loss Curve](file:///d:/KLTNHUFLIT/sdn-anomaly-detection-ml/reports/autoencoder_training_loss.png)
*Hình 6. Đồ thị hàm mất mát Loss Curve*

#### 4.2.2. Nhận xét phân tích kết quả Autoencoder
Mô hình học sâu không giám sát Autoencoder đạt độ chính xác tổng thể là 56.38% và chỉ số AUC đạt 0.5721. Mạng học tốt hành vi của luồng dữ liệu sạch (Normal) với chỉ số Recall đạt tới 0.94, cho thấy khi dữ liệu đầu vào tuân theo phân phối thông thường, mạng nén và tái cấu trúc dữ liệu với sai số MSE rất thấp.

Tuy nhiên, mô hình gặp lỗi nghiêm trọng tại lớp Anomaly khi chỉ số Recall chỉ đạt 0.05 và F1-Score đạt 0.09 (bỏ sót 95% dữ liệu tấn công). Do tập đặc trưng dòng OpenFlow trích xuất tương đối hẹp (10 thuộc tính), các gói tin tấn công ở giai đoạn đầu vô tình có các chỉ số trùng khớp với lưu lượng kiểm tra mạng. Mạng Autoencoder đã tối ưu hóa và tái tạo tốt luôn cả các luồng độc hại này, dẫn đến sai số lỗi tái tạo của lớp Anomaly không đủ lớn để tạo khoảng cách phân tách rõ rệt qua ngưỡng Threshold 2.355.

---

### 4.3. Kết quả mô hình Isolation Forest

#### 4.3.1. Các bảng chỉ số hiệu năng và hình ảnh thực nghiệm

*Bảng 5. Bảng kết quả tổng quan mô hình Isolation Forest (Binary: Normal vs Anomaly)*

| Metric | Giá trị |
|---|---|
| Accuracy | 0.9031 |
| F1-Score | 0.9475 |
| AUC | 0.9877 |

![Ma trận nhầm lẫn Isolation Forest](file:///d:/KLTNHUFLIT/sdn-anomaly-detection-ml/reports/confusion_matrix_isolation_forest.png)
*Hình 7. Ma trận nhầm lẫn Isolation Forest*

![Đường cong ROC Isolation Forest](file:///d:/KLTNHUFLIT/sdn-anomaly-detection-ml/reports/roc_curve_isolation_forest.png)
*Hình 8. Đường cong ROC Isolation Forest*

![Phân phối điểm bất thường Isolation Forest](file:///d:/KLTNHUFLIT/sdn-anomaly-detection-ml/reports/isolation_forest_score_dist.png)
*Hình 9. Phân phối điểm bất thường Isolation Forest*

#### 4.3.2. Nhận xét phân tích kết quả Isolation Forest
Mô hình học máy không giám sát Isolation Forest đạt kết quả vượt trội với độ chính xác tổng thể (Accuracy) đạt 90.31%, F1-Score đạt 94.75%, và đặc biệt chỉ số AUC đạt tới **0.9877**. 

Chỉ số AUC cận mức tối ưu (0.9877) thể hiện khả năng phân tách cực kỳ tốt giữa lưu lượng mạng bình thường và lưu lượng bất thường. Kết quả này vượt trội hơn hẳn so với Autoencoder (AUC = 0.5721). Nguyên nhân chủ yếu do cơ chế phân hoạch ngẫu nhiên theo không gian đặc trưng của Isolation Forest hoạt động cực kỳ hiệu quả trên dữ liệu dạng bảng có số lượng đặc trưng hạn chế (10 features). Các điểm bất thường nhanh chóng bị cô lập ở các nhánh cạn của cây nhị phân mà không gặp phải hiện tượng nhòe hay chồng lấp ranh giới tái cấu trúc như mạng nơ-ron sâu Autoencoder.

---

### 4.4. So sánh hiệu năng các mô hình
Nghiên cứu tiến hành đối chiếu toàn diện hiệu năng định lượng giữa cả 3 mô hình học máy:

*Bảng 6. Bảng tổng hợp so sánh hiệu năng giữa XGBoost, Isolation Forest và Autoencoder*

| Mô hình (Model) | Tiếp cận (Approach) | Accuracy | F1-Score | AUC |
|---|---|---|---|---|
| **XGBoost** | Có giám sát (Supervised) | 1.0000 | 1.0000 | — |
| **Isolation Forest** | Không giám sát (Unsupervised) | 0.9031 | 0.9475 | 0.9877 |
| **Autoencoder** | Không giám sát (Unsupervised) | 0.5638 | 0.4000 | 0.5721 |

![So sánh hiệu năng các mô hình](file:///d:/KLTNHUFLIT/sdn-anomaly-detection-ml/reports/model_comparison_chart.png)
*Hình 10. So sánh hiệu năng các mô hình ML*

#### 4.4.1. Phân tích sự chênh lệch hiệu năng định lượng
Dựa trên số liệu thống kê thực nghiệm, mô hình có giám sát XGBoost vượt trội tuyệt đối với độ chính xác 100% nhờ khai thác triệt để nhãn dữ liệu trong pha huấn luyện để xây dựng các ranh giới phân lớp tối ưu.

Trong nhóm học không giám sát (Unsupervised Learning) phục vụ phát hiện tấn công zero-day, mô hình **Isolation Forest** là lựa chọn tối ưu nhất với F1-Score đạt 94.75% và AUC đạt 0.9877, bỏ xa mô hình học sâu **Autoencoder** (F1-Score chỉ đạt 40% và AUC đạt 0.5721). 

Điều này chứng minh rằng đối với dữ liệu luồng mạng OpenFlow dạng bảng có số chiều hẹp (10 đặc trưng), các mô hình dựa trên cây phân hoạch ngẫu nhiên đơn giản như Isolation Forest mang lại hiệu năng cao hơn, ổn định hơn và yêu cầu ít chi phí tính toán hơn so với cấu trúc nơ-ron sâu phức tạp của Autoencoder. Autoencoder bị rơi vào trạng thái mất cân bằng nghiêm trọng do ranh giới tái tạo bị nhòe ở vùng không gian đặc trưng giao thoa giữa dữ liệu normal và anomaly.

---

### 4.5. Triển khai Real-time Anomaly Detection
Nhóm đã tích hợp mô hình XGBoost và scaler trực tiếp vào bộ điều khiển Ryu/os-ken dưới dạng ứng dụng monitor điều khiển thời gian thực (`realtime_detector.py`). Khi switch kết nối, bộ điều khiển cài đặt luồng IP và định kỳ 5 giây thu thập flow stats để thực hiện suy diễn (Inference). Khi phát hiện dấu hiệu của tấn công DDoS hoặc Portscan, hệ thống sẽ ngay lập tức bật cảnh báo đỏ (Alarm) lên giao diện dòng lệnh của bộ điều khiển với độ trễ cực thấp, giúp người quản trị kịp thời đưa ra các chính sách ngăn chặn.

---

<a id="ket-luan"></a>
## KẾT LUẬN
Trong khóa luận này, nhóm đã nghiên cứu và xây dựng thành công một hệ thống phát hiện bất thường và phân loại lỗi mạng trong môi trường mạng định nghĩa bằng phần mềm (SDN) dựa trên các kỹ thuật học máy. Hệ thống được triển khai trên môi trường giả lập Mininet kết hợp với bộ điều khiển Ryu/os-ken nhằm thu thập dữ liệu luồng mạng OpenFlow, từ đó tiến hành tiền xử lý, huấn luyện và đánh giá các mô hình học máy.

Về mặt thực nghiệm, nghiên cứu đã triển khai và đánh giá hai hướng tiếp cận chính: mô hình học máy có giám sát (XGBoost) đạt hiệu năng tuyệt đối trong phân loại các cuộc tấn công đã biết; mô hình học máy không giám sát (Isolation Forest, Autoencoder) chứng minh năng lực phát hiện bất thường không cần nhãn. Trong đó, Isolation Forest tỏ ra vượt trội hoàn toàn so với Autoencoder khi đối phó với tập đặc trưng số lượng ít của dòng OpenFlow.

**Hạn chế của đề tài:**
*   Phạm vi giả lập trên Mininet mang tính tiền định và thiếu nhiễu nền thực tế.
*   Tập dữ liệu chỉ mới tập trung vào 3 loại lưu lượng chính (Normal, DDoS, Portscan) và số mẫu DDoS thu được ban đầu còn hạn chế.
*   Chưa triển khai các biện pháp phản ứng tự động kích hoạt luật tường lửa để cô lập kẻ tấn công sau khi phát hiện.

---

<a id="bang-phan-cong-viec"></a>
## BẢNG PHÂN CÔNG VIỆC

| STT | Họ và tên | Công việc phân công chi tiết |
|---|---|---|
| 1 | **Trịnh Hoàng Tú** | - Thiết lập hạ tầng SDN giả lập (Mininet, Ryu/os-ken).<br>- Viết kịch bản tấn công sinh dữ liệu (DDoS, Port Scan).<br>- Trích xuất đặc trưng dòng (Flow Features) ghi ra CSV.<br>- Quản lý mã nguồn trên Repo GitHub và kiểm soát logic hệ thống. |
| 2 | **Trần Minh Thiện** | - Thiết kế pipeline làm sạch dữ liệu, chuẩn hóa và cân bằng dữ liệu (SMOTE).<br>- Huấn luyện và tinh chỉnh mô hình học máy (XGBoost, Isolation Forest, Autoencoder).<br>- Đánh giá hiệu năng và trực quan hóa kết quả thực nghiệm.<br>- Soạn thảo nội dung báo cáo Chương 1, 2, 3 và 4. |

---

<a id="tai-lieu-tham-khao"></a>
## TÀI LIỆU THAM KHẢO

1.  D. Kreutz, F. M. Ramos, P. E. Verissimo, C. E. Rothenberg, S. Azodolmolky, and S. Uhlig, “Software-defined networking: A comprehensive survey,” *Proceedings of the IEEE*, vol. 103, no. 1, pp. 14-76, 2015.
2.  M. S. Elsayed, N. A. Le-Khac, and S. Dev, “InSDN: A novel SDN intrusion dataset,” *IEEE Access*, vol. 8, pp. 221691-221705, 2020.
3.  L. Breiman, “Random forests,” *Machine Learning*, vol. 45, no. 1, pp. 5-32, 2001.
4.  T. Chen and C. Guestrin, “XGBoost: A scalable tree boosting system,” *Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining*, pp. 785-794, 2016.
5.  F. T. Liu, K. M. Ting, and Z. H. Zhou, “Isolation forest,” *2008 Eighth IEEE International Conference on Data Mining*, pp. 413-422, 2008.
6.  S. Scott-Hayward, G. O'Callaghan, and S. Sezer, “SDN security: A survey,” *2013 IEEE SDN for Future Networks and Services (SDN4FNS)*, pp. 1-7, 2013.
7.  V. Chandola, A. Banerjee, and V. Kumar, “Anomaly detection: A survey,” *ACM Computing Surveys*, vol. 41, no. 3, pp. 1-58, 2009.
8.  N. McKeown et al., "OpenFlow: Enabling Innovation in Campus Networks," *ACM SIGCOMM Computer Communication Review*, vol. 38, no. 2, pp. 69-74, 2008.
9.  N. V. Chawla et al., "SMOTE: Synthetic Minority Over-sampling Technique," *Journal of Artificial Intelligence Research*, vol. 16, pp. 321-357, 2002.
