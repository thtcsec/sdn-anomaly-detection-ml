# PHỤ LỤC

## Phụ lục A: Mã nguồn SDN Controller - Thu thập Flow Statistics

File: `controller/monitor.py`

```python
class FlowMonitor(app_manager.OSKenApp):
    """
    Controller app thu thập flow statistics từ các switch.
    Dữ liệu được ghi ra file CSV để phục vụ training ML model.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowMonitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self._init_csv()
        self._load_ml_model()

    def _load_ml_model(self):
        """Tải mô hình XGBoost và Scaler để dự đoán Real-time."""
        model_path = os.path.join(MODELS_DIR, 'xgboost_model.pkl')
        scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')
        self.model = None
        self.scaler = None
        self.label_mapping = {0: 'DDOS', 1: 'NORMAL', 2: 'PORTSCAN'}

        if os.path.exists(model_path) and os.path.exists(scaler_path):
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.logger.info("[✓] Tải thành công mô hình XGBoost.")
        else:
            self.logger.warning("[!] Không tìm thấy mô hình.")

    def _monitor(self):
        """Thread gửi request flow stats định kỳ mỗi 5 giây."""
        while True:
            for dp_id, dp in self.datapaths.items():
                self._request_stats(dp)
            hub.sleep(MONITOR_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Xử lý flow stats reply - trích xuất features và ghi CSV."""
        body = ev.msg.body
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        for stat in body:
            if 'ipv4_src' not in stat.match:
                continue

            ip_proto = stat.match.get('ip_proto', 0)
            tp_src = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
            tp_dst = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))

            duration = stat.duration_sec + stat.duration_nsec / 1e9
            pkt_per_sec = stat.packet_count / duration if duration > 0 else 0
            byte_per_sec = stat.byte_count / duration if duration > 0 else 0
            pkt_size_avg = stat.byte_count / stat.packet_count if stat.packet_count > 0 else 0

            # Real-time inference
            if self.model and self.scaler:
                features = pd.DataFrame([{
                    'ip_proto': ip_proto, 'tp_src': tp_src, 'tp_dst': tp_dst,
                    'packet_count': stat.packet_count,
                    'byte_count': stat.byte_count,
                    'duration_sec': stat.duration_sec,
                    'packet_count_per_sec': pkt_per_sec,
                    'byte_count_per_sec': byte_per_sec,
                    'packet_size_avg': pkt_size_avg,
                    'flow_duration': duration
                }])
                features_scaled = self.scaler.transform(features)
                prediction = self.model.predict(features_scaled)[0]
                label = self.label_mapping.get(prediction, 'UNKNOWN')

                if label != 'NORMAL':
                    self.logger.warning(
                        "⚠️ ALERT %s -> %s | prediction=%s",
                        stat.match['ipv4_src'], stat.match['ipv4_dst'], label)
```

---

## Phụ lục B: Mã nguồn Tiền xử lý Dữ liệu

File: `src/preprocess.py`

```python
def preprocess_pipeline():
    """Pipeline tiền xử lý hoàn chỉnh."""
    # 1. Load data
    df = load_data()

    # 2. Clean data (xóa duplicates, missing values)
    df = clean_data(df)

    # 3. Extract 10 numerical features
    X, y = extract_features(df)
    # Features: ip_proto, tp_src, tp_dst, packet_count, byte_count,
    #           duration_sec, packet_count_per_sec, byte_count_per_sec,
    #           packet_size_avg, flow_duration

    # 4. Encode labels (ddos=0, normal=1, portscan=2)
    y_encoded, label_encoder = encode_labels(y)

    # 5. Split train/test (80/20, stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    # 6. Save processed data
    train_df.to_csv(TRAIN_CSV, index=False)
    test_df.to_csv(TEST_CSV, index=False)
```

---

## Phụ lục C: Mã nguồn Huấn luyện XGBoost

File: `src/train_model.py`

```python
def train_xgboost(X_train, y_train):
    """Huấn luyện XGBoost classifier."""
    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric='mlogloss'
    )
    model.fit(X_train, y_train, verbose=True)
    return model

def main():
    # 1. Load data
    X_train, X_test, y_train, y_test = load_train_test()

    # 2. Scale features
    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(
        scaler.fit_transform(X_train), columns=X_train.columns)
    X_test_scaled = pd.DataFrame(
        scaler.transform(X_test), columns=X_test.columns)

    # 3. Train model
    model = train_xgboost(X_train_scaled, y_train)

    # 4. Evaluate
    y_pred, accuracy, f1 = evaluate_model(model, X_test_scaled, y_test,
                                          ['ddos', 'normal', 'portscan'])

    # 5. Save model + scaler
    joblib.dump(model, 'models/xgboost_model.pkl')
    joblib.dump(scaler, 'models/scaler.pkl')
```

---

## Phụ lục D: Mã nguồn Topology Mininet

File: `topology/custom_topo.py`

```python
class SDNAnomalyTopo(Topo):
    """Topology cho thí nghiệm phát hiện bất thường SDN."""

    def build(self):
        # 2 switches OpenFlow 1.3
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')

        # Mạng nội bộ (normal users)
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')

        # Mạng ngoài (attacker có thể ở đây)
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
        h5 = self.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
        h6 = self.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')

        # Links
        self.addLink(h1, s1); self.addLink(h2, s1); self.addLink(h3, s1)
        self.addLink(h4, s2); self.addLink(h5, s2); self.addLink(h6, s2)
        self.addLink(s1, s2)  # Inter-switch link
```

---

## Phụ lục E: Mã nguồn Thu thập Dữ liệu Tự động

File: `src/collect_data.py` (trích đoạn giả lập tấn công)

```python
def generate_ddos(net, duration=45):
    """Tạo DDoS: SYN flood, UDP flood, ICMP flood."""
    h4, h5, h6 = net.get('h4', 'h5', 'h6')

    # SYN Flood: h4 → h1
    h4.cmd(f'timeout {duration} hping3 -S --flood -p 80 10.0.0.1 &')
    # UDP Flood: h5 → h2
    h5.cmd(f'timeout {duration} hping3 --udp --flood -p 53 10.0.0.2 &')
    # ICMP Flood: h6 → h3
    h6.cmd(f'timeout {duration} hping3 --icmp --flood 10.0.0.3 &')

    time.sleep(duration + 2)
    for h in [h4, h5, h6]:
        h.cmd('killall hping3 2>/dev/null')


def generate_portscan(net, duration=30):
    """Tạo Port Scan: nmap từ attacker hosts."""
    h4, h5, h6 = net.get('h4', 'h5', 'h6')

    # SYN scan h4 → h1
    h4.cmd(f'timeout {duration} nmap -sS -p 1-1024 --max-rate 200 10.0.0.1 &')
    # SYN scan h5 → h2
    h5.cmd(f'timeout {duration} nmap -sS -p 1-500 --max-rate 150 10.0.0.2 &')
    # Scan subnet h6
    h6.cmd(f'timeout {duration} nmap -sS -p 22,80,443,8080,3306 10.0.0.0/24 &')

    time.sleep(duration + 2)
    for h in [h4, h5, h6]:
        h.cmd('killall nmap 2>/dev/null')
```

---

## Phụ lục F: Cấu trúc Dataset

### Header file `dataset/flow_stats.csv` (17 cột):

| # | Tên cột | Mô tả | Kiểu |
|---|---------|--------|------|
| 1 | timestamp | Thời điểm thu thập | datetime |
| 2 | datapath_id | ID switch gửi stats | int |
| 3 | flow_id | Hash ID duy nhất của flow | int |
| 4 | ip_src | Địa chỉ IP nguồn | string |
| 5 | ip_dst | Địa chỉ IP đích | string |
| 6 | ip_proto | Giao thức (1=ICMP, 6=TCP, 17=UDP) | int |
| 7 | tp_src | Cổng nguồn | int |
| 8 | tp_dst | Cổng đích | int |
| 9 | packet_count | Tổng số gói tin | int |
| 10 | byte_count | Tổng số bytes | int |
| 11 | duration_sec | Thời gian sống (giây) | int |
| 12 | duration_nsec | Thời gian sống (nano giây) | int |
| 13 | packet_count_per_sec | Tốc độ gói tin/giây | float |
| 14 | byte_count_per_sec | Tốc độ bytes/giây | float |
| 15 | packet_size_avg | Kích thước TB gói tin | float |
| 16 | flow_duration | Tổng thời gian thực tế | float |
| 17 | label | Nhãn phân loại | string |

### Phân bố dữ liệu sau augmentation:

| Label | Số mẫu | Tỷ lệ |
|-------|---------|--------|
| portscan | 10,565 | 92.81% |
| ddos | 506 | 4.45% |
| normal | 312 | 2.74% |
| **Tổng** | **11,383** | **100%** |

---

## Phụ lục G: Kết quả Model sau Data Augmentation (LỊCH SỬ — tập 11k)

**Không dán vào Kết quả.** Acc 0,9991 (99,91%) là bảng augmentation 11.283 mẫu. Số hiện tại: LOSO `reports/binary_realtime_loso_summary.csv` (RF Acc 0,7724 · XGB 0,7520 · min-recall 0). Random-split ~0,999 chỉ phụ lục leakage.

### XGBoost (Supervised - Multiclass):
- **Accuracy:** 0.9991 (99.91%) — *historical 11k table*
- **F1-Score (weighted):** 0.9991

| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------|
| DDoS | 0.98 | 1.00 | 0.99 | 101 |
| Normal | 1.00 | 0.98 | 0.99 | 63 |
| Portscan | 1.00 | 1.00 | 1.00 | 2113 |

### Isolation Forest (Unsupervised - Binary):
- **Accuracy:** 0.97 (97%)
- **AUC:** 0.9521
