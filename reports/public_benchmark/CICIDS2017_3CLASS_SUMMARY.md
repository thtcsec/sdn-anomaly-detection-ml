# CICIDS2017 3-class public benchmark

## Phạm vi (khóa Word/slides)

CICIDS2017 được sử dụng ở mức tham khảo/benchmark bổ sung cho bài toán intrusion detection nói chung. Do dataset không được thu thập từ kiến trúc SDN/OpenFlow, kết quả không được sử dụng để đánh giá khả năng tổng quát hóa của pipeline SDN hoặc mô hình triển khai trên os-ken Controller.

## Purpose

Supplement the original Mininet lab benchmark with a larger external flow
dataset so the project is not defended only with `6` real DDoS lab rows. Appendix only — do not run new CICIDS jobs for the defense.

## Source

- `Monday-WorkingHours.pcap_ISCX.csv.parquet`
- `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet`
- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet`

Mirror root used locally:

- `D:\huflit_logs\public_datasets\cicids2017`

## Canonical mapping

Imported by:

```bash
python src/import_public_cicids2017.py
```

Trained/evaluated by:

```bash
python src/run_public_benchmark.py
```

Mapped labels:

- `BENIGN -> normal`
- `DDoS -> ddos`
- `PortScan -> portscan`

## Dataset size

- Rows after clean/dedup: **880,176**
- `normal`: **662,383**
- `ddos`: **127,175**
- `portscan`: **90,618**

Split/export:

- `train_raw.csv`: **704,140**
- `test_raw.csv`: **176,036**
- `train.csv` after SMOTE: **1,589,718**

Runtime caps used in the benchmark runner:

- supervised train cap: **100,000 / class**
- unsupervised normal-train cap: **100,000**

## Results

| Model | Scope | Accuracy | Precision | Recall | F1 |
|------|------|---------:|----------:|-------:|---:|
| XGBoost | macro multiclass | 0.9994 | 0.9989 | 0.9993 | 0.9991 |
| Random Forest | macro multiclass | 0.9995 | 0.9993 | 0.9993 | 0.9993 |
| Isolation Forest | anomaly-class binary | 0.7224 | 0.1672 | 0.0306 | 0.0518 |
| Autoencoder | anomaly-class binary | 0.7509 | 0.4886 | 0.1452 | 0.2238 |

Latency from `model_comparison.csv`:

- XGBoost: **2.88 ms/sample**
- Random Forest: **54.77 ms/sample**
- Isolation Forest: **12.48 ms/sample**
- Autoencoder: **76.31 ms/sample**

## Interpretation

1. Supervised models remain extremely strong on a much larger external flow
   benchmark, so the project is no longer defended only on the tiny DDoS lab
   set.
2. Unsupervised models degrade sharply on this distribution, which is an honest
   and useful result for the defense.
3. This benchmark is **supplementary**, not a replacement for the SDN lab
   deployment benchmark or the grouped real-only protocol.

## Caveats

1. This mirror omitted `Protocol` and `Source Port`, so the importer used:
   - `ip_proto = 6` when TCP flag counts were present, else `0`
   - `tp_src = -1` sentinel
2. The split is stratified random-flow, not source-held-out, because DDoS and
   PortScan each come from dedicated source files in this focused 3-class slice.
3. Do not present this as a realtime SDN benchmark; it is a public external
   flow benchmark mapped into the repo's 10-feature schema.
