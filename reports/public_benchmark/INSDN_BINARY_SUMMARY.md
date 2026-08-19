# InSDN binary public supplementary

## Phạm vi (khóa Word/slides)

Sử dụng InSDN như một external benchmark cho nhánh phát hiện bất thường an ninh trong môi trường SDN, nhằm đánh giá khả năng của XGBoost và Random Forest trên dữ liệu SDN độc lập với testbed tự xây dựng. Kết quả được báo cáo như thực nghiệm bổ sung và không được sử dụng thay thế cho benchmark chính hoặc mô hình realtime.

- Source: Hugging Face `Sharukesh/INSDN` (`Dataset.csv`), because official UCD zip was unreachable.
- Rows: **343,889** · `normal` 68,424 · `anomaly` 275,465
- This mirror is **binary**, not the paper's multiclass Normal/DoS/DDoS/Probe split.
- Mapped to the thesis 10-feature schema. **Not** mixed into Mininet controller training.

## Results

| Model | Acc | Precision | Recall | F1 |
|-------|-----|-----------|--------|-----|
| XGBoost | 0.9986 | 0.9987 | 0.9995 | 0.9991 |
| Random Forest | 0.9987 | 0.9988 | 0.9997 | 0.9992 |

Scripts: `src/import_public_insdn.py`, `src/run_public_insdn_binary.py`
