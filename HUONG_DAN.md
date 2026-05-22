
---

## BƯỚC 1: Lấy code về máy

Mở terminal (Ubuntu/WSL), chạy từng dòng:

```bash
cd ~
git clone https://github.com/thtcsec/sdn-anomaly-detection-ml.git
cd sdn-anomaly-detection-ml
```

Nếu đã clone rồi thì:
```bash
cd ~/sdn-anomaly-detection-ml
git fetch origin
git checkout master
git pull origin master
```

---

## BƯỚC 2: Cài đặt môi trường

Chạy từng dòng một:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Kiểm tra cài thành công:
```bash
python -c "import pandas; import xgboost; import tensorflow; print('OK')"
```

Kiểm tra GPU (không bắt buộc, CPU cũng chạy được):
```bash
python -c "import tensorflow as tf; print(tf.config.list_physical_devices('GPU'))"
```
- Nếu in ra `[]` → đang dùng CPU, train sẽ hơi lâu (~2-3 phút) nhưng vẫn OK.
- Nếu có GPU thì nhanh hơn.

> **LƯU Ý:** Mỗi lần mở terminal mới đều phải chạy lại:
> ```bash
> cd ~/sdn-anomaly-detection-ml
> source .venv/bin/activate
> ```

---

## BƯỚC 3: Thêm SMOTE vào file tiền xử lý

Mở file `src/preprocess.py`:
```bash
code src/preprocess.py
```

**Tìm dòng này** (khoảng dòng 80-85):
```python
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)
```

**Thêm ngay BÊN DƯỚI dòng đó:**
```python
    # SMOTE - cân bằng dữ liệu (vì ddos ít hơn normal)
    # CHỈ áp dụng cho tập TRAIN, KHÔNG BAO GIỜ áp dụng cho tập TEST
    from imblearn.over_sampling import SMOTE
    smote = SMOTE(random_state=42)
    X_train, y_train = smote.fit_resample(X_train, y_train)
    print(f"[*] After SMOTE: {len(X_train)} train samples")
```

> ⚠️ **QUAN TRỌNG:** SMOTE chỉ dùng cho tập train. Tuyệt đối KHÔNG oversample tập test. Nếu oversample test thì kết quả sẽ sai hoàn toàn.

Lưu file.

---

## BƯỚC 4: Chạy tiền xử lý

```bash
python src/preprocess.py
```

Kết quả mong đợi:
- In ra số lượng records
- In ra label mapping (normal=0, ddos=1, portscan=2)
- In ra "After SMOTE: xxx train samples"
- Tạo ra 3 file trong thư mục `dataset/`:
  - `processed_data.csv`
  - `train.csv`
  - `test.csv`

Kiểm tra:
```bash
ls dataset/
```
Phải thấy 3 file mới ở trên.

---

## BƯỚC 5: Train XGBoost

```bash
python src/train_model.py
```

Kết quả mong đợi:
- In ra Accuracy, F1-Score
- Tạo file `reports/confusion_matrix_xgboost.png`
- Tạo file `reports/feature_importance_xgboost.png`
- Tạo file `models/xgboost_model.pkl`

**Ghi lại số Accuracy và F1-Score** → cần cho báo cáo.

---

## BƯỚC 6: Viết Autoencoder

Tạo file mới `src/train_autoencoder.py`:
```bash
code src/train_autoencoder.py
```

Copy **TOÀN BỘ** code dưới đây vào file đó:

```python
"""
Train Autoencoder để phát hiện bất thường (Unsupervised).
Ý tưởng: train model chỉ với data NORMAL, khi gặp attack thì
reconstruction error sẽ cao → phát hiện bất thường.
"""

import os
import numpy as np
import pandas as pd
import random
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc
from tensorflow import keras
import tensorflow as tf
import joblib

# Reproducibility - đảm bảo mỗi lần chạy ra kết quả giống nhau
np.random.seed(42)
tf.random.set_seed(42)
random.seed(42)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


def main():
    print("=" * 60)
    print("  Autoencoder Training - SDN Anomaly Detection")
    print("=" * 60)

    # 1. Load data
    train_df = pd.read_csv(os.path.join(DATASET_DIR, 'train.csv'))
    test_df = pd.read_csv(os.path.join(DATASET_DIR, 'test.csv'))

    X_train_all = train_df.drop('label', axis=1)
    y_train_all = train_df['label']
    X_test = test_df.drop('label', axis=1)
    y_test = test_df['label']

    # 2. Chỉ lấy data NORMAL để train (label=0)
    X_train_normal = X_train_all[y_train_all == 0]
    print(f"[*] Training data (normal only): {len(X_train_normal)} samples")
    print(f"[*] Test data (all labels): {len(X_test)} samples")

    # 3. Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_normal)
    X_test_scaled = scaler.transform(X_test)

    # 4. Xây dựng Autoencoder
    # Kiến trúc: 10 → 8 → 6 → 4 → 6 → 8 → 10
    input_dim = X_train_scaled.shape[1]

    autoencoder = keras.Sequential([
        # Encoder
        keras.layers.Dense(8, activation='relu', input_shape=(input_dim,)),
        keras.layers.Dense(6, activation='relu'),
        keras.layers.Dense(4, activation='relu'),  # Bottleneck

        # Decoder
        keras.layers.Dense(6, activation='relu'),
        keras.layers.Dense(8, activation='relu'),
        keras.layers.Dense(input_dim, activation='linear'),
    ])

    autoencoder.compile(optimizer='adam', loss='mse')
    autoencoder.summary()

    # 5. Train với EarlyStopping (tự dừng khi không cải thiện)
    early_stop = keras.callbacks.EarlyStopping(
        monitor='val_loss',
        patience=10,
        restore_best_weights=True
    )

    print("\n[*] Training Autoencoder...")
    history = autoencoder.fit(
        X_train_scaled, X_train_scaled,  # Input = Output (reconstruction)
        epochs=100,
        batch_size=32,
        validation_split=0.1,
        callbacks=[early_stop],
        verbose=1
    )

    # 6. Tính reconstruction error trên test set
    X_test_pred = autoencoder.predict(X_test_scaled)
    mse = np.mean(np.power(X_test_scaled - X_test_pred, 2), axis=1)

    # 7. Tìm threshold
    normal_mask = (y_test == 0)
    mse_normal = mse[normal_mask]
    threshold = np.percentile(mse_normal, 95)
    print(f"\n[*] Threshold (95th percentile of normal): {threshold:.6f}")

    # 8. Dự đoán: error > threshold → anomaly (1), ngược lại → normal (0)
    y_pred_ae = (mse > threshold).astype(int)
    y_test_binary = (y_test != 0).astype(int)

    # 9. Đánh giá
    print("\n" + "=" * 60)
    print("  AUTOENCODER EVALUATION (Binary: Normal vs Anomaly)")
    print("=" * 60)
    print(classification_report(y_test_binary, y_pred_ae,
                                target_names=['Normal', 'Anomaly']))

    # 10. Vẽ biểu đồ phân bố reconstruction error
    plt.figure(figsize=(10, 6))
    plt.hist(mse[normal_mask], bins=50, alpha=0.7, label='Normal', color='blue')
    plt.hist(mse[~normal_mask], bins=50, alpha=0.7, label='Attack', color='red')
    plt.axvline(threshold, color='black', linestyle='--',
                label=f'Threshold={threshold:.4f}')
    plt.xlabel('Reconstruction Error (MSE)')
    plt.ylabel('Count')
    plt.title('Autoencoder - Reconstruction Error Distribution')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'autoencoder_error_dist.png'), dpi=150)
    plt.close()
    print("[✓] Saved: reports/autoencoder_error_dist.png")

    # 11. ROC Curve
    fpr, tpr, _ = roc_curve(y_test_binary, mse)
    roc_auc = auc(fpr, tpr)

    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2,
             label=f'Autoencoder (AUC = {roc_auc:.4f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve - Autoencoder')
    plt.legend(loc='lower right')
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'roc_curve_autoencoder.png'), dpi=150)
    plt.close()
    print(f"[✓] Saved: reports/roc_curve_autoencoder.png (AUC={roc_auc:.4f})")

    # 12. Confusion Matrix
    cm = confusion_matrix(y_test_binary, y_pred_ae)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Oranges',
                xticklabels=['Normal', 'Anomaly'],
                yticklabels=['Normal', 'Anomaly'])
    plt.title('Confusion Matrix - Autoencoder')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'confusion_matrix_autoencoder.png'), dpi=150)
    plt.close()
    print("[✓] Saved: reports/confusion_matrix_autoencoder.png")

    # 13. Training loss curve
    plt.figure(figsize=(8, 5))
    plt.plot(history.history['loss'], label='Train Loss')
    plt.plot(history.history['val_loss'], label='Validation Loss')
    plt.xlabel('Epoch')
    plt.ylabel('MSE Loss')
    plt.title('Autoencoder Training Loss')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'autoencoder_training_loss.png'), dpi=150)
    plt.close()
    print("[✓] Saved: reports/autoencoder_training_loss.png")

    # 14. Lưu model
    autoencoder.save(os.path.join(MODELS_DIR, 'autoencoder_model.keras'))
    joblib.dump(scaler, os.path.join(MODELS_DIR, 'autoencoder_scaler.pkl'))
    print("[✓] Saved: models/autoencoder_model.keras")

    print("\n[✓] Autoencoder training complete!")
    print(f"[*] AUC Score: {roc_auc:.4f}")


if __name__ == '__main__':
    main()
```

Lưu file, rồi chạy:
```bash
python src/train_autoencoder.py
```

Kết quả: tạo ra 4 biểu đồ trong `reports/` + model trong `models/`.

---

## BƯỚC 7: Commit và push code

```bash
git fetch origin
git checkout -b feature/ml-training
git add .
git commit -m "feat: add SMOTE, train XGBoost + Autoencoder"
git push -u origin feature/ml-training
```

Sau đó vào GitHub → tạo Pull Request → báo merge.

---

## BƯỚC 8: Viết báo cáo

Viết vào file Word/Google Docs. Cấu trúc:

### Chương 1: Tổng quan (3-4 trang)
- 1.1 Đặt vấn đề: mạng SDN ngày càng phổ biến, nhưng dễ bị tấn công DDoS, port scan
- 1.2 Mục tiêu: xây dựng hệ thống phát hiện bất thường tự động bằng ML
- 1.3 Phạm vi: giả lập trên Mininet, dùng XGBoost + Autoencoder
- 1.4 Phương pháp: thu thập flow stats → trích xuất features → train model

### Chương 2: Cơ sở lý thuyết (5-7 trang)
- 2.1 Mạng SDN: kiến trúc 3 lớp (Application, Control, Data), OpenFlow protocol
- 2.2 Các loại tấn công: DDoS (SYN flood, UDP flood, ICMP flood), Port Scanning
- 2.3 Machine Learning:
  - XGBoost: supervised, ensemble method, gradient boosting
  - Autoencoder: unsupervised, neural network, reconstruction error
- 2.4 SMOTE: kỹ thuật oversampling cho dữ liệu imbalance
- 2.5 Các metric đánh giá: Accuracy, Precision, Recall, F1, AUC, Confusion Matrix

### Chương 3: Thiết kế và triển khai (5-7 trang)
- 3.1 Kiến trúc hệ thống: vẽ sơ đồ bằng draw.io hoặc Excalidraw (KHÔNG dùng SmartArt)
  - Sơ đồ: Mininet → os-ken Controller → CSV → Preprocessing → ML Model → Prediction
- 3.2 Topology mạng: 2 switches, 6 hosts, mô tả vai trò từng host
- 3.3 Thu thập dữ liệu: giải thích 10 features
  - packet_count_per_sec: số packet mỗi giây (DDoS sẽ rất cao)
  - byte_count_per_sec: số byte mỗi giây
  - packet_size_avg: kích thước trung bình packet
  - flow_duration: thời gian flow tồn tại
  - ip_proto: giao thức (1=ICMP, 6=TCP, 17=UDP)
  - tp_src, tp_dst: port nguồn/đích (portscan sẽ có nhiều port khác nhau)
- 3.4 Tiền xử lý: cleaning, scaling (StandardScaler), SMOTE
- 3.5 Mô hình XGBoost: hyperparameters đã dùng, giải thích tại sao chọn
- 3.6 Mô hình Autoencoder: kiến trúc 10→8→6→4→6→8→10, cách tìm threshold 95%
- 3.7 Limitations (hạn chế):
  - Dataset nhỏ (940 samples), sinh từ môi trường giả lập
  - Chưa test trên mạng SDN thật
  - Chưa deploy inference real-time
  - Chỉ 3 loại traffic, thực tế có nhiều loại tấn công hơn

### Format tài liệu tham khảo: IEEE
```
[1] N. McKeown et al., "OpenFlow: Enabling Innovation in Campus Networks," ACM SIGCOMM CCR, vol. 38, no. 2, pp. 69-74, 2008.
[2] T. Chen and C. Guestrin, "XGBoost: A Scalable Tree Boosting System," in Proc. KDD, pp. 785-794, 2016.
[3] N. V. Chawla et al., "SMOTE: Synthetic Minority Over-sampling Technique," JAIR, vol. 16, pp. 321-357, 2002.
```

---

## TÓM TẮT: chạy lệnh theo thứ tự

```bash
# 1. Setup
cd ~/sdn-anomaly-detection-ml
git fetch origin
git checkout master
git pull origin master
source .venv/bin/activate
pip install -r requirements.txt

# 2. Sửa preprocess.py (thêm SMOTE như BƯỚC 3)

# 3. Chạy
python src/preprocess.py
python src/train_model.py
python src/train_autoencoder.py

# 4. Push
git checkout -b feature/ml-training
git add .
git commit -m "feat: add SMOTE, train XGBoost + Autoencoder"
git push -u origin feature/ml-training
```

---

