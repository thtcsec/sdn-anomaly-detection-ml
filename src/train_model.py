"""
Script wrapper cho XGBoost training pipeline.
Gọi trực tiếp src/train_xgboost.py để đảm bảo tương thích ngược.

Chạy: python src/train_model.py  hoặc  python src/train_xgboost.py
"""

import sys
import os

# Thêm project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.train_xgboost import main

if __name__ == '__main__':
    main()
