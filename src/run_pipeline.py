"""
Chạy nhanh toàn bộ pipeline ML (harden + retrain + real-only eval).

  python src/run_pipeline.py
  python src/run_pipeline.py --smoke          # bỏ AE/CV/SHAP nặng
  python src/run_pipeline.py --bootstrap 400  # bootstrap DDoS từ seed real
  python src/run_pipeline.py --replace-handcraft
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(cmd: list[str]) -> None:
    print('\n>>>', ' '.join(cmd))
    proc = subprocess.run(cmd, cwd=BASE_DIR)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--smoke', action='store_true',
                        help='Bỏ autoencoder / CV / SHAP (nhanh)')
    parser.add_argument('--bootstrap', type=int, default=400,
                        help='Số DDoS bootstrap từ seed real (0=skip)')
    parser.add_argument('--replace-handcraft', action='store_true',
                        help='Xóa synthetic handcraft 2026-05-15 trước khi bootstrap')
    args = parser.parse_args()

    py = sys.executable
    run([py, 'src/mark_data_provenance.py'])

    if args.bootstrap > 0:
        boot = [py, 'src/bootstrap_real_ddos.py', '--target', str(args.bootstrap)]
        if args.replace_handcraft:
            boot.append('--replace-old-handcraft')
        run(boot)
        run([py, 'src/mark_data_provenance.py'])

    steps = [
        'src/preprocess.py',
        'src/train_model.py',
        'src/train_isolation_forest.py',
    ]
    if not args.smoke:
        steps.append('src/train_autoencoder.py')
    steps.extend([
        'src/compare_models.py',
        'src/baseline_comparison.py',
    ])
    if not args.smoke:
        steps.extend([
            'src/cross_validate.py',
            'src/explain_model.py',
        ])
    steps.append('src/eval_real_only.py')

    for script in steps:
        try:
            run([py, script])
        except SystemExit as exc:
            print(f'[!] {script} failed (exit {exc.code}) — tiếp tục nếu không critical')
            if script in ('src/preprocess.py', 'src/train_model.py', 'src/eval_real_only.py'):
                raise

    print('\n[✓] Pipeline done. Xem reports/model_comparison.csv và reports/real_only_metrics.csv')


if __name__ == '__main__':
    main()
