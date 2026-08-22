"""Smoke the grouped eval protocol (no Mininet). Keep.

Expected with current legacy-only data:
  - ensure_legacy_provenance.py succeeds
  - merge_independent_runs.py succeeds
  - eval_grouped_real_only.py exits with insufficient_groups (no known run_id)
  - audit_feature_overlap.py writes reports/feature_overlap_audit.csv
  - collect_* --dry-run succeeds
  - model_comparison.csv untouched hash

Chạy: python scripts/smoke_grouped_protocol.py
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


def run(args, check=True):
    print('\n$', ' '.join(args))
    return subprocess.run(args, cwd=BASE, check=check)


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        h.update(f.read())
    return h.hexdigest()


def main():
    mc = os.path.join(BASE, 'reports', 'model_comparison.csv')
    before = sha(mc) if os.path.exists(mc) else None

    run([PY, 'src/ensure_legacy_provenance.py'])
    run([PY, 'src/merge_independent_runs.py'])
    run([PY, 'src/audit_feature_overlap.py'])
    run([PY, 'src/collect_independent_ddos_runs.py', '--dry-run'])
    run([PY, 'src/collect_independent_support_runs.py', '--dry-run'])

    r = run([PY, 'src/eval_grouped_real_only.py'], check=False)
    if r.returncode == 0:
        print('[!] Unexpected success — did independent runs already exist?')
    elif r.returncode in (2, 3):
        print(f'[✓] Grouped eval failed as expected (code={r.returncode}) until enough runs exist')
    else:
        print(f'[!] Unexpected exit code {r.returncode}')
        sys.exit(r.returncode)

    after = sha(mc) if os.path.exists(mc) else None
    if before and after and before != after:
        print('[FAIL] model_comparison.csv changed — should be immutable in this protocol')
        sys.exit(1)
    print('[✓] model_comparison.csv unchanged')
    print('[✓] Smoke checks finished')


if __name__ == '__main__':
    main()
