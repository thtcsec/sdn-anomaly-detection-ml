#!/usr/bin/env python3
"""
Đóng gói dự án SDN Anomaly Detection để mang đi review (AI / máy khác).

Bao gồm: code, dataset chính, reports, docs, requirements, README.
Loại trừ: .venv, .git, __pycache__, log tạm, PDF/DOCX backup nặng (tùy chọn).

Chạy:
  python scripts/pack_project_bundle.py
  python scripts/pack_project_bundle.py --with-models
  python scripts/pack_project_bundle.py --with-thesis-docx

Output mặc định: dist/sdn-anomaly-detection-ml_bundle_YYYYMMDD_HHMM.zip
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import zipfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Thư mục / file luôn bỏ
EXCLUDE_DIR_NAMES = {
    '.git',
    '.venv',
    'venv',
    'ENV',
    '__pycache__',
    '.ipynb_checkpoints',
    'node_modules',
    'dist',
    '.pytest_cache',
    '.mypy_cache',
    '.ruff_cache',
    'agent-tools',
}

EXCLUDE_GLOBS = [
    '*.pyc',
    '*.pyo',
    '*.log',
    'Thumbs.db',
    '.DS_Store',
    'pipeline_run_output*.txt',
    'khoaluan1.pdf',
    'KhoaLuanTotNghiep.backup.docx',
    '_thesis_extract.txt',
    '_audit_snip.txt',
]

# Mặc định không đóng gói (nặng / gitignore) — bật bằng flag
DEFAULT_SKIP_GLOBS = [
    '*.pkl',
    '*.keras',
    'KhoaLuanTotNghiep.docx',
]

# Path relative nên có (ưu tiên review)
INCLUDE_HINTS = [
    'README.md',
    'requirements.txt',
    'PHAN_VIEC_THIEN.md',
    'WORD_EDIT_FOR_THIEN.md',
    'HUONG_DAN.md',
    'Bao_cao_khoa_luan.md',
    'controller/',
    'dashboard/',
    'src/',
    'topology/',
    'docs/',
    'reports/',
    'dataset/flow_stats.csv',
    'dataset/train.csv',
    'dataset/test.csv',
    'dataset/label_log.csv',
    'scripts/pack_project_bundle.py',
]


def should_exclude(rel: str, parts: tuple[str, ...], with_models: bool, with_thesis: bool) -> bool:
    if any(p in EXCLUDE_DIR_NAMES for p in parts):
        return True
    name = parts[-1] if parts else rel
    for g in EXCLUDE_GLOBS:
        if fnmatch.fnmatch(name, g) or fnmatch.fnmatch(rel.replace('\\', '/'), g):
            return True
    if not with_models:
        for g in ('*.pkl', '*.keras', '*.model'):
            if fnmatch.fnmatch(name, g):
                return True
    if not with_thesis:
        if name.lower() in {'khoaluantotnghiep.docx', 'khoaluan1.pdf'}:
            return True
        if name.endswith('.backup.docx'):
            return True
    # alerts runtime — giữ file rỗng/JSON nhỏ OK; bỏ tmp
    if name.endswith('.tmp'):
        return True
    return False


def iter_files(root: Path, with_models: bool, with_thesis: bool):
    for dirpath, dirnames, filenames in os.walk(root):
        # prune dirs in-place
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIR_NAMES and not d.startswith('.venv')]
        for fn in filenames:
            full = Path(dirpath) / fn
            try:
                rel = full.relative_to(root).as_posix()
            except ValueError:
                continue
            parts = tuple(rel.split('/'))
            if should_exclude(rel, parts, with_models=with_models, with_thesis=with_thesis):
                continue
            yield full, rel


def write_manifest(files: list[tuple[Path, str]], out_txt: Path, root: Path) -> None:
    lines = [
        f'Bundle root: {root}',
        f'Created: {datetime.now().isoformat(timespec="seconds")}',
        f'File count: {len(files)}',
        '',
        '=== INCLUDED ===',
    ]
    total = 0
    for full, rel in sorted(files, key=lambda x: x[1]):
        size = full.stat().st_size
        total += size
        lines.append(f'{size:12d}  {rel}')
    lines.append('')
    lines.append(f'TOTAL_BYTES={total}')
    lines.append(f'TOTAL_MB={total / (1024 * 1024):.2f}')
    lines.append('')
    lines.append('=== REVIEW HINTS ===')
    lines.append('- Dataset provenance: dataset/flow_stats.csv (is_synthetic, source)')
    lines.append('- Official metrics: reports/model_comparison.csv')
    lines.append('- Real-only: reports/real_only_metrics.csv, reports/random_forest_real_only_metrics.csv')
    lines.append('- Timing: reports/model_timing.csv')
    lines.append('- Train RF: src/train_random_forest.py')
    lines.append('- Realtime: controller/run_realtime.py + dashboard/app.py')
    lines.append('- Models (.pkl/.keras) omitted unless --with-models')
    out_txt.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main() -> None:
    parser = argparse.ArgumentParser(description='Pack SDN anomaly project for offline AI review')
    parser.add_argument('--with-models', action='store_true', help='Include *.pkl / *.keras (larger)')
    parser.add_argument('--with-thesis-docx', action='store_true', help='Include KhoaLuanTotNghiep.docx if present')
    parser.add_argument('--out', type=str, default='', help='Output zip path')
    args = parser.parse_args()

    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M')
    out = Path(args.out) if args.out else dist / f'sdn-anomaly-detection-ml_bundle_{stamp}.zip'

    files = list(iter_files(ROOT, with_models=args.with_models, with_thesis=args.with_thesis_docx))
    if not files:
        raise SystemExit('No files to pack')

    manifest = dist / f'BUNDLE_MANIFEST_{stamp}.txt'
    write_manifest(files, manifest, ROOT)

    # Also put a copy of manifest inside zip
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.write(manifest, arcname='BUNDLE_MANIFEST.txt')
        for full, rel in files:
            zf.write(full, arcname=rel)

    size_mb = out.stat().st_size / (1024 * 1024)
    print('=' * 60)
    print('  PROJECT BUNDLE READY')
    print('=' * 60)
    print(f'  Files:  {len(files)} (+ manifest)')
    print(f'  Zip:    {out}')
    print(f'  Size:   {size_mb:.2f} MB')
    print(f'  Manifest: {manifest}')
    print(f'  Models included: {args.with_models}')
    print(f'  Thesis docx:     {args.with_thesis_docx}')
    print('=' * 60)
    missing = [h for h in INCLUDE_HINTS if h.endswith('/') is False and not (ROOT / h).exists()]
    if missing:
        print('[!] Missing expected files:')
        for m in missing:
            print('   -', m)


if __name__ == '__main__':
    main()
