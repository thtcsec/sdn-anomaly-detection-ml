"""Pack the thesis/submission zip (code + grouped CSV, no .venv). Keep."""

from __future__ import annotations

import zipfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "dist"

INCLUDE_DIRS = (
    "src",
    "controller",
    "dashboard",
    "topology",
    "docs",
)

INCLUDE_ROOT_FILES = (
    "README.md",
    "requirements.txt",
    "start_demo.bat",
    "CHAY_DEMO.md",
    "HUONG_DAN.md",
    "HUONG_DAN_QUAY_VIDEO_DEMO.md",
    "HUONG_DAN_CHINH_SUA_KHOA_LUAN_DOCX_VA_SLIDES.md",
)

INCLUDE_SCRIPTS = (
    "scripts/trigger_traffic.py",
    "scripts/pack_submission_zip.py",
)

INCLUDE_DATASET = (
    "dataset/flow_stats_grouped.csv",
    "dataset/train.csv",
    "dataset/test.csv",
    "dataset/processed_data.csv",
    "dataset/controller_config.json",
    "dataset/independent_runs/manifest.csv",
    "dataset/independent_runs/README.md",
)

# Anh/CSV muc reports/ (khong gom public_benchmark). Bo file > MAX_REPORT_BYTES.
MAX_REPORT_BYTES = 8 * 1024 * 1024
INCLUDE_REPORT_SUFFIXES = {".png", ".csv", ".txt"}
SKIP_REPORT_NAMES = {
    "confusion_matrix_random_forest_domain_shift.png",
    "confusion_matrix_random_forest_real_only.png",
    "feature_importance_random_forest_real_only.png",
}

SKIP_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".ipynb_checkpoints",
    "tmp",
    "dist",
    "public_benchmark",
    "run_logs",
    ".cursor",
}

SKIP_SUFFIXES = {".pyc", ".pyo", ".log", ".bak"}
SKIP_NAMES = {
    "flow_stats.csv",
    "alerts.json",
    "current_label.txt",
    "label_log.csv",
    "Thumbs.db",
    ".DS_Store",
    ".gitkeep",
}


def _skip_dir(path: Path) -> bool:
    return any(part in SKIP_DIR_NAMES for part in path.parts)


def _collect() -> list[Path]:
    files: list[Path] = []

    for name in INCLUDE_ROOT_FILES:
        path = ROOT / name
        if path.is_file():
            files.append(path)

    for dirname in INCLUDE_DIRS:
        folder = ROOT / dirname
        if not folder.is_dir():
            continue
        for path in folder.rglob("*"):
            if not path.is_file():
                continue
            if _skip_dir(path.relative_to(ROOT)):
                continue
            if path.suffix.lower() in SKIP_SUFFIXES or path.name in SKIP_NAMES:
                continue
            files.append(path)

    for rel in INCLUDE_SCRIPTS:
        path = ROOT / rel
        if path.is_file():
            files.append(path)

    for rel in INCLUDE_DATASET:
        path = ROOT / rel
        if path.is_file():
            files.append(path)

    reports = ROOT / "reports"
    if reports.is_dir():
        for path in reports.iterdir():
            if not path.is_file():
                continue
            if path.suffix.lower() not in INCLUDE_REPORT_SUFFIXES:
                continue
            if path.name in SKIP_REPORT_NAMES:
                continue
            if path.stat().st_size > MAX_REPORT_BYTES:
                continue
            files.append(path)

    models = ROOT / "models"
    if models.is_dir():
        for path in models.iterdir():
            if not path.is_file():
                continue
            if path.suffix.lower() in {".pkl", ".keras", ".json"}:
                files.append(path)

    unique = sorted({p.resolve() for p in files})
    return [p for p in unique if p.is_file()]


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_path = OUT_DIR / f"sdn-anomaly-detection-ml_{stamp}.zip"
    files = _collect()
    if not files:
        raise SystemExit("Khong tim thay file de dong goi.")

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            zf.write(path, path.relative_to(ROOT).as_posix())

    size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"Files: {len(files)}")
    print(f"Zip:   {zip_path}")
    print(f"Size:  {size_mb:.1f} MB")
    print("Excluded: .venv, .git, tmp, flow_stats.csv, independent run dumps, public_benchmark")


if __name__ == "__main__":
    main()
