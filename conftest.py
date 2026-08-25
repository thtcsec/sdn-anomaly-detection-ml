"""Repo-root pytest hooks. Keep tests/conftest.py for fixtures."""

# WSL .venv → /root/sdn-anomaly-venv: Windows cannot stat it (WinError 1920).
collect_ignore = [".venv", "venv"]


def pytest_ignore_collect(collection_path, config):
    try:
        name = collection_path.name
    except OSError:
        return True
    if name in {".venv", "venv"}:
        return True
    return None
