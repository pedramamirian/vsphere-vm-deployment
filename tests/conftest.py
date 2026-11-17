import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "fixtures"))


@pytest.fixture(autouse=True)
def isolated_dirs(tmp_path, monkeypatch):
    """Every test gets its own config/cache/log/images folders and never touches the real keychain."""
    for var, sub in (("VMDEPLOY_CONFIG_DIR", "cfg"), ("VMDEPLOY_CACHE_DIR", "cache"), ("VMDEPLOY_LOG_DIR", "logs"),
                     ("VMDEPLOY_IMAGES_DIR", "images")):
        d = tmp_path / sub
        d.mkdir()
        monkeypatch.setenv(var, str(d))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    for var in ("VMDEPLOY_PASSWORD", "VMDEPLOY_CLIENT_SECRET", "VMDEPLOY_ACCESS_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path
