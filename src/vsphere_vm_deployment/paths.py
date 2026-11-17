"""Where the tool keeps its files. Everything lives in per-user OS-standard locations, never in the repo."""

from __future__ import annotations

import os
from pathlib import Path

from platformdirs import PlatformDirs

_dirs = PlatformDirs(appname="vsphere-vm-deployment", appauthor=False)


def _ensure(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


def config_dir() -> Path:
    """Profiles and trusted certificates. Override with VMDEPLOY_CONFIG_DIR (used by the tests)."""
    override = os.environ.get("VMDEPLOY_CONFIG_DIR")
    return _ensure(Path(override).expanduser() if override else Path(_dirs.user_config_dir))


def cache_dir() -> Path:
    """Downloaded images. Override with VMDEPLOY_CACHE_DIR."""
    override = os.environ.get("VMDEPLOY_CACHE_DIR")
    return _ensure(Path(override).expanduser() if override else Path(_dirs.user_cache_dir) / "images")


def log_dir() -> Path:
    override = os.environ.get("VMDEPLOY_LOG_DIR")
    return _ensure(Path(override).expanduser() if override else Path(_dirs.user_log_dir))


def images_dir() -> Path:
    """The folder users drop local images into for `--local`. Defaults to ./images (the repo's gitignored
    folder) and can be overridden with VMDEPLOY_IMAGES_DIR."""
    override = os.environ.get("VMDEPLOY_IMAGES_DIR")
    return Path(override).expanduser() if override else Path.cwd() / "images"
