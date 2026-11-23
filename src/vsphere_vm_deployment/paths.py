"""Where the tool keeps its files: per-user OS-standard locations by default, never the install folder or the repo.
The log folder can be chosen (`vmdeploy logs --folder`), e.g. a synced or network folder that outlasts a logoff."""

from __future__ import annotations

import json
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


def settings_file() -> Path:
    """Settings that are not about a connection (today only the log folder)."""
    return config_dir() / "settings.json"


def read_settings() -> dict:
    """The saved settings; {} when there are none or the file cannot be read (a log_dir_problem() then says so)."""
    global _settings_problem
    _settings_problem = None
    path = settings_file()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        _settings_problem = f"Could not read {path} ({e}): its settings are ignored."
        return {}
    return data if isinstance(data, dict) else {}


def write_settings(data: dict) -> None:
    path = settings_file()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def default_log_dir() -> Path:
    return Path(_dirs.user_log_dir)


_log_problem: str | None = None
_settings_problem: str | None = None


def log_dir_source() -> str:
    """Where the log folder comes from: "env" (VMDEPLOY_LOG_DIR), "setting" (`vmdeploy logs --folder`) or
    "default"."""
    if os.environ.get("VMDEPLOY_LOG_DIR"):
        return "env"
    return "setting" if read_settings().get("log_folder") else "default"


def log_dir() -> Path:
    """Logs and batch results files. VMDEPLOY_LOG_DIR wins, then the folder chosen with `vmdeploy logs --folder`,
    then the OS-standard per-user folder. A chosen folder that is not reachable (a disconnected share or drive)
    is never created from scratch: its own folder is re-created if only that was deleted, otherwise the default
    is used and log_dir_problem() says why."""
    global _log_problem
    _log_problem = None
    override = os.environ.get("VMDEPLOY_LOG_DIR")
    if override:
        return _ensure(Path(override).expanduser())
    chosen = read_settings().get("log_folder")
    if isinstance(chosen, str) and chosen:
        p = Path(chosen)
        try:
            p.mkdir(exist_ok=True)  # never its parents: they belong to a drive or share that may be missing
            if p.is_dir():
                _log_problem = None
                return p
            reason = "not a folder"
        except OSError as e:
            reason = e.strerror or str(e)
        _log_problem = f"The log folder {p} is not available ({reason}); using {default_log_dir()} this time."
    return _ensure(default_log_dir())


def log_dir_problem() -> str | None:
    """Why the last log_dir() did not use the chosen folder (or could not read the settings), if it did not."""
    return _log_problem or _settings_problem


def fallback_log_dir(reason: str) -> Path:
    """The default folder, when the chosen one turned out not to be writable."""
    global _log_problem
    _log_problem = reason
    return _ensure(default_log_dir())


def images_dir() -> Path:
    """The folder users drop local images into for `--local`. Defaults to ./images (the repo's gitignored
    folder) and can be overridden with VMDEPLOY_IMAGES_DIR."""
    override = os.environ.get("VMDEPLOY_IMAGES_DIR")
    return Path(override).expanduser() if override else Path.cwd() / "images"
