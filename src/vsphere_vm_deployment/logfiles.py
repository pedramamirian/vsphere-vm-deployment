"""Finding logs and batch results files again: `latest`, a bare file name, and the `vmdeploy logs` listing."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .errors import ConfigError
from .paths import log_dir

LATEST = "latest"
_STAMP = re.compile(r"(\d{8}-\d{6})")


def batch_files() -> list[Path]:
    """The batch results files in the log folder, newest first (their names start with the date and time)."""
    return sorted(log_dir().glob("batch-*.json"), key=lambda f: f.name, reverse=True)


def log_files() -> list[Path]:
    return sorted(log_dir().glob("vmdeploy-*.log"), key=lambda f: f.name, reverse=True)


def results_file(value: Path) -> Path:
    """A results file given on the command line: `latest` (the newest in the log folder), a file name alone
    (looked up in the log folder when it is not in the current one), or a path."""
    text = str(value)
    if value.exists():
        return value
    if text.lower() == LATEST:
        files = batch_files()
        if not files:
            raise ConfigError(f"There are no batch results files in {log_dir()}.",
                              hint="`vmdeploy logs` shows the log folder; give the results file's full path if it "
                                   "is somewhere else.")
        return files[0]
    if value.name == text:  # no folder given: the name a summary or `vmdeploy logs` printed
        candidate = log_dir() / text
        if candidate.exists():
            return candidate
    return value


def stamp_of(f: Path) -> datetime | None:
    m = _STAMP.search(f.name)
    try:
        return datetime.strptime(m.group(1), "%Y%m%d-%H%M%S") if m else None
    except ValueError:
        return None


@dataclass
class BatchRun:
    path: Path
    started: datetime | None
    datacenter: str = ""
    image: str = ""
    total: int = 0
    deployed: int = 0  # including the ones deployed with a problem
    problems: int = 0
    readable: bool = True


def read_batch(f: Path) -> BatchRun:
    try:
        doc = json.loads(f.read_text(encoding="utf-8"))
        vms = doc["vms"]
        totals = doc.get("totals") or {}
        started = datetime.fromisoformat(doc["started"]) if doc.get("started") else stamp_of(f)
        return BatchRun(f, started, str(doc.get("datacenter") or ""), str(doc.get("image") or ""), len(vms),
                        int(totals.get("deployed", 0)) + int(totals.get("problem", 0)), int(totals.get("problem", 0)))
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return BatchRun(f, stamp_of(f), readable=False)


def inside_git_repository(folder: Path) -> Path | None:
    """The Git working tree that contains this folder, if any."""
    for p in (folder, *folder.parents):
        if (p / ".git").exists():
            return p
    return None
