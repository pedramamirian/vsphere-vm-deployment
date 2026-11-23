"""Logging with secret redaction.

Every run writes a log file (path printed at the end) so users can attach it to a GitHub issue.
Passwords, tokens, session cookies, cloud-init user-data and private keys are scrubbed before
anything is written, both to the file and to the console in verbose mode.
"""

from __future__ import annotations

import logging
import re
import threading
from datetime import datetime
from pathlib import Path

from .paths import fallback_log_dir, log_dir

_PATTERNS = [
    # key=value / "key": "value" style secrets
    (re.compile(r"(?i)(password|passwd|pwd|secret|token|client_secret|access_token|id_token|subject_token|"
                r"actor_token|user-data|userdata)(['\"]?\s*[=:]\s*['\"]?)([^'\"\s,}&]+)"), r"\1\2***"),
    (re.compile(r"(?i)(authorization:\s*)(\S+\s+)?\S+"), r"\1***"),
    (re.compile(r"(?i)(vmware_soap_session=)[^;\s]+"), r"\1***"),
    (re.compile(r"(?i)(vmware-api-session-id:\s*)\S+"), r"\1***"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "***PRIVATE KEY***"),
    (re.compile(r"<saml2?:Assertion.*?</saml2?:Assertion>", re.S), "***SAML***"),
]

# Exact secret values registered at runtime (e.g. the password the user typed) are also scrubbed.
_runtime_secrets: set[str] = set()

_URL_USERINFO = re.compile(r"(https?://)[^/\s@]+@")
_URL_QUERY = re.compile(r"(https?://[^\s?#]+)\?[^\s#]*")


def safe_url(url: str) -> str:
    """URL without user:password@ and without the query string (pre-signed URLs carry tokens there)."""
    if not url:
        return url
    return _URL_QUERY.sub(r"\1?***", _URL_USERINFO.sub(r"\1***@", url))


def register_secret(value: str | None) -> None:
    if value and len(value) >= 4:
        _runtime_secrets.add(value)


def redact(text: str) -> str:
    for secret in sorted(_runtime_secrets, key=len, reverse=True):
        text = text.replace(secret, "***")
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return safe_url(text)


_context = threading.local()


def set_log_label(label: str | None) -> None:
    """Prefix this thread's log lines with `label` (a batch names the VM each line is about), or stop (None)."""
    _context.label = label


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 - never let logging crash the tool
            msg = str(record.msg)
        label = getattr(_context, "label", None)
        if label and not getattr(record, "vmdeploy_labelled", False):  # each handler filters the same record
            msg = f"[{label}] {msg}"
            record.vmdeploy_labelled = True
        record.msg = redact(msg)
        record.args = ()
        return True


class RedactingFormatter(logging.Formatter):
    """Also scrubs tracebacks, which logging formats after filters have run."""

    def formatException(self, ei) -> str:  # noqa: N802 - logging API
        return redact(super().formatException(ei))

    def formatStack(self, stack_info: str) -> str:  # noqa: N802 - logging API
        return redact(super().formatStack(stack_info))

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


_log_file: Path | None = None


# Pass as `extra=` for lines that only belong in the log file (the console already showed the message).
FILE_ONLY = {"file_only": True}


class _NotFileOnly(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not getattr(record, "file_only", False)


def setup_logging(verbose: int = 0) -> Path:
    """Configure the root logger. Returns the path of this run's log file."""
    global _log_file
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    _log_file = log_dir() / f"vmdeploy-{stamp}.log"
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.DEBUG)

    try:
        fh = logging.FileHandler(_log_file, encoding="utf-8")
    except OSError as e:  # a chosen folder that exists but cannot be written to: the run still gets a log
        folder = _log_file.parent
        _log_file = fallback_log_dir(f"Cannot write to the log folder {folder} ({e.strerror or e}); using the "
                                     "default folder this time.") / f"vmdeploy-{stamp}.log"
        fh = logging.FileHandler(_log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(RedactingFormatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    fh.addFilter(RedactingFilter())
    root.addHandler(fh)

    if verbose:
        from rich.logging import RichHandler

        from .ui import console

        ch = RichHandler(console=console, show_path=False, markup=False, rich_tracebacks=False)
        ch.setLevel(logging.DEBUG if verbose > 1 else logging.INFO)
        ch.addFilter(RedactingFilter())
        ch.addFilter(_NotFileOnly())
        root.addHandler(ch)

    # pyVmomi and urllib3 are chatty at DEBUG; keep them at WARNING unless -vv.
    for noisy in ("urllib3", "pyVmomi", "pyVim"):
        logging.getLogger(noisy).setLevel(logging.DEBUG if verbose > 1 else logging.WARNING)
    return _log_file


def current_log_file() -> Path | None:
    return _log_file
