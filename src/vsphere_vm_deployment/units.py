"""Sizes as vmdeploy shows them: 1024-based and labelled KB/MB/GB, the way vSphere and Windows show them (and the
way vmdeploy shows VM disks, memory and datastore space), and dates. No vmdeploy imports, so any module may
use it."""

_UNITS = ("bytes", "KB", "MB", "GB", "TB")


def size_unit(n: float) -> int:
    """Index into the units for `n`: the largest unit whose shown value (one decimal) stays below 1024, so a size
    just under a boundary reads '1.0 GB', not '1024.0 MB'."""
    i = 0
    while i < len(_UNITS) - 1 and (n >= 1024 if i == 0 else round(n / 1024 ** i, 1) >= 1024):
        i += 1
    return i


def human_size(n: float, unit: int | None = None) -> str:
    """3,405,469,696 bytes -> '3.2 GB'; `unit` (from size_unit) shows several values in one unit."""
    i = size_unit(n) if unit is None else unit
    return f"{int(n)} bytes" if i == 0 else f"{n / 1024 ** i:.1f} {_UNITS[i]}"


def local_date(stamp: str, tz=None) -> str:
    """The date of a saved timestamp (ISO 8601, saved in UTC) in this computer's time zone (or `tz`): west of UTC,
    something saved in the evening showed the next day's date. The saved text's first 10 characters when it is not
    a timestamp."""
    from datetime import datetime

    try:
        return datetime.fromisoformat(stamp).astimezone(tz).date().isoformat()
    except (TypeError, ValueError, OSError, OverflowError):  # OSError/OverflowError: out of range for the OS
        return str(stamp)[:10]
