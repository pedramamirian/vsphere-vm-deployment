"""The Notes vmdeploy writes on every VM it creates. A marker line identifies vmdeploy's VMs: `list` shows them,
`destroy` and `access remove` delete only them (`destroy --force` excepted), and `deploy --replace` replaces an
unmarked VM only after asking (never with --yes). The deployment details follow the marker. Every reader and
writer of the block is here, so the rule is the same everywhere.

The marker is a label, not a lock: anyone allowed to edit a VM's Notes can add or remove it. What keeps deletion
safe is that destructive commands name the VMs and ask first (or need --yes / --force).

Read `config.annotation` together with whatever else is needed (inventory.vm_properties, find_vm_with,
vm_properties_of): `vm.config` downloads the VM's whole configuration and fails on an orphaned VM."""

from __future__ import annotations

from datetime import datetime

from . import ANNOTATION_MARKER, __version__


def build(user_notes: str | None, image: str, sha256: str | None) -> str:
    """The Notes for a new VM: the manifest's own notes (if any), then vmdeploy's block (always last)."""
    head = (user_notes + "\n\n") if user_notes else ""
    return (f"{head}{ANNOTATION_MARKER}\nversion: {__version__}\n"
            f"deployed: {datetime.now().astimezone().isoformat(timespec='seconds')}\n"
            f"image: {image}\nimage-sha256: {sha256 or 'n/a'}")


def is_marked(annotation: str | None) -> bool:
    """Do these Notes carry vmdeploy's marker, i.e. was the VM deployed by vmdeploy?"""
    return ANNOTATION_MARKER in (annotation or "")


def field(annotation: str | None, key: str) -> str:
    """A value from vmdeploy's block, e.g. field(notes, "deployed"); "" when it is not there. The block is the last
    one: notes copied from another vmdeploy VM into the manifest may hold an older block above it."""
    lines = (annotation or "").splitlines()
    start = next((i for i in range(len(lines) - 1, -1, -1) if ANNOTATION_MARKER in lines[i]), None)
    if start is None:
        return ""
    prefix = f"{key}:"
    return next((line[len(prefix):].strip() for line in lines[start + 1:] if line.startswith(prefix)), "")
