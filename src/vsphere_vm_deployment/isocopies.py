"""ISO copies vmdeploy left in `vmdeploy-iso/` folders: which VMs use them, and deleting the unused ones.

vmdeploy puts an ISO into `<datastore>/vmdeploy-iso/` when it has to be on the VM's datastore (uploaded from this
computer, or copied from another host). The copies are kept on purpose, so the next deployment to that datastore
reuses them. Nothing here deletes anything without the user's explicit choice.
"""

from __future__ import annotations

import logging
import re

from pyVmomi import vim

from . import inventory, isolib
from .logsetup import FILE_ONLY
from .tasks import fault_message, wait_task

log = logging.getLogger(__name__)
_SPACES = re.compile(r"\]\s*/?")


def norm(path: str) -> str:
    """'[ds]/a/b.iso', '[ds]  a/b.iso' -> '[ds] a/b.iso' (servers differ in format)."""
    return _SPACES.sub("] ", (path or "").strip(), count=1)


def is_copy(path: str) -> bool:
    try:
        return isolib.split(path)[1].startswith(f"{isolib.ISO_FOLDER}/")
    except ValueError:
        return False


def iso_users(conn) -> dict[str, list[str]]:
    """Every ISO attached to a VM's CD/DVD drive -> the names of the VMs using it. Raises DeploymentError when the
    VMs cannot be read: an empty answer would make every copy look unused, and unused copies get deleted. Keyed by
    path only, in every datacenter: a path used in one datacenter counts as used everywhere (never too few)."""
    from .errors import DeploymentError

    users: dict[str, list[str]] = {}
    try:
        vms = inventory.collect(conn, vim.VirtualMachine, ["name", "config.hardware.device"], strict=True)
    except Exception as e:  # noqa: BLE001
        raise DeploymentError(f"Could not read which VMs use the ISO copies ({fault_message(e)}); "
                              "nothing was deleted.", hint="Run the command again.") from e
    for _obj, props in vms:
        for path in iso_paths(props.get("config.hardware.device")):
            users.setdefault(path, []).append(props.get("name", "?"))
    return users


def iso_paths(devices, *, connected_only: bool = False) -> list[str]:
    """The ISO files attached to these devices' CD/DVD drives (a VM's config.hardware.device), as normalised
    "[datastore] path". The one rule for "a VM uses this ISO": attached, connected or not (`connected_only`: only
    drives connected now, as for the files a running VM keeps locked)."""
    return [norm(dev.backing.fileName) for dev in devices or []
            if isinstance(dev, vim.vm.device.VirtualCdrom)
            and isinstance(getattr(dev, "backing", None), vim.vm.device.VirtualCdrom.IsoBackingInfo)
            and dev.backing.fileName
            and (not connected_only or getattr(getattr(dev, "connectable", None), "connected", False))]


def datacenter_of(obj) -> str | None:
    """The name of the datacenter an inventory object (e.g. a VM) is in; None if it cannot be read."""
    try:
        while obj is not None and not isinstance(obj, vim.Datacenter):
            obj = getattr(obj, "parent", None) or getattr(obj, "parentVApp", None)
        return obj.name if obj is not None else None
    except Exception as e:  # noqa: BLE001
        log.debug("could not find the datacenter: %s", e)
        return None


def copies_attached(devices, dc: str | None) -> list[tuple[str | None, str]]:
    """The vmdeploy ISO copies attached to these CD/DVD devices (a VM's config.hardware.device, read together with
    whatever else is needed), as (datacenter name, path): datastore names are unique only within a datacenter."""
    return [(dc, path) for path in iso_paths(devices) if is_copy(path)]


def copies(inv, skipped: list[str] | None = None) -> list[isolib.DatastoreIso]:
    """All ISO files in vmdeploy-iso/ folders on the datastores this account may browse. Datastores that could
    not be searched are added to `skipped`."""
    found = []
    for dc in inv.datacenters.values():
        found += [i for i in isolib.find_isos(dc, skipped=skipped) if i.path.startswith(f"{isolib.ISO_FOLDER}/")]
    return found


def folder_entries(ds_obj, ds_name: str) -> list[str] | None:
    """What is inside <datastore>/vmdeploy-iso/ (names), or None when there is no such folder."""
    spec = vim.host.DatastoreBrowser.SearchSpec(matchPattern=["*"])
    try:
        res = wait_task(ds_obj.browser.SearchDatastore_Task(datastorePath=f"[{ds_name}] {isolib.ISO_FOLDER}",
                                                            searchSpec=spec), what="datastore search")
    except Exception as e:  # noqa: BLE001 - no folder (FileNotFound) or not browsable
        log.debug("no %s folder on %s: %s", isolib.ISO_FOLDER, ds_name, e)
        return None
    return [f.path for f in (res.file if res else None) or []]


def empty_folders(inv) -> list[tuple[object, str, object]]:
    """(datacenter, datastore name, datastore object) for every vmdeploy-iso/ folder with nothing in it."""
    out = []
    for dc in inv.datacenters.values():
        for ds in dc.datastores.values():
            if ds.usable and folder_entries(ds.obj, ds.name) == []:
                out.append((dc, ds.name, ds.obj))
    return out


def delete_empty_folder(conn, dc, ds_name: str, ds_obj) -> bool:
    """Delete <datastore>/vmdeploy-iso/ only if it is still empty (checked again just before)."""
    if folder_entries(ds_obj, ds_name) != []:
        return False
    wait_task(conn.content.fileManager.DeleteDatastoreFile_Task(name=f"[{ds_name}] {isolib.ISO_FOLDER}",
                                                                datacenter=dc.obj), what="Delete empty folder")
    log.info("Deleted the empty folder [%s] %s", ds_name, isolib.ISO_FOLDER, extra=FILE_ONLY)
    return True


def delete(conn, inv, full: str, datacenter: str | None = None) -> None:
    """Delete one ISO copy. Datastore names are unique only within a datacenter: `datacenter` says which one is
    meant; without it the datastore name must be unique."""
    from .errors import DeploymentError

    ds_name, _ = isolib.split(full)
    dcs = isolib.datacenters_with(inv, ds_name, datacenter)
    if len(dcs) != 1:
        why = (f"was not found in datacenter {datacenter}" if datacenter is not None else
               "is ambiguous: several datacenters have a datastore of that name" if dcs else "was not found")
        raise DeploymentError(f"Not deleted: {full} {why}.")
    dc = dcs[0]
    wait_task(conn.content.fileManager.DeleteDatastoreFile_Task(name=full, datacenter=dc.obj), what="Delete ISO")
    log.info("Deleted the ISO copy %s (datacenter %s)", full, dc.name, extra=FILE_ONLY)  # destroy, access, prune
    # vmdeploy made the vmdeploy-iso/ folder: remove it too once its last copy is gone
    ds = dc.datastores.get(ds_name)
    if ds is not None:
        try:
            delete_empty_folder(conn, dc, ds_name, ds.obj)
        except Exception as e:  # noqa: BLE001 - the copy itself is deleted; an empty folder is harmless
            log.debug("could not remove the empty %s folder on %s: %s", isolib.ISO_FOLDER, ds_name, e)
