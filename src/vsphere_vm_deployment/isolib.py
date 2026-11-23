"""ISOs already on datastores: find them, recognise common installers, and copy one to a datastore the target
host can see (vCenter copies it host to host; nothing passes through this computer).

A VM can only boot an ISO from a datastore its host has mounted. A *shared* datastore (NFS, iSCSI, FC, vSAN)
works for every host; a host's *local* datastore only for that host. When the ISO is on another host's local
datastore it is copied once into `vmdeploy-iso/` on the VM's datastore and reused by later deployments.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from pyVmomi import vim, vmodl

from .errors import DeploymentError
from .tasks import fault_message, wait_task
from .units import human_size

log = logging.getLogger(__name__)


class FolderListError(DeploymentError):
    """A datastore folder could not be listed. A free name cannot be told from a taken one then, so nothing may be
    written there: this is never a reason to try another way of writing to the same folder."""

ISO_FOLDER = "vmdeploy-iso"


def any_case(*extensions: str) -> tuple[str, ...]:
    """Datastore search patterns for these extensions in every letter case ("iso" -> "*.iso", "*.Iso", ...,
    "*.ISO"): the search compares letter case, and vmdeploy takes Win11.Iso for an ISO like Win11.iso."""
    from itertools import product

    return tuple("*." + "".join(letters) for ext in extensions
                 for letters in product(*((c.lower(), c.upper()) for c in ext)))


ISO_PATTERNS = any_case("iso")


def is_iso_name(name: str) -> bool:
    """Is this file name an ISO by vmdeploy's rule (the .iso extension, in any letter case)? The one rule for
    deploy, `images prune` (through ISO_PATTERNS) and `access audit`."""
    return name.lower().endswith(".iso")
_DS_PATH = re.compile(r"^\[(?P<ds>[^\]]+)\]\s*/?(?P<path>.*?)/*$")


@dataclass
class DatastoreIso:
    datastore: str
    path: str  # inside the datastore, e.g. "ISO/en-us_windows_server_2022.iso"
    size: int = 0
    hosts: set[str] = field(default_factory=set)
    all_hosts: int = 0  # hosts in the datacenter, to tell shared from local datastores
    datacenter: str = ""  # datastore names are unique only within a datacenter

    @property
    def full(self) -> str:
        return f"[{self.datastore}] {self.path}"

    def label(self) -> str:
        import urllib.parse

        size = human_size(self.size) if self.size else "size unknown"
        shared = self.all_hosts > 1 and len(self.hosts) >= self.all_hosts
        where = f"shared ({self.all_hosts} hosts)" if shared else (", ".join(sorted(self.hosts)) or "no host")
        low = self.path.lower()
        note = ("read through this computer with its disk files; needs that space free here" if low.endswith(".ovf")
                else "read through this computer; needs this much free space here" if low.endswith(".ova") else
                "usable on every host" if shared else "copied automatically if you deploy to another host")
        return f"{where} › [{urllib.parse.unquote(self.datastore)}] {self.path}  ({size}; {note})"


def split(full: str) -> tuple[str, str]:
    """'[ds] a/b.iso' -> ('ds', 'a/b.iso')."""
    m = _DS_PATH.match(full.strip())
    if not m:
        raise ValueError(f"Not a datastore path: {full!r} (expected \"[datastore] folder/file.iso\")")
    return m["ds"], m["path"]


def find_isos(dc, patterns=ISO_PATTERNS, skipped: list[str] | None = None) -> list[DatastoreIso]:
    """Image files (by default ISOs, in any letter case) on the datacenter's accessible datastores. Datastores that could not be
    searched (usually: the account may not browse them) are added to `skipped` when a list is given."""
    found: list[DatastoreIso] = []
    for ds in dc.datastores.values():
        if not ds.usable:
            continue
        spec = vim.host.DatastoreBrowser.SearchSpec(
            matchPattern=list(patterns), details=vim.host.DatastoreBrowser.FileInfo.Details(fileSize=True))
        try:
            task = ds.obj.browser.SearchDatastoreSubFolders_Task(datastorePath=f"[{ds.name}]", searchSpec=spec)
            results = wait_task(task, what=f"Search {ds.name}") or []
        except Exception as e:  # noqa: BLE001 - no Datastore.Browse on this datastore, or it is busy
            log.debug("ISO search on %s failed: %s", ds.name, e)
            if skipped is not None:
                skipped.append(ds.name)
            continue
        for res in results:
            _ds, folder = split(res.folderPath) if res.folderPath.strip().startswith("[") else (ds.name, "")
            for f in res.file or []:
                path = f"{folder}/{f.path}" if folder else f.path
                found.append(DatastoreIso(ds.name, path, getattr(f, "fileSize", 0) or 0, set(ds.hosts),
                                          len(dc.hosts), getattr(dc, "name", "")))
    return sorted(found, key=lambda i: (", ".join(sorted(i.hosts)), i.datastore, i.path.lower()))


# Windows installers are recognised from their file name (Microsoft's names contain the product and build).
# Build numbers must stand alone, so dates such as 20261016 are not mistaken for a build.
_B = r"(?<!\d){}(?!\d)"
_WINDOWS = [
    (re.compile(r"server[ _-]?2025|" + _B.format("26100") + r".*server", re.I), "windows2022srvNext_64Guest"),
    (re.compile(r"server[ _-]?2022|" + _B.format("20348"), re.I), "windows2019srvNext_64Guest"),  # = Server 2022
    (re.compile(r"server[ _-]?2019|" + _B.format("17763"), re.I), "windows2019srv_64Guest"),
    (re.compile(r"server[ _-]?2016|" + _B.format("14393"), re.I), "windows9Server64Guest"),     # = Server 2016
    (re.compile(r"win(dows)?[ _-]?11|" + _B.format("2(2[0-9]|6[0-9])[0-9]{2}"), re.I), "windows11_64Guest"),
    (re.compile(r"win(dows)?[ _-]?10|" + _B.format("19[0-9]{3}"), re.I), "windows9_64Guest"),  # = Windows 10
]


def find_images(dc, skipped: list[str] | None = None) -> list[DatastoreIso]:
    """ISOs, OVAs and OVFs on the datastores."""
    return find_isos(dc, any_case("iso", "ova", "ovf"), skipped)


# Other installers, recognised from common file names. Each gives guest IDs to try in order; the first one the
# host offers is suggested (newer IDs are missing on older ESXi). Versions are read from the name when present.
def _versions(family: str, found: int | None, newest: int, oldest: int, suffix: str = "_64Guest") -> list[str]:
    start = found if found and oldest <= found <= newest else newest
    return [f"{family}{v}{suffix}" for v in range(start, oldest - 1, -1)]


def _version_after(word: str, text: str) -> int | None:
    m = re.search("(?:" + word + r")[^0-9]{0,12}?(?<!\d)(\d{1,2})(?!\d)", text, re.I)
    return int(m.group(m.lastindex)) if m else None  # the last group is the number


_EVE = re.compile(r"(?<![a-z])eve[-_ ]?(ng|pro|ce)(?![a-z])", re.I)
_NESTED = re.compile(r"(?<![a-z])(eve[-_ ]?(ng|pro|ce)|vmvisor|esxi|proxmox|gns3|cml)(?![a-z])", re.I)


def guess_guest_ids(name: str) -> list[str]:
    """Guest OS IDs that fit an installer's file name, best first (empty when it is not recognised)."""
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    for pattern, guest_id in _WINDOWS:
        if pattern.search(base):
            return [guest_id]
    low = base.lower()
    if _EVE.search(low) or "ubuntu" in low:  # EVE-NG is installed on Ubuntu (its docs: "Ubuntu Linux (64-bit)")
        return ["ubuntu64Guest"]
    if "vmvisor" in low or re.search(r"(?<![a-z])esxi", low):
        return _versions("vmkernel", _version_after("(esxi|installer)", low), 9, 6, suffix="Guest")
    if "proxmox" in low:  # Proxmox VE 8 is Debian 12, 7 is Debian 11
        ver = _version_after("(proxmox|ve)", low)
        return _versions("debian", ver + 4 if ver else None, 12, 10)
    if "debian" in low:
        return _versions("debian", _version_after("debian", low), 13, 10)
    if re.search(r"(?<![a-z])(rhel|red[-_ ]?hat)", low):
        return _versions("rhel", _version_after("(rhel|hat)", low), 10, 7)
    if "rocky" in low:
        return ["rockylinux_64Guest", "rhel9_64Guest", "rhel8_64Guest"]
    if "alma" in low:
        return ["almalinux_64Guest", "rhel9_64Guest", "rhel8_64Guest"]
    if "centos" in low:
        return _versions("centos", _version_after("centos", low), 9, 7)
    if "oracle" in low or re.search(r"(?<![a-z])ol\d", low):
        return _versions("oracleLinux", _version_after("(linux|ol)", low), 9, 7)
    if re.search(r"(?<![a-z])(sles|sle|suse)", low):
        return _versions("sles", _version_after("(sles|sle|suse)", low), 16, 12)
    if "photon" in low:
        return ["vmwarePhoton64Guest"]
    if re.search(r"freebsd|pfsense|opnsense|truenas[-_ ]?core", low):
        return _versions("freebsd", _version_after("freebsd", low), 14, 11)
    if "linux" in low or re.search(r"fedora|arch|kali|mint|nixos|talos", low):
        return ["other6xLinux64Guest", "other5xLinux64Guest", "other4xLinux64Guest", "other3xLinux64Guest"]
    return []


def guess_guest_id(name: str) -> str | None:
    ids = guess_guest_ids(name)
    return ids[0] if ids else None


def suggests_nested(name: str) -> bool:
    """Hypervisors and network labs (EVE-NG, ESXi, Proxmox, GNS3, CML) run VMs themselves, so they need the CPU's
    virtualisation features passed through to them."""
    return bool(_NESTED.search(name or ""))


def is_windows(guest_id: str | None) -> bool:
    return bool(guest_id) and guest_id.lower().startswith("win")


def needs_vtpm(guest_id: str | None) -> bool:
    """Windows 11 refuses to install without TPM 2.0."""
    return bool(guest_id) and guest_id.lower().startswith("windows11")


def suggests_vtpm(guest_id: str | None) -> bool:
    """Windows 11, and Windows Server 2025 (Microsoft recommends TPM 2.0)."""
    return needs_vtpm(guest_id) or (guest_id or "").lower().startswith("windows2022srvnext")


def copy_target(dest_datastore: str, source_path: str) -> str:
    """Where vmdeploy copies an ISO on another datastore: vmdeploy-iso/<its file name>. `source_path` is a file
    name, a local path or a datastore path ("[ds] file.iso" in the top folder has no "/" to split on)."""
    return f"[{dest_datastore}] {ISO_FOLDER}/{file_name(source_path)}"


def file_name(path: str) -> str:
    """The file name of a datastore path, a local path (either slash) or a bare name."""
    try:
        path = split(path)[1]
    except ValueError:
        pass
    return re.split(r"[/\\]", path)[-1]


def copy_variant(fname: str, name: str) -> bool:
    """Is `name` a copy of `fname` as vmdeploy names them: the name itself, or with -2, -3, ... added."""
    stem, dot, ext = fname.rpartition(".")
    pattern = (re.escape(stem) + r"(-\d+)?\." + re.escape(ext)) if dot else (re.escape(fname) + r"(-\d+)?")
    return re.fullmatch(pattern, name) is not None


def is_vmdeploy_copy(image_name: str, path: str) -> bool:
    """Is `path` (inside a datastore) one of vmdeploy's copies of `image_name`: vmdeploy-iso/<name>, or the -2,
    -3, ... a taken name made it use. Still only a candidate: its content must be checked before use."""
    folder, _, fname = path.rpartition("/")
    return folder == ISO_FOLDER and copy_variant(image_name, fname)


def list_folder(ds_obj, ds_name: str, folder: str) -> dict[str, int]:
    """{file name: size} of one datastore folder, in a single search; {} if the folder does not exist. Raises
    DeploymentError when the folder could not be searched: callers that choose where to write must never take a
    failed search for "nothing there"."""
    hint = "Check that this account may browse that datastore and that it is reachable, then try again."
    spec = vim.host.DatastoreBrowser.SearchSpec(matchPattern=["*"],  # explicit: some servers match nothing without
                                                details=vim.host.DatastoreBrowser.FileInfo.Details(fileSize=True))
    try:
        res = wait_task(ds_obj.browser.SearchDatastore_Task(datastorePath=f"[{ds_name}] {folder}", searchSpec=spec),
                        what="datastore search")
    except vim.fault.FileNotFound:
        return {}
    except DeploymentError as e:
        if isinstance(getattr(e, "fault", None), vim.fault.FileNotFound):
            return {}  # the folder does not exist yet
        raise FolderListError(f"Could not list [{ds_name}] {folder}: {e.message}", hint=hint) from e
    except Exception as e:  # noqa: BLE001
        raise FolderListError(f"Could not list [{ds_name}] {folder}: {e}", hint=hint) from e
    return {f.path: (getattr(f, "fileSize", 0) or 0) for f in (res.file if res else []) or []}


def copies_in(ds_obj, target: str, size: int | None) -> list[str]:
    """The existing copies of `target`'s file (the name and its -N variants) in its folder with exactly `size`
    bytes, the plain name first. A candidate list only: the caller must still confirm the content. The folder is
    listed even without a size, so a folder that cannot be listed is reported (FolderListError) before anything
    is read or uploaded for it."""
    ds, path = split(target)
    folder, _, fname = path.rpartition("/")
    listing = list_folder(ds_obj, ds, folder)
    if size is None:
        return []
    names = [n for n, s in listing.items() if s == size and copy_variant(fname, n)]
    names.sort(key=lambda n: (n != fname, len(n), n))
    return [f"[{ds}] {folder}/{n}" for n in names]


def unused_target(dest_datastore_obj, target: str) -> str:
    """`target`, or the same name with -2, -3, ... added: a path where no file exists yet (one folder listing).
    Files in vmdeploy-iso/ may be in use by other VMs, and anyone with file rights on that datastore could have
    put one there, so a new upload or copy never overwrites one. A folder that cannot be listed is an error,
    never "free"."""
    ds, path = split(target)
    folder, _, fname = path.rpartition("/")
    taken = set(list_folder(dest_datastore_obj, ds, folder))
    if fname not in taken:
        return target
    stem, dot, ext = fname.rpartition(".")
    n = 2
    while (alt := f"{stem}-{n}.{ext}" if dot else f"{fname}-{n}") in taken:
        n += 1
    return f"[{ds}] {folder}/{alt}"


def ensure_copied(conn, dc_obj, source_full: str, dest_datastore_obj, dest_full: str, *, on_progress=None,
                  reuse_if=None) -> tuple[str, str]:
    """Copy the ISO to `dest_full` (server-side, within `dc_obj`). Returns (where it is now, how it went).

    An earlier copy in the destination folder (the name or a -N variant, same size) is used when `reuse_if(path)`
    confirms it (the caller checks the content); otherwise the copy goes to an unused name. Nothing is overwritten,
    and a name taken meanwhile by another deployment is never deleted: another free name is tried."""
    dest_ds, dest_path = split(dest_full)
    folder, _, fname = dest_path.rpartition("/")
    fm = conn.content.fileManager
    try:
        fm.MakeDirectory(name=f"[{dest_ds}] {folder}", datacenter=dc_obj, createParentDirectories=True)
    except vim.fault.FileAlreadyExists:
        pass
    src_size = _size(conn, dc_obj, source_full)
    if reuse_if is not None:
        for cand in copies_in(dest_datastore_obj, dest_full, src_size):
            if reuse_if(cand):
                return cand, "copied earlier; checked; reused"

    def remove_partial(attempt: str) -> None:  # our own copy failed part-way: never leave a half-copied ISO
        d_ds, d_path = split(attempt)
        d_folder, _, d_name = d_path.rpartition("/")
        left = _size_on(dest_datastore_obj, d_ds, d_folder, d_name)
        if left is not None and left != src_size:
            try:
                wait_task(fm.DeleteDatastoreFile_Task(name=attempt, datacenter=dc_obj), what="Delete partial copy")
            except Exception as de:  # noqa: BLE001
                log.debug("could not delete the partial copy %s: %s", attempt, de)

    dest = _to_free_name(dest_datastore_obj, dest_full, what="Copy ISO", on_progress=on_progress,
                         on_failure=remove_partial,
                         start=lambda name: fm.CopyDatastoreFile_Task(
                             sourceName=source_full, sourceDatacenter=dc_obj, destinationName=name,
                             destinationDatacenter=dc_obj, force=False))
    return dest, "copied by vCenter, host to host"


def place_upload(conn, dc_obj, dest_datastore_obj, uploaded_full: str, wanted_full: str) -> str:
    """Give an upload made under a name of its own the name `wanted_full`, or the next free -N name if that one is
    taken, and return where it is now. A datastore upload (HTTP PUT) replaces any file of its name; a move with
    force=False never does, so a file another deployment put there meanwhile is left alone."""
    fm = conn.content.fileManager
    return _to_free_name(dest_datastore_obj, wanted_full, what="Name the uploaded ISO",
                         start=lambda name: fm.MoveDatastoreFile_Task(
                             sourceName=uploaded_full, sourceDatacenter=dc_obj, destinationName=name,
                             destinationDatacenter=dc_obj, force=False))


def _to_free_name(dest_datastore_obj, wanted_full: str, *, start, what: str, on_progress=None,
                  on_failure=None) -> str:
    """Write `wanted_full`, or the next free -N name, with `start(name)`: a vSphere task that writes `name` with
    force=False, so nothing is ever overwritten. A name another deployment takes in the meantime is left alone and
    the next one is tried. `on_failure(name)` cleans up after a task this run started that then failed; a call
    refused before its task started has written nothing, and the file at that name is someone else's. Returns
    the name written."""
    ds, path = split(wanted_full)
    folder, _, fname = path.rpartition("/")
    for _attempt in range(3):
        attempt = unused_target(dest_datastore_obj, wanted_full)
        task = None
        try:
            task = start(attempt)  # inside the try: a server may refuse the call itself (a fault, not a task)
            wait_task(task, what=what, on_progress=on_progress)
            return attempt
        except Exception as e:
            if _already_exists(e):
                continue  # another deployment took the name just now: theirs is left alone
            if task is not None and on_failure is not None:
                on_failure(attempt)
            if isinstance(e, vmodl.MethodFault):  # refused by the server: reported like a failed task
                err = DeploymentError(f"{what} failed: {fault_message(e)}")
                err.fault = e
                raise err from e
            raise
    raise DeploymentError(f"Could not find a free name for {fname} in [{ds}] {folder}.",
                          hint="Other deployments are writing the same ISO there; try again in a moment.")


def _already_exists(e: BaseException) -> bool:
    """FileAlreadyExists, raised by the call itself or reported by its task (wait_task wraps it)."""
    return isinstance(e if isinstance(e, vim.fault.FileAlreadyExists) else getattr(e, "fault", None),
                      vim.fault.FileAlreadyExists)


def datacenters_with(inv, ds_name: str, datacenter: str | None = None) -> list:
    """The datacenters with a datastore named `ds_name` (only `datacenter`, when given). Datastore names are unique
    only within a datacenter: callers treat more than one as ambiguous and never pick one themselves."""
    return [d for d in inv.datacenters.values()
            if ds_name in d.datastores and (datacenter is None or d.name == datacenter)]


def _size(conn, dc_obj, full: str) -> int | None:
    found = _stat(conn, dc_obj, full)
    return found[0] if found else None


def _stat(conn, dc_obj, full: str) -> tuple[int, str | None] | None:
    """(size, last modified) of a datastore file in `dc_obj`; None when it is not there or cannot be read."""
    ds_name, path = split(full)
    ds = next((d for d in dc_obj.datastore if d.name == ds_name), None)
    folder, _, fname = path.rpartition("/")
    return _stat_on(ds, ds_name, folder, fname) if ds else None


def _size_on(ds_obj, ds_name: str, folder: str, fname: str) -> int | None:
    found = _stat_on(ds_obj, ds_name, folder, fname)
    return found[0] if found else None


def _stat_on(ds_obj, ds_name: str, folder: str, fname: str) -> tuple[int, str | None] | None:
    try:
        spec = vim.host.DatastoreBrowser.SearchSpec(
            matchPattern=[fname], details=vim.host.DatastoreBrowser.FileInfo.Details(fileSize=True, modification=True))
        res = wait_task(ds_obj.browser.SearchDatastore_Task(datastorePath=f"[{ds_name}] {folder}", searchSpec=spec),
                        what="datastore search")
        f = next((x for x in (res.file if res else []) or [] if x.path == fname), None)
        if f is None:
            return None
        modified = getattr(f, "modification", None)
        return (getattr(f, "fileSize", 0) or 0,
                modified.isoformat() if hasattr(modified, "isoformat") else (str(modified) if modified else None))
    except Exception:  # noqa: BLE001 - folder missing etc.
        return None
