"""The deployment orchestrator: one interactive, step-by-step run from sign-in to a powered-on VM.

Nothing in vCenter/ESXi is changed until the user has reviewed and confirmed the plan. Everything before
that point (sign-in, discovery, image download/verification, OVF inspection, questions, pre-flight
checks) is read-only on the server side.
"""

from __future__ import annotations

import logging
import re
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from pyVmomi import vim, vmodl
from rich.markup import escape as esc
from rich.table import Table

from . import __version__, appliances, compat, crypto, guestspecs, isolib, netcheck, vmnotes
from . import cloudinit as ci
from . import ovf as ovflib
from .connection import Connection, connect
from .errors import ConfigError, DeploymentError, PreflightError, TrustError, UserAborted, VmDeployError
from .images import ResolvedImage, resolve
from .inventory import ClusterInfo, DatacenterInventory, DatastoreInfo, GiB, HostInfo, NetworkInfo, discover
from .manifest import VM_NAME_RE, GuestSpec, Manifest, Provisioning
from .ovf import OvfPackage
from .privileges import check as check_privileges
from .profiles import Profile
from .tasks import wait_task
from .transfer import datastore_url_path, upload_stream
from .trust import TrustManager
from .ui import DeploymentView, Prompter, console
from .units import human_size
from .vmspec import (
    COMMON_GUEST_IDS,
    create_spec,
    provisioning_to_ovf,
    reconfigure_spec,
    size_import_spec,
    split_config_spec,
)

log = logging.getLogger(__name__)

# Licences up to this size are shown in full; longer ones as a preview plus a file (see _accept_eulas).
EULA_SHOW_LINES = 60
EULA_SHOW_CHARS = 6000
EULA_PREVIEW_LINES = 15
EULA_PREVIEW_CHARS = 1200  # licence "lines" are often whole paragraphs (vCenter's: ~360 characters each)


def eula_title(text: str, limit: int = 60) -> str:
    """A licence's first sentence or line, shortened at a word boundary."""
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    first = re.split(r"(?<=[.!?])\s", first, maxsplit=1)[0]
    if len(first) <= limit:
        return first
    cut = first[:limit].rsplit(" ", 1)[0].rstrip(",;:")
    return (cut or first[:limit]) + "…"


def eula_preview(text: str) -> str:
    """The start of a long licence: whole lines, up to EULA_PREVIEW_LINES and about EULA_PREVIEW_CHARS."""
    out, size = [], 0
    for line in text.splitlines()[:EULA_PREVIEW_LINES]:
        if out and size + len(line) > EULA_PREVIEW_CHARS:
            break
        out.append(line)
        size += len(line) + 1
    return "\n".join(out)
# The fault text of HostAccessRestrictedToManagementServer: an ESXi host managed by vCenter refusing a change
# made over a direct connection.
RESTRICTED_BY_MANAGER = "restricted to the server that is managing it"

_UNKNOWN_CONFIG_KEY = re.compile(r"Unable to parse '([^']+)' for attribute 'key' on element 'Config'")


def explain_import_warning(msg: str, server: str = "vCenter") -> str:
    """The server's OVF import warnings in plain words. Unknown VMware-specific settings in newer images are the
    common case and are harmless: the server simply leaves them out."""
    m = _UNKNOWN_CONFIG_KEY.search(msg)
    if m:
        return (f"{server} skipped the image setting '{m.group(1)}', which this vSphere version does not know "
                "(harmless; the VM works without it).")
    return f"{server}: {msg}"


def min_sec(seconds: int) -> str:
    """153 -> '2 min 33 sec', 49 -> '0 min 49 sec', 300 -> '5 min'."""
    minutes, secs = divmod(max(0, int(seconds)), 60)
    return f"{minutes} min" if secs == 0 and minutes else f"{minutes} min {secs} sec"


def wait_text(elapsed: int, limit: int) -> str:
    """'12 sec of 30 sec' for limits under a minute, otherwise '2 min 33 sec of 5 min'."""
    if limit < 60:
        return f"{max(0, int(elapsed))} sec of {int(limit)} sec"
    return f"{min_sec(elapsed)} of {min_sec(limit)}"


def suggest_vm_name(raw: str | None, existing: set[str] | None = None) -> str:
    """A short default VM name from the image's product name, unique in the datacenter.
    'ubuntu-resolute-26.04-cloudimg-20261016' -> 'ubuntu-resolute-26.04' (if taken: see next_free_vm_name)."""
    name = re.sub(r"[/\\%]", "-", raw or "new-vm")
    name = re.sub(r"(?i)[-_ ]?cloud-?img", "", name)
    name = re.sub(r"[-_ ]?(19|20)\d{6}(\.\d+)?$", "", name)  # trailing build date, e.g. -20261016
    name = re.sub(r"-{2,}", "-", name).strip("-_ ")[:60] or "new-vm"
    return next_free_vm_name(name, existing or set())


def next_free_vm_name(name: str, existing: set[str], limit: int = 80) -> str:
    """`name` if free; else the first free of name-2, name-3, ... ('web01' -> 'web01-2', or 'web01-3' when that is
    taken too). Numbers in a name are never counted up: 'rhel9' or 'x64' are versions as often as counters. Never
    longer than `limit` characters."""
    if name not in existing:
        return name
    n = 2
    while (cand := f"{name[:limit - len(str(n)) - 1]}-{n}") in existing:
        n += 1
    return cand


def read_key_file(path) -> str:
    """Read an SSH public key file written by any common tool.

    Decoding is explicit rather than left to the platform default (cp1252 on Windows). A UTF-8 byte-order
    mark (Notepad) is stripped, and UTF-16 (`>` / `Out-File` in Windows PowerShell 5.1) is detected by its
    BOM; otherwise the leading BOM character would make a valid key fail the format check.
    """
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace").strip()
    return raw.decode("utf-8-sig", errors="replace").strip()


STEPS = [
    ("connect", "Connect and sign in", 1),
    ("discover", "Discover inventory", 1),
    ("image", "Acquire and verify image", 3),
    ("inspect", "Inspect image (descriptor, manifest, licence)", 2),
    ("configure", "Choose placement and sizing", 1),
    ("preflight", "Pre-flight checks", 1),
    ("plan", "Review plan", 0.5),
    ("upload_iso", "Upload ISO to datastore", 10),
    ("create", "Create VM", 2),
    ("upload_disks", "Upload disks", 20),
    ("reconfigure", "Configure CPU, memory and disks", 1),
    ("customize", "Guest customisation (cloud-init)", 0.5),
    ("power", "Power on", 1),
    ("ip", "Wait for guest IP address", 2),
    ("snapshot", "Baseline snapshot", 0.5),
]


@dataclass
class DeployOptions:
    profile: Profile
    manifest: Manifest
    image_kind: str | None = None
    image_value: str | None = None
    sha256: str | None = None
    interactive: bool = True
    replace: bool = False
    trust_fingerprints: list[str] = field(default_factory=list)


@dataclass
class Plan:
    dc: DatacenterInventory
    name: str = ""
    folder_path: str = "/"
    folder: object = None
    cluster: ClusterInfo | None = None
    host: HostInfo | None = None  # None with a DRS cluster = let DRS choose
    pool_path: str = ""
    pool: object = None
    datastore: DatastoreInfo | None = None
    provisioning: Provisioning = Provisioning.THIN
    cpu: int | None = None
    cores_per_socket: int | None = None
    memory_mb: int | None = None
    disk_gb: int | None = None
    image_disk_gb: int | None = None  # the image's disk 1, rounded up to a whole GB (the default answer)
    extra_disks: list[tuple[int, Provisioning | None]] = field(default_factory=list)
    networks: list[tuple[str | None, NetworkInfo, str]] = field(default_factory=list)
    deployment_option: str | None = None
    ovf_properties: dict[str, str] = field(default_factory=dict)
    guest: GuestSpec | None = None
    guest_route: str | None = None  # "ovf" | "guestinfo" | None
    guest_id: str | None = None
    firmware: str = "efi"
    secure_boot: bool = False
    hardware_version: str | None = None
    disk_controller: str = "pvscsi"  # ISO installs: pvscsi | nvme | lsilogicsas
    vtpm: bool = False
    nested_hv: bool = False  # expose hardware-assisted virtualisation to the guest
    iommu: bool = False  # expose IOMMU to the guest
    notes: list[str] = field(default_factory=list)  # vendor guidance shown at the review (not problems)
    key_provider: object = None  # crypto.KeyProvider when a vTPM was considered
    iso_copy_from: str | None = None  # "[ds] path.iso" to copy to iso_datastore_path before creating the VM
    iso_copy_via_pc: bool = False  # no copy rights on the source: read it through this computer and upload
    iso_found_on_datastore: bool = False  # a local/downloaded ISO was found on a datastore and is used from there
    # Datastore files never used for the ISO: the user said No, sampled bytes differ, or a full check failed.
    iso_rejected: set[str] = field(default_factory=set)
    compat_upgrade: bool = False  # an OVA/OVF is upgraded after import (needs UpgradeVirtualHardware)
    iso_datastore_path: str | None = None  # "[ds] path/file.iso" once known
    power_on: bool = True
    wait_for_ip: bool = True
    snapshot: bool = False
    replace_vm: object = None
    warnings: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)  # must be fixed before deploying (e.g. IP conflict)

    @property
    def host_names(self) -> set[str]:
        if self.host:
            return {self.host.name}
        if self.cluster:
            return set(self.cluster.hosts)
        return set()


class Deployment:
    def __init__(self, opts: DeployOptions):
        self.o = opts
        self.m = opts.manifest
        # "Choose placement and sizing" and "Review plan" are the user's own answers: no time shown for them.
        self.view = DeploymentView(f"vsphere-vm-deployment {__version__}", STEPS, enabled=True,
                                   untimed=("configure", "plan"))
        self.p = Prompter(opts.interactive, self.view)
        self.trust = TrustManager(prompter=self.p, assume_fingerprints=opts.trust_fingerprints)
        self.conn: Connection | None = None
        self.image: ResolvedImage | None = None
        self.pkg: OvfPackage | None = None
        self.appliance: appliances.Appliance | None = None
        self.aborted_vm = None  # VM of an import that was aborted (vCenter should remove it)
        self.vm_dir: str | None = None  # "[ds] name" folder the import created
        self.plan: Plan | None = None
        # The datacenter of a file picked from the datastore list (datastore names are unique only per datacenter)
        self.image_dc: str | None = None
        self._fresh_sha: dict[str, str] = {}  # SHA-256 of files read from a datastore during this run
        self._source_sizes: dict[str, int | None] = {}  # sizes of ISO sources compared with earlier copies
        self.vm = None
        self.created = False
        self.vm_ready = False  # set once the VM is fully built; later failures never delete it
        self.summary: dict = {}

    # ================================================================================== entry point
    def run(self) -> dict:
        try:
            with self.view:
                try:
                    self._run_steps()
                except (VmDeployError, KeyboardInterrupt) as e:
                    self.view.fail_running(getattr(e, "message", "cancelled") if not isinstance(e, KeyboardInterrupt)
                                           else "cancelled")
                    raise
                except Exception:
                    self.view.fail_running("unexpected error (see log)")
                    raise
        except BaseException as e:
            self._cleanup_after_failure(e)
            raise
        finally:
            if self.pkg:
                self.pkg.close()
            if self.conn:
                self.conn.close()
        return self.summary

    def _run_steps(self) -> None:
        v = self.view
        # ---------------------------------------------------------------- connect
        v.start("connect", self.o.profile.endpoint)
        self.conn = connect(self.o.profile, self.p, self.trust)
        v.done("connect", f"{self.conn.product} as {self.conn.user}")

        # ---------------------------------------------------------------- discover
        v.start("discover")
        inv = discover(self.conn, self.m.placement.datacenter or self.o.profile.default_datacenter)
        if not inv.datacenters:
            raise PreflightError("No datacenter found (or the account cannot see any).",
                                 hint="Check the datacenter name and the account's permissions.")
        self.inv = inv
        v.done("discover", ", ".join(f"{d.name}: {len(d.hosts)} host(s), {len(d.datastores)} datastore(s), "
                                     f"{len(d.usable_networks())} network(s)" for d in inv.datacenters.values()))

        # ---------------------------------------------------------------- image
        self._acquire_image()

        # ---------------------------------------------------------------- inspect
        if self.image.is_iso:
            v.skip("inspect", "ISO image (nothing to inspect)")
        else:
            self._inspect_package()
        info = self.pkg.info if self.pkg else None
        self.appliance = appliances.detect(self.image.display, info.product if info else "",
                                           info.name if info else "", info.version if info else "")
        if self.appliance:
            v.note("inspect" if self.pkg else "image",
                   f"Recognised {self.appliance.name}: using {self.appliance.vendor}'s recommended settings.",
                   style="green")

        # ------------------------------------------------- configure -> preflight -> review (repeatable)
        # "Change my answers" at the review comes back here; the image, sign-in and inventory are reused.
        while True:
            v.start("configure")
            self.plan = self._configure(inv)
            v.done("configure", f"{self.plan.name} on {self._target_label()}")

            v.start("preflight")
            self._preflight()
            if self.plan.blockers:
                v.done("preflight", f"{len(self.plan.blockers)} problem(s) to fix", status="failed")
            else:
                v.done("preflight", "all checks passed" if not self.plan.warnings else
                       f"{len(self.plan.warnings)} warning(s)", status="done" if not self.plan.warnings else "warn")

            v.start("plan")
            if self._review_plan():
                break
            v.reset("configure", "preflight", "plan")
            self.p.start_revision()
        v.done("plan", "confirmed")

        if self.plan.replace_vm is not None:
            self._destroy(self.plan.replace_vm, "existing VM (replace)")

        if self.image.is_iso:
            self._deploy_iso()
        else:
            self._deploy_ova()

        self._power_and_finish()

    # ================================================================================== image
    def _choose_image_source(self) -> tuple[str, str | None]:
        if self.o.image_kind:
            return self.o.image_kind, self.o.image_value
        if self.m.image.kind:
            return self.m.image.kind, self.m.image.value
        with self.p.section("Choose an image source"):
            kind = self.p.select("Where is the VM image?", [
                ("A file on this computer (in the images/ folder)", "local"),
                ("A file already on a datastore (ISO or OVA)", "datastore"),
                ("Download from the internet (URL to an .ova or .iso)", "url"),
                ("A preset (e.g. newest Ubuntu LTS, downloaded and verified automatically)", "preset"),
            ], field_name="image")
            value = None
            if kind == "url":
                value = self.p.text("URL of the .ova or .iso:", field_name="image.url")
            elif kind == "preset":
                from .images import load_presets

                value = self.p.select("Which preset?", [(f"{n}  - {p.description}", n)
                                                        for n, p in load_presets().items()], field_name="image.preset")
            elif kind == "datastore":
                value = self._pick_datastore_iso()
        return kind, value

    def _pick_datastore_iso(self) -> str:
        """List the ISOs on the datastores (with the hosts that can use them), or let the user type a path."""
        isos: list = []
        skipped: list[str] = []
        with console.status("Looking for ISO and OVA files on all datastores..."):
            for dc in getattr(self, "inv", None).datacenters.values() if getattr(self, "inv", None) else []:
                isos += isolib.find_images(dc, skipped)
        if skipped:
            console.print(f"[yellow]Not searched ({len(skipped)} datastore(s) this account may not browse): "
                          f"{', '.join(sorted(skipped))}. An administrator can let it read images there with "
                          "`vmdeploy access setup` (image datastores).[/]")
        typed = "__type__"
        # Each entry carries its datacenter: datastore names (and so paths) can repeat across datacenters.
        several = len({iso.datacenter for iso in isos}) > 1
        choices = [((f"{iso.datacenter} › " if several else "") + iso.label(), (iso.datacenter, iso.full))
                   for iso in isos]
        if choices:
            console.print("[dim]ISOs are used where they are (an ISO on another host's local datastore is copied "
                          "once, host to host). OVAs and OVFs are read once through this computer, because vCenter "
                          "cannot import them straight from a datastore; the VM can go to any datastore.[/]")
            pick = self.p.select("Which file?", choices + [("Type a datastore path instead", typed)],
                                 field_name="image.datastore", auto_single=False)
            if pick != typed:
                # Used in the datacenter it was listed in: another datacenter may have a datastore of the same name
                # with a different file at that path.
                dc_name, full = pick
                self.image_dc = dc_name or None
                return full
        else:
            console.print("[yellow]No ISO, OVA or OVF files were found on the datastores this account can browse.[/]")
        return self.p.text('Datastore path, e.g. "[datastore1] iso/windows.iso":', field_name="image.datastore")

    def _acquire_image(self) -> None:
        v = self.view
        kind, value = self._choose_image_source()
        from .logsetup import safe_url

        # A URL may carry a password (user:pass@) or a pre-signed token (?X-Amz-Signature=…): never shown.
        v.start("image", f"{kind}: {(safe_url(value) if kind in ('url', 'preset') else value) or '(choose)'}")
        if kind in ("url", "preset"):
            v.steps["image"].weight = 15

        def progress_factory(desc: str, total: int | None):
            return v.begin_transfer("image", desc, total)

        sha256 = self.o.sha256 or self.m.image.sha256
        if kind in ("datastore", "datastore_iso") and (value or "").lower().rstrip().endswith((".ova", ".ovf")):
            local = self._read_datastore_package(value, progress_factory, sha256)
            # Hashed while it was read (or just checked against --sha256): not read a second time for that.
            self.image = resolve("local", str(local), sha256=sha256, prompter=self.p, progress_factory=progress_factory,
                                 known_sha256=getattr(self, "_fresh_sha", {}).get(str(local)))
            self.image.source_kind = "datastore_ova"
            self.image.display = f"{value.strip()} (read through this computer)"
        else:
            self.image = resolve(kind, value, sha256=sha256, prompter=self.p, progress_factory=progress_factory)
            if self.image.source_kind == "datastore_iso" and sha256:
                self._verify_datastore_iso(sha256)
        v.end_transfer()
        v.done("image", f"{self.image.display}  [{self.image.format.upper()}]")
        v.note("image", f"Integrity: {self.image.integrity}", style="green" if "match" in self.image.integrity
               else "yellow")

    def _datacenter_of(self, ds_name: str):
        """The datacenter whose datastore `ds_name` a path refers to: the deployment's datacenter once it is chosen
        (vCenter resolves the VM's paths there), otherwise the only one with a datastore of that name. Datastore
        names are unique only within a datacenter, so a name found in several is an error: checking one
        datacenter's file while the VM uses another's would defeat the integrity checks (security review)."""
        plan_dc = getattr(getattr(self, "plan", None), "dc", None)
        if plan_dc is not None:
            if ds_name in plan_dc.datastores:
                return plan_dc
            raise ConfigError(f"Datastore '{ds_name}' is not in datacenter {plan_dc.name}, where the VM goes.",
                              hint="Use a file on one of that datacenter's datastores (`vmdeploy inventory`).")
        matches = isolib.datacenters_with(self.inv, ds_name)
        picked = [d for d in matches if d.name == getattr(self, "image_dc", None)]
        if picked:  # a file picked from the list: its own datacenter
            return picked[0]
        if not matches:
            raise ConfigError(f"Datastore '{ds_name}' was not found.",
                              hint="Names are case-sensitive. `vmdeploy inventory` lists the datastores.")
        if len(matches) > 1:
            raise ConfigError(f"Datastore '{ds_name}' exists in several datacenters "
                              f"({', '.join(sorted(d.name for d in matches))}).",
                              hint="Name the datacenter with `placement: {datacenter: NAME}` in a manifest (-f).")
        return matches[0]

    def _datastore_http(self, full: str):
        """(trust decision, URL path, headers) to read a file through vCenter/ESXi's datastore HTTP access."""
        ds_name, path = isolib.split(full)
        dc = self._datacenter_of(ds_name)
        dc_path = _inventory_path(dc.obj, self.conn.content.rootFolder) if self.conn.is_vcenter else "ha-datacenter"
        return (self.conn.decision, datastore_url_path(dc_path, ds_name, path),
                {"Cookie": self.conn.session_cookie})

    def _read_datastore_package(self, full: str, progress_factory, expected_sha: str | None = None) -> Path:
        """vCenter cannot import an OVA/OVF straight from a datastore, so read it once into the local cache.
        `expected_sha` (--sha256) is for the OVA, or the .ovf descriptor."""
        if full.lower().rstrip().endswith(".ovf"):
            return self._read_datastore_ovf(full, progress_factory, expected_sha)
        return self._read_datastore_file(full, progress_factory, expected_sha=expected_sha)

    def _datastore_cache(self, full: str) -> Path:
        import hashlib as _hashlib

        from .paths import cache_dir

        # The datacenter is part of the key: datastore names (and so paths) repeat across datacenters.
        dc = self._datacenter_of(isolib.split(full)[0]).name
        key = _hashlib.sha256(f"{self.conn.profile.endpoint}|{dc}|{full.strip()}".encode()).hexdigest()[:16]
        return cache_dir() / "datastore" / key

    def _read_datastore_ovf(self, full: str, progress_factory, expected_sha: str | None = None) -> Path:
        """An .ovf lists its disks (and other files) separately; they sit next to it on the datastore. All of them,
        and the .mf manifest when there is one, are read into one local folder, so the package can be checked."""
        from .images import safe_filename
        from .ovf import parse_descriptor

        ds_name, path = isolib.split(full.strip())
        folder = path.rpartition("/")[0]
        base = self._datastore_cache(full)
        ovf_local = self._read_datastore_file(full, progress_factory, dest=base / safe_filename(path),
                                              expected_sha=expected_sha)
        info = parse_descriptor(ovf_local.read_text(encoding="utf-8-sig"))
        for href in info.files:
            target = (base / href).resolve()
            if "://" in href or href.startswith(("/", "\\")) or base.resolve() not in target.parents:
                raise ConfigError(f"The OVF refers to a file outside its folder: {href}",
                                  hint="Only packages whose files sit next to the .ovf can be used.")
            self._read_datastore_file(f"[{ds_name}] {folder + '/' if folder else ''}{href}", progress_factory,
                                      dest=target)
        mf = path.rsplit(".", 1)[0] + ".mf"
        try:
            self._read_datastore_file(f"[{ds_name}] {mf}", progress_factory, dest=ovf_local.with_suffix(".mf"),
                                      optional=True)
        except DeploymentError as e:
            log.debug("no manifest next to the OVF: %s", e)
        return ovf_local

    def _read_datastore_file(self, full: str, progress_factory, *, dest: Path | None = None,
                             optional: bool = False, expected_sha: str | None = None, step: str = "image") -> Path:
        """Read a datastore file once into the local cache. A copy read earlier is used again only while it is the
        same file: with `expected_sha`, when it still has that SHA-256 (and a fresh read must have it); otherwise
        when the datastore file's size and last-modified time are unchanged since it was read. Notes go to `step`.
        A SHA-256 computed here is kept in `_fresh_sha`, so the file is not hashed again in this run."""
        import hashlib as _hashlib

        from .images import _norm_sha, _read_meta, _write_meta, safe_filename
        from .transfer import read_stream, sha256_file

        ds_name, path = isolib.split(full)
        dest = dest or self._datastore_cache(full) / safe_filename(path)
        dc = self._datacenter_of(ds_name)  # e.g. a typo in --datastore-file: a clear error
        remote_size, modified = isolib._stat(self.conn, dc.obj, full.strip()) or (None, None)
        if optional and remote_size is None:
            raise DeploymentError(f"{full.strip()} does not exist")
        want = _norm_sha(expected_sha) if expected_sha else None
        fresh = self.__dict__.setdefault("_fresh_sha", {})
        if dest.exists() and remote_size and dest.stat().st_size == remote_size:
            if want is not None:
                same = sha256_file(dest) == want
            else:
                same = modified is None or _read_meta(dest).get("modified") == modified
            if same:
                if want is not None:
                    fresh[str(dest)] = want
                self.view.note(step, f"Using the copy read earlier from {full.strip()} ("
                                     + ("SHA-256 checked)." if want else "unchanged since)."), style="dim")
                return dest
            self.view.note(step, f"The copy read earlier from {full.strip()} is out of date; reading it again.",
                           style="dim")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if remote_size:
            check_local_space(dest.parent, remote_size, f"read {full.strip()}")
            if remote_size >= GiB:
                what = ("vCenter cannot import an OVA/OVF straight from a datastore" if step == "image" else
                        "it is uploaded from here to the VM's datastore")
                self.view.note(step, f"{dest.name} ({human_size(remote_size)}) is read once into this computer's "
                                     f"cache ({dest.parent}); {what}. Later deployments of the same file reuse it.",
                               style="dim")
        part = dest.with_name(dest.name + ".part")
        decision, url, headers = self._datastore_http(full)
        h = _hashlib.sha256()
        try:
            with open(part, "wb") as out:
                def sink(chunk: bytes) -> None:
                    out.write(chunk)
                    h.update(chunk)

                read_stream(decision, url, sink, headers=headers, progress_factory=progress_factory,
                            description=f"Reading {dest.name} from the datastore")
        except DeploymentError as e:
            part.unlink(missing_ok=True)
            if " 401 " in e.message or " 403 " in e.message:
                raise DeploymentError(f"This account may not read {full.strip()}: {e.message}",
                                      hint=f"An administrator can allow it with `vmdeploy access setup` (choose "
                                           f"{ds_name} as an image datastore).") from e
            raise
        if want is not None and h.hexdigest() != want:
            from .errors import ChecksumMismatch

            part.unlink(missing_ok=True)
            raise ChecksumMismatch(f"SHA-256 of {full.strip()} does not match the expected value (or the file "
                                   f"changed after it was checked).\n  expected {want}\n  got      {h.hexdigest()}",
                                   hint="Nothing was uploaded. Check the value and the file, then run the "
                                        "deployment again.")
        part.replace(dest)
        _write_meta(dest, source=full.strip(), size=remote_size, modified=modified, sha256=h.hexdigest())
        fresh[str(dest)] = h.hexdigest()
        return dest

    def _datastore_sha256(self, full: str, step: str, description: str | None = None, *,
                          strict: bool = False) -> str | None:
        """SHA-256 of a datastore file, read once through this computer (nothing is stored). None if it cannot
        be read (strict: the error is raised instead). A certificate that does not validate always stops the run:
        it is never 'could not be read'."""
        import hashlib as _hashlib

        from .transfer import read_stream

        v, h = self.view, _hashlib.sha256()
        try:
            decision, url, headers = self._datastore_http(full)
            read_stream(decision, url, h.update, headers=headers,
                        progress_factory=lambda d, t: v.begin_transfer(step, d, t),
                        description=description or f"Checking {full.strip()} (read once, not stored)")
        except TrustError:
            raise
        except VmDeployError as e:
            if strict:
                raise
            log.debug("could not read %s to check it: %s", full, e)
            return None
        finally:
            v.end_transfer()
        return h.hexdigest()

    def _copy_is_genuine(self, full: str, step: str = "upload_iso") -> bool:
        """May this existing datastore file be used as the image? Only when its whole content has the image's
        SHA-256 (known for local and downloaded ISOs, and for datastore ISOs given --sha256). A matching name and
        size, or matching sampled bytes, are not enough: anyone with file rights on that datastore (e.g. another
        deploy account) could have put a different file there. A file that failed once is not read again."""
        want, v = self.image.sha256 if self.image else None, self.view
        rejected = self.plan.iso_rejected if getattr(self, "plan", None) is not None else set()
        if not want or full.strip() in rejected:
            return False
        v.start(step, f"checking {full.strip()} (read once; nothing is uploaded if it matches)")  # its clock runs on
        from .images import _norm_sha

        got = self._datastore_sha256(full, step)
        if got != _norm_sha(want):
            what = "could not be read" if got is None else "has different content"
            log.warning("%s %s than the image (SHA-256 %s); not used", full, what, got)
            v.note(step, f"{full.strip()} {what}; not used.", style="yellow")
            rejected.add(full.strip())
            return False
        return True

    def _copy_matches(self, full: str, step: str = "upload_iso") -> bool:
        """May this earlier copy on the VM's own datastore be used? With a known SHA-256 (local or downloaded ISO,
        or --sha256): only on a full match. For a datastore ISO without --sha256 (no integrity was asked for), a
        sampled comparison with that source is enough here: anyone who can write the VM's own datastore can change
        the VM's files anyway, and without it every deployment would make another full copy."""
        if self.image and self.image.sha256:
            return self._copy_is_genuine(full, step)
        plan = getattr(self, "plan", None)
        source = plan.iso_copy_from if plan is not None else None
        if not source or full.strip() in plan.iso_rejected:
            return False
        same = self._same_remote(source, full)
        if not same:
            plan.iso_rejected.add(full.strip())
            self.view.note(step, f"{full.strip()} {'differs from' if same is False else 'could not be compared with'} "
                                 f"{source.strip()}; not used.", style="dim")
        return bool(same)

    def _same_remote(self, a: str, b: str) -> bool | None:
        """Sampled comparison of two datastore files of the same size (ranged reads, a few MB). None: not possible."""
        from .transfer import read_range

        sizes = self.__dict__.setdefault("_source_sizes", {})  # the source is compared with each earlier copy
        size = sizes.get(a.strip())
        if size is None:
            ds_a, _ = isolib.split(a)
            size = isolib._size(self.conn, self._datacenter_of(ds_a).obj, a.strip())
            if size is not None:  # a failed read is not remembered: the next comparison tries again
                sizes[a.strip()] = size
        if not size:
            return None
        piece, offsets = _sample_offsets(size)
        try:
            (da, ua, ha), (db, ub, hb) = self._datastore_http(a), self._datastore_http(b)
        except VmDeployError as e:
            log.debug("cannot compare %s with %s: %s", a, b, e)
            return None
        for off in offsets:
            x, y = read_range(da, ua, off, piece, headers=ha), read_range(db, ub, off, piece, headers=hb)
            if x is None or y is None:
                return None
            if x != y:
                return False
        return True

    def _verify_datastore_iso(self, expected: str) -> None:
        """Read the ISO once (not stored) and compare its SHA-256 with the value the user gave."""
        from .images import _norm_sha

        digest = self._datastore_sha256(self.image.display, "image",
                                        "Checking the ISO's SHA-256 (read once, not stored)", strict=True)
        want = _norm_sha(expected)
        if digest != want:
            from .errors import ChecksumMismatch

            raise ChecksumMismatch(f"SHA-256 of {self.image.display} does not match the expected value.\n"
                                   f"  expected {want}\n  got      {digest}",
                                   hint="Check the value from your download portal, or replace the file.")
        self.image.sha256 = digest
        self.image.integrity = "SHA-256 matches the value you supplied (read once through this computer)"

    def _inspect_package(self) -> None:
        v = self.view
        v.start("inspect")
        if self.image.format not in ("ova", "ovf") or not self.image.path:
            raise ConfigError(f"Unsupported image format: {self.image.format}")
        self.pkg = OvfPackage(self.image.path)
        info = self.pkg.info
        n_files = len(self.pkg.manifest_entries())
        if n_files:
            adv = v.begin_transfer("inspect", "Verifying package manifest", self.pkg.manifest_bytes())
            verified = self.pkg.verify_manifest(adv)
            v.end_transfer()
            v.note("inspect", f"Package manifest: {verified} file(s) verified", style="green")
        else:
            v.note("inspect", "Package has no .mf manifest; contents could not be integrity-checked")
        hw = info.hardware(self.m.ovf.deployment_option)
        opts = info.deployment_options
        if len(opts) > 6:  # e.g. Cisco's 16: a range here, the full list when choosing
            hws = [info.hardware(o.id) for o in opts]
            cpus = sorted({h["cpu"] for h in hws if h["cpu"]})
            mems = sorted({h["memory_mb"] for h in hws if h["memory_mb"]})
            span = ", ".join(x for x in (
                f"{cpus[0]}-{cpus[-1]} vCPU" if cpus else "", f"{mems[0] / 1024:g}-{mems[-1] / 1024:g} GB RAM"
                if mems else "") if x)
            v.note("inspect", f"Deployment sizes defined by the image: {len(opts)}" + (f" ({span})" if span else "")
                   + "; you choose one next")
        elif opts:
            v.note("inspect", "Deployment sizes defined by the image: " + "; ".join(
                f"{o.label} ({info.option_summary(o.id) or 'no sizing'})" for o in opts))
        v.note("inspect", f"Licence agreement: {len(info.eulas)}, shown next for you to accept" if info.eulas
               else "Licence agreement: none in this image")
        disks = info.disks_for(self.m.ovf.deployment_option)  # the default size's disks, not every definition
        disk_gb = sum(d.capacity_bytes for d in disks) / GiB
        which = "" if not opts else (f" (size {self.m.ovf.deployment_option})" if self.m.ovf.deployment_option
                                     else " (default size)")
        v.update("inspect", f"{info.product or info.name}{which}: {hw['cpu'] or '?'} vCPU, "
                            f"{(hw['memory_mb'] or 0) / 1024:.1f} GB RAM, {len(disks)} disk(s) {disk_gb:.1f} GB, "
                            f"{len(info.networks)} network(s), {len(info.properties)} propert(ies)")
        if info.eulas:
            self._accept_eulas(info.eulas)
        v.done("inspect")

    def _accept_eulas(self, eulas: list[str]) -> None:
        with self.p.section("Licence agreement"):
            if not self.p.interactive:
                if not self.m.ovf.accept_eula:
                    raise UserAborted("This image includes a licence agreement that must be accepted.",
                                      hint="Read it by running interactively, or set `ovf.accept_eula: true` in "
                                           "the manifest to record that you accept it.")
                self.p.record("Licence", "accepted via manifest (ovf.accept_eula)")
                return
            n = len(eulas)
            long_ones: dict[int, Path] = {}
            for i, text in enumerate(eulas, 1):
                lines = text.splitlines()
                title = eula_title(text)
                console.rule(f"Licence {i} of {n}" + (f": {title}" if title else ""))
                if len(lines) <= EULA_SHOW_LINES and len(text) <= EULA_SHOW_CHARS:
                    console.print(text, markup=False)
                else:
                    # A full vendor licence (vCenter's is ~94,000 characters, ~1,500 lines) scrolls the question
                    # off screen: show its start, keep the full text in a file, offer it in full on request.
                    path = self._save_eula(i, text)
                    long_ones[i] = path
                    console.print(eula_preview(text), markup=False)
                    console.print(f"[dim]… {len(lines):,} lines ({len(text):,} characters) in total. Full text: "
                                  f"{esc(str(path))}[/]")
                console.rule()
            if not long_ones:
                if not self.p.confirm("Do you accept the licence agreement(s) above?", default=False):
                    raise UserAborted("Licence agreement declined; nothing was deployed.")
            else:
                shown: set[int] = set()

                def covers() -> str:
                    return "; ".join(
                        f"{i}: {eula_title(t) or 'untitled'} ("
                        + ("in full above" if i not in long_ones else "shown in full" if i in shown
                           else f"start above, full text in {long_ones[i]}") + ")"
                        for i, t in enumerate(eulas, 1))

                while True:
                    console.print(f"Accepting accepts all {n} licence(s): {esc(covers())}.")
                    choice = self.p.select(
                        "Do you accept the licence agreement(s)?",
                        [("Accept", "accept")]
                        + [(f"Show licence {i} in full here first", f"show:{i}") for i in long_ones if i not in shown]
                        + [("Decline (nothing is deployed)", "decline")],
                        default="decline", field_name="ovf.accept_eula")
                    if choice == "decline":
                        raise UserAborted("Licence agreement declined; nothing was deployed.")
                    if choice == "accept":
                        break
                    i = int(choice.split(":")[1])
                    shown.add(i)  # offered once: no going round in circles
                    console.rule(f"Licence {i} of {n} (full text)")
                    console.print(eulas[i - 1], markup=False)
                    console.rule(f"End of licence {i}")
                    # The short ones scrolled away with that text: show them again, right above the question.
                    for k, t in enumerate(eulas, 1):
                        if k not in long_ones:
                            console.rule(f"Licence {k} of {n}" + (f": {eula_title(t)}" if eula_title(t) else ""))
                            console.print(t, markup=False)
                            console.rule()
            self.p.record("Licence", f"{n} agreement(s) accepted")

    def _save_eula(self, i: int, text: str) -> Path:
        """Long licences go to a file next to the logs, so they can be read in any editor."""
        from .paths import log_dir

        info = self.pkg.info
        stem = re.sub(r"[^A-Za-z0-9._-]+", "-", info.product or info.name or "image").strip("-")[:60] or "image"
        folder = log_dir() / "licences"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{stem}-licence-{i}.txt"
        path.write_text(text, encoding="utf-8")
        return path

    # ================================================================================== configure
    def _choose_datacenter(self, dcs: list) -> tuple[object, bool]:
        """(datacenter, chosen by the ISO). An ISO picked from the datastore list is used where it is, so the VM
        goes to that ISO's datacenter (a datastore path names the file in the VM's datacenter). An OVA or OVF is
        read through this computer first, so its VM may go to any datacenter."""
        picked = getattr(self, "image_dc", None)
        if picked and getattr(self.image, "source_kind", None) == "datastore_iso":
            for d in dcs:
                if d.name == picked:
                    return d, True
        return (dcs[0] if len(dcs) == 1 else self.p.select("Datacenter:", [(d.name, d) for d in dcs],
                                                           field_name="placement.datacenter")), False

    def _configure(self, inv) -> Plan:
        p, m = self.p, self.m
        dcs = list(inv.datacenters.values())
        with p.section("Placement"):
            dc, by_iso = self._choose_datacenter(dcs)
            plan = Plan(dc=dc)
            p.record("Datacenter", dc.name + (" (where the chosen ISO is)" if by_iso else ""))
            plan.name = self._ask_name(dc)
            plan.folder_path, plan.folder = self._ask_folder(dc)
            self._ask_compute(plan)
            self._ask_pool(plan)

        if self.image.is_iso:  # the guest OS decides the suggested sizing, so it is asked first
            with p.section("Guest operating system"):
                self._ask_guest_os(plan)

        with p.section("Sizing"):
            self._ask_sizing(plan)

        with p.section("Storage"):
            self._ask_datastore(plan)

        with p.section("Networking"):
            self._ask_networks(plan)

        if self.image.is_iso:
            with p.section("Virtual hardware"):
                self._ask_iso_hardware(plan)
        else:
            with p.section("Virtual hardware"):
                self._ask_compat(plan)
                plan.nested_hv = self._ask_nested(plan)
            self._ask_guest(plan)
            self._ask_ovf_options(plan)

        # Network adapters not set in the manifest: e1000e for Windows ISO installs (driver built into Windows
        # Setup), vmxnet3 otherwise (fastest; Linux has the driver).
        auto = "e1000e" if self.image.is_iso and isolib.is_windows(plan.guest_id) else "vmxnet3"
        plan.networks = [(o, n, a or auto) for o, n, a in plan.networks]

        pd = m.post_deploy
        app = self.appliance
        plan.power_on = pd.power_on
        plan.wait_for_ip = pd.wait_for_ip and not self.image.is_iso and plan.power_on
        if app and not app.gets_ip_before_setup and "wait_for_ip" not in pd.model_fields_set:
            plan.wait_for_ip = False  # e.g. ISE: no address until its console setup has run
        if app:
            plan.notes = list(app.notes)
        if app and not app.snapshots_supported:
            if pd.snapshot:
                plan.warnings.append(f"{app.vendor} does not support snapshots of {app.name}; none is taken.")
            plan.snapshot = False
        elif pd.snapshot is None and plan.power_on and not self.image.is_iso and self.p.interactive:
            with p.section("After deployment"):
                plan.snapshot = p.confirm("Take a 'clean baseline' snapshot once the VM has booted?", default=False,
                                          field_name="post_deploy.snapshot")
        else:
            plan.snapshot = bool(pd.snapshot) and plan.power_on and not self.image.is_iso
        return plan

    def _ask_name(self, dc: DatacenterInventory) -> str:
        p = self.p
        default = self.m.vm.name or suggest_vm_name(self.pkg.info.name if self.pkg else None, dc.vm_names)
        def valid(s: str):
            return bool(VM_NAME_RE.fullmatch(s)) or "1-80 characters, without / \\ or %"

        if self.m.vm.name:
            name = self.m.vm.name
        else:
            name = p.text("VM name:", default=re.sub(r"[/\\%]", "-", default or "new-vm"), field_name="vm.name",
                          validate=valid)
        while name in dc.vm_names:
            if self.o.replace:
                break
            if not p.interactive:
                raise PreflightError(f"A VM named '{name}' already exists in {dc.name}.",
                                     hint="Choose another vm.name, or pass --replace to delete and re-create it.")
            from .ui import warn

            warn(f"A VM named '{name}' already exists.")
            name = p.text("Choose another VM name:", default=next_free_vm_name(name, dc.vm_names), validate=valid)
        p.record("VM name", name)
        return name

    def _ask_folder(self, dc: DatacenterInventory):
        want = self.m.placement.folder
        if want:
            key = "/" + want.strip("/") if want.strip("/") else "/"
            if key not in dc.folders:
                raise ConfigError(f"VM folder '{want}' not found in {dc.name}.",
                                  hint=f"Available: {', '.join(sorted(dc.folders))}")
            path = key
        else:
            # vCLS is vSphere's own folder for its cluster service VMs; it can still be named in a manifest.
            shown = [k for k in sorted(dc.folders) if k != "/vCLS" and not k.startswith("/vCLS/")]
            if len(shown) == 1:
                path = "/"
            else:
                path = self.p.select("VM folder:", [(k if k != "/" else "/ (top level)", k) for k in shown],
                                     default="/", field_name="placement.folder", assume_default=True)
        self.p.record("Folder", path)
        return path, dc.folders[path]

    def _ask_compute(self, plan: Plan) -> None:
        p, pl, dc = self.p, self.m.placement, plan.dc
        if pl.host:
            h = dc.hosts.get(pl.host)
            if not h:
                raise ConfigError(f"Host '{pl.host}' not found.", hint=f"Hosts: {', '.join(sorted(dc.hosts))}")
            plan.host = h
            plan.cluster = dc.clusters.get(h.cluster) if h.cluster else None
        elif pl.cluster:
            plan.cluster = dc.clusters.get(pl.cluster)
            if not plan.cluster:
                raise ConfigError(f"Cluster '{pl.cluster}' not found.", hint=f"Clusters: {', '.join(dc.clusters)}")
        else:
            choices = [(f"Cluster {c.name}  (DRS {'on' if c.drs else 'off'}, {len(c.hosts)} host(s))", ("c", c.name))
                       for c in dc.clusters.values()]
            choices += [(f"Standalone host {h.label()}", ("h", h.name)) for h in dc.hosts.values() if not h.cluster]
            if len(choices) == 1:
                kind, nm = choices[0][1]
            else:
                kind, nm = p.select("Deploy to:", choices, field_name="placement.cluster or placement.host")
            if kind == "c":
                plan.cluster = dc.clusters[nm]
            else:
                plan.host = dc.hosts[nm]

        if plan.cluster and not plan.host:
            hosts = [dc.hosts[n] for n in plan.cluster.hosts if n in dc.hosts]
            usable = [h for h in hosts if h.usable]
            if not usable:
                raise PreflightError(f"No usable hosts in cluster {plan.cluster.name} "
                                     "(all disconnected or in maintenance mode).")
            drs = "__drs__"  # questionary returns the title for None values, so use a sentinel
            choices = []
            if plan.cluster.drs:
                choices.append(("Let DRS choose the host (recommended)", drs))
            choices += [(h.label(), h.name) for h in usable]
            pick = p.select("Host:", choices, default=drs if plan.cluster.drs else usable[0].name,
                            field_name="placement.host", assume_default=plan.cluster.drs)
            plan.host = None if pick == drs else dc.hosts[pick]

        if plan.host and not plan.host.usable:
            raise PreflightError(f"Host {plan.host.name} is not usable ({plan.host.connection_state}"
                                 f"{', maintenance mode' if plan.host.maintenance else ''}).")
        p.record("Compute", self._target_label(plan))

    def _target_label(self, plan: Plan | None = None) -> str:
        plan = plan or self.plan
        if plan.cluster and not plan.host:
            return f"cluster {plan.cluster.name} (DRS placement)"
        if plan.cluster:
            return f"cluster {plan.cluster.name} / host {plan.host.name}"
        return f"host {plan.host.name}"

    def _ask_pool(self, plan: Plan) -> None:
        dc = plan.dc
        standalone_root = dc.standalone_pools.get(plan.host.name) if (plan.host and not plan.cluster) else None
        root_name = plan.cluster.name if plan.cluster else next(
            (k for k, v in dc.resource_pools.items() if "/" not in k and standalone_root is not None
             and v._moId == standalone_root._moId), None)
        candidates = {k: v for k, v in dc.resource_pools.items() if root_name and (k == root_name or
                                                                                    k.startswith(root_name + "/"))}
        want = self.m.placement.resource_pool
        if want:
            key = want if want in candidates else f"{root_name}/{want.strip('/')}"
            if key not in candidates:
                raise ConfigError(f"Resource pool '{want}' not found.", hint=f"Pools: {', '.join(candidates)}")
        elif len(candidates) <= 1:
            key = root_name
        else:
            key = self.p.select("Resource pool:", [(k, k) for k in sorted(candidates)], default=root_name,
                                field_name="placement.resource_pool", assume_default=True)
        plan.pool_path = key or ""
        plan.pool = candidates.get(key) if key else (plan.cluster.resource_pool if plan.cluster else
                                                     dc.standalone_pools.get(plan.host.name))
        if plan.pool_path and "/" in plan.pool_path:
            self.p.record("Resource pool", plan.pool_path)

    def _ask_sizing(self, plan: Plan) -> None:
        p, r = self.p, self.m.resources
        ovf_hw = self.pkg.info.hardware(self.m.ovf.deployment_option) if self.pkg else {}
        host = plan.host
        max_cpu = max((h.cpu_threads for h in (plan.dc.hosts[n] for n in plan.host_names)), default=None) \
            if plan.host_names else None

        if self.pkg and self.pkg.info.deployment_options:
            opts = self.pkg.info.deployment_options
            if self.m.ovf.deployment_option:
                plan.deployment_option = self.m.ovf.deployment_option
            else:
                def label(o):
                    # Short enough for one line; the vendor's description (vCenter's run past the screen edge)
                    # shows under the highlighted size instead.
                    size = self.pkg.info.option_summary(o.id)
                    disk_bytes = sum(d.capacity_bytes for d in self.pkg.info.disks_for(o.id))
                    parts = [x for x in (size, f"{disk_bytes / GiB:,.0f} GB disk" if disk_bytes else "") if x]
                    return o.label + (f": {', '.join(parts)}" if parts else "")

                plan.deployment_option = p.select(
                    "Deployment size (defined by the image):",
                    [(label(o), o.id, " ".join(o.description.split()) or None) for o in opts],
                    default=self.pkg.info.default_option, field_name="ovf.deployment_option", assume_default=True)
            if plan.deployment_option not in {o.id for o in opts}:
                raise ConfigError(f"ovf.deployment_option '{plan.deployment_option}' is not defined by the image.",
                                  hint="Image sizes: " + ", ".join(o.id for o in opts))
            ovf_hw = self.pkg.info.hardware(plan.deployment_option)
            size = self.pkg.info.option_summary(plan.deployment_option)
            p.record("Deployment option", plan.deployment_option + (f" ({size})" if size else ""))
        # Disk 1 of the chosen size, not the image's largest disk: vCenter's OVA declares a 1,430 GB disk that only
        # its "xlstorage" sizes use, and taking that as disk 1 would have grown the 48.6 GB system disk to 1,430 GB.
        size_disks = self.pkg.info.disks_for(plan.deployment_option) if self.pkg else []
        ovf_disk_gb = (size_disks[0].capacity_bytes + GiB - 1) // GiB if size_disks else None
        plan.image_disk_gb = ovf_disk_gb

        def pick_int(value, ovf_value, question, field, minimum=1, maximum=None, fallback=None):
            if value:
                return value
            default = ovf_value or fallback
            if not p.interactive and default:
                return default
            return p.integer(question, default=default, minimum=minimum, maximum=maximum, field_name=field)

        # ISO installs: VMware's recommendation for the chosen guest type, never below Microsoft's minimum.
        sug = None
        app = self.appliance if self.image.is_iso and self.appliance and self.appliance.minimum else None
        if app:  # the vendor's documented sizing (e.g. EVE-NG), the recommended size when the host can hold it
            hosts_ = [plan.dc.hosts[n] for n in plan.host_names if n in plan.dc.hosts]
            size = appliances.default_size(app, max((h.cpu_threads for h in hosts_), default=None),
                                           max((h.mem_bytes // 2**20 for h in hosts_), default=None))
            sug = guestspecs.Suggestion(size.cpu, size.memory_mb, size.disk_gb,
                                        size.cpu if app.single_socket else None,
                                        f"{app.vendor}'s {size.label}" if size is not app.recommended else
                                        f"{app.vendor} recommends",
                                        None, None)
            console.print(f"[dim]{app.name}: {sug.cpu} vCPU, {sug.memory_mb / 1024:g} GB RAM, {sug.disk_gb} GB disk "
                          f"({esc(sug.source)}"
                          + (", the most this host can hold" if size is not app.recommended else "")
                          + "). Press Enter to accept or type other values.[/]")
        elif self.image.is_iso and plan.guest_id:
            sug = guestspecs.suggest(plan.guest_id, getattr(self, "_guest_descriptors", {}).get(plan.guest_id))
            console.print(f"[dim]Suggested sizing for {plan.guest_id}: {sug.cpu} vCPU, {sug.memory_mb / 1024:g} GB "
                          f"RAM, {sug.disk_gb} GB disk ({sug.source}). Press Enter to accept or type more.[/]")
        hint = ((lambda kind: appliances.hint(app, kind)) if app else
                (lambda kind: guestspecs.hint(kind, sug)) if sug else (lambda kind: ""))

        plan.cpu = pick_int(r.cpu, ovf_hw.get("cpu"), f"vCPUs{hint('cpu')}:", "resources.cpu", maximum=None,
                            fallback=sug.cpu if sug else 2)
        plan.cores_per_socket = r.cores_per_socket or ovf_hw.get("cores_per_socket") or \
            (sug.cores_per_socket if sug and sug.cores_per_socket else 1)
        if app and app.single_socket and not r.cores_per_socket:
            plan.cores_per_socket = plan.cpu  # the vendor's "CPU 1/N": one socket with all the cores
        if plan.cpu % plan.cores_per_socket:
            plan.cores_per_socket = 1
        mem_default = (ovf_hw.get("memory_mb") or 0) / 1024 or (sug.memory_mb / 1024 if sug else 4)
        if r.memory_gb:
            mem_gb = r.memory_gb
        elif not p.interactive:
            mem_gb = mem_default
        else:
            mem_gb = float(p.text(f"Memory (GB){hint('memory')}:", default=f"{mem_default:g}",
                                  field_name="resources.memory_gb",
                                  validate=lambda s: _is_pos_float(s) or "Enter a number of GB, e.g. 4 or 0.5"))
        plan.memory_mb = int(round(mem_gb * 1024 / 4) * 4) or 4
        disk_min = ovf_disk_gb or 1
        plan.disk_gb = pick_int(r.disk_gb, ovf_disk_gb,
                                f"Primary disk size (GB){hint('disk')}:" if sug else
                                f"Primary disk size (GB, minimum {disk_min}):",
                                "resources.disk_gb", minimum=disk_min, fallback=sug.disk_gb if sug else 40)
        if ovf_disk_gb and plan.disk_gb < ovf_disk_gb:
            raise ConfigError(f"resources.disk_gb ({plan.disk_gb}) is smaller than the image's disk ({ovf_disk_gb} GB);"
                              " disks can only grow.")
        plan.extra_disks = [(d.size_gb, d.provisioning) for d in r.extra_disks]
        low = appliances.below_minimum(app, plan.cpu, plan.memory_mb, plan.disk_gb)
        if low:
            plan.warnings.append(f"Below {app.vendor}'s minimum for {app.name}: {', '.join(low)}.")
        vendor = self.appliance
        if vendor and self.pkg and ovf_hw and ((ovf_hw.get("cpu") and plan.cpu < ovf_hw["cpu"]) or
                                               (ovf_hw.get("memory_mb") and plan.memory_mb < ovf_hw["memory_mb"])):
            plan.warnings.append(
                f"Less CPU or memory than {vendor.name} size {plan.deployment_option or ''} "
                f"({self.pkg.info.option_summary(plan.deployment_option)}), which {vendor.vendor} recommends.")
        problems, hard = guestspecs.below_minimum(plan.guest_id if self.image.is_iso else None, plan.cpu,
                                                  plan.memory_mb, plan.disk_gb)
        if problems:
            ms = guestspecs.MICROSOFT[plan.guest_id]
            text = f"Below Microsoft's minimum for {ms.name}: {', '.join(problems)}."
            if hard:  # Windows 11 Setup refuses to install
                plan.blockers.append(text + f" {ms.name} Setup will refuse to install; increase the sizing.")
            else:
                plan.warnings.append(text + " Setup may fail or the OS may run poorly.")
        p.record("Sizing", f"{plan.cpu} vCPU ({plan.cores_per_socket} per socket), {plan.memory_mb / 1024:g} GB RAM, "
                           f"{plan.disk_gb} GB disk" + (f" + {len(plan.extra_disks)} extra disk(s)" if plan.extra_disks else ""))

        # Overcommit warnings (never blocking): compare against the chosen host, or the largest host in the cluster.
        hosts = [host] if host else [plan.dc.hosts[n] for n in plan.host_names if n in plan.dc.hosts]
        if hosts:
            ref = max(hosts, key=lambda h: h.cpu_threads)
            if max_cpu and plan.cpu > max_cpu:
                plan.warnings.append(f"{plan.cpu} vCPU is more than the {max_cpu} logical CPUs on {ref.name}; "
                                     "the VM may not power on.")
            ratio = (ref.allocated_vcpus + plan.cpu) / ref.cpu_threads if ref.cpu_threads else 0
            if ratio > 4:
                plan.warnings.append(f"{ref.name} would have {ref.allocated_vcpus + plan.cpu} vCPU on "
                                     f"{ref.cpu_threads} logical CPUs ({ratio:.1f}:1 overcommit).")
            free_gb = max(h.mem_free_gb for h in hosts)
            if plan.memory_mb / 1024 > free_gb:
                plan.warnings.append(f"{plan.memory_mb / 1024:g} GB RAM is more than the ~{free_gb:.0f} GB currently "
                                     "free on the host(s); expect memory contention.")
            alloc = (ref.allocated_mem_mb + plan.memory_mb) / 1024
            if ref.mem_bytes and alloc > ref.mem_bytes / GiB:
                plan.warnings.append(f"{ref.name} would have {alloc:.0f} GB of VM memory allocated on "
                                     f"{ref.mem_bytes / GiB:.0f} GB physical RAM.")

    def _needed_bytes(self, plan: Plan) -> int:
        total = (plan.disk_gb or 0) * GiB + sum(s for s, _ in plan.extra_disks) * GiB
        if self.pkg:  # the image's other disks for this size (disk 1 is plan.disk_gb, possibly grown)
            total += sum(d.capacity_bytes for d in self.pkg.info.disks_for(plan.deployment_option)[1:])
        total += (plan.memory_mb or 0) * 1024 * 1024  # swap file (no memory reservation)
        if self.image.is_iso and self.image.path:
            total += self.image.path.stat().st_size
        return total

    def _ask_datastore(self, plan: Plan) -> None:
        p, dc = self.p, plan.dc
        candidates = [d for d in dc.datastores_for(plan.host_names) if d.usable] if plan.host_names else \
            [d for d in dc.datastores.values() if d.usable]
        if not candidates:
            raise PreflightError("No accessible datastores are mounted on the chosen host(s).")
        want = self.m.placement.datastore
        if want:
            ds = dc.datastores.get(want)
            if not ds:
                raise ConfigError(f"Datastore '{want}' not found.", hint=f"Datastores: {', '.join(dc.datastores)}")
            if plan.host_names and not (ds.hosts & plan.host_names):
                raise PreflightError(f"Datastore {want} is not mounted on {', '.join(sorted(plan.host_names))}.")
        else:
            ds = p.select("Datastore:", [(d.label(), d) for d in candidates], field_name="placement.datastore")
        plan.datastore = ds
        if plan.cluster and not plan.host and not plan.host_names <= ds.hosts:
            plan.warnings.append(f"Datastore {ds.name} is not mounted on every host in {plan.cluster.name}; "
                                 "DRS will only use the hosts that can see it.")
        if ds.is_vsan:
            plan.provisioning = Provisioning.THIN
            p.record("Datastore", f"{ds.name} (vSAN: the datastore's default storage policy is applied)")
        else:
            vendor_prov = Provisioning(self.appliance.provisioning) if self.appliance and \
                self.appliance.provisioning else None
            rec = f" ({self.appliance.vendor} recommends)" if vendor_prov else ""
            prov = self.m.resources.disk_provisioning or p.select(
                "Disk provisioning:", [("Thin (allocate as used)" + (rec if vendor_prov == Provisioning.THIN else ""),
                                        Provisioning.THIN),
                                       ("Thick, lazy-zeroed" + (rec if vendor_prov == Provisioning.THICK else ""),
                                        Provisioning.THICK),
                                       ("Thick, eager-zeroed (slowest to create, needed for some clustering)"
                                        + (rec if vendor_prov == Provisioning.EAGER else ""), Provisioning.EAGER)],
                default=vendor_prov or Provisioning.THIN, field_name="resources.disk_provisioning",
                assume_default=True)
            plan.provisioning = prov
            p.record("Datastore", f"{ds.name}, {prov.value} provisioning")
        # Extra disks without their own provisioning get the VM's (e.g. a vendor's eager-zeroed), not thin.
        plan.extra_disks = [(size, prov or plan.provisioning) for size, prov in plan.extra_disks]
        need = self._needed_bytes(plan)
        thin = plan.provisioning == Provisioning.THIN
        initial = (self.pkg.total_disk_bytes() if self.pkg and thin else need) if not self.image.is_iso else \
            (self.image.path.stat().st_size if self.image.path and thin else need)
        if thin:  # thick extra disks take their full size right away
            initial += sum(size for size, prov in plan.extra_disks if prov != Provisioning.THIN) * GiB
        if initial > ds.free:
            plan.warnings.append(f"Datastore {ds.name} has {human_size(ds.free)} free but this VM needs about "
                                 f"{human_size(initial)} right away; the deployment will probably fail.")
        elif need > ds.free:
            plan.warnings.append(f"If the thin disks fill up, this VM can use {human_size(need)} but {ds.name} "
                                 f"only has {human_size(ds.free)} free (overcommitted storage).")
        if initial <= ds.free and ds.capacity and (ds.provisioned + need) / ds.capacity > 1.0:
            # (when the VM does not fit at all, the warning above already says so)
            plan.warnings.append(f"{ds.name} would be {(ds.provisioned + need) / ds.capacity * 100:.0f}% provisioned: "
                                 "its VMs could use more than its capacity if their thin disks fill up.")

    @staticmethod
    def _disk_growth(plan: Plan) -> int | None:
        """The size to grow an image's disk 1 to, or None to keep it. The default answer is the image's size
        rounded up to a whole GB (48.6 -> 49): accepting it must not grow the disk."""
        if plan.disk_gb and plan.image_disk_gb and plan.disk_gb <= plan.image_disk_gb:
            return None
        return plan.disk_gb

    def _ask_networks(self, plan: Plan) -> None:
        p, dc = self.p, plan.dc
        avail = dc.usable_networks(plan.host_names)
        if not avail:
            raise PreflightError("No VM networks are available on the chosen host(s).")
        by_name = {n.name: n for n in avail}
        ovf_nets = self.pkg.info.networks if self.pkg else []
        specs = list(self.m.networks)
        slots = ovf_nets or [None] * max(1, len(specs))
        # `ovf_network` binds an entry to that image network; the other entries fill the remaining networks in
        # order. An entry is used once, and one that fits nowhere is an error rather than silently dropped.
        named = {s.ovf_network: s for s in specs if s.ovf_network}
        unknown = sorted(set(named) - set(ovf_nets))
        if unknown:
            have = ", ".join(ovf_nets) or "(none: an ISO or an image without networks)"
            raise ConfigError(f"networks: ovf_network {', '.join(map(repr, unknown))} is not a network of this "
                              "image.", hint=f"Image networks: {have}")
        positional = [s for s in specs if not s.ovf_network]
        free_slots = [o for o in slots if o not in named]
        if len(positional) > len(free_slots):
            raise ConfigError(f"networks has {len(specs)} entries but the image has {len(slots)} network(s).",
                              hint="Remove the extra entries, or bind each entry to an image network with "
                                   "`ovf_network`." if ovf_nets else "Remove the extra entries.")
        by_slot = dict(zip(free_slots, positional, strict=False))
        for i, ovf_name in enumerate(slots):
            spec = named.get(ovf_name) if ovf_name in named else by_slot.get(ovf_name) if ovf_name else (
                specs[i] if i < len(specs) else None)
            adapter = spec.adapter if spec and spec.adapter else None  # decided once the guest OS is known
            if spec and spec.portgroup:
                net = by_name.get(spec.portgroup)
                if not net:
                    hidden = dc.networks.get(spec.portgroup)
                    why = "is an uplink portgroup" if hidden and hidden.uplink else "is not available on the host(s)"
                    raise ConfigError(f"Network '{spec.portgroup}' {why}.",
                                      hint=f"Available: {', '.join(by_name)}")
            else:
                label = f"Network for '{ovf_name}':" if ovf_name else f"Network for NIC {i + 1}:"
                net = p.select(label, [(n.label(), n) for n in avail], field_name=f"networks[{i}].portgroup")
            plan.networks.append((ovf_name, net, adapter))
            p.record(f"NIC {i + 1}", f"{net.name}" + (f"  (image network '{ovf_name}')" if ovf_name else ""))

    def _ask_guest_os(self, plan: Plan) -> None:
        p, hw = self.p, self.m.hardware
        guest_choices, _default_hw = self._guest_os_options(plan)
        ids = {g for _, g in guest_choices}
        guessed = next((g for g in isolib.guess_guest_ids(self.image.display) if g in ids), None)
        if hw.guest_os:
            plan.guest_id = hw.guest_os
        else:
            plan.guest_id = p.select("Guest operating system:", guest_choices, field_name="hardware.guest_os",
                                     default=guessed, assume_default=guessed is not None)  # --yes: name guess
        p.record("Guest OS", next((label for label, g in guest_choices if g == plan.guest_id), plan.guest_id))

    def _ask_iso_hardware(self, plan: Plan) -> None:
        p, hw = self.p, self.m.hardware
        app = self.appliance
        windows = isolib.is_windows(plan.guest_id)
        fw_default = (app.firmware if app and app.firmware else "efi")
        plan.firmware = (hw.firmware.value if hw.firmware else
                         p.select("Firmware:", [("UEFI (recommended)", "efi"), ("BIOS (legacy)", "bios")],
                                  default=fw_default, field_name="hardware.firmware", assume_default=True))
        if plan.firmware == "efi":
            sb = app.secure_boot if app and app.secure_boot is not None else windows
            why = f" {app.vendor} recommends {'on' if sb else 'off'}." if app and app.secure_boot is not None else ""
            plan.secure_boot = hw.secure_boot if hw.secure_boot is not None else p.confirm(
                "Enable UEFI Secure Boot? (the OS installer must support it; Windows does)" + why, default=sb,
                assume=sb, field_name="hardware.secure_boot")
        self._ask_compat(plan)
        self._ask_vtpm(plan)
        plan.nested_hv = self._ask_nested(plan)
        wants_iommu = hw.iommu if hw.iommu is not None else bool(app and app.iommu and plan.nested_hv)
        version = compat.number(plan.hardware_version)
        if wants_iommu and (plan.firmware != "efi" or (version and version < 14)):
            plan.warnings.append("IOMMU is not exposed to the guest: it needs UEFI firmware and VM version 14 or "
                                 "later.")
            wants_iommu = False
        plan.iommu = wants_iommu
        if windows:
            # Windows Setup has no PVSCSI driver; NVMe (VM version 13+) and LSI Logic SAS are built in.
            plan.disk_controller = "nvme" if (version == 0 or version >= 13) else "lsilogicsas"
        p.record("Hardware", f"{plan.guest_id}, {plan.firmware.upper()}"
                             f"{' + Secure Boot' if plan.secure_boot else ''}, disk controller {plan.disk_controller}"
                             f"{', virtual TPM' if plan.vtpm else ''}"
                             f"{', nested virtualisation' if plan.nested_hv else ''}"
                             f"{', IOMMU' if plan.iommu else ''}")

    def _ask_nested(self, plan: Plan) -> bool:
        """Expose the CPU's virtualisation features to the guest, so it can run VMs itself (EVE-NG, ESXi, ...)."""
        given = self.m.hardware.nested_virtualization
        if given is not None:
            return given
        names = " ".join(x for x in (self.image.display, self.pkg.info.product if self.pkg else "",
                                     self.pkg.info.name if self.pkg else "") if x)
        app = self.appliance
        suggested = isolib.suggests_nested(names) or bool(app and app.nested_hv)
        if not self.image.is_iso and not suggested:
            return False  # appliances: only when the manifest asks, or the image looks like a hypervisor
        nested = self.p.confirm("Expose hardware-assisted virtualisation to the guest? Needed to run VMs inside it "
                                "(EVE-NG, GNS3, ESXi, Proxmox)." + (
                                    f"  {app.vendor} recommends it." if app and app.nested_hv else
                                    "  Suggested: the image looks like one." if suggested else ""),
                                default=suggested, assume=suggested, field_name="hardware.nested_virtualization")
        if nested and not self.image.is_iso:
            self.p.record("Nested virtualisation", "on")
        return nested

    def _ask_vtpm(self, plan: Plan) -> None:
        """Windows 11 needs a virtual TPM; Server 2025 is offered one; other guests only when asked for."""
        hw, p = self.m.hardware, self.p
        # A vTPM needs EFI. Non-Windows guests only get one when the manifest asks for it.
        if plan.firmware != "efi" or (not isolib.is_windows(plan.guest_id) and hw.vtpm is None):
            plan.vtpm = bool(hw.vtpm) and plan.firmware == "efi"
            return
        plan.key_provider = crypto.key_provider(self.conn, plan.host.obj if plan.host else None)
        if hw.vtpm is not None:
            plan.vtpm = hw.vtpm
            if not hw.vtpm and isolib.needs_vtpm(plan.guest_id):
                # Only an explicit `hardware.vtpm: false` gets here (e.g. installing with Setup's TPM check bypassed).
                plan.warnings.append("Windows 11 without a virtual TPM (`hardware.vtpm: false`): Windows 11 Setup "
                                     "stops at its requirements check unless that check is bypassed, which "
                                     "Microsoft does not support (docs/windows.md).")
        elif isolib.needs_vtpm(plan.guest_id):
            if plan.key_provider.status == "no":
                self._key_provider_for_windows_11(plan)  # fixes it (the user's choice) or stops
            elif plan.key_provider.native and _on_standalone_host(plan):
                # Stop now rather than after every other question: pre-flight would refuse it anyway.
                raise PreflightError(_needs_cluster_reason(plan, plan.key_provider.provider),
                                     hint=_needs_cluster_hint(plan))
            plan.vtpm = True
            p.record("Virtual TPM", "added (Windows 11 requires TPM 2.0)")
        elif plan.key_provider.status == "no":
            plan.vtpm = False
        else:
            plan.vtpm = p.confirm("Add a virtual TPM 2.0? (BitLocker, Credential Guard; needs a key provider)",
                                  default=isolib.suggests_vtpm(plan.guest_id), assume=False, field_name="hardware.vtpm")

    def _compute_resource(self, plan: Plan):
        return plan.cluster.obj if plan.cluster else (plan.host.obj.parent if plan.host else None)

    def _ask_compat(self, plan: Plan) -> None:
        """VM compatibility (virtual hardware version); see compat.py."""
        image_version = self.pkg.info.hardware_version if self.pkg else None
        c = compat.discover(self._compute_resource(plan), plan.dc.obj, host=plan.host.obj if plan.host else None,
                            image=image_version)
        given = self.m.hardware.hardware_version
        if given:
            key = c.resolve(given)
        else:
            options = c.options()
            prefer_upgrade = self.image.is_iso or self.image.source_kind == "preset"
            default = c.recommended(prefer_upgrade=prefer_upgrade)
            if not options:
                key = image_version
            elif len(options) == 1:
                key = options[0][1]
            else:
                key = self.p.select("VM compatibility (virtual hardware version):", options, default=default,
                                    field_name="hardware.hardware_version", assume_default=True, auto_single=False)
        plan.hardware_version = key
        plan.compat_upgrade = bool(image_version and key and compat.number(key) > compat.number(image_version))
        plan.warnings.extend(c.warnings(key))
        self.p.record("VM compatibility", compat.describe(key)
                      + (f"  (upgraded from the image's version {compat.number(image_version)})"
                         if plan.compat_upgrade else ""))

    def _guest_os_options(self, plan: Plan):
        cr = plan.cluster.obj if plan.cluster else (plan.host.obj.parent if plan.host else None)
        try:
            eb = cr.environmentBrowser
            default_key = next((d.key for d in eb.QueryConfigOptionDescriptor() if d.defaultConfigOption), None)
            opts = eb.QueryConfigOption(key=default_key, host=plan.host.obj if plan.host else None)
            self._guest_descriptors = {g.id: g for g in opts.guestOSDescriptor or []}
            choices = sorted(((g.fullName, g.id) for g in opts.guestOSDescriptor), key=lambda x: x[0].lower())
            if choices:
                return choices, default_key
        except Exception as e:  # noqa: BLE001
            log.debug("environment browser query failed: %s", e)
        return COMMON_GUEST_IDS, None

    def _ask_ovf_options(self, plan: Plan) -> None:
        info = self.pkg.info
        given = dict(self.m.ovf.properties)
        from .logsetup import register_secret

        for pr in info.properties:  # passwords supplied in the manifest must never reach the log either
            if pr.password and pr.key in given:
                register_secret(given[pr.key])
        # The image's own cloud-init properties are never asked raw: either vmdeploy fills them from the first-boot
        # answers, or first-boot setup was switched off and they keep the image's defaults (a manifest can still
        # set them under ovf.properties). Other appliance settings (admin password, IP, ...) are asked as usual.
        cloudinit_keys = {"user-data", "hostname", "instance-id", "public-keys", "password", "seedfrom"} \
            if info.has_cloud_init_properties else set()
        to_ask = [pr for pr in info.properties if pr.user_configurable and pr.key not in given
                  and pr.key.split(".")[-1] not in cloudinit_keys]
        known = {pr.key: pr for pr in info.properties}
        unknown = set(self.m.ovf.properties) - set(known)
        if unknown:
            raise ConfigError(f"ovf.properties has keys the image does not define: {', '.join(sorted(unknown))}",
                              hint=f"Image properties: {', '.join(sorted(known)) or '(none)'}")
        for key, val in given.items():  # manifest values: the same checks as typed answers
            why = ovflib.check_value(known[key], val)
            if why:
                raise ConfigError(f"ovf.properties.{key}: {why}", hint=f"Given: {val!r}.")
        if to_ask:
            with self.p.section("Image settings (OVF properties)"):
                for pr in to_ask:
                    fname = f"ovf.properties.{pr.key}"
                    label = pr.label.strip().rstrip(".:?") or pr.key  # "…during upgrade." + "?" read badly
                    if not self.p.interactive:
                        # Unattended: keep the image's default; vCenter rejects the import if a required
                        # property is still empty, and that error names the property.
                        if pr.default:
                            given[pr.key] = pr.default
                        continue
                    desc = ovflib.one_line(pr.description)
                    if desc:  # in full, above the question (descriptors can be several sentences long)
                        console.print(f"[dim]{esc(desc)}[/]")
                    allowed = ovflib.value_map(pr)
                    if ovflib.is_boolean(pr):
                        val = self.p.confirm(f"{label}?", default=bool(ovflib.as_bool(pr.default)),
                                             field_name=fname)
                        shown = "yes" if val else "no"
                    elif allowed:
                        val = self.p.select(f"{label}:", [(a, a) for a in allowed],
                                            default=pr.default if pr.default in allowed else allowed[0],
                                            field_name=fname)
                        shown = val
                    elif pr.password:
                        val = self.p.text(f"{label} (Enter to leave empty):", field_name=fname, secret=True,
                                          validate=lambda v, pr=pr: ovflib.check_value(pr, v) or True)
                        from .logsetup import register_secret

                        register_secret(val)
                        shown = "********" if val else "(empty)"
                    else:
                        val = self.p.text(f"{label}:", default=pr.default, field_name=fname,
                                          assume_default=bool(pr.default),
                                          validate=lambda v, pr=pr: ovflib.check_value(pr, v) or True)
                        shown = val or "(empty)"
                    given[pr.key] = val
                    self.p.record(label, shown)
        # As vCenter accepts them (booleans as True/False, whatever the descriptor or manifest spelled).
        plan.ovf_properties = {k: ovflib.vcenter_value(known[k], v) for k, v in given.items()}

    def _ask_guest(self, plan: Plan) -> None:
        """cloud-init customisation for images that support it."""
        info = self.pkg.info
        supports = (self.image.provisioning == "cloud-init" or info.has_cloud_init_properties)
        g = self.m.guest
        if g.enabled is False:
            return
        if not supports:
            if g.enabled or g.username or g.network:
                raise ConfigError("The manifest has a `guest:` section but this image does not advertise cloud-init "
                                  "support.", hint="Remove `guest:` or use a cloud-init capable image (e.g. --preset "
                                                   "ubuntu-lts).")
            return
        p = self.p
        with p.section("Guest OS first-boot settings (cloud-init)"):
            # A manifest that already gives first-boot settings means yes: asking would only lead to no questions.
            given = bool(g.hostname or g.username or g.ssh_authorized_keys or g.password_hash or g.network)
            if g.enabled is None and not given and not p.confirm(
                    "Configure hostname, login and network for the first boot?",
                    default=True, assume=False, field_name="guest.enabled"):
                return
            spec = g.model_copy(deep=True)
            derived = re.sub(r"[^A-Za-z0-9-]", "-", plan.name)[:63].strip("-") or "vm"
            if p.previous.get("guest.hostname") == p.previous.get("_derived_hostname"):
                p.previous.pop("guest.hostname", None)  # it was the default: follow the (possibly new) VM name
            spec.hostname = spec.hostname or p.text(
                "Hostname:", default=derived, field_name="guest.hostname", assume_default=True,
                validate=lambda s: bool(re.fullmatch(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)", s)) or "letters, digits, hyphens")
            p.answers["_derived_hostname"] = derived
            spec.username = spec.username or p.text("Admin username to create:", default="vmadmin",
                                                    field_name="guest.username",
                                                    validate=lambda s: bool(re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", s))
                                                    or "lower-case letters, digits, - and _")
            if not spec.ssh_authorized_keys and not spec.password_hash:
                how = p.select("How will you log in?", [
                    ("SSH public key (recommended)", "key"), ("Password", "password"), ("Both", "both")],
                    field_name="guest.ssh_authorized_keys or guest.password_hash")
                if how in ("key", "both"):
                    spec.ssh_authorized_keys = [self._read_ssh_key()]
                if how in ("password", "both"):
                    spec.password_hash = self._ask_password_hash()
            if spec.network is None and p.interactive:
                mode = p.select("Guest IP addressing:", [("DHCP", "dhcp"), ("Static", "static")], default="dhcp",
                                field_name="guest.network.mode")
                if mode == "static":
                    from .manifest import GuestNetwork

                    addr = p.text("IP address with prefix (e.g. 192.0.2.50/24):", field_name="guest.network.address",
                                  validate=lambda s: netcheck.address_error(s) or True).strip()
                    p.record("Subnet", netcheck.describe(addr))
                    gw = p.text("Default gateway:", default=netcheck.suggested_gateway(addr),
                                field_name="guest.network.gateway",
                                validate=lambda s: netcheck.gateway_error(s, addr) or True).strip()
                    dns = p.text("DNS servers (comma separated):", default=gw, field_name="guest.network.dns",
                                 validate=lambda s: netcheck.dns_error([d for d in s.replace(",", " ").split()])
                                 or True)
                    spec.network = GuestNetwork(mode="static", address=addr, gateway=gw,
                                                dns=[d for d in dns.replace(",", " ").split()])
            plan.guest = spec
            # OVF properties reach the guest through vCenter (the OVF environment). A host reached directly drops
            # them, so the guest would boot without its user, key and hostname: use guestinfo there.
            plan.guest_route = "ovf" if info.has_cloud_init_properties and self.conn.is_vcenter else "guestinfo"
            net = spec.network.mode if spec.network else "dhcp"
            complete = bool(g.hostname and g.username and (g.ssh_authorized_keys or g.password_hash) and g.network)
            p.record("Guest" + (" (from the manifest)" if complete else ""),
                     f"hostname {spec.hostname}, user {spec.username}, "
                              f"{'SSH key' if spec.ssh_authorized_keys else ''}"
                              f"{' + ' if spec.ssh_authorized_keys and spec.password_hash else ''}"
                              f"{'password' if spec.password_hash else ''}, network {net}"
                              + (f" {spec.network.address}" if spec.network and spec.network.address else ""))

    def _read_ssh_key(self) -> str:
        from pathlib import Path

        default = next((str(p) for p in (Path.home() / ".ssh" / n for n in ("id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub"))
                        if p.exists()), "")
        val = self.p.text("Path to your SSH public key file, or paste the key:", default=default,
                          field_name="guest.ssh_authorized_keys")
        path = Path(val).expanduser()
        key = read_key_file(path) if path.is_file() else val.strip()
        if not re.match(r"^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-\S+|sk-\S+) \S+", key):
            raise ConfigError("That does not look like an SSH public key (expected 'ssh-ed25519 AAAA...').")
        if "PRIVATE KEY" in key:
            raise ConfigError("That is a PRIVATE key. Use the .pub file.")
        return key

    def _ask_password_hash(self) -> str:
        from .logsetup import register_secret

        previous = getattr(self, "_last_password_hash", None)
        if previous and self.p.confirm("Keep the guest password you entered before?", default=True, assume=True):
            return previous
        while True:
            pw = self.p.password("Password for the guest user:")
            if len(pw) < 8:
                from .ui import warn

                warn("Use at least 8 characters.")
                continue
            if pw != self.p.password("Repeat the password:"):
                from .ui import warn

                warn("The passwords did not match.")
                continue
            register_secret(pw)
            self._last_password_hash = ci.sha512_crypt(pw)  # only the hash, only for this run
            return self._last_password_hash

    # ================================================================================== checks & plan
    def _preflight(self) -> None:
        plan, v = self.plan, self.view
        conn = self.conn
        for w in plan.warnings:
            v.note("preflight", w)
        if plan.extra_disks and self.pkg:
            # Known before anything is imported: extra disks go on the image's SCSI or NVMe controller.
            kinds = self.pkg.info.storage_controllers(plan.deployment_option)
            if kinds and not kinds & {"scsi", "nvme"}:
                plan.blockers.append(f"The image's VM has only {', '.join(sorted(k.upper() for k in kinds))} disk "
                                     "controller(s); extra disks need a SCSI or NVMe controller. Remove "
                                     "resources.extra_disks (add the disks after deployment instead).")
        if plan.name in plan.dc.vm_names and self.o.replace:
            from .inventory import find_vm_with

            # the VM and its Notes in one read; an unreadable configuration is missing, i.e. not marked (no crash)
            found = find_vm_with(conn, plan.name, ["config.annotation"], root=plan.dc.vm_folder)
            existing, props = found if found else (None, {})
            marked = existing is not None and vmnotes.is_marked(props.get("config.annotation"))
            if not marked and not self.p.interactive:
                raise PreflightError(f"--replace refuses to delete '{plan.name}' non-interactively because it was not "
                                     "deployed by this tool.")
            with self.p.section("Replace existing VM"):
                if not self.p.confirm(f"Delete the existing VM '{plan.name}' (power off + delete from disk) and "
                                      "re-create it?", default=False, assume=marked):
                    raise UserAborted("Replace declined; nothing was changed.")
            plan.replace_vm = existing
        targets = {"folder": plan.folder, "resource_pool": plan.pool, "datastore": plan.datastore.obj,
                   "network": plan.networks[0][1].obj if plan.networks else None, "virtual_machine": plan.folder}
        if plan.compat_upgrade:
            targets["compatibility_upgrade"] = plan.folder
        if plan.vtpm:
            targets["vtpm"] = plan.folder
            self._check_vtpm()
        missing = check_privileges(conn, targets)
        if missing is None:
            v.note("preflight", "Privilege check not available on this server; skipped", style="dim")
        else:
            for group, ids in missing.items():
                msg = f"Missing privileges on {group.replace('_', ' ')}: {', '.join(ids)}"
                plan.warnings.append(msg)
                v.note("preflight", msg, style="red")
        if self.image.source_kind == "datastore_iso":
            self._check_iso_on_datastore()
        elif self.image.is_iso and self.image.path:
            self._find_same_iso_on_datastores()
        self._check_static_ip()
        if self.appliance and self.appliance.portgroup_security:
            self._check_portgroup_security()

    SAMPLES = 8  # 1 MiB pieces compared (first, last and evenly between) to tell whether two files are the same

    def _find_same_iso_on_datastores(self) -> None:
        """A local/downloaded ISO may already be on a datastore: a file of the same name and size, or one of
        vmdeploy's earlier uploads of it (vmdeploy-iso/<name>, <name>-2, ...). The best one whose sampled content
        matches (ranged reads, a few MB) is offered, to use where it is or have vCenter copy it host to host,
        instead of uploading. Sampling only decides the offer: before the VM uses a copy, its full SHA-256 is
        checked (_deploy_iso), and a mismatch means the local file is uploaded after all.

        One question at most. "No" rules out that file only: vmdeploy's other earlier uploads are still used at the
        upload step once their full SHA-256 matches (_reuse_uploaded_iso), and the question says so. A file whose
        content cannot be sampled is offered only with `reuse_datastore_copy: true`."""
        plan, img, v = self.plan, self.image, self.view
        given = self.m.image.reuse_datastore_copy
        if given is False:
            return
        size = img.path.stat().st_size
        try:
            with console.status(f"Looking for {img.path.name} on the datastores..."):
                found = [i for i in isolib.find_isos(plan.dc) if i.size == size]
        except Exception as e:  # noqa: BLE001 - an optimisation; never block the deployment
            log.debug("search for the same ISO failed: %s", e)
            return
        ours = {i.full: isolib.is_vmdeploy_copy(img.path.name, i.path) for i in found}  # earlier uploads
        same = sorted((i for i in found if ours[i.full] or i.path.rsplit("/", 1)[-1] == img.path.name),
                      key=lambda i: _iso_rank(plan, i, ours[i.full]))
        unsampled = []
        for cand in same:
            verdict = self._same_content(img.path, cand)
            if verdict is False:
                plan.iso_rejected.add(cand.full)
                v.note("preflight", f"{cand.full} has the same size but different content (sampled); not used.",
                       style="dim")
                continue
            if verdict is None:
                unsampled.append(cand)
                continue
            _offer_iso_copy(self, cand, size, same, ours, sampled=True)
            return
        if unsampled and given is True:  # opted in: used once its full SHA-256 matches, even without sampling
            _offer_iso_copy(self, unsampled[0], size, same, ours, sampled=False)
        elif unsampled:  # none offered: the upload step still uses an earlier upload whose full SHA-256 matches
            later = ("; an earlier upload in vmdeploy-iso/ is still used if its full SHA-256 matches"
                     if any(ours[c.full] for c in unsampled) else "")
            self.p.record("ISO", f"not taken from {', '.join(c.full for c in unsampled)} (the contents could not "
                                 f"be compared){later}")

    def _same_content(self, local: Path, cand) -> bool | None:
        """Compare SAMPLES pieces of the local file with the datastore file. None: ranged reads not available."""
        from .transfer import read_range

        piece, offsets = _sample_offsets(local.stat().st_size)
        try:
            decision, url, headers = self._datastore_http(cand.full)
        except Exception as e:  # noqa: BLE001
            log.debug("cannot read %s: %s", cand.full, e)
            return None
        with open(local, "rb") as f:
            for off in offsets:
                remote = read_range(decision, url, off, piece, headers=headers)
                if remote is None:
                    return None
                f.seek(off)
                if f.read(piece) != remote:
                    return False
        return True

    def _check_portgroup_security(self) -> None:
        """EVE-NG's lab nodes send traffic with their own MAC addresses: the portgroup must accept promiscuous
        mode, forged transmits and MAC changes (EVE cookbook 3.2.1). Read-only; a warning, never a blocker."""
        plan, app = self.plan, self.appliance
        for _ovf, net, _a in plan.networks:
            try:
                rejected = _rejected_security(net, [plan.dc.hosts[n].obj for n in plan.host_names
                                                    if n in plan.dc.hosts])
            except Exception as e:  # noqa: BLE001 - informational only
                log.debug("portgroup security of %s not readable: %s", net.name, e)
                continue
            if rejected:
                plan.warnings.append(
                    f"Network {net.name} rejects {', '.join(rejected)}. {app.vendor} recommends Accept for "
                    "promiscuous mode, forged transmits and MAC changes (portgroup and vSwitch), or lab nodes "
                    "cannot reach outside networks.")

    def _check_static_ip(self) -> None:
        """Is the static address already used by a running VM or an ESXi host? (DHCP is the DHCP server's job.)"""
        plan, v = self.plan, self.view
        net = plan.guest.network if plan.guest else None
        if not net or net.mode != "static" or not net.address or not plan.networks:
            return
        net0 = plan.networks[0][1]
        portgroup = getattr(net0, "vc_name", "") or net0.name  # VMs report vCenter's own network name
        uses = netcheck.ip_uses(self.conn)
        replacing = plan.name if plan.replace_vm is not None else None
        blockers, warnings = netcheck.find_conflicts(uses, net.address, portgroup, ignore_vm=replacing)
        for b in blockers:
            plan.blockers.append(b)
            v.note("preflight", b, style="red")
        for w in warnings:
            plan.warnings.append(w)
            v.note("preflight", w)
        if not blockers:
            v.note("preflight", f"IP {net.address.split('/')[0]}: no conflict among {len(uses)} address(es) reported by "
                                "running VMs (VMware Tools) and ESXi hosts; devices without VMware Tools are not "
                                "visible to this check.", style="dim")

    def _key_provider_for_windows_11(self, plan: Plan) -> None:
        """Windows 11 needs a virtual TPM, and a virtual TPM needs a usable key provider in vCenter. Stop here, early,
        unless the user chooses to fix it now: back up the existing Native Key Provider, add one, or make one the
        default. That is a separate change with its own plan and confirmation (nothing of the deployment itself
        happens before the review); otherwise the exact command to run is given."""
        from . import keyprovider as kp

        conn, p, prof = self.conn, self.p, self.conn.profile.name
        why = (f"Windows 11 requires a TPM 2.0, so this VM needs a virtual TPM, and vCenter can only give it one with "
               f"a usable key provider: {plan.key_provider.detail}.")
        if not conn.is_vcenter:
            raise PreflightError("Windows 11 requires a TPM 2.0, so this VM needs a virtual TPM, and an ESXi host "
                                 "reached directly cannot give it one.", hint=crypto.no_vtpm_on_esxi(conn))
        try:
            provs = kp.providers(conn)
        except VmDeployError as e:
            log.debug("listing key providers failed: %s", e)
            provs = []
        unbacked = next((k for k in provs if k.native and k.backed_up is False), None)
        usable = [k for k in provs if not (k.native and k.backed_up is False)]
        if _on_standalone_host(plan) and (unbacked or not usable or usable[0].native):
            # Setting up a Native Key Provider would not help: this host could not use it. Say so, and stop.
            raise PreflightError(_needs_cluster_reason(plan, unbacked.name if unbacked else None),
                                 hint=_needs_cluster_hint(plan))
        if unbacked:
            fix, cmd = (f"Back up {unbacked.name} now (vCenter only uses it after a backup)", "backup"), \
                f"vmdeploy keyprovider backup -p {prof} --provider {unbacked.name}"
        elif usable and not any(k.default for k in provs):
            fix, cmd = (f"Make {usable[0].name} vCenter's default key provider now", "default"), \
                f"vmdeploy keyprovider default -p {prof} --provider {usable[0].name}"
        else:
            fix, cmd = ("Add a Native Key Provider now (free, built into vCenter), make it the default and back it "
                        "up", "add"), f"vmdeploy keyprovider add -p {prof}"
        hint = (f"Set it up first, as an administrator: `{cmd}`. Then run this deployment again (your answers in a "
                "manifest are kept). docs/windows.md explains it.")
        with p.section("Windows 11 needs a key provider"):
            console.print(why)
            if not (p.interactive and conn.rest_credentials):
                raise PreflightError("Windows 11 needs a usable key provider in vCenter for its virtual TPM.",
                                     hint=hint)
            if unbacked:
                kp.show_table(provs)
            choice = p.select("What would you like to do?", [
                fix, ("Cancel the deployment (nothing has been changed)", "cancel")], field_name="hardware.vtpm")
            if choice == "cancel":
                raise UserAborted("Nothing was changed.", hint=hint)
            console.print("[dim]This changes vCenter now, separately from the deployment, and only after you "
                          "confirm it.[/]")
            if choice == "backup":
                kp.backup_flow(conn, p, unbacked.name)
                if not any(k.default for k in provs) and p.confirm(
                        f"Make {unbacked.name} vCenter's default key provider? (needed for new virtual TPMs)",
                        default=True):
                    kp.set_default(conn, unbacked.name)
            elif choice == "default":
                if not p.confirm(f"Make {usable[0].name} vCenter's default key provider?", default=True):
                    raise UserAborted("Nothing was changed.", hint=hint)
                kp.set_default(conn, usable[0].name)
            else:
                kp.add_flow(conn, p)
        plan.key_provider = crypto.key_provider(conn, plan.host.obj if plan.host else None)
        if plan.key_provider.status == "no":
            raise PreflightError(f"vCenter still has no usable key provider: {plan.key_provider.detail}.", hint=hint)
        p.record("Key provider", plan.key_provider.detail)

    def _check_vtpm(self) -> None:
        plan, v = self.plan, self.view
        kp = plan.key_provider or crypto.key_provider(self.conn, plan.host.obj if plan.host else None)
        if compat.number(plan.hardware_version) and compat.number(plan.hardware_version) < 14:
            plan.blockers.append(f"A virtual TPM needs VM compatibility ESXi 6.7 or later (version 14+); "
                                 f"{compat.describe(plan.hardware_version)} was chosen.")
        if kp.status == "no":
            why = "Windows 11 requires a virtual TPM" if isolib.needs_vtpm(plan.guest_id) else "A virtual TPM was requested"
            if not self.conn.is_vcenter:
                fix = crypto.no_vtpm_on_esxi(self.conn)
            elif _on_standalone_host(plan):
                fix = _needs_cluster_hint(plan) + " A key provider is also needed (`vmdeploy keyprovider add`)."
            else:
                fix = crypto.HOW_TO_ADD
            plan.blockers.append(f"{why}, but {kp.detail}. {fix}")
        elif kp.status == "unknown":
            plan.warnings.append(f"Virtual TPM: {kp.detail}. If vCenter has no key provider, creating the VM fails "
                                 "and nothing is left behind.")
        else:
            v.note("preflight", f"Virtual TPM: {kp.detail}.", style="dim")
            if kp.native and _on_standalone_host(plan):
                # vCenter: "The host does not support Native Key Provider because it is not in a cluster."
                plan.blockers.append(f"{_needs_cluster_reason(plan, kp.provider)} {_needs_cluster_hint(plan)}")
            if kp.tpm_required and not plan.blockers:
                self._check_host_tpm(kp)

    def _check_host_tpm(self, kp) -> None:
        """The default key provider was created with "Use key provider only with TPM protected ESXi hosts": a VM
        with a virtual TPM can then only use it on a host that has a physical TPM 2.0."""
        plan, v = self.plan, self.view
        dc = plan.dc
        hosts = [plan.host] if plan.host else [dc.hosts[n] for n in (plan.cluster.hosts if plan.cluster else [])
                                                if n in dc.hosts and dc.hosts[n].usable]
        state = {h.name: crypto.host_tpm(h.obj) for h in hosts}
        without = [n for n, (has, _) in state.items() if has is False]
        unknown = [n for n, (has, _) in state.items() if has is None]
        with_tpm = [n for n, (has, _) in state.items() if has]
        others = [h.name for h in dc.hosts.values() if h.name not in state and h.usable
                  and crypto.host_tpm(h.obj)[0]]
        why = (f"The default key provider '{kp.provider}' only works on hosts with a physical TPM 2.0 (it was created "
               "with 'Use key provider only with TPM protected ESXi hosts')")
        fix = ("Choose a host that has one" + (f" ({', '.join(others)})" if others else "") + ", or add a key "
               "provider without that restriction and make it the default (`vmdeploy keyprovider add`, without "
               "--tpm-required).")
        if hosts and not with_tpm and not unknown:
            where = f"host {without[0]} has none" if plan.host else "no host in the cluster has one"
            plan.blockers.append(f"{why}, and {where}. {fix}")
        elif without:
            plan.warnings.append(f"{why}. DRS may place the VM on a host without one ({', '.join(without)}). {fix}")
        elif unknown:
            plan.warnings.append(f"{why}; whether {', '.join(unknown)} has a TPM 2.0 could not be read.")
        else:
            v.note("preflight", f"Host TPM: {', '.join(f'{n}: {state[n][1]}' for n in with_tpm)}.", style="dim")

    def _check_iso_on_datastore(self) -> None:
        plan, img = self.plan, self.image
        ds = plan.dc.datastores.get(img.datastore)
        if not ds:
            raise PreflightError(f"Datastore '{img.datastore}' (holding the ISO) was not found.")
        folder, _, fname = img.datastore_path.rpartition("/")
        try:
            browser = ds.obj.browser
            task = browser.SearchDatastore_Task(datastorePath=f"[{img.datastore}] {folder}",
                                                searchSpec=vim.host.DatastoreBrowser.SearchSpec(matchPattern=[fname]))
            res = wait_task(task, what="datastore search")
            found = bool(res and res.file)
            search_error = None
        except (DeploymentError, vim.fault.NoPermission) as e:
            found, search_error = False, getattr(e, "message", None) or getattr(e, "msg", None) or str(e)
        if not found:
            raise PreflightError(f"ISO not found on the datastore: [{img.datastore}] {img.datastore_path}",
                                 hint=(f"The datastore could not be searched ({search_error}); the account may lack "
                                       f"Datastore.Browse on {img.datastore}." if search_error else
                                       "Check the path (case matters) in the vSphere Client's datastore browser."))
        source = f"[{img.datastore}] {img.datastore_path}"
        # Every host the VM may run on must see the ISO (with DRS any host of the cluster can be chosen).
        if plan.host_names and not plan.host_names <= ds.hosts:
            # The ISO is on a datastore the target host cannot see (e.g. another host's local datastore):
            # copy it once to the VM's datastore, server-side.
            if not self.conn.is_vcenter:
                raise PreflightError(f"Datastore {img.datastore} is not mounted on this host.")
            plan.iso_copy_from = source
            plan.iso_datastore_path = isolib.copy_target(plan.datastore.name, img.datastore_path)
            self.view.note("preflight", f"{img.datastore} is not visible to {', '.join(sorted(plan.host_names))}: the "
                                        f"ISO will be copied once into {plan.iso_datastore_path.rpartition('/')[0]}/ "
                                        "by vCenter (host to host; later deployments reuse the copy once it is "
                                        "checked against the source).", style="dim")
            missing = check_privileges(self.conn, {"datastore": ds.obj}) or {}
            lacking = set(missing.get("datastore", []))
            if "Datastore.Browse" in lacking:
                plan.blockers.append(f"This account may not read datastore {img.datastore}, so the ISO cannot be used. "
                                     "An administrator can allow it with `vmdeploy access setup` (image datastores).")
            elif "Datastore.FileManagement" in lacking:
                plan.iso_copy_via_pc = True  # can read but not copy server-side: read it here and upload
                self.view.note("preflight", f"No copy rights on {img.datastore}: the ISO will be read through this "
                                            "computer and uploaded instead (slower; later deployments reuse it).",
                               style="dim")
            return
        plan.iso_datastore_path = source

    def _review_plan(self) -> bool:
        """Show the plan. True = deploy, False = go back and change answers."""
        plan = self.plan
        t = Table(show_header=False, box=None, padding=(0, 2))
        # Values are escaped: Rich would read "[datastore1] ..." as a style tag and drop it.
        t.add_row("[bold]VM", esc(f"{plan.name}  (folder {plan.folder_path})"))
        t.add_row("[bold]Image", esc(f"{self.image.display}  [{self.image.format.upper()}]"))
        t.add_row("[bold]Compute", esc(self._target_label() + (f", pool {plan.pool_path}" if "/" in plan.pool_path
                                                                else "")))
        t.add_row("[bold]Sizing", f"{plan.cpu} vCPU, {plan.memory_mb / 1024:g} GB RAM, {plan.disk_gb} GB disk "
                                  f"({plan.provisioning.value})"
                  + "".join(f", +{s} GB" + (f" ({pv.value})" if pv and pv != plan.provisioning else "")
                            for s, pv in plan.extra_disks))
        t.add_row("[bold]Datastore", esc(plan.datastore.label()))
        t.add_row("[bold]Networks", esc(", ".join(n.name for _, n, _ in plan.networks)))
        if self.image.is_iso:
            t.add_row("[bold]Hardware", f"{plan.guest_id}, {plan.firmware}{' + Secure Boot' if plan.secure_boot else ''}"
                                        f", disk controller {plan.disk_controller}"
                                        f", NIC {', '.join(sorted({a for _, _, a in plan.networks}))}"
                                        f"{', virtual TPM' if plan.vtpm else ''}"
                                        f"{', nested virtualisation' if plan.nested_hv else ''}"
                                        f"{', IOMMU' if plan.iommu else ''}")
            if plan.iso_copy_from:
                how = "read through this computer and uploaded" if plan.iso_copy_via_pc else "by vCenter, host to host"
                found = "already on a datastore: " if plan.iso_found_on_datastore else ""
                into = (plan.iso_datastore_path or "").rpartition("/")[0] + "/"  # name, or name-2 ... if taken
                t.add_row("[bold]ISO", esc(f"{found}{plan.iso_copy_from} -> copied once into {into} "
                                           f"({how}; checked in full first; no upload from this computer)" if found else
                                           f"{plan.iso_copy_from} -> copied once into {into} ({how}; an earlier copy "
                                           "there is reused once checked)"))
            elif plan.iso_found_on_datastore:
                t.add_row("[bold]ISO", esc(f"{plan.iso_datastore_path} (already on the datastore; checked in full, "
                                           "then used where it is; no upload)"))
        if self.appliance:
            t.add_row("[bold]Vendor", esc(f"{self.appliance.name}: {self.appliance.vendor}'s recommended settings"))
        if plan.deployment_option:
            size = self.pkg.info.option_summary(plan.deployment_option) if self.pkg else ""
            t.add_row("[bold]Image size", esc(plan.deployment_option + (f" (this size, as defined by the image: {size})"
                                                                         if size else "")))
        if plan.nested_hv and not self.image.is_iso:
            t.add_row("[bold]Hardware", "nested virtualisation (hardware-assisted virtualisation exposed to the guest)")
        t.add_row("[bold]Compatibility", compat.describe(plan.hardware_version)
                  + ("  (upgraded after import)" if plan.compat_upgrade else ""))
        if plan.guest:
            g = plan.guest
            login = " + ".join(x for x, on in (("SSH key", g.ssh_authorized_keys), ("password", g.password_hash)) if on)
            net = (f"static {g.network.address}" if g.network and g.network.mode == "static" and g.network.address
                   else "DHCP")
            mg = self.m.guest
            given = bool(mg.hostname and mg.username and (mg.ssh_authorized_keys or mg.password_hash) and mg.network)
            t.add_row("[bold]First boot", esc(
                f"cloud-init via {'OVF properties' if plan.guest_route == 'ovf' else 'guestinfo'}: hostname "
                f"{g.hostname}, user {g.username}" + (f" ({login})" if login else "") + f", {net}"
                + (" (from the manifest)" if given else "")))
        if plan.ovf_properties:
            t.add_row("[bold]Properties", f"{len(plan.ovf_properties)} OVF propert(ies) set")
        eulas = self.pkg.info.eulas if self.pkg else []
        if eulas:
            t.add_row("[bold]Licence", f"{len(eulas)} agreement(s) accepted"
                      + ("" if self.p.interactive else " (ovf.accept_eula in the manifest)"))
        t.add_row("[bold]After", ", ".join(x for x in (
            "power on" if plan.power_on else "leave powered off",
            "wait for IP" if plan.wait_for_ip else "", "baseline snapshot" if plan.snapshot else "") if x))
        if plan.replace_vm is not None:
            t.add_row("[bold red]Replace", esc(f"existing VM '{plan.name}' will be DELETED first"))
        with self.p.section("Review the plan (nothing has been changed yet)"):
            console.print(t)
            for n in plan.notes:
                console.print(f"[dim]  i {esc(n)}")
            for w in plan.warnings:
                console.print(f"[yellow]  ! {esc(w)}")
            for b in plan.blockers:
                console.print(f"[bold red]  ✖ {esc(b)}")
            if plan.blockers:
                console.print("[red]This must be fixed before deploying.[/]")
                if not self.p.interactive:
                    # A blocker is a fixable configuration problem: exit code 2, like a missing answer.
                    raise ConfigError("Cannot deploy: " + " ".join(plan.blockers),
                                      hint="Fix the problem(s) above in the manifest or the command line, then run "
                                           "again. Nothing was changed.")
            elif not self.p.interactive:
                return True
            options = [] if plan.blockers else [("Deploy now", "deploy")]
            options += [
                ("Change my answers (your answers are pre-selected; the image is not downloaded again)", "change"),
                ("Cancel (nothing is changed)", "cancel"),
            ]
            choice = self.p.select("What next?", options, default="change" if plan.blockers else "deploy",
                                   auto_single=False)
            if choice == "cancel":
                raise UserAborted("Deployment cancelled at the review step; nothing was changed.")
            return choice == "deploy"

    # ================================================================================== ISO pipeline
    def _deploy_iso(self) -> None:
        plan, v = self.plan, self.view
        for k in ("upload_disks", "customize", "ip", "snapshot"):
            v.skip(k, "not applicable to ISO installs")
        if plan.iso_found_on_datastore and not self._copy_is_genuine(plan.iso_copy_from or plan.iso_datastore_path):
            # Not the same file after all (or unreadable), and now in iso_rejected: one of vmdeploy's earlier uploads
            # that passes the full check is used instead, otherwise the verified local ISO is uploaded.
            plan.iso_copy_from, plan.iso_copy_via_pc, plan.iso_found_on_datastore = None, False, False
            plan.iso_datastore_path = None
            self._upload_iso()
        elif plan.iso_copy_from and plan.iso_copy_via_pc:
            existing = self._reuse_uploaded_iso_named(plan.iso_datastore_path)
            if not existing:
                v.start("upload_iso", f"reading {plan.iso_copy_from} through this computer")
                local = self._read_datastore_file(plan.iso_copy_from, lambda d, t: v.begin_transfer("upload_iso", d, t),
                                                  expected_sha=self.image.sha256, step="upload_iso")
                self._upload_iso(local)
        elif plan.iso_copy_from:
            v.start("upload_iso", f"copying {plan.iso_copy_from} -> {plan.iso_datastore_path} (server-side)")
            try:
                plan.iso_datastore_path, how = isolib.ensure_copied(
                    self.conn, plan.dc.obj, plan.iso_copy_from, plan.datastore.obj, plan.iso_datastore_path,
                    on_progress=lambda f: v.update("upload_iso", fraction=f), reuse_if=self._copy_matches)
                v.done("upload_iso", f"{plan.iso_datastore_path} ({how})")
            except isolib.FolderListError:
                raise  # the VM's datastore folder cannot be listed: an upload could not be written there either
            except DeploymentError as e:
                self._copy_through_pc_after(e)
        elif plan.iso_datastore_path and plan.iso_found_on_datastore:
            v.done("upload_iso", f"{plan.iso_datastore_path} (already on the datastore; SHA-256 verified; no upload)")
        elif plan.iso_datastore_path:
            v.skip("upload_iso", "ISO already on datastore")
        else:
            self._upload_iso()

        v.start("create", "creating VM with an empty disk and the ISO attached")
        annotation = self._annotation()
        spec = create_spec(name=plan.name, guest_id=plan.guest_id, datastore_name=plan.datastore.name, cpu=plan.cpu,
                           cores_per_socket=plan.cores_per_socket, memory_mb=plan.memory_mb, disk_gb=plan.disk_gb,
                           provisioning=plan.provisioning, firmware=plan.firmware, secure_boot=plan.secure_boot,
                           hardware_version=plan.hardware_version,
                           networks=[(n, a) for _, n, a in plan.networks], iso_path=plan.iso_datastore_path,
                           annotation=annotation, disk_controller=plan.disk_controller, vtpm=plan.vtpm,
                           nested_hv=plan.nested_hv, iommu=plan.iommu)
        task = plan.folder.CreateVM_Task(config=spec, pool=plan.pool, host=plan.host.obj if plan.host else None)
        self.vm = wait_task(task, what="Create VM", on_progress=lambda f: v.update("create", fraction=f))
        self.created = True
        v.done("create", f"{plan.name} ({self.vm._moId})")
        if plan.extra_disks:
            v.start("reconfigure")
            rspec, changes = reconfigure_spec(self.vm, cpu=None, cores_per_socket=None, memory_mb=None, disk_gb=None,
                                              extra_disks=plan.extra_disks, annotation=None, extra_config=None)
            wait_task(self.vm.ReconfigVM_Task(spec=rspec), what="Reconfigure VM")
            v.done("reconfigure", "; ".join(changes))
        else:
            v.skip("reconfigure", "configured at creation")

    def _copy_through_pc_after(self, error: DeploymentError) -> None:
        """vCenter could not copy the ISO host to host: say why if we can tell, then (if allowed) read it through
        this computer and upload it to the VM's datastore, which reaches the same result."""
        plan, v = self.plan, self.view
        in_use = self._running_vms_using(plan.iso_copy_from)
        why = (f" It is attached to the running VM(s) {', '.join(in_use)}, whose host may hold it locked; "
               "disconnecting their CD/DVD drive frees it." if in_use else "")
        v.note("upload_iso", f"vCenter could not copy the ISO: {error.message}.{why}", style="yellow")
        size = isolib._size(self.conn, plan.dc.obj, plan.iso_copy_from)
        gb = f" ({human_size(size)})" if size else ""
        allowed = self.m.image.fallback_via_pc
        if not self.p.confirm(f"Read the ISO{gb} through this computer and upload it to {plan.datastore.name} "
                              "instead? (slower; the result is the same)", default=True,
                              assume=True if allowed is None else allowed, field_name="image.fallback_via_pc"):
            raise DeploymentError(f"{error.message}.{why}",
                                  hint="Nothing was created. Copy the ISO to a datastore the target host can see "
                                       "(or choose that host), or allow the copy through this computer.") from error
        plan.iso_copy_via_pc = True
        if self._reuse_uploaded_iso_named(plan.iso_datastore_path):
            return
        if self.image.path:  # the ISO is on this computer anyway: upload it, no need to read the datastore copy
            self._upload_iso(self.image.path, reuse=False)
            return
        v.start("upload_iso", f"reading {plan.iso_copy_from} through this computer")
        local = self._read_datastore_file(plan.iso_copy_from, lambda d, t: v.begin_transfer("upload_iso", d, t),
                                          expected_sha=self.image.sha256, step="upload_iso")
        self._upload_iso(local)

    def _running_vms_using(self, iso_path: str) -> list[str]:
        """Powered-on VMs with this ISO connected to a CD/DVD drive (ESXi locks files that running VMs use)."""
        from . import inventory, isocopies

        target = isocopies.norm(iso_path)
        names = []
        try:
            for _obj, props in inventory.collect(self.conn, vim.VirtualMachine,
                                                 ["name", "runtime.powerState", "config.hardware.device"]):
                if props.get("runtime.powerState") != "poweredOn":
                    continue
                if target in isocopies.iso_paths(props.get("config.hardware.device"), connected_only=True):
                    names.append(props.get("name", "?"))
        except Exception as e:  # noqa: BLE001 - diagnosis only
            log.debug("could not check which VMs use %s: %s", iso_path, e)
        return names

    def _reuse_uploaded_iso(self, size: int) -> bool:
        """An earlier upload of the same ISO (vmdeploy-iso/<name>, <name>-2, ..., same size) is used, or copied
        host to host, only after its full SHA-256 matches the image: a name and size can be faked by anyone with
        file rights on that datastore. Never a file the user said No to, or that failed a check (iso_rejected), and
        never with `reuse_datastore_copy: false`."""
        plan, v, img = self.plan, self.view, self.image
        if self.m.image.reuse_datastore_copy is False or not img.sha256:
            return False
        try:
            same = [i for i in isolib.find_isos(plan.dc) if i.size == size and i.full not in plan.iso_rejected
                    and isolib.is_vmdeploy_copy(img.path.name, i.path)]
        except Exception as e:  # noqa: BLE001 - never block an upload on this optimisation
            log.debug("search for earlier uploads failed: %s", e)
            return False
        same.sort(key=lambda i: _iso_rank(plan, i, True))  # usable where it is first (copied: vCenter only)
        for cand in same:
            in_place = _iso_in_place(plan, cand)
            if not in_place and not self.conn.is_vcenter:
                continue
            if not self._copy_is_genuine(cand.full):
                continue
            if in_place:
                plan.iso_datastore_path = cand.full
                v.done("upload_iso", f"{cand.full} (uploaded earlier; SHA-256 verified; no upload needed)")
                return True
            target = isolib.copy_target(plan.datastore.name, img.path.name)
            v.update("upload_iso", f"copying the earlier upload {cand.full} -> {plan.datastore.name} (server-side)")
            try:
                plan.iso_datastore_path, how = isolib.ensure_copied(
                    self.conn, plan.dc.obj, cand.full, plan.datastore.obj, target,
                    on_progress=lambda f: v.update("upload_iso", fraction=f), reuse_if=self._copy_is_genuine)
            except isolib.FolderListError:
                raise  # the VM's datastore folder cannot be listed: the upload could not be written there either
            except DeploymentError as e:  # e.g. the source is locked by a running VM: upload instead
                log.warning("copying %s failed (%s); uploading instead", cand.full, e.message)
                v.note("upload_iso", f"Copying {cand.full} failed ({e.message}); uploading instead.", style="dim")
                return False
            v.done("upload_iso", f"{plan.iso_datastore_path} ({how}; no upload needed)")
            return True
        return False

    def _reuse_uploaded_iso_named(self, target: str) -> bool:
        """The copy-through-this-computer target already exists from an earlier deployment, as the same file (same
        size as the source). A different file of that name is never taken for it. A folder that cannot be listed
        stops here (FolderListError), before the ISO is read through this computer for an upload that would fail."""
        plan, v = self.plan, self.view
        source = isolib._size(self.conn, plan.dc.obj, plan.iso_copy_from) if plan.iso_copy_from else None
        for cand in isolib.copies_in(plan.datastore.obj, target, source):
            if self._copy_matches(cand):
                plan.iso_datastore_path = cand
                v.done("upload_iso", f"{cand} (copied earlier; checked; reused)")
                return True
        return False

    def _upload_iso(self, local: Path | None = None, reuse: bool = True) -> None:
        plan, v, conn, img = self.plan, self.view, self.conn, self.image
        ds = plan.datastore
        local = local or img.path
        size = local.stat().st_size
        if reuse and local is img.path and self._reuse_uploaded_iso(size):
            return
        v.steps["upload_iso"].weight = max(5, size / GiB * 5)
        folder = isolib.ISO_FOLDER
        v.start("upload_iso", f"{local.name} -> [{ds.name}] {folder}/")
        try:
            conn.content.fileManager.MakeDirectory(name=f"[{ds.name}] {folder}", datacenter=plan.dc.obj,
                                                   createParentDirectories=True)
        except vim.fault.FileAlreadyExists:
            pass
        # Never overwrite a file of the same name: another VM may boot from it, and it may not be this file. An
        # upload (HTTP PUT) replaces whatever has its name, and another deployment may be uploading the same ISO
        # right now, so it goes to a name of its own and then gets its name by a move that never overwrites.
        wanted = f"[{ds.name}] {folder}/{local.name}"
        isolib.list_folder(ds.obj, ds.name, folder)  # a folder that cannot be listed stops here, before the upload
        # Still an .iso, so `images prune` and `access audit` see it if a run is cut off; never taken for a copy.
        own = f"{folder}/{local.stem}.vmdeploy-upload-{secrets.token_hex(4)}.iso"
        dc_path = _inventory_path(plan.dc.obj, conn.content.rootFolder) if conn.is_vcenter else "ha-datacenter"
        adv = v.begin_transfer("upload_iso", f"Uploading {local.name}", size)
        try:
            with open(local, "rb") as f:
                upload_stream(conn.decision, "PUT", datastore_url_path(dc_path, ds.name, own), f, size,
                              headers={"Cookie": conn.session_cookie, "Content-Type": "application/octet-stream"},
                              progress=adv, timeout=600)
        except BaseException:
            # A cancelled or failed upload is deleted, with its folder if that is now empty, so it is never
            # mistaken for a copy. Only this run's own file is touched.
            self._delete_partial_upload(f"[{ds.name}] {own}")
            raise
        try:
            plan.iso_datastore_path = isolib.place_upload(conn, plan.dc.obj, ds.obj, f"[{ds.name}] {own}", wanted)
        except VmDeployError as e:
            # The upload is complete under a name no other deployment uses: keep it rather than upload it again.
            plan.iso_datastore_path = f"[{ds.name}] {own}"
            log.warning("could not name the upload %s (%s); used as it is", own, e.message)
            v.note("upload_iso", f"Could not give the upload its name ({e.message}); the VM uses it as {own}.",
                   style="yellow")
        v.done("upload_iso", plan.iso_datastore_path)

    def _delete_partial_upload(self, full: str) -> None:
        from . import isocopies

        deadline = time.monotonic() + 60  # the host may hold the file briefly after the connection drops
        try:
            with console.status(f"Deleting the partly uploaded {esc(full)}..."):
                while True:
                    try:
                        isocopies.delete(self.conn, self.inv, full, self.plan.dc.name)
                        console.print(f"[green]Deleted the partly uploaded ISO {esc(full)}.[/]")
                        return
                    except Exception as e:  # noqa: BLE001
                        ds_name, path = isolib.split(full)
                        folder, _, fname = path.rpartition("/")
                        if isolib._size_on(self.plan.datastore.obj, ds_name, folder, fname) is None:
                            return  # nothing there (the upload never started writing)
                        if time.monotonic() >= deadline:
                            raise e
                        time.sleep(5)
        except BaseException as e:  # noqa: BLE001 - never mask the original failure
            log.warning("could not delete the partial upload %s: %s", full, e)
            console.print(f"[yellow]The partly uploaded ISO {esc(full)} may be left on the datastore; "
                          "`vmdeploy images prune` deletes it.[/]")

    # ================================================================================== OVA pipeline
    def _deploy_ova(self) -> None:
        plan, v, conn, info = self.plan, self.view, self.conn, self.pkg.info
        v.skip("upload_iso", "not needed for OVA/OVF")

        user_data = None
        if plan.guest:
            user_data = ci.render_user_data(plan.guest, plan.guest.hostname,
                                            network_in_userdata=plan.guest_route == "ovf")
            if plan.guest_route == "ovf":
                plan.ovf_properties.update(ci.ovf_property_values({p.key for p in info.properties}, user_data,
                                                                  plan.guest.hostname))

        v.start("create", "validating import spec with vCenter")
        params = vim.OvfManager.CreateImportSpecParams(
            entityName=plan.name, diskProvisioning=provisioning_to_ovf(plan.provisioning),
            networkMapping=[vim.OvfManager.NetworkMapping(name=ovf, network=net.obj)
                            for ovf, net, _ in plan.networks if ovf],
            propertyMapping=[vim.KeyValue(key=k, value=val) for k, val in plan.ovf_properties.items()],
            deploymentOption=plan.deployment_option or "",
            hostSystem=plan.host.obj if plan.host else None)
        result = conn.content.ovfManager.CreateImportSpec(ovfDescriptor=self.pkg.descriptor, resourcePool=plan.pool,
                                                          datastore=plan.datastore.obj, cisp=params)
        if result.error:
            msgs = "; ".join(getattr(e, "msg", None) or str(e) for e in result.error)
            raise DeploymentError(f"vCenter rejected the image: {msgs}")
        for w in result.warning or []:
            v.note("create", explain_import_warning(getattr(w, "msg", None) or str(w),
                                                    "vCenter" if conn.is_vcenter else "ESXi"), style="dim")
        # Created with the chosen CPU and memory, not resized afterwards (a vCenter-managed ESXi host refuses
        # resizing over a direct connection).
        sized = size_import_spec(result.importSpec, cpu=plan.cpu, cores_per_socket=plan.cores_per_socket,
                                 memory_mb=plan.memory_mb, disk_gb=self._disk_growth(plan) if conn.managed_by else None)
        v.update("create", "creating VM objects")
        lease = plan.pool.ImportVApp(spec=result.importSpec, folder=plan.folder,
                                     host=plan.host.obj if plan.host else None)
        while lease.state == vim.HttpNfcLease.State.initializing:
            time.sleep(0.5)
        if lease.state == vim.HttpNfcLease.State.error:
            raise DeploymentError(f"vCenter could not create the VM: {getattr(lease.error, 'msg', lease.error)}")
        entity = lease.info.entity
        # The lease reports the entity as a generic ManagedEntity reference; bind it as a VirtualMachine.
        self.vm = entity if isinstance(entity, vim.VirtualMachine) else vim.VirtualMachine(entity._moId, entity._stub)
        self.created = True
        try:  # the folder this import made, so an aborted import can be cleaned up completely
            self.vm_dir = self.vm.config.files.vmPathName.rsplit("/", 1)[0]
        except Exception as e:  # noqa: BLE001
            log.debug("could not read the new VM's folder: %s", e)
        v.done("create", f"{plan.name} ({self.vm._moId})")

        self._upload_disks(lease, result.fileItem or [])

        # Reconfigure
        v.start("reconfigure")
        upgraded = []
        if plan.compat_upgrade:
            v.update("reconfigure", f"upgrading VM compatibility to {compat.describe(plan.hardware_version)}")
            wait_task(self.vm.UpgradeVM_Task(version=plan.hardware_version), what="Upgrade VM compatibility")
            upgraded = [f"compatibility upgraded to {compat.describe(plan.hardware_version)}"]
        extra = None
        if plan.guest and plan.guest_route == "guestinfo":
            extra = ci.guestinfo_extra_config(user_data, ci.render_metadata(plan.guest.hostname, plan.guest))
        # Images without a NetworkSection have no NIC to map; add the requested NICs instead.
        new_nics = [(net, adapter) for ovf, net, adapter in plan.networks if not ovf] if not info.networks else []
        rspec, changes = reconfigure_spec(self.vm, cpu=plan.cpu, cores_per_socket=plan.cores_per_socket,
                                          memory_mb=plan.memory_mb, disk_gb=self._disk_growth(plan),
                                          extra_disks=plan.extra_disks,
                                          annotation=self._annotation(), extra_config=extra, new_nics=new_nics,
                                          nested_hv=plan.nested_hv)
        log.debug("reconfigure: %s", "; ".join(changes) or "no sizing changes")
        try:
            wait_task(self.vm.ReconfigVM_Task(spec=rspec), what="Reconfigure VM",
                      on_progress=lambda f: v.update("reconfigure", fraction=f))
        except DeploymentError as e:
            if RESTRICTED_BY_MANAGER not in str(e):
                raise
            self._reconfigure_in_parts(rspec, e)
        v.done("reconfigure", "; ".join(upgraded + sized + [c for c in changes if "cloud-init" not in c])
               or "matches the image")

        if plan.guest and plan.guest.network and plan.guest.network.mode == "static" and len(plan.networks) > 1:
            self._bind_static_address_to_nic1(plan, user_data, info)

        if plan.guest:
            v.done("customize", f"cloud-init via {'OVF properties' if plan.guest_route == 'ovf' else 'guestinfo'} "
                                f"(hostname {plan.guest.hostname}, user {plan.guest.username})")
        else:
            v.skip("customize", "not requested" if not info.has_cloud_init_properties else "skipped by user")

    def _nic1_mac(self, plan: Plan) -> str | None:
        """MAC address of the adapter on the first chosen network (the lowest device key if several are)."""
        want = plan.networks[0][1]
        cards = [d for d in self.vm.config.hardware.device if isinstance(d, vim.vm.device.VirtualEthernetCard)]

        def on_first_network(card) -> bool:
            b = card.backing
            if isinstance(b, vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo):
                return want.kind == "dvpg" and b.port.portgroupKey == want.portgroup_key
            if isinstance(b, vim.vm.device.VirtualEthernetCard.OpaqueNetworkBackingInfo):
                return want.kind == "opaque" and b.opaqueNetworkId == want.opaque_id
            net = getattr(b, "network", None)
            return net is not None and getattr(want.obj, "_moId", None) == net._moId

        ordered = sorted((c for c in cards if on_first_network(c)), key=lambda c: c.key) or \
            sorted(cards, key=lambda c: c.key)
        return ordered[0].macAddress if ordered and ordered[0].macAddress else None

    def _bind_static_address_to_nic1(self, plan: Plan, user_data: str, info) -> None:
        """Several NICs and a static address: written with netplan's `en*` match, every adapter would get the
        address and a default route. The settings are bound to NIC 1's MAC address, known only once the VM exists,
        before its first boot. The other adapters are left unconfigured."""
        v, g = self.view, plan.guest
        mac = self._nic1_mac(plan)
        spec = None
        if mac and plan.guest_route == "guestinfo":
            extra = ci.guestinfo_extra_config(user_data, ci.render_metadata(g.hostname, g, mac=mac))
            spec = vim.vm.ConfigSpec(extraConfig=[vim.option.OptionValue(key=k, value=val) for k, val in extra.items()])
        elif mac:
            values = ci.ovf_property_values({p.key for p in info.properties},
                                            ci.render_user_data(g, g.hostname, network_in_userdata=True, mac=mac),
                                            g.hostname)
            edits = []
            for prop in (getattr(self.vm.config.vAppConfig, "property", None) or []):
                full = ".".join(x for x in (prop.classId, prop.id, prop.instanceId) if x)
                if full in values and full.split(".")[-1] == "user-data":
                    edits.append(vim.vApp.PropertySpec(operation="edit", info=vim.vApp.PropertyInfo(
                        key=prop.key, value=values[full])))
            spec = vim.vm.ConfigSpec(vAppConfig=vim.vApp.VmConfigSpec(property=edits)) if edits else None
        if spec is None:
            plan.warnings.append(f"Could not bind the static address to NIC 1; every network adapter may get "
                                 f"{g.network.address}. Remove the other adapters' addresses in the guest.")
            v.note("customize", plan.warnings[-1])
            return
        try:
            wait_task(self.vm.ReconfigVM_Task(spec=spec), what="Bind the static address to NIC 1")
        except DeploymentError as e:
            if RESTRICTED_BY_MANAGER not in str(e):
                raise
            self._reconfigure_in_parts(spec, e)
        v.note("customize", f"Static address bound to NIC 1 ({mac}); the other adapters are left unconfigured.",
               style="dim")

    def _reconfigure_in_parts(self, rspec, error: DeploymentError) -> None:
        """An ESXi host managed by vCenter refused the reconfigure over a direct connection. Apply each part on its
        own to find what the host refuses: the rest still goes through, and the error names exactly what failed."""
        refused = []
        for label, part in split_config_spec(rspec):
            try:
                wait_task(self.vm.ReconfigVM_Task(spec=part), what=f"Reconfigure VM ({label})")
                log.debug("reconfigure part accepted by the host: %s", label)
            except DeploymentError as e:
                if RESTRICTED_BY_MANAGER not in str(e):
                    raise
                log.debug("reconfigure part refused by the host: %s", label)
                if label == "disk size" and self._extend_disk_file(part.deviceChange[0].device):
                    continue
                refused.append(label)
        if refused:
            raise DeploymentError(
                f"{error} Refused: {', '.join(refused)}.",
                hint="This ESXi host is managed by vCenter, and it refuses these changes over a direct connection. "
                     "Deploy through vCenter instead (a profile for the vCenter Server).")
        self.view.note("reconfigure", "Applied in parts: this vCenter-managed host refused the combined change.",
                       style="dim")

    def _extend_disk_file(self, disk) -> bool:
        """Grow a (powered-off) VM's disk through the disk file itself (VirtualDiskManager), for hosts that refuse
        growing it through a VM reconfigure. The guest grows its partition at first boot (cloud-init)."""
        name = getattr(disk.backing, "fileName", None)
        if not name:
            return False
        eager = self.plan.provisioning == Provisioning.EAGER
        try:
            wait_task(self.conn.content.virtualDiskManager.ExtendVirtualDisk_Task(
                name=name, datacenter=self.plan.dc.obj, newCapacityKb=disk.capacityInKB, eagerZero=eager),
                what="Extend virtual disk")
        except Exception as e:  # noqa: BLE001 - reported as the refused part
            log.debug("extending %s through the disk file failed: %s", name, e)
            return False
        log.debug("extended %s to %d KB through the disk file", name, disk.capacityInKB)
        self.view.note("reconfigure", "Disk grown through the disk file (this host refuses it as a VM change).",
                       style="dim")
        return True

    def _upload_disks(self, lease, file_items) -> None:
        v, conn = self.view, self.conn
        items = {fi.deviceId: fi for fi in file_items}
        manifest = self.pkg.manifest_entries()
        unchecked: list[str] = []  # files the package manifest does not list
        uploads = []
        for dev in lease.info.deviceUrl or []:
            fi = items.get(dev.importKey)
            if fi is None:
                continue
            uploads.append((dev, fi, self.pkg.member_size(fi.path)))
        all_bytes = sum(s for _, _, s in uploads)
        total = all_bytes or 1  # for the progress arithmetic only
        v.steps["upload_disks"].weight = max(5, total / GiB * 8)
        v.start("upload_disks", f"{len(uploads)} file(s), {human_size(all_bytes)}")
        adv = v.begin_transfer("upload_disks", "Uploading disks", total)
        done = [0]
        stop = threading.Event()

        def keepalive():
            # HttpNfcLeaseProgress must be called periodically or the lease times out and vCenter removes
            # everything it created (vSphere Web Services SDK Programming Guide, 'Importing an OVF Package').
            while not stop.wait(5):
                try:
                    lease.HttpNfcLeaseProgress(int(done[0] * 100 / total))
                except Exception as e:  # noqa: BLE001
                    log.debug("lease progress failed: %s", e)

        def advance(n: int) -> None:
            done[0] += n
            adv(n)

        t = threading.Thread(target=keepalive, daemon=True)
        t.start()
        try:
            for dev, fi, size in uploads:
                url = urllib.parse.urlparse(dev.url)
                if url.hostname in ("*", None) or url.netloc.startswith("*"):
                    # "*" means "the server you are connected to" (common when connected straight to ESXi).
                    host, port = self.o.profile.host, url.port or self.o.profile.port
                else:
                    host, port = url.hostname, url.port or 443
                decision = self.trust.vouch(host, port, getattr(dev, "sslThumbprint", None))
                if fi.create:  # non-disk files (e.g. ISO, NVRAM)
                    method, headers = "PUT", {"Overwrite": "t", "Content-Type": "application/octet-stream"}
                else:
                    method, headers = "POST", {"Content-Type": "application/x-vnd.vmware-streamVmdk"}
                # The NFC URL carries its own lease ticket. The vCenter session cookie is only sent back to the
                # server we signed in to (standalone ESXi), never to another host.
                if (host, port) == (self.o.profile.host, self.o.profile.port):
                    headers["Cookie"] = conn.session_cookie
                path = url.path + (f"?{url.query}" if url.query else "")
                expected = manifest.get(fi.path) or manifest.get(fi.path.rsplit("/", 1)[-1])
                if manifest and not expected:
                    unchecked.append(fi.path)
                    log.warning("%s is not listed in the package manifest; uploaded without a checksum", fi.path)
                import hashlib

                digest = hashlib.new(expected[0]) if expected else None
                v.update("upload_disks", f"{fi.path} -> {host}")
                with self.pkg.open_member(fi.path) as src:
                    upload_stream(decision, method, path, src, size, headers=headers, progress=advance,
                                  timeout=600, digest=digest)
                if digest is not None and digest.hexdigest() != expected[1]:
                    raise DeploymentError(f"The bytes sent for {fi.path} do not match the package manifest.")
            stop.set()
            lease.HttpNfcLeaseProgress(100)
            lease.HttpNfcLeaseComplete()
        except BaseException as e:
            stop.set()
            try:
                lease.HttpNfcLeaseAbort(vmodl_fault(str(e)))
            except Exception as ae:  # noqa: BLE001
                log.debug("lease abort failed: %s", ae)
            # vCenter removes the VM when an import lease is aborted; the clean-up checks that it really went.
            self.aborted_vm, self.vm, self.created = self.vm, None, False
            raise
        if not manifest:
            v.done("upload_disks", f"{human_size(all_bytes)} uploaded")
        elif unchecked:  # the .mf does not list every file: say exactly what was not checked
            v.done("upload_disks", f"{human_size(all_bytes)} uploaded; checked against the package manifest except "
                                   f"{', '.join(unchecked)} (not listed in it)", status="warn")
        else:
            v.done("upload_disks", f"{human_size(all_bytes)} uploaded and verified against the package manifest")

    # ================================================================================== finish
    def _power_and_finish(self) -> None:
        plan, v = self.plan, self.view
        vm = self.vm
        self.vm_ready = True
        if plan.power_on:
            v.start("power")
            wait_task(vm.PowerOnVM_Task(), what="Power on", on_progress=lambda f: v.update("power", fraction=f))
            host = vm.runtime.host.name if vm.runtime.host else "?"
            v.done("power", f"running on {host}")
        else:
            v.skip("power", "left powered off as requested")

        ip = None
        if plan.wait_for_ip:
            v.start("ip", "waiting for VMware Tools to report an address")
            ip = self._wait_for_ip(vm, self.m.post_deploy.wait_timeout_s)
            if ip:
                v.done("ip", ip)
            else:
                v.done("ip", "no IPv4 address reported", status="warn")
                if not plan.guest:
                    # Vendor appliances configure themselves; many (routers, firewalls) never report their address
                    # to vCenter, even with one (Cisco Catalyst 8000V got its DHCP address within the wait).
                    v.note("ip", "VMware Tools did not report an address. Many appliances do not report theirs to "
                                 "vCenter even when they have one, or are still booting: check in the VM console.")
                elif not (plan.guest.network and plan.guest.network.mode == "static"):
                    v.note("ip", "The VM may still be booting, or the network may have no DHCP server: check in the "
                                 "VM console, or redeploy with a static address.")
        elif v.steps["ip"].status == "pending":
            v.skip("ip", "not requested")

        if ip:
            latest = self._current_ipv4(vm)
            if latest and latest != ip:
                v.note("ip", f"The address changed to {latest} after it was first reported ({ip}).", style="yellow")
                ip = latest
            if not (plan.guest and plan.guest.network and plan.guest.network.mode == "static"):
                v.note("ip", "Assigned by DHCP: it can change later. Reserve it on your DHCP server for a fixed "
                             "address.", style="dim")

        if plan.snapshot:
            v.start("snapshot")
            wait_task(vm.CreateSnapshot_Task(name="clean-baseline", description=f"Created by vsphere-vm-deployment "
                                             f"{__version__} after first boot", memory=False, quiesce=False),
                      what="Snapshot")
            v.done("snapshot", "clean-baseline")
        elif v.steps["snapshot"].status == "pending":
            v.skip("snapshot", "not requested")

        self.summary = {
            "vm": plan.name, "moid": vm._moId, "datacenter": plan.dc.name, "target": self._target_label(),
            "datastore": plan.datastore.name, "networks": [n.name for _, n, _ in plan.networks],
            "cpu": plan.cpu, "memory_mb": plan.memory_mb, "disk_gb": plan.disk_gb, "ip": ip,
            "compatibility": plan.hardware_version,
            "powered_on": plan.power_on, "iso_install": self.image.is_iso,
            "windows": isolib.is_windows(plan.guest_id), "vtpm": plan.vtpm,
            "image": self.image.display, "image_sha256": self.image.sha256,
            "console_url": self._console_url(vm), "on_esxi": not self.conn.is_vcenter, "warnings": plan.warnings,
            "guest_user": plan.guest.username if plan.guest else None,
            "timings_s": self.view.timings(),  # working time per step (answers excluded); total added at the end
        }

    def _wait_for_ip(self, vm, timeout: int) -> str | None:
        """Poll VMware Tools for an IPv4 address. Ctrl-C only stops the waiting; the VM is kept."""
        try:
            return self._poll_ip(vm, timeout)
        except KeyboardInterrupt:
            self.view.note("ip", "Stopped waiting (Ctrl-C); the VM is deployed and running.", style="dim")
            return getattr(self, "_ip_candidate", None)  # the last address seen, if any (re-read below)

    IP_SETTLE_S = 30  # an address must stay the same this long before it is reported

    @staticmethod
    def _current_ipv4(vm) -> str | None:
        guest = vm.guest
        if guest.ipAddress and ":" not in guest.ipAddress and not guest.ipAddress.startswith("169.254."):
            return guest.ipAddress
        for nic in guest.net or []:
            for addr in nic.ipAddress or []:
                if ":" not in addr and not addr.startswith("169.254."):
                    return addr
        return None

    def _poll_ip(self, vm, timeout: int) -> str | None:
        """Wait for an IPv4 address that stays the same for IP_SETTLE_S seconds. A freshly booted cloud image
        often gets one DHCP lease early in boot and another once cloud-init has set the hostname and the
        network service restarts (seen on Ubuntu 26.04: .213 first, then .214); reporting the first one sent
        users to an address nobody answers on."""
        start = time.monotonic()
        seen, seen_at = None, 0.0
        while time.monotonic() - start < timeout:
            ip = self._current_ipv4(vm)
            now = time.monotonic()
            if ip and ip != seen:
                if seen:
                    log.info("Guest IP changed from %s to %s while waiting for it to settle", seen, ip)
                seen, seen_at = ip, now
                self._ip_candidate = seen
            if seen and now - seen_at >= self.IP_SETTLE_S:
                return seen
            elapsed = int(now - start)
            if seen:
                self.view.update("ip", f"{seen} reported; checking it stays the same "
                                       f"({wait_text(int(now - seen_at), self.IP_SETTLE_S)}; "
                                       "Ctrl-C to stop waiting)", fraction=min(0.95, elapsed / timeout))
                time.sleep(3)
                continue
            guest = vm.guest
            self.view.update("ip", f"waiting for VMware Tools ({wait_text(elapsed, timeout)}, tools: "
                                   f"{guest.toolsRunningStatus}; Ctrl-C to stop waiting)",
                             fraction=min(0.95, elapsed / timeout))
            time.sleep(3)
        return seen  # may still change; the final check below reads it again

    def _annotation(self) -> str:
        # A local image by its file name only: the full path (user name, folders) would be readable by everyone who
        # can see the VM in vCenter. The SHA-256 identifies the file.
        img = self.image
        image = f"{img.path.name} (local file)" if img.source_kind == "local" and img.path else img.display
        return vmnotes.build(self.m.vm.notes, image, img.sha256)

    def _console_url(self, vm) -> str:
        prof = self.o.profile
        host = prof.url_host if prof.port == 443 else prof.endpoint  # IPv6 in [brackets], with or without a port
        if self.conn.is_vcenter:
            # vSphere Client deep link to the VM summary page (unverified URL format; the tool also prints the
            # VM name so it can be found manually).
            uuid = self.conn.about.instanceUuid
            return f"https://{host}/ui/app/vm;nav=v/urn:vmomi:VirtualMachine:{vm._moId}:{uuid}/summary"
        return f"https://{host}/ui/#/host/vms/{vm._moId}"

    # ================================================================================== cleanup
    def _destroy(self, vm, what: str) -> None:
        from .access import delete_vm

        try:
            delete_vm(vm, what)  # powers it off first; logged there
        except Exception as e:  # noqa: BLE001
            raise DeploymentError(f"Could not delete {what}: {e}") from e

    IMPORT_ABORT_WAIT_S = 60  # how long vCenter gets to remove an aborted import's VM before vmdeploy deletes it

    def _confirm_import_removed(self, vm) -> None:
        """After an aborted import vCenter deletes the partial VM itself; check it did, and delete it if not."""
        name = getattr(self.plan, "name", "the VM")
        deadline = time.monotonic() + self.IMPORT_ABORT_WAIT_S
        with console.status(f"Waiting for vCenter to remove the partially created VM '{name}'..."):
            while time.monotonic() < deadline:
                if _vm_gone(vm):
                    folder = self._delete_import_folder()
                    if folder == "failed":
                        console.print(f"[yellow]The upload was stopped and vCenter removed the partially created VM "
                                      f"'{name}', but its folder {esc(self.vm_dir)} could not be deleted. Delete it in "
                                      "the vSphere Client (datastore Files tab).[/]")
                    else:
                        console.print(f"[green]The upload was stopped and the partially created VM '{name}' was "
                                      "removed" + (" (vCenter removed the VM; vmdeploy deleted its folder)"
                                                   if folder == "deleted" else "") + ". Nothing is left behind.")
                    return
                time.sleep(2)
        log.warning("vCenter did not remove %s after the aborted import; deleting it", name)
        try:
            self._destroy(vm, f"partially created VM '{name}'")
            console.print(f"[green]Removed the partially created VM '{name}'.")
        except BaseException as e:  # noqa: BLE001 - never mask the original failure
            console.print(f"[red]Could not remove '{name}' automatically: {e}. Remove it with `vmdeploy destroy "
                          f"{name}`.")

    # The host can hold the half-written disk open for minutes after an abort (seen in the lab: ~2.5 min for a
    # 300 GB ISE disk), so the folder delete is retried this long. A second Ctrl+C skips the wait.
    IMPORT_FOLDER_RETRY_S = 300

    def _delete_import_folder(self) -> str:
        """vCenter unregisters an aborted import's VM but leaves its folder on the datastore. That folder was made by
        this import (vCenter picks a new folder name if one already exists), so it is deleted. Right after the abort
        the host may still hold its files (CannotDeleteFile), so the delete is retried for a while.
        Returns "deleted", "none" (no folder left) or "failed"."""
        if not self.vm_dir or self.plan is None:
            return "none"
        try:
            ds_name, path = isolib.split(self.vm_dir)
        except ValueError:
            return "none"
        if not path or "/" in path.strip("/"):
            return "none"  # only a top-level VM folder, never a datastore root or anything deeper
        base = path.strip("/")
        if not self._folder_exists(ds_name, base):
            return "none"
        deadline = time.monotonic() + self.IMPORT_FOLDER_RETRY_S
        try:
            with console.status(f"Deleting the folder {esc(self.vm_dir)}: the host may take a few minutes to release "
                                "the disk (Ctrl+C to skip and delete it yourself later)..."):
                return self._retry_folder_delete(ds_name, base, deadline)
        except KeyboardInterrupt:
            log.warning("folder delete of %s skipped by Ctrl+C", self.vm_dir)
            return "failed"

    def _retry_folder_delete(self, ds_name: str, base: str, deadline: float) -> str:
        last = None
        while True:
            try:
                wait_task(self.conn.content.fileManager.DeleteDatastoreFile_Task(name=self.vm_dir,
                                                                                 datacenter=self.plan.dc.obj),
                          what="Delete the aborted import's folder")
                return "deleted"
            except Exception as e:  # noqa: BLE001 - retried, then reported; never masks the cancel
                last = e
                if not self._folder_exists(ds_name, base):
                    return "deleted"  # gone after all (deleted by the host or vCenter meanwhile)
                if time.monotonic() >= deadline:
                    break
                time.sleep(5)
        log.warning("could not delete %s after the aborted import: %s", self.vm_dir, last)
        return "failed"

    def _folder_exists(self, ds_name: str, name: str) -> bool:
        spec = vim.host.DatastoreBrowser.SearchSpec(matchPattern=[name])
        try:
            res = wait_task(self.plan.datastore.obj.browser.SearchDatastore_Task(datastorePath=f"[{ds_name}]",
                                                                                 searchSpec=spec), what="search")
            return any(f.path.rstrip("/") == name for f in (res.file if res else None) or [])
        except Exception:  # noqa: BLE001
            return False

    def _cleanup_after_failure(self, exc: BaseException) -> None:
        if self.aborted_vm is not None and self.conn is not None:
            self._confirm_import_removed(self.aborted_vm)
            return
        if not (self.created and self.vm is not None and self.conn is not None):
            return
        name = getattr(self.plan, "name", "the VM")
        if self.vm_ready:
            console.print(f"[yellow]'{name}' was fully created before the failure, so it has been kept. Review it in "
                          "vCenter, or remove it with `vmdeploy destroy`.[/]")
            return
        try:
            keep = False
            if self.p.interactive and not isinstance(exc, KeyboardInterrupt):
                keep = not self.p.confirm(f"The deployment failed after '{name}' was created. Delete the partially "
                                          "created VM?", default=True)
            elif self.p.interactive:
                keep = not self.p.confirm(f"Cancelled. Delete the partially created VM '{name}'?", default=True)
            if keep:
                console.print(f"[yellow]Left '{name}' in place for troubleshooting.")
                return
            self._destroy(self.vm, f"partially created VM '{name}'")
            console.print(f"[green]Removed the partially created VM '{name}'.")
        except BaseException as e:  # noqa: BLE001 - never mask the original failure
            log.warning("cleanup failed: %s", e)
            console.print(f"[red]Could not remove '{name}' automatically: {e}. Remove it manually.")


def _on_standalone_host(plan) -> bool:
    """vCenter: the VM goes to a host that is not in a cluster."""
    return getattr(plan, "cluster", None) is None and plan.host is not None and not plan.host.cluster


def _needs_cluster_reason(plan, provider: str | None) -> str:
    why = "Windows 11 needs a virtual TPM" if isolib.needs_vtpm(plan.guest_id) else "A virtual TPM was requested"
    what = f"the Native Key Provider '{provider}'" if provider else "a Native Key Provider"
    return (f"{why}, and its key would come from {what}, which vCenter only supports on hosts in a cluster. "
            f"Host {plan.host.name} is not in a cluster.")


def _needs_cluster_hint(plan) -> str:
    in_cluster = sorted(h.name for h in plan.dc.hosts.values() if h.cluster and h.usable)
    where = (f"Choose a host that is in a cluster ({', '.join(in_cluster)}), or put this host in one."
             if in_cluster else "No host in this datacenter is in a cluster yet, so this host has to be put in one first.")
    return f"{crypto.CLUSTER_RULE} {where} {crypto.CLUSTER_FIX}"


def _rejected_security(net, hosts) -> list[str]:
    """Which of promiscuous mode / forged transmits / MAC changes the portgroup rejects."""
    names = {"allowPromiscuous": "promiscuous mode", "forgedTransmits": "forged transmits", "macChanges": "MAC changes"}
    if net.kind == "dvpg":
        pol = net.obj.config.defaultPortConfig.securityPolicy
        return [label for key, label in names.items() if getattr(getattr(pol, key, None), "value", True) is False]
    out: set[str] = set()
    for host in hosts:
        for pg in host.config.network.portgroup or []:
            if pg.spec.name == net.name:
                sec = pg.computedPolicy.security
                out |= {label for key, label in names.items() if getattr(sec, key, True) is False}
    return [label for label in names.values() if label in out]


def check_local_space(folder: Path, needed: int, what: str) -> None:
    """Stop before a large read into this computer's cache if the disk is too full (keeps 1 GB spare)."""
    import shutil

    try:
        free = shutil.disk_usage(folder).free
    except OSError:
        return
    if free < needed + GiB:
        raise PreflightError(
            f"Not enough free space on this computer to {what}: it needs {human_size(needed)} (+1 GB spare) in "
            f"{folder}, but only {human_size(free)} is free. Nothing was changed in vCenter.",
            hint="Free some space (`vmdeploy images clear-cache` removes earlier downloads), or point the cache at "
                 "a bigger drive with the VMDEPLOY_CACHE_DIR environment variable.")


def _vm_gone(vm) -> bool:
    try:
        vm.name  # noqa: B018 - reading any property fails once the VM no longer exists
        return False
    except vmodl.fault.ManagedObjectNotFound:  # (a vmodl fault, not vim.fault)
        return True
    except Exception:  # noqa: BLE001 - e.g. a VM being deleted; treat as still there
        return False


def _sample_offsets(size: int) -> tuple[int, list[int]]:
    """(piece size, offsets) of the Deployment.SAMPLES pieces compared to tell whether two files of `size` bytes
    are the same: the first, the last and evenly between, 1 MiB each. One rule for every comparison."""
    n = Deployment.SAMPLES
    piece = min(GiB // 1024, size)
    return piece, sorted({min(size - piece, size * i // (n - 1)) for i in range(n)})


def _offer_iso_copy(dep: Deployment, cand, size: int, same: list, ours: dict[str, bool], *, sampled: bool) -> None:
    """Ask once whether to use `cand` instead of uploading the ISO. Yes: it is used (its full SHA-256 is checked
    first). No: that file is not used, here or at the upload step; vmdeploy's other earlier uploads still are, once
    their full SHA-256 matches, otherwise the ISO is uploaded. The question says which."""
    plan, img = dep.plan, dep.image
    here = _iso_in_place(plan, cand)
    how = "used where it is" if here else f"copied by vCenter to {plan.datastore.name}, host to host"
    where = cand.label().split(" › ", 1)[0]
    others = any(ours[i.full] and i.full != cand.full and i.full not in plan.iso_rejected for i in same)
    otherwise = ("an earlier upload in vmdeploy-iso/ is used if its full SHA-256 matches, otherwise the ISO is "
                 "uploaded from this computer" if others else "the ISO is uploaded from this computer")
    said = "Sampled contents match." if sampled else "Its contents could not be compared."
    given = dep.m.image.reuse_datastore_copy
    previous, answers = getattr(dep.p, "previous", None), getattr(dep.p, "answers", None)
    if previous is not None and previous.get("_iso_copy_offered") != cand.full:
        # "Change my answers": an earlier answer about another file is not this file's default ("No" = not that file)
        previous.pop("image.reuse_datastore_copy", None)
    if answers is not None:
        answers["_iso_copy_offered"] = cand.full
    with dep.p.section("ISO already on a datastore"):
        use = dep.p.confirm(
            f"{img.path.name} is already on {cand.full}, seen by {where}. {said} Use it instead of uploading "
            f"{human_size(size)} from this computer? It would be {how}, after a full SHA-256 check (read once, "
            f"nothing stored). If not, {otherwise}.",
            default=True, assume=True if given is None else given, field_name="image.reuse_datastore_copy")
        checked = "contents match (sampled)" if sampled else "contents not compared; checked in full first"
        dep.p.record("ISO", f"{cand.full} ({checked}; {how})" if use else f"not {cand.full}: {otherwise}")
    if not use:
        plan.iso_rejected.add(cand.full)  # this file only: not used here or at the upload step
        return
    if here:
        plan.iso_datastore_path = cand.full
    else:
        plan.iso_copy_from = cand.full
        # the image's own name: a copy of an earlier '-2' upload is not '-2' again (nor '-2-2' if taken), which
        # later runs would not recognise as a copy of this image
        plan.iso_datastore_path = isolib.copy_target(plan.datastore.name, img.path.name)
    plan.iso_found_on_datastore = True


def _iso_in_place(plan, i) -> bool:
    """Can the VM's host(s) use this datastore ISO where it is (no host-to-host copy)? Always on the VM's own
    datastore: the VM only runs on hosts that see it (even in a cluster where not every host mounts it)."""
    if plan.datastore is not None and i.datastore == plan.datastore.name:
        return True
    return plan.host_names <= i.hosts if plan.host_names else True


def _iso_rank(plan, i, ours: bool) -> tuple:
    """Order of preference for an ISO already on a datastore, the same before the review and at the upload step:
    usable where it is, then vmdeploy's own earlier uploads, then on the VM's own datastore."""
    return not _iso_in_place(plan, i), not ours, i.datastore != plan.datastore.name


def _inventory_path(entity, root) -> str:
    """Datacenter path for datastore HTTP access (dcPath); datacenters may sit inside folders."""
    parts = []
    obj = entity
    while obj is not None and obj._moId != root._moId and len(parts) < 32:
        parts.append(obj.name)
        obj = obj.parent
    return "/".join(reversed(parts))


def vmodl_fault(message: str):
    from pyVmomi import vmodl

    return vmodl.MethodFault(msg=message[:500])


def _is_pos_float(s: str) -> bool:
    try:
        return float(s) > 0
    except ValueError:
        return False

