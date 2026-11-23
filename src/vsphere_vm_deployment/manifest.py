"""Deployment manifest (YAML) schema.

Every field is optional: anything the manifest leaves out is read from the image (OVA/OVF descriptor) or
asked for interactively. In `--yes` mode a missing value stops the run with the name of the field to set.
Unknown keys are rejected so typos are caught before anything is deployed.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .errors import ConfigError

VM_NAME_RE = re.compile(r"^[^/\\%]{1,80}$")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Provisioning(StrEnum):
    THIN = "thin"
    THICK = "thick"  # lazy-zeroed
    EAGER = "eager-zeroed"


class Firmware(StrEnum):
    EFI = "efi"
    BIOS = "bios"


class ImageSpec(Strict):
    local: str | None = None
    url: str | None = None
    preset: str | None = None
    datastore_iso: str | None = None  # kept for compatibility; same as `datastore`
    datastore: str | None = None  # "[datastore1] folder/file.iso" or ".ova" already on a datastore
    sha256: str | None = None
    # If vCenter cannot copy a datastore ISO host to host: read it through this computer and upload it instead.
    # Unset: asked (yes in --yes mode).
    fallback_via_pc: bool | None = None
    # A local or downloaded ISO that is already on a datastore (same name and size, and sampled content matches)
    # is offered for use from there instead of being uploaded; its full SHA-256 is checked before the VM uses
    # it. Unset: asked (yes in --yes mode). true: also a copy whose content could not be sampled (still checked
    # in full). false: always upload (no datastore copy is used).
    reuse_datastore_copy: bool | None = None

    @model_validator(mode="after")
    def _one_source(self):
        given = [k for k in ("local", "url", "preset", "datastore_iso", "datastore") if getattr(self, k)]
        if len(given) > 1:
            raise ValueError(f"image: choose one source, got {', '.join(given)}")
        if self.sha256 is not None:
            from .errors import ConfigError
            from .transfer import check_sha256  # the same rule as --sha256, in the canonical form

            try:
                self.sha256 = check_sha256(self.sha256, "image.sha256")
            except ConfigError as e:
                raise ValueError(e.message) from None
        return self

    @property
    def kind(self) -> str | None:
        for k in ("local", "url", "preset", "datastore_iso", "datastore"):
            if getattr(self, k):
                return "datastore" if k == "datastore_iso" else k
        return None

    @property
    def value(self) -> str | None:
        if self.kind == "datastore":
            return self.datastore or self.datastore_iso
        return getattr(self, self.kind) if self.kind else None


class Placement(Strict):
    datacenter: str | None = None
    cluster: str | None = None
    host: str | None = None  # omit with a DRS cluster to let DRS choose
    resource_pool: str | None = None
    folder: str | None = None  # e.g. "/Lab/Servers"
    datastore: str | None = None
    storage_policy: str | None = None  # reserved for vSAN / SPBM policies (planned)

    @field_validator("storage_policy")
    @classmethod
    def _not_yet(cls, v):
        """Accepted by the schema but not implemented: refuse it rather than silently ignore it (code audit)."""
        if v is not None:
            raise ValueError("choosing a storage policy is not supported yet; VMs get the datastore's default "
                             "policy (README: Known limitations). Remove this key.")
        return v


class ExtraDisk(Strict):
    size_gb: int = Field(..., ge=1)
    provisioning: Provisioning | None = None


class Resources(Strict):
    cpu: int | None = Field(None, ge=1, le=768)
    cores_per_socket: int | None = Field(None, ge=1)
    memory_gb: float | None = Field(None, gt=0)
    disk_gb: int | None = Field(None, ge=1, description="Size of the primary disk; OVA disks are only ever grown")
    disk_provisioning: Provisioning | None = None
    extra_disks: list[ExtraDisk] = Field(default_factory=list, max_length=14)  # free units on one controller


class Hardware(Strict):
    guest_os: str | None = None  # vSphere guestId, e.g. ubuntu64Guest (ISO deployments)
    firmware: Firmware | None = None
    secure_boot: bool | None = None
    vtpm: bool | None = None  # virtual TPM 2.0 (needs a key provider in vCenter); Windows 11 always gets one
    # Expose hardware-assisted virtualisation to the guest (nested VMs: EVE-NG, ESXi, Proxmox). Unset: asked for
    # ISO installs (suggested when the file name looks like a hypervisor); images recognised as one are asked too.
    nested_virtualization: bool | None = None
    # Expose IOMMU to the guest (vIOMMU; needs UEFI). Unset: on when the vendor asks for it (EVE-NG) together with
    # nested virtualisation.
    iommu: bool | None = None
    # VM compatibility: keep | default | newest | vmx-NN. Unset: asked (default = the administrator's cluster or
    # datacenter policy if set; otherwise upgrade for presets/ISO installs, keep for vendor appliances).
    hardware_version: str | None = None


class NetworkSpec(Strict):
    portgroup: str | None = None
    ovf_network: str | None = None  # which network inside the OVA this maps to (defaults to order)
    adapter: str | None = None  # vmxnet3 | e1000e | e1000; default vmxnet3 (e1000e for Windows ISO installs)

    @field_validator("adapter")
    @classmethod
    def _known_adapter(cls, v):
        """Checked when the manifest is read, not after an upload: an unknown type used to fail at VM creation."""
        if v is None:
            return v
        v = v.strip().lower()
        if v not in ("vmxnet3", "e1000e", "e1000"):
            raise ValueError("must be vmxnet3, e1000e or e1000")
        return v


class OvfSpec(Strict):
    deployment_option: str | None = None
    properties: dict[str, str] = Field(default_factory=dict)
    accept_eula: bool = False  # only honoured in --yes mode; interactive runs always show the EULA

    @field_validator("properties", mode="before")
    @classmethod
    def _as_text(cls, v):
        return _properties_as_text(v)


def _properties_as_text(v):
    """YAML turns `true` and `22` into a boolean and a number; appliance settings are text to vCenter."""
    if isinstance(v, dict):
        return {k: (("true" if x else "false") if isinstance(x, bool) else
                    str(x) if isinstance(x, int | float) else x) for k, x in v.items()}
    return v


class GuestNetwork(Strict):
    mode: str = "dhcp"  # dhcp | static
    address: str | None = None  # CIDR, e.g. 192.0.2.50/24
    gateway: str | None = None
    dns: list[str] = Field(default_factory=list)
    search: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self):
        if self.mode not in ("dhcp", "static"):
            raise ValueError("guest.network.mode must be 'dhcp' or 'static'")
        from .netcheck import address_error, dns_error, gateway_error

        if self.mode == "static":
            if not self.address:
                raise ValueError("guest.network.address (CIDR) is required for static addressing")
            if problem := address_error(self.address):
                raise ValueError(f"guest.network.address: {problem}")
            if self.gateway and (problem := gateway_error(self.gateway, self.address)):
                raise ValueError(f"guest.network.gateway: {problem}")
        if problem := dns_error(self.dns):
            raise ValueError(f"guest.network.dns: {problem}")
        return self


class GuestSpec(Strict):
    """First-boot customisation through cloud-init (images that support it)."""
    enabled: bool | None = None  # default: on for presets, ask for other cloud-init capable images
    hostname: str | None = None
    username: str | None = None
    password_hash: str | None = None  # SHA-512 crypt hash ($6$...), never a plain password
    ssh_authorized_keys: list[str] = Field(default_factory=list)
    timezone: str | None = None
    ntp_servers: list[str] = Field(default_factory=list)
    network: GuestNetwork | None = None
    # With DHCP: how the guest identifies itself to the DHCP server. "mac": by its MAC address, set before the first
    # boot (DHCP reservations by MAC then work, and a fresh Ubuntu image does not ask under a second identity).
    # "image": the image's default (Ubuntu: an identifier derived from the machine id, not the MAC).
    dhcp_identifier: str = "mac"

    @field_validator("dhcp_identifier")
    @classmethod
    def _dhcp_identifier(cls, v: str) -> str:
        if v not in ("mac", "image"):
            raise ValueError("guest.dhcp_identifier must be 'mac' or 'image'")
        return v

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, v: str | None) -> str | None:
        if v and not re.fullmatch(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)", v):
            raise ValueError("guest.hostname must be a single DNS label (letters, digits, hyphens)")
        return v

    @field_validator("password_hash")
    @classmethod
    def _hash(cls, v: str | None) -> str | None:
        if v and not v.startswith("$"):
            raise ValueError("guest.password_hash must be a crypt hash (e.g. from `mkpasswd -m sha-512`), "
                             "never a plain-text password")
        return v


class PostDeploy(Strict):
    power_on: bool = True
    wait_for_ip: bool = True
    wait_timeout_s: int = 300  # DHCP + VMware Tools normally report within 1-2 minutes
    snapshot: bool | None = None  # "clean baseline" snapshot after first boot


class VmSpec(Strict):
    name: str | None = None
    notes: str | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        if v is not None and not VM_NAME_RE.fullmatch(v):
            raise ValueError("vm.name must be 1-80 characters and may not contain / \\ or %")
        return v


# ------------------------------------------------------------------------------------------------ batch
# One image, the same settings, many targets (docs/design/batch-deployment.md). The rest of the manifest holds the
# settings every VM shares; `batch:` says where the VMs go and what differs between them.

class BatchOvf(Strict):
    """Per-target OVF property overrides. Values may use the batch placeholders ({name}, {n}, {address}, ...)."""
    properties: dict[str, str] = Field(default_factory=dict)

    @field_validator("properties", mode="before")
    @classmethod
    def _as_text(cls, v):
        return _properties_as_text(v)


class BatchTarget(Strict):
    """One selector: a host, every host of a cluster or host folder, hosts matching a name pattern, a DRS cluster,
    or a resource pool (where hosts are hidden, e.g. hosted VMware clouds)."""
    host: str | None = None
    cluster: str | None = None
    folder: str | None = None  # a host folder, e.g. "/Lab/Hosts"
    hosts_matching: str | None = None  # shell-style pattern, e.g. "esx-east-*"
    resource_pool: str | None = None
    drs: bool = False  # with `cluster:` (or a resource pool in a DRS cluster): DRS places each VM
    datastore: str | None = None  # a name, or "auto" (the usable datastore with the most free space)
    count: int | None = Field(None, ge=1, le=1000)
    ovf: BatchOvf | None = None

    @model_validator(mode="after")
    def _one_selector(self):
        given = [k for k in ("host", "cluster", "folder", "hosts_matching") if getattr(self, k)]
        if len(given) > 1:
            raise ValueError(f"batch.targets: one of host, cluster, folder or hosts_matching per entry, got "
                             f"{', '.join(given)}")
        if not given and not self.resource_pool:
            raise ValueError("batch.targets: each entry needs host, cluster, folder, hosts_matching or resource_pool")
        if self.drs and not (self.cluster or self.resource_pool):
            raise ValueError("batch.targets: drs: true needs a cluster (or a resource pool in a DRS cluster)")
        return self


class BatchAddresses(Strict):
    """Guest IPv4 addresses for the batch's VMs (through cloud-init, or OVF properties that use {address})."""
    mode: str = "dhcp"  # dhcp (nothing written: the image's default, normally DHCP) | static
    range: str | None = None  # "192.0.2.50-192.0.2.69" (or "192.0.2.50-69")
    addresses: list[str] = Field(default_factory=list, alias="list")  # one per VM, in VM order
    prefix: int | None = Field(None, ge=1, le=32)  # e.g. 24; may also be given as address/prefix in `list`
    gateway: str | None = None
    dns: list[str] = Field(default_factory=list)
    search: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    @model_validator(mode="after")
    def _check(self):
        if self.mode not in ("dhcp", "static"):
            raise ValueError("batch.addresses.mode must be 'dhcp' or 'static'")
        if self.mode == "static" and bool(self.range) == bool(self.addresses):
            raise ValueError("batch.addresses: static addressing needs either `range` or `list` (one of them)")
        if self.mode == "dhcp" and (self.range or self.addresses or self.gateway):
            raise ValueError("batch.addresses: range, list and gateway are only used with mode: static")
        from .netcheck import dns_error

        if problem := dns_error(self.dns):
            raise ValueError(f"batch.addresses.dns: {problem}")
        return self


class BatchParallel(Strict):
    vms: int = Field(4, ge=1, le=64)  # VMs being built at the same time
    uploads: int = Field(2, ge=1, le=32)  # uploads from this computer at the same time
    per_host: int = Field(2, ge=1, le=64)  # VMs being built on one host at the same time


class BatchSpec(Strict):
    name: str | None = None  # VM name pattern, e.g. "web-{n:02}"
    names: list[str] = Field(default_factory=list)  # or exactly one name per VM
    start: int = Field(1, ge=0)  # the first {n}
    name_conflict: str = "skip"  # skip | next-free | replace
    hostname: str | None = None  # pattern, a fixed name, or "skip" (the image's own). Default: "{name}"
    distribution: str = "per_host"  # per_host | total
    count: int | None = Field(None, ge=1, le=1000)  # VMs per host (per_host, default 1) or in total (total)
    targets: list[BatchTarget] = Field(default_factory=list)
    addresses: BatchAddresses | None = None
    parallel: BatchParallel = Field(default_factory=BatchParallel)
    on_check_failure: str = "skip"  # skip | cancel (--yes; interactive runs ask)
    on_failure: str = "continue"  # continue | stop
    keep_failed: bool = False  # keep a VM that failed half-way, for troubleshooting

    @model_validator(mode="after")
    def _check(self):
        choices = {"name_conflict": ("skip", "next-free", "replace"), "distribution": ("per_host", "total"),
                   "on_check_failure": ("skip", "cancel"), "on_failure": ("continue", "stop")}
        for key, allowed in choices.items():
            if getattr(self, key) not in allowed:
                raise ValueError(f"batch.{key} must be one of: {', '.join(allowed)}")
        if self.name and self.names:
            raise ValueError("batch: give either `name` (a pattern) or `names` (a list), not both")
        for n in self.names:
            if not VM_NAME_RE.fullmatch(n):
                raise ValueError(f"batch.names: '{n}' must be 1-80 characters without / \\ or %")
        if len(set(self.names)) != len(self.names):
            raise ValueError("batch.names: the names must be different from each other")
        from .batchplan import check_pattern

        try:
            if self.name:
                check_pattern(self.name, "batch.name")
            if self.hostname and self.hostname != "skip":
                check_pattern(self.hostname, "batch.hostname", hostname=True)
        except ConfigError as e:
            raise ValueError(e.message) from None
        return self


class Manifest(Strict):
    profile: str | None = None
    vm: VmSpec = Field(default_factory=VmSpec)
    image: ImageSpec = Field(default_factory=ImageSpec)
    placement: Placement = Field(default_factory=Placement)
    resources: Resources = Field(default_factory=Resources)
    hardware: Hardware = Field(default_factory=Hardware)
    networks: list[NetworkSpec] = Field(default_factory=list)
    ovf: OvfSpec = Field(default_factory=OvfSpec)
    guest: GuestSpec = Field(default_factory=GuestSpec)
    post_deploy: PostDeploy = Field(default_factory=PostDeploy)
    batch: BatchSpec | None = None

    @model_validator(mode="after")
    def _batch_owns_placement(self):
        """With `batch:` each VM's name, host and datastore come from the batch, and its hostname and address
        from the batch patterns: the single-VM keys would be ambiguous, so they are refused, not ignored."""
        if self.batch is None:
            return self
        clashes = [key for key, value in (
            ("vm.name", self.vm.name), ("placement.host", self.placement.host),
            ("placement.cluster", self.placement.cluster), ("placement.datastore", self.placement.datastore),
            ("guest.hostname", self.guest.hostname), ("guest.network", self.guest.network)) if value]
        if clashes:
            raise ValueError(f"with batch: remove {', '.join(clashes)} (use batch.name, batch.targets, "
                             "batch.hostname and batch.addresses instead)")
        return self


def load_manifest(path: str | Path | None) -> Manifest:
    if not path:
        return Manifest()
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"Manifest not found: {p}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"{p} is not valid YAML: {e}") from e
    try:
        return Manifest.model_validate(data)
    except ValidationError as e:
        lines = []
        for err in e.errors():
            loc = ".".join(str(x) for x in err["loc"])
            lines.append(f"  {loc}: {err['msg']}")
        raise ConfigError(f"{p} has {len(lines)} problem(s):\n" + "\n".join(lines)) from None
