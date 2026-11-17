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
