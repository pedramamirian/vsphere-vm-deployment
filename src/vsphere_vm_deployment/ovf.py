"""Reading OVA / OVF packages locally: descriptor parsing, manifest (checksum) verification, member access.

Parsing locally lets the tool show what an image contains (sizing, networks, properties, deployment
options, EULA) *before* anything is created in vCenter. vCenter's own OvfManager.CreateImportSpec is still
the authority at import time; its warnings and errors are surfaced to the user.

Structure follows the DMTF OVF specification (DSP0243): References, DiskSection, NetworkSection,
DeploymentOptionSection, and per VirtualSystem: ProductSection, EulaSection, OperatingSystemSection,
VirtualHardwareSection.
"""

from __future__ import annotations

import hashlib
import re
import tarfile
import xml.etree.ElementTree as ET  # noqa: S405 - descriptor parsed with defusing below
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from .errors import ChecksumMismatch, ImageError

CHUNK = 1024 * 1024


def _ln(tag: str) -> str:
    """Local name of a namespaced XML tag/attribute."""
    return tag.rsplit("}", 1)[-1]


def _attr(el: ET.Element, name: str, default: str | None = None) -> str | None:
    for k, v in el.attrib.items():
        if _ln(k) == name:
            return v
    return default


def _children(el: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in el if _ln(c.tag) == name]


def _child(el: ET.Element, name: str) -> ET.Element | None:
    for c in el:
        if _ln(c.tag) == name:
            return c
    return None


def _text(el: ET.Element | None, name: str, default: str = "") -> str:
    if el is None:
        return default
    c = _child(el, name)
    return (c.text or "").strip() if c is not None and c.text else default


_UNIT_RE = re.compile(r"byte\s*\*\s*2\s*\^\s*(\d+)", re.I)


def to_bytes(value: str | int | None, units: str | None) -> int:
    n = int(value or 0)
    if not units:
        return n
    m = _UNIT_RE.search(units)
    if m:
        return n * (2 ** int(m.group(1)))
    u = units.lower()
    for word, mult in (("kilo", 2**10), ("mega", 2**20), ("giga", 2**30), ("tera", 2**40)):
        if word in u:
            return n * mult
    return n


@dataclass
class OvfDisk:
    disk_id: str
    capacity_bytes: int
    file_href: str | None
    populated_bytes: int | None = None


@dataclass
class OvfProperty:
    key: str  # fully qualified id used for propertyMapping
    type: str
    default: str
    label: str
    description: str
    user_configurable: bool
    password: bool
    qualifiers: str = ""


_TRUE = {"true", "yes", "y", "1", "on"}
_FALSE = {"false", "no", "n", "0", "off"}
_INT_RANGES = {"uint8": (0, 2**8 - 1), "sint8": (-(2**7), 2**7 - 1), "uint16": (0, 2**16 - 1),
               "sint16": (-(2**15), 2**15 - 1), "uint32": (0, 2**32 - 1), "sint32": (-(2**31), 2**31 - 1),
               "uint64": (0, 2**64 - 1), "sint64": (-(2**63), 2**63 - 1), "int": (-(2**31), 2**31 - 1)}


def is_boolean(prop: OvfProperty) -> bool:
    return prop.type.lower() == "boolean"


def as_bool(value: object) -> bool | None:
    """'true' / 'False' / 'yes' / 1 ... -> bool; None if it is not a yes/no value."""
    s = str(value).strip().lower()
    return True if s in _TRUE else False if s in _FALSE else None


def value_map(prop: OvfProperty) -> list[str]:
    """Allowed values from a qualifier such as ValueMap{"small","large"} (empty: any value)."""
    m = re.search(r"ValueMap\{([^}]*)\}", prop.qualifiers or "")
    return [v.strip().strip('"') for v in m.group(1).split(",") if v.strip()] if m else []


def check_value(prop: OvfProperty, value: str) -> str | None:
    """Why `value` is not valid for the property, or None. Empty is allowed (vCenter decides whether a property
    must be set). Mirrors what vCenter checks at import, so mistakes are caught while answering."""
    value = str(value).strip()
    if not value:
        return None
    if is_boolean(prop):
        return None if as_bool(value) is not None else "Answer true or false."
    allowed = value_map(prop)
    if allowed and value not in allowed:
        return f"Must be one of: {', '.join(allowed)}."
    rng = _INT_RANGES.get(prop.type.lower())
    if rng:
        try:
            n = int(value)
        except ValueError:
            return "Must be a whole number."
        lo, hi = rng
        m = re.search(r"MinValue\((-?\d+)\)", prop.qualifiers or "")
        lo = int(m.group(1)) if m else lo
        m = re.search(r"MaxValue\((-?\d+)\)", prop.qualifiers or "")
        hi = int(m.group(1)) if m else hi
        if not lo <= n <= hi:
            return f"Must be between {lo} and {hi}."
    m = re.search(r"MinLen\((\d+)\)", prop.qualifiers or "")
    if m and len(value) < int(m.group(1)):
        return f"Must be at least {m.group(1)} characters."
    m = re.search(r"MaxLen\((\d+)\)", prop.qualifiers or "")
    if m and len(value) > int(m.group(1)):
        return f"Must be at most {m.group(1)} characters."
    return None


def vcenter_value(prop: OvfProperty, value: object) -> str:
    """The value as vCenter accepts it. Booleans: vCenter takes 'True' / 'False' and rejects the OVF spelling
    'true' / 'false' that descriptors use for defaults (found with Cisco's Catalyst 8000V OVA)."""
    if is_boolean(prop):
        b = as_bool(value)
        if b is not None:
            return "True" if b else "False"
    return "" if value is None else str(value).strip()


def one_line(text: str) -> str:
    """A description on one line: descriptors wrap their text with newlines and indentation."""
    return " ".join((text or "").split())


@dataclass
class DeploymentOption:
    id: str
    label: str
    description: str
    default: bool


@dataclass
class OvfInfo:
    name: str = ""
    product: str = ""
    vendor: str = ""
    version: str = ""
    os_id: str = ""
    os_type: str = ""  # vmw:osType, e.g. ubuntu64Guest
    firmware: str | None = None
    hardware_version: str | None = None  # vssd:VirtualSystemType, e.g. vmx-10 (highest if several are listed)
    disks: list[OvfDisk] = field(default_factory=list)
    files: list[str] = field(default_factory=list)  # every file the descriptor references (References/File href)
    networks: list[str] = field(default_factory=list)
    properties: list[OvfProperty] = field(default_factory=list)
    deployment_options: list[DeploymentOption] = field(default_factory=list)
    eulas: list[str] = field(default_factory=list)
    _hw_items: list[tuple[set[str] | None, ET.Element]] = field(default_factory=list, repr=False)

    @property
    def default_option(self) -> str | None:
        for d in self.deployment_options:
            if d.default:
                return d.id
        return self.deployment_options[0].id if self.deployment_options else None

    def hardware(self, option: str | None = None) -> dict:
        """CPU / memory / cores for a deployment option (items tagged ovf:configuration apply only there)."""
        option = option or self.default_option
        cpu = mem_mb = cores = None
        # Items for every size first, then the chosen size's own items, which take priority whatever their order.
        ordered = [x for x in self._hw_items if x[0] is None] + [x for x in self._hw_items if x[0] is not None]
        for configs, item in ordered:
            if configs is not None and option not in configs:
                continue
            rtype = _text(item, "ResourceType")
            if rtype == "3":
                cpu = int(_text(item, "VirtualQuantity", "1") or 1)
                cps = _child(item, "CoresPerSocket")
                if cps is not None and cps.text:
                    cores = int(cps.text)
            elif rtype == "4":
                mem_mb = to_bytes(_text(item, "VirtualQuantity", "0"), _text(item, "AllocationUnits", "byte * 2^20")) // 2**20
        return {"cpu": cpu, "memory_mb": mem_mb, "cores_per_socket": cores}

    def storage_controllers(self, option: str | None = None) -> set[str]:
        """The kinds of disk controller the VM gets with a deployment option: "scsi", "nvme", "sata", "ide"
        (empty when the descriptor lists none)."""
        option = option or self.default_option
        kinds: set[str] = set()
        for configs, item in self._hw_items:
            if configs is not None and option not in configs:
                continue
            rtype, sub = _text(item, "ResourceType"), _text(item, "ResourceSubType").lower()
            if rtype == "6":
                kinds.add("scsi")
            elif rtype == "5":
                kinds.add("ide")
            elif rtype == "20":  # "other storage": SATA (AHCI) or NVMe, told apart by the subtype
                kinds.add("nvme" if "nvme" in sub else "sata")
        return kinds

    def disks_for(self, option: str | None = None) -> list[OvfDisk]:
        """The disks the VM gets with a deployment option, in descriptor order (disk 1 first). An appliance can
        declare many disks and let each size pick some: vCenter's OVA has 34 disk definitions and 269 disk items
        tagged per size. Items without ovf:configuration apply to every size."""
        option = option or self.default_option
        by_id = {d.disk_id: d for d in self.disks}
        out = []
        for configs, item in self._hw_items:
            if (configs is not None and option not in configs) or _text(item, "ResourceType") != "17":
                continue
            ref = _text(item, "HostResource").rsplit("/", 1)[-1]
            if ref in by_id:
                out.append(by_id[ref])
        return out or list(self.disks)  # no disk items found: every declared disk

    def option_summary(self, option: str | None = None) -> str:
        """'4 vCPU, 16 GB RAM' for a deployment option (or the default sizing)."""
        hw = self.hardware(option)
        parts = [f"{hw['cpu']} vCPU"] if hw["cpu"] else []
        if hw["memory_mb"]:
            parts.append(f"{hw['memory_mb'] / 1024:g} GB RAM")
        return ", ".join(parts)

    @property
    def has_cloud_init_properties(self) -> bool:
        """Ubuntu cloud images expose `user-data` (and friends) as OVF properties for cloud-init's OVF
        datasource."""
        return any(p.key.split(".")[-1] in ("user-data",) or p.key == "user-data" for p in self.properties)


def _defused_fromstring(text: str) -> ET.Element:
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise ImageError("The OVF descriptor contains a DTD/ENTITY declaration, which is not allowed.")
    return ET.fromstring(text)  # noqa: S314 - DTDs rejected above


def parse_descriptor(text: str) -> OvfInfo:
    try:
        root = _defused_fromstring(text)
    except ET.ParseError as e:
        raise ImageError(f"The OVF descriptor is not valid XML: {e}") from e
    if _ln(root.tag) != "Envelope":
        raise ImageError("Not an OVF descriptor (root element is not <Envelope>).")
    info = OvfInfo()

    files = {}
    refs = _child(root, "References")
    if refs is not None:
        for f in _children(refs, "File"):
            files[_attr(f, "id")] = _attr(f, "href")
    info.files = [h for h in files.values() if h]

    for section in root:
        ln = _ln(section.tag)
        if ln == "DiskSection":
            for d in _children(section, "Disk"):
                populated = _attr(d, "populatedSize")
                info.disks.append(OvfDisk(
                    disk_id=_attr(d, "diskId", ""),
                    capacity_bytes=to_bytes(_attr(d, "capacity"), _attr(d, "capacityAllocationUnits")),
                    file_href=files.get(_attr(d, "fileRef")),
                    populated_bytes=int(populated) if populated and populated.isdigit() else None))
        elif ln == "NetworkSection":
            info.networks = [_attr(n, "name", "") for n in _children(section, "Network")]
        elif ln == "DeploymentOptionSection":
            for c in _children(section, "Configuration"):
                info.deployment_options.append(DeploymentOption(
                    id=_attr(c, "id", ""), label=_text(c, "Label", _attr(c, "id", "")),
                    description=_text(c, "Description"), default=(_attr(c, "default", "false") == "true")))

    vs = _child(root, "VirtualSystem")
    if vs is None:
        vsc = _child(root, "VirtualSystemCollection")
        if vsc is not None:
            raise ImageError("Multi-VM OVF packages (VirtualSystemCollection / vApps) are not supported yet.")
        raise ImageError("The OVF descriptor has no VirtualSystem.")
    info.name = _text(vs, "Name") or _attr(vs, "id", "") or ""
    for section in vs:
        ln = _ln(section.tag)
        if ln == "ProductSection":
            info.product = info.product or _text(section, "Product")
            info.vendor = info.vendor or _text(section, "Vendor")
            info.version = info.version or _text(section, "Version")
            cls = _attr(section, "class", "") or ""
            inst = _attr(section, "instance", "") or ""
            for prop in [p for p in section.iter() if _ln(p.tag) == "Property"]:
                key = _attr(prop, "key", "")
                full = ".".join(x for x in (cls, key, inst) if x)
                info.properties.append(OvfProperty(
                    key=full, type=_attr(prop, "type", "string") or "string",
                    default=_attr(prop, "value", "") or "",
                    label=_text(prop, "Label", key), description=_text(prop, "Description"),
                    user_configurable=(_attr(prop, "userConfigurable", "false") == "true"),
                    password=(_attr(prop, "password", "false") == "true"),
                    qualifiers=_attr(prop, "qualifiers", "") or ""))
        elif ln == "EulaSection":
            lic = _child(section, "License")
            if lic is not None and (lic.text or "").strip():
                info.eulas.append(lic.text.strip())
        elif ln == "OperatingSystemSection":
            info.os_id = _attr(section, "id", "") or ""
            info.os_type = _attr(section, "osType", "") or ""
        elif ln == "VirtualHardwareSection":
            for item in section:
                iln = _ln(item.tag)
                if iln in ("Item", "StorageItem", "EthernetPortItem"):
                    cfg = _attr(item, "configuration")
                    info._hw_items.append((set(cfg.split()) if cfg else None, item))
                elif iln == "Config" and _attr(item, "key") == "firmware":
                    info.firmware = _attr(item, "value")
                elif iln == "System":
                    types = " ".join((c.text or "") for c in item if _ln(c.tag) == "VirtualSystemType")
                    versions = [t for t in types.replace(",", " ").split() if t.startswith("vmx-")]
                    if versions:
                        info.hardware_version = max(versions, key=lambda t: int(t[4:]) if t[4:].isdigit() else 0)
    return info


# --------------------------------------------------------------------------------------- package access
class OvfPackage:
    """An .ova (tar archive) or an .ovf file with its referenced files next to it."""

    def __init__(self, path: Path):
        self.path = Path(path)
        suffix = self.path.suffix.lower()
        if suffix == ".ova":
            self.kind = "ova"
            try:
                self._tar = tarfile.open(self.path, "r:")  # noqa: SIM115 - kept open for streaming members
            except tarfile.TarError as e:
                raise ImageError(f"{self.path.name} is not a valid OVA (tar) archive: {e}") from e
            self._members = {m.name: m for m in self._tar.getmembers() if m.isfile()}
            ovfs = [n for n in self._members if n.lower().endswith(".ovf")]
            if not ovfs:
                raise ImageError(f"{self.path.name} does not contain an .ovf descriptor.")
            self.descriptor_name = ovfs[0]
            self.descriptor = self._tar.extractfile(self._members[self.descriptor_name]).read().decode("utf-8-sig")
            mfs = [n for n in self._members if n.lower().endswith(".mf")]
            self.manifest_text = self._tar.extractfile(self._members[mfs[0]]).read().decode("utf-8-sig") if mfs else None
        elif suffix == ".ovf":
            self.kind = "ovf"
            self._tar = None
            self.descriptor_name = self.path.name
            self.descriptor = self.path.read_text(encoding="utf-8-sig")
            mf = self.path.with_suffix(".mf")
            self.manifest_text = mf.read_text(encoding="utf-8-sig") if mf.exists() else None
            self._members = {}
        else:
            raise ImageError(f"{self.path.name}: expected an .ova or .ovf file.")
        self.info = parse_descriptor(self.descriptor)

    def close(self) -> None:
        if self._tar:
            self._tar.close()

    # .............................................................................................
    def member_size(self, name: str) -> int:
        if self.kind == "ova":
            m = self._find(name)
            return m.size
        return (self.path.parent / name).stat().st_size

    def _find(self, name: str) -> tarfile.TarInfo:
        if name in self._members:
            return self._members[name]
        base = name.rsplit("/", 1)[-1]
        for k, m in self._members.items():
            if k.rsplit("/", 1)[-1] == base:
                return m
        raise ImageError(f"{self.path.name} references '{name}', which is missing from the package.")

    def open_member(self, name: str) -> BinaryIO:
        if self.kind == "ova":
            f = self._tar.extractfile(self._find(name))
            if f is None:
                raise ImageError(f"Cannot read '{name}' from {self.path.name}.")
            return f
        p = (self.path.parent / name).resolve()
        if self.path.parent.resolve() not in p.parents:
            raise ImageError(f"OVF references a file outside its folder: {name}")
        return open(p, "rb")  # noqa: SIM115

    def total_disk_bytes(self) -> int:
        return sum(self.member_size(d.file_href) for d in self.info.disks if d.file_href)

    # ..................................................................................... manifest
    def manifest_entries(self) -> dict[str, tuple[str, str]]:
        """{filename: (algorithm, hexdigest)} from the .mf file, e.g. SHA256(disk1.vmdk)= abc..."""
        out = {}
        for line in (self.manifest_text or "").splitlines():
            m = re.match(r"\s*(SHA1|SHA256|SHA512)\s*\((.+?)\)\s*=\s*([0-9a-fA-F]+)\s*$", line)
            if m:
                out[m.group(2)] = (m.group(1).lower(), m.group(3).lower())
        return out

    def verify_manifest(self, progress: Callable[[int], None] | None = None) -> int:
        """Check every file listed in the .mf against its digest. Returns the number of files verified."""
        entries = self.manifest_entries()
        for name, (algo, expected) in entries.items():
            h = hashlib.new(algo)
            if name == self.descriptor_name and self.kind == "ovf":
                stream: BinaryIO = open(self.path, "rb")  # noqa: SIM115
            else:
                stream = self.open_member(name)
            with stream:
                while chunk := stream.read(CHUNK):
                    h.update(chunk)
                    if progress:
                        progress(len(chunk))
            if h.hexdigest() != expected:
                raise ChecksumMismatch(f"Integrity check failed for '{name}' inside {self.path.name}: "
                                       f"{algo.upper()} does not match the package manifest.",
                                       hint="The image is corrupted or was modified. Re-download it.")
        return len(entries)

    def manifest_bytes(self) -> int:
        total = 0
        for name in self.manifest_entries():
            try:
                total += self.member_size(name)
            except ImageError:
                total += 0
        return total
