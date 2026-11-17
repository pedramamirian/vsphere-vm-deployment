"""Vendor guidance for products vmdeploy recognises, applied the way VMware's and Microsoft's values are for
Windows: the vendor's documented values become the defaults, and going below the vendor's minimum is warned.

Every value here comes from the vendor document named in `source`; nothing is guessed. When a vendor does not
state something (e.g. Cisco does not name a firmware or guest OS for ISE), vmdeploy keeps its normal behaviour.

EVE-NG 7 (Professional, and the free "Freemium" edition, which uses the same ISO; the separate Community Edition
6.x is end-of-life): EVE-NG Professional Cookbook 7.10 (October 2026),
  https://www.eve-ng.net/wp-content/uploads/2026/10/EVE-PE-BOOK-7.10-2026.pdf
  2.1.1 "Minimal Laptop/PC Desktop system requirements", EVE VM: CPU 1/8, RAM 16 GB or more, HDD 120 GB or more
  2.1.2 "Recommended Laptop/PC Desktop system requirements", EVE VM: CPU 1/16, RAM 32 GB or more, HDD 300 GB
  2.1.3 "Virtual Server system requirements", EVE VM: CPU 2/24 (48), dedicated CPU and RAM reservation, RAM 64 GB
        or more, dedicated SSD 800 GB or more; "Expose hardware assisted virtualization" and "Expose IOMMU" ON
  3.2.1.1 "EVE-NG ESXi VM Setup and Settings": guest OS Linux / Ubuntu 64-bit; expose hardware-assisted
        virtualization and IOMMU; "Thick Provisioned eagerly" recommended; adapter VMXNET3; ESXi 8.0 or later:
        firmware EFI with Secure Boot unchecked; vSwitch/portgroup security policy (promiscuous mode, forged
        transmits, MAC changes) set to Accept.

Cisco ISE 3.3, 3.4 and 3.5: Cisco ISE Installation Guide, chapter "Cisco Secured Network Server Series Appliances
and Virtual Machine Requirements":
  3.3 https://www.cisco.com/c/en/us/td/docs/security/ise/3-3/install_guide/b_ise_installationGuide33/b_ise_InstallationGuide33_chapter_2.html
  3.4 https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/install_guide/b_ise_installationGuide34/b_ise_InstallationGuide_chapter_2.html
  3.5 https://www.cisco.com/c/en/us/td/docs/security/ise/3-5/install_guide/b_ise_Installation_Guide_35/g_systemrequirements/r_vmware_appliance_size_recommendations.html
  The OVA's own deployment sizes carry Cisco's "OVA template reservations" table (CPU, memory and the matching
  reservations), so they are used as they are. In addition: "Reserve CPU and memory resources to match the
  required allocation"; "If you decrease the RAM or CPU allocation for a VM, you must reimage Cisco ISE";
  "Cisco ISE does not support VM snapshots"; the 300 GB OVA templates suit dedicated Policy Service / pxGrid
  nodes, 600 GB+ are recommended for Administration or Monitoring nodes; 3.4 and later: "ESXi: Enable Expose
  hardware-assisted virtualization to the guest OS" (section "CPU requirements for hypervisors").
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace


@dataclass(frozen=True)
class Size:
    cpu: int
    memory_mb: int
    disk_gb: int
    label: str  # where the value comes from, e.g. "minimal VM (2.1.1)"


@dataclass(frozen=True)
class Appliance:
    key: str
    name: str  # e.g. "EVE-NG 7"
    vendor: str  # who recommends, in output: "EVE-NG recommends 32 GB"
    source: str  # the document (docs and code only; output stays short)
    url: str
    minimum: Size | None = None
    recommended: Size | None = None
    larger: Size | None = None  # e.g. EVE's "virtual server" size, shown as a hint only
    single_socket: bool = False  # "CPU 1/8": one socket, all cores in it
    guest_os: str | None = None
    firmware: str | None = None
    secure_boot: bool | None = None
    nested_hv: bool | None = None
    iommu: bool | None = None
    adapter: str | None = None
    provisioning: str | None = None  # thin | thick | eager-zeroed
    snapshots_supported: bool = True
    gets_ip_before_setup: bool = True  # False: the guest has no IP until its console setup is done
    portgroup_security: bool = False  # promiscuous mode, forged transmits and MAC changes must be Accept
    notes: tuple[str, ...] = field(default_factory=tuple)


_EVE_URL = "https://www.eve-ng.net/wp-content/uploads/2026/10/EVE-PE-BOOK-7.10-2026.pdf"
EVE_NG_7 = Appliance(
    key="eve-ng-7", name="EVE-NG 7", vendor="EVE-NG",
    source="EVE-NG Professional Cookbook 7.10, sections 2.1 and 3.2.1.1", url=_EVE_URL,
    minimum=Size(8, 16 * 1024, 120, "minimum"),
    recommended=Size(16, 32 * 1024, 300, "recommended"),
    larger=Size(48, 64 * 1024, 800, "dedicated server"),
    single_socket=True, guest_os="ubuntu64Guest", firmware="efi", secure_boot=False, nested_hv=True, iommu=True,
    adapter="vmxnet3", provisioning="eager-zeroed", portgroup_security=True,
    notes=("For a host dedicated to EVE-NG, EVE-NG recommends 48 vCPU, 64 GB RAM and 800 GB SSD, with all CPU "
           "and RAM reserved.",))

_ISE_URLS = {
    3: "https://www.cisco.com/c/en/us/td/docs/security/ise/3-3/install_guide/b_ise_installationGuide33/"
       "b_ise_InstallationGuide33_chapter_2.html",
    4: "https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/install_guide/b_ise_installationGuide34/"
       "b_ise_InstallationGuide_chapter_2.html",
    5: "https://www.cisco.com/c/en/us/td/docs/security/ise/3-5/install_guide/b_ise_Installation_Guide_35/"
       "g_systemrequirements/r_vmware_appliance_size_recommendations.html",
}


def _ise(minor: int) -> Appliance:
    return Appliance(
        key=f"cisco-ise-3.{minor}", name=f"Cisco ISE 3.{minor}", vendor="Cisco",
        source=f"Cisco ISE 3.{minor} Installation Guide, VM requirements", url=_ISE_URLS[minor],
        nested_hv=True if minor >= 4 else None, snapshots_supported=False, gets_ip_before_setup=False,
        notes=("Lowering CPU or RAM later means reimaging ISE.",
               "Cisco recommends 600 GB or more for Administration or Monitoring nodes (300 GB: Policy Service or "
               "pxGrid only).",
               "Shut ISE down with `application stop`, then `halt`, before powering it off."))


_EVE = re.compile(r"(?<![a-z])eve[-_ ]?(ng|pro|ce)(?![a-z])", re.I)
_ISE = re.compile(r"(?<![a-z])(vise|identity[ _-]?services[ _-]?engine)(?![a-z])", re.I)
_ISE_VERSION = re.compile(r"(?<!\d)3\.(\d)\.\d")


def detect(*names: str) -> Appliance | None:
    """The product an image is, from its file name and (for OVAs) the product name inside it."""
    text = " ".join(n for n in names if n)
    if _EVE.search(text):
        m = re.search(r"eve[-_ a-z]*?[-_](\d+)\.\d+\.\d+", text, re.I)
        major = int(m.group(1)) if m else 7
        # The values come from the EVE-NG 7 cookbook; other releases get the same settings under their own name.
        return EVE_NG_7 if major == 7 else replace(EVE_NG_7, key=f"eve-ng-{major}", name=f"EVE-NG {major}")
    if _ISE.search(text):
        m = _ISE_VERSION.search(text)
        if m and int(m.group(1)) in _ISE_URLS:
            return _ise(int(m.group(1)))
    return None


def default_size(app: Appliance, host_threads: int | None, host_mem_mb: int | None) -> Size | None:
    """The recommended size when the host can hold it, otherwise the minimum."""
    rec, low = app.recommended, app.minimum
    if rec and (not host_threads or rec.cpu <= host_threads) and (not host_mem_mb or rec.memory_mb <= host_mem_mb):
        return rec
    return low or rec


def hint(app: Appliance, kind: str) -> str:
    """'(EVE-NG recommends 32 GB, minimum 16 GB)' for a sizing question."""
    def val(s: Size) -> str:
        return {"cpu": f"{s.cpu}", "memory": f"{s.memory_mb / 1024:g} GB", "disk": f"{s.disk_gb} GB"}[kind]

    parts = ([f"{app.vendor} recommends {val(app.recommended)}"] if app.recommended else []) + \
        ([f"minimum {val(app.minimum)}"] if app.minimum else [])
    return f" ({', '.join(parts)})" if parts else ""


def below_minimum(app: Appliance | None, cpu: int, memory_mb: int, disk_gb: int) -> list[str]:
    if not app or not app.minimum:
        return []
    m, out = app.minimum, []
    if cpu < m.cpu:
        out.append(f"{cpu} vCPU (minimum {m.cpu})")
    if memory_mb < m.memory_mb:
        out.append(f"{memory_mb / 1024:g} GB RAM (minimum {m.memory_mb / 1024:g} GB)")
    if disk_gb < m.disk_gb:
        out.append(f"{disk_gb} GB disk (minimum {m.disk_gb} GB)")
    return out
