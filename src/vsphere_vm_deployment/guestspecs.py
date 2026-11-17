"""Suggested sizing for ISO installs: VMware's recommendation for the guest type (from the host's guest OS
descriptors, the same values the vSphere Client's New VM wizard uses), never below Microsoft's published
minimum for Windows.

Microsoft publishes minimums, not recommendations ("The highly diverse scope of potential deployments makes it
unrealistic to state recommended hardware requirements"); the only explicit recommendation is 4 GB RAM for
Windows Server 2025 with Desktop Experience. Sources:
  https://learn.microsoft.com/windows-server/get-started/hardware-requirements
  https://learn.microsoft.com/windows/whats-new/windows-11-requirements
  https://support.microsoft.com/windows/windows-10-system-requirements-6d4e9a79-66bf-7950-467c-795cf0386715
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Minimum:
    name: str
    cpu: int
    memory_mb: int
    disk_gb: int
    hard: bool = False  # Setup refuses to install below these values
    recommended_memory_mb: int | None = None  # only where Microsoft explicitly recommends a value
    note: str = ""


# Windows Server values are for "Server with Desktop Experience" (the larger option; Server Core needs less).
MICROSOFT = {
    "windows11_64Guest": Minimum("Windows 11", 2, 4096, 64, hard=True),
    "windows9_64Guest": Minimum("Windows 10", 1, 2048, 32),
    "windows2022srvNext_64Guest": Minimum("Windows Server 2025", 1, 2048, 32, recommended_memory_mb=4096,
                                          note="Desktop Experience"),
    "windows2019srvNext_64Guest": Minimum("Windows Server 2022", 1, 2048, 32, note="Desktop Experience"),
    "windows2019srv_64Guest": Minimum("Windows Server 2019", 1, 2048, 32, note="Desktop Experience"),
    "windows9Server64Guest": Minimum("Windows Server 2016", 1, 2048, 32, note="Desktop Experience"),
}


@dataclass
class Suggestion:
    cpu: int
    memory_mb: int
    disk_gb: int
    cores_per_socket: int | None
    source: str  # who the defaults come from, for the prompts
    vmware: tuple[int, int, int] | None  # (cpu, memory_mb, disk_gb) VMware recommends, if known
    minimum: Minimum | None


def vmware_recommendation(descriptor) -> tuple[int, int, int, int | None] | None:
    """(cpu, memory MB, disk GB, cores per socket) from a vim.vm.GuestOsDescriptor, or None."""
    if descriptor is None:
        return None
    mem = getattr(descriptor, "recommendedMemMB", None) or 0
    disk_mb = getattr(descriptor, "recommendedDiskSizeMB", None) or 0
    sockets = getattr(descriptor, "numRecommendedPhysicalSockets", None) or 0
    cores = getattr(descriptor, "numRecommendedCoresPerSocket", None) or 0
    if not mem and not disk_mb:
        return None
    cpu = max(1, sockets * max(1, cores)) if sockets else max(1, cores or 1)
    return cpu, int(mem), max(1, -(-int(disk_mb) // 1024)), cores or None


def suggest(guest_id: str | None, descriptor) -> Suggestion:
    """VMware's recommendation, raised to Microsoft's minimum where that is higher; fallbacks if unknown."""
    ms = MICROSOFT.get(guest_id or "")
    vm = vmware_recommendation(descriptor)
    if vm:
        cpu, mem, disk, cores = vm
        source = "VMware's recommendation for this guest type"
    else:
        cpu, mem, disk, cores = 2, 4096, 64 if ms else 40, None
        source = "vmdeploy's default (the host did not report a recommendation)"
    if ms:
        cpu = max(cpu, ms.cpu)
        mem = max(mem, ms.recommended_memory_mb or 0, ms.memory_mb)
        disk = max(disk, ms.disk_gb)
    return Suggestion(cpu, mem, disk, cores, source, (vm[0], vm[1], vm[2]) if vm else None, ms)


def hint(kind: str, s: Suggestion) -> str:
    """Text shown in the sizing question, e.g. '(VMware recommends 2; Microsoft minimum for Windows 11: 2)'."""
    parts = []
    if s.vmware:
        value = {"cpu": f"{s.vmware[0]}", "memory": f"{s.vmware[1] / 1024:g} GB", "disk": f"{s.vmware[2]} GB"}[kind]
        parts.append(f"VMware recommends {value}")
    if s.minimum:
        m = s.minimum
        value = {"cpu": f"{m.cpu}", "memory": f"{m.memory_mb / 1024:g} GB", "disk": f"{m.disk_gb} GB"}[kind]
        extra = ""
        if kind == "memory" and m.recommended_memory_mb:
            extra = f", {m.recommended_memory_mb / 1024:g} GB recommended"
        label = f"{m.name}{' ' + m.note if m.note else ''}"
        parts.append(f"Microsoft minimum for {label}: {value}{extra}")
    return f" ({'; '.join(parts)})" if parts else ""


def below_minimum(guest_id: str | None, cpu: int, memory_mb: int, disk_gb: int) -> tuple[list[str], bool]:
    """(problems, hard) when the sizing is below Microsoft's minimum for this Windows version."""
    ms = MICROSOFT.get(guest_id or "")
    if not ms:
        return [], False
    problems = []
    if cpu < ms.cpu:
        problems.append(f"{cpu} vCPU (minimum {ms.cpu})")
    if memory_mb < ms.memory_mb:
        problems.append(f"{memory_mb / 1024:g} GB RAM (minimum {ms.memory_mb / 1024:g} GB)")
    if disk_gb < ms.disk_gb:
        problems.append(f"{disk_gb} GB disk (minimum {ms.disk_gb} GB)")
    return problems, ms.hard
