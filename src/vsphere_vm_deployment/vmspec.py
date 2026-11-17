"""Builders for vSphere VirtualMachineConfigSpec objects (new VMs, NICs, disks, CD-ROMs, reconfiguration)."""

from __future__ import annotations

import re

from pyVmomi import vim

from .errors import DeploymentError
from .inventory import NetworkInfo
from .manifest import Provisioning

KB_PER_GB = 1024 * 1024


def _hardware_version(vm) -> int:
    """The VM's virtual hardware version ("vmx-21" -> 21); 0 when it cannot be read."""
    m = re.search(r"\d+", str(getattr(vm.config, "version", "") or ""))
    return int(m.group()) if m else 0

ADAPTERS = {
    "vmxnet3": vim.vm.device.VirtualVmxnet3,
    "e1000e": vim.vm.device.VirtualE1000e,
    "e1000": vim.vm.device.VirtualE1000,
}

# Fallback guest OS list when the host's environment browser cannot be queried.
COMMON_GUEST_IDS = [
    ("Ubuntu Linux (64-bit)", "ubuntu64Guest"),
    ("Debian GNU/Linux 12 (64-bit)", "debian12_64Guest"),
    ("Red Hat Enterprise Linux 9 (64-bit)", "rhel9_64Guest"),
    ("Rocky Linux (64-bit)", "rockylinux_64Guest"),
    ("Other 5.x or later Linux (64-bit)", "other5xLinux64Guest"),
    ("Microsoft Windows Server 2025 (64-bit)", "windows2022srvNext_64Guest"),
    ("Microsoft Windows Server 2022 (64-bit)", "windows2019srvNext_64Guest"),
    ("Microsoft Windows Server 2019 (64-bit)", "windows2019srv_64Guest"),
    ("Microsoft Windows Server 2016 (64-bit)", "windows9Server64Guest"),
    ("Microsoft Windows 11 (64-bit)", "windows11_64Guest"),
    ("Microsoft Windows 10 (64-bit)", "windows9_64Guest"),
    ("Other (64-bit)", "otherGuest64"),
]


def nic_backing(net: NetworkInfo):
    if net.kind == "dvpg":
        port = vim.dvs.PortConnection(switchUuid=net.dvs_uuid, portgroupKey=net.portgroup_key)
        return vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo(port=port)
    if net.kind == "opaque":
        return vim.vm.device.VirtualEthernetCard.OpaqueNetworkBackingInfo(
            opaqueNetworkId=net.opaque_id, opaqueNetworkType=net.opaque_type)
    # vCenter's own name: `name` may carry a "[switch]" suffix that exists only in vmdeploy's lists.
    return vim.vm.device.VirtualEthernetCard.NetworkBackingInfo(deviceName=getattr(net, "vc_name", "") or net.name,
                                                                network=net.obj)


def new_nic(net: NetworkInfo, adapter: str = "vmxnet3", key: int = -100) -> vim.vm.device.VirtualDeviceSpec:
    cls = ADAPTERS.get(adapter.lower())
    if cls is None:
        raise ValueError(f"Unknown network adapter type '{adapter}' (use one of {', '.join(ADAPTERS)})")
    nic = cls(key=key, backing=nic_backing(net),
              connectable=vim.vm.device.VirtualDevice.ConnectInfo(startConnected=True, allowGuestControl=True,
                                                                  connected=True))
    return vim.vm.device.VirtualDeviceSpec(operation=vim.vm.device.VirtualDeviceSpec.Operation.add, device=nic)


def _disk_backing(provisioning: Provisioning | None, datastore_name: str | None):
    b = vim.vm.device.VirtualDisk.FlatVer2BackingInfo(diskMode="persistent")
    prov = provisioning or Provisioning.THIN
    b.thinProvisioned = prov == Provisioning.THIN
    b.eagerlyScrub = prov == Provisioning.EAGER
    if datastore_name:
        b.fileName = f"[{datastore_name}]"
    return b


def new_disk(controller_key: int, unit: int, size_gb: int, provisioning: Provisioning | None,
             datastore_name: str | None, key: int) -> vim.vm.device.VirtualDeviceSpec:
    disk = vim.vm.device.VirtualDisk(key=key, controllerKey=controller_key, unitNumber=unit,
                                     capacityInKB=size_gb * KB_PER_GB, backing=_disk_backing(provisioning, datastore_name))
    return vim.vm.device.VirtualDeviceSpec(operation=vim.vm.device.VirtualDeviceSpec.Operation.add,
                                           fileOperation=vim.vm.device.VirtualDeviceSpec.FileOperation.create,
                                           device=disk)


def provisioning_to_ovf(p: Provisioning | None) -> str:
    """Values accepted by OvfCreateImportSpecParams.diskProvisioning."""
    return {Provisioning.THIN: "thin", Provisioning.THICK: "thick", Provisioning.EAGER: "eagerZeroedThick"}.get(
        p or Provisioning.THIN, "thin")


def create_spec(*, name: str, guest_id: str, datastore_name: str, cpu: int, cores_per_socket: int,
                memory_mb: int, disk_gb: int, provisioning: Provisioning | None, firmware: str, secure_boot: bool,
                hardware_version: str | None, networks: list[tuple[NetworkInfo, str]],
                iso_path: str | None, annotation: str, disk_controller: str = "pvscsi",
                vtpm: bool = False, nested_hv: bool = False, iommu: bool = False) -> vim.vm.ConfigSpec:
    """A fresh VM for an ISO install: disk controller + disk, SATA CD-ROM with the ISO, NICs, optional vTPM.

    disk_controller: "pvscsi" (Linux; fastest), "nvme" (Windows 10/11/Server 2016+: Windows Setup has the driver
    built in, needs VM version 13+), or "lsilogicsas" (older Windows / older VM versions)."""
    devices = []
    sharing = vim.vm.device.VirtualSCSIController.Sharing.noSharing
    if disk_controller == "nvme":
        ctrl = vim.vm.device.VirtualNVMEController(key=-1000, busNumber=0)
    elif disk_controller == "lsilogicsas":
        ctrl = vim.vm.device.VirtualLsiLogicSASController(key=-1000, busNumber=0, sharedBus=sharing)
    else:
        ctrl = vim.vm.device.ParaVirtualSCSIController(key=-1000, busNumber=0, sharedBus=sharing)
    devices.append(vim.vm.device.VirtualDeviceSpec(operation=vim.vm.device.VirtualDeviceSpec.Operation.add,
                                                   device=ctrl))
    devices.append(new_disk(-1000, 0, disk_gb, provisioning, datastore_name, key=-1001))
    if iso_path:
        sata = vim.vm.device.VirtualAHCIController(key=-2000, busNumber=0)
        devices.append(vim.vm.device.VirtualDeviceSpec(operation=vim.vm.device.VirtualDeviceSpec.Operation.add,
                                                       device=sata))
        cd = vim.vm.device.VirtualCdrom(
            key=-2001, controllerKey=-2000, unitNumber=0,
            backing=vim.vm.device.VirtualCdrom.IsoBackingInfo(fileName=iso_path),
            connectable=vim.vm.device.VirtualDevice.ConnectInfo(startConnected=True, connected=True,
                                                                allowGuestControl=True))
        devices.append(vim.vm.device.VirtualDeviceSpec(operation=vim.vm.device.VirtualDeviceSpec.Operation.add,
                                                       device=cd))
    for i, (net, adapter) in enumerate(networks):
        devices.append(new_nic(net, adapter, key=-3000 - i))
    if vtpm:  # needs EFI, VM version 14+ and a key provider in vCenter (the VM's home files are encrypted)
        devices.append(vim.vm.device.VirtualDeviceSpec(operation=vim.vm.device.VirtualDeviceSpec.Operation.add,
                                                       device=vim.vm.device.VirtualTPM(key=-7000)))

    spec = vim.vm.ConfigSpec(
        name=name, guestId=guest_id, numCPUs=cpu, numCoresPerSocket=cores_per_socket, memoryMB=memory_mb,
        files=vim.vm.FileInfo(vmPathName=f"[{datastore_name}]"), deviceChange=devices, annotation=annotation,
        firmware=firmware)
    if hardware_version:
        spec.version = hardware_version
    if nested_hv:  # "Expose hardware assisted virtualization to the guest OS" (EVE-NG, nested ESXi, Proxmox)
        spec.nestedHVEnabled = True
    if iommu:  # "Expose IOMMU to the guest OS" (needs EFI)
        spec.flags = vim.vm.FlagInfo(vvtdEnabled=True)
    if firmware == "efi":
        spec.bootOptions = vim.vm.BootOptions(efiSecureBootEnabled=bool(secure_boot))
    return spec


def size_import_spec(import_spec, *, cpu: int | None, cores_per_socket: int | None,
                     memory_mb: int | None, disk_gb: int | None = None) -> list[str]:
    """Put the chosen CPU and memory into an OVF import spec, so the VM is created with them and no resize is
    needed afterwards. An ESXi host managed by vCenter refuses CPU/memory changes made directly on the host
    ("Access to resource settings on the host is restricted to the server that is managing it"), but accepts
    them at creation. `disk_gb` (only passed for such hosts, which also refuse growing a disk afterwards) creates
    the first disk at that size; the image's disk content is then written into the larger disk.
    Returns the change descriptions (empty for a vApp, which is left to the later reconfigure)."""
    cs = getattr(import_spec, "configSpec", None)
    if not isinstance(import_spec, vim.VirtualMachineImportSpec) or cs is None:
        return []
    changes: list[str] = []
    if cpu and cpu != cs.numCPUs:
        changes.append(f"vCPU {cs.numCPUs} -> {cpu}")
        cs.numCPUs = cpu
    if cores_per_socket and cores_per_socket != cs.numCoresPerSocket:
        if cs.numCoresPerSocket or cores_per_socket != 1:  # unset in the image means 1: not a change worth naming
            changes.append(f"cores/socket {cs.numCoresPerSocket or 1} -> {cores_per_socket}")
        cs.numCoresPerSocket = cores_per_socket
    if memory_mb and memory_mb != cs.memoryMB:
        changes.append(f"memory {cs.memoryMB} MB -> {memory_mb} MB")
        cs.memoryMB = memory_mb
        alloc = cs.memoryAllocation
        if alloc is not None and alloc.reservation and alloc.reservation > memory_mb:
            changes.append(f"memory reservation {alloc.reservation} MB -> {memory_mb} MB")
            alloc.reservation = memory_mb
    disks = [dc.device for dc in cs.deviceChange or [] if isinstance(dc.device, vim.vm.device.VirtualDisk)]
    if disk_gb and disks:
        first = disks[0]  # the order of the image's disks: disk 1 first
        want_kb = disk_gb * KB_PER_GB
        if want_kb > (first.capacityInKB or 0):
            first.capacityInKB = want_kb
            if getattr(first, "capacityInBytes", None):
                first.capacityInBytes = want_kb * 1024
            changes.append(f"disk 1 created at {disk_gb} GB")
    return changes


def split_config_spec(spec: vim.vm.ConfigSpec) -> list[tuple[str, vim.vm.ConfigSpec]]:
    """One ConfigSpec per kind of change (and per device change), each with a label for messages."""
    groups = [("CPU", ("numCPUs", "numCoresPerSocket")), ("memory", ("memoryMB", "memoryAllocation")),
              ("hardware virtualisation", ("nestedHVEnabled",)), ("VM notes", ("annotation",)),
              ("cloud-init data (guestinfo)", ("extraConfig",)), ("boot options", ("bootOptions",)),
              ("flags", ("flags",))]
    parts = []
    for label, attrs in groups:
        vals = {a: getattr(spec, a) for a in attrs if getattr(spec, a, None) not in (None, [])}
        if vals:
            parts.append((label, vim.vm.ConfigSpec(**vals)))
    for dc in spec.deviceChange or []:
        dev = dc.device
        if isinstance(dev, vim.vm.device.VirtualDisk):
            label = "new disk" if dc.operation == vim.vm.device.VirtualDeviceSpec.Operation.add else "disk size"
        else:
            label = f"{'new' if dc.operation == vim.vm.device.VirtualDeviceSpec.Operation.add else 'changed'} " \
                    f"{type(dev).__name__.replace('Virtual', '')}"
        parts.append((label, vim.vm.ConfigSpec(deviceChange=[dc])))
    return parts


def reconfigure_spec(vm, *, cpu: int | None, cores_per_socket: int | None, memory_mb: int | None,
                     disk_gb: int | None, extra_disks: list[tuple[int, Provisioning | None]],
                     annotation: str | None, extra_config: dict[str, str] | None,
                     new_nics: list[tuple[NetworkInfo, str]] | None = None,
                     nested_hv: bool = False) -> tuple[vim.vm.ConfigSpec, list[str]]:
    """Reconfigure an imported VM. Disks are only ever grown. Returns (spec, list of change descriptions)."""
    spec = vim.vm.ConfigSpec()
    changes: list[str] = []
    hw = vm.config.hardware
    if cpu and cpu != hw.numCPU:
        spec.numCPUs = cpu
        changes.append(f"vCPU {hw.numCPU} -> {cpu}")
    if cores_per_socket and cores_per_socket != hw.numCoresPerSocket:
        spec.numCoresPerSocket = cores_per_socket
        changes.append(f"cores/socket {hw.numCoresPerSocket} -> {cores_per_socket}")
    if memory_mb and memory_mb != hw.memoryMB:
        spec.memoryMB = memory_mb
        changes.append(f"memory {hw.memoryMB} MB -> {memory_mb} MB")
        # Appliances often reserve all their memory (e.g. Cisco ISE); a reservation above the memory is refused.
        reserved = getattr(getattr(vm.config, "memoryAllocation", None), "reservation", None)
        if reserved and reserved > memory_mb:
            spec.memoryAllocation = vim.ResourceAllocationInfo(reservation=memory_mb)
            changes.append(f"memory reservation {reserved} MB -> {memory_mb} MB")
    if nested_hv and not getattr(vm.config, "nestedHVEnabled", False):
        spec.nestedHVEnabled = True
        changes.append("hardware virtualisation exposed to the guest")
    device_changes = []
    disks = [d for d in hw.device if isinstance(d, vim.vm.device.VirtualDisk)]
    if disk_gb and disks:
        first = sorted(disks, key=lambda d: (d.controllerKey, d.unitNumber))[0]
        want_kb = disk_gb * KB_PER_GB
        if want_kb > first.capacityInKB:
            first.capacityInKB = want_kb
            if hasattr(first, "capacityInBytes"):
                first.capacityInBytes = want_kb * 1024
            device_changes.append(vim.vm.device.VirtualDeviceSpec(
                operation=vim.vm.device.VirtualDeviceSpec.Operation.edit, device=first))
            changes.append(f"disk 1 grown to {disk_gb} GB")
    if extra_disks:
        controller = next((d for d in hw.device if isinstance(d, (vim.vm.device.VirtualSCSIController,
                                                                    vim.vm.device.VirtualNVMEController))), None)
        if controller is None:
            raise DeploymentError("The VM has no SCSI or NVMe controller to attach the extra disks to.",
                                  hint="Remove resources.extra_disks and add the disks after deployment.")
        used = {d.unitNumber for d in hw.device if getattr(d, "controllerKey", None) == controller.key}
        scsi = isinstance(controller, vim.vm.device.VirtualSCSIController)
        if scsi:
            used.add(7)  # unit 7 is reserved for the SCSI controller itself
        # The highest unit, erring towards what newer virtual hardware allows (vCenter has the final say): a
        # paravirtual SCSI controller takes 64 disks from hardware version 14 and an NVMe controller 64 from
        # version 21; otherwise units 0-15 (SCSI) or 0-14 (NVMe).
        hw = _hardware_version(vm)
        if scsi:
            last = 63 if isinstance(controller, vim.vm.device.ParaVirtualSCSIController) and hw >= 14 else 15
        else:
            last = 63 if hw >= 21 else 14
        unit = 0
        for i, (size, prov) in enumerate(extra_disks):
            while unit in used:
                unit += 1
            if unit > last:
                raise DeploymentError(f"The VM's disk controller has no free slot for {len(extra_disks) - i} more "
                                      "disk(s).", hint="Use fewer resources.extra_disks.")
            used.add(unit)
            device_changes.append(new_disk(controller.key, unit, size, prov, None, key=-4000 - i))
            changes.append(f"added {size} GB disk ({(prov or Provisioning.THIN).value})")
    for i, (net, adapter) in enumerate(new_nics or []):
        device_changes.append(new_nic(net, adapter, key=-5000 - i))
        changes.append(f"added {adapter} NIC on {net.name}")
    if device_changes:
        spec.deviceChange = device_changes
    if annotation is not None:
        spec.annotation = annotation
    if extra_config:
        spec.extraConfig = [vim.option.OptionValue(key=k, value=v) for k, v in extra_config.items()]
        changes.append("cloud-init data added to guestinfo")
    return spec, changes
