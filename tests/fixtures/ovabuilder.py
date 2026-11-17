"""Builds small but structurally realistic OVA packages for tests (descriptor modelled on Ubuntu cloud OVAs)."""

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

DESCRIPTOR = """<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common"
 xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
 xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
 xmlns:vmw="http://www.vmware.com/schema/ovf"
 xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData">
  <References>
    <File ovf:href="{disk}" ovf:id="file1" ovf:size="{size}"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="10" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="vmdisk1" ovf:fileRef="file1"
          ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection>
    <Info>The list of logical networks</Info>
    <Network ovf:name="VM Network"><Description>The VM Network network</Description></Network>
  </NetworkSection>
  {options}
  <VirtualSystem ovf:id="{name}">
    <Info>A virtual machine</Info>
    <Name>{name}</Name>
    <OperatingSystemSection ovf:id="94" vmw:osType="ubuntu64Guest"><Info>The kind of OS</Info></OperatingSystemSection>
    <ProductSection ovf:required="false">
      <Info>Cloud-Init customization</Info>
      <Product>Test Ubuntu Server</Product>
      <Property ovf:key="instance-id" ovf:type="string" ovf:userConfigurable="true" ovf:value="id-ovf">
        <Label>A Unique Instance ID for this instance</Label></Property>
      <Property ovf:key="hostname" ovf:type="string" ovf:userConfigurable="true" ovf:value="ubuntuguest">
        <Description>Specifies the hostname for the appliance</Description></Property>
      <Property ovf:key="public-keys" ovf:type="string" ovf:userConfigurable="true" ovf:value=""><Label>ssh keys</Label></Property>
      <Property ovf:key="user-data" ovf:type="string" ovf:userConfigurable="true" ovf:value="">
        <Label>Encoded user-data</Label></Property>
      <Property ovf:key="password" ovf:type="string" ovf:userConfigurable="true" ovf:value="">
        <Label>Default User's password</Label></Property>
      {extra_props}
    </ProductSection>
    {eula}
    <VirtualHardwareSection ovf:transport="iso">
      <Info>Virtual hardware requirements</Info>
      <System><vssd:ElementName>Virtual Hardware Family</vssd:ElementName><vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemType>vmx-10</vssd:VirtualSystemType></System>
      <Item><rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits><rasd:ElementName>2 virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID><rasd:ResourceType>3</rasd:ResourceType><rasd:VirtualQuantity>2</rasd:VirtualQuantity></Item>
      {large_cpu}
      <Item><rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits><rasd:ElementName>1024MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID><rasd:ResourceType>4</rasd:ResourceType><rasd:VirtualQuantity>1024</rasd:VirtualQuantity></Item>
      <Item><rasd:Address>0</rasd:Address><rasd:ElementName>SCSI Controller 0</rasd:ElementName><rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>VirtualSCSI</rasd:ResourceSubType><rasd:ResourceType>6</rasd:ResourceType></Item>
      <Item><rasd:AddressOnParent>0</rasd:AddressOnParent><rasd:ElementName>Hard Disk 1</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource><rasd:InstanceID>4</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent><rasd:ResourceType>17</rasd:ResourceType></Item>
      <Item><rasd:AddressOnParent>0</rasd:AddressOnParent><rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>VM Network</rasd:Connection><rasd:ElementName>Ethernet 1</rasd:ElementName>
        <rasd:InstanceID>5</rasd:InstanceID><rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType><rasd:ResourceType>10</rasd:ResourceType></Item>
      <vmw:Config ovf:required="false" vmw:key="firmware" vmw:value="efi"/>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
"""

OPTIONS = """<DeploymentOptionSection><Info>Sizes</Info>
    <Configuration ovf:id="small" ovf:default="true"><Label>Small</Label><Description>2 vCPU</Description></Configuration>
    <Configuration ovf:id="large"><Label>Large</Label><Description>8 vCPU</Description></Configuration>
  </DeploymentOptionSection>"""

LARGE_CPU = """<Item ovf:configuration="large"><rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:ElementName>8 virtual CPU(s)</rasd:ElementName><rasd:InstanceID>11</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType><rasd:VirtualQuantity>8</rasd:VirtualQuantity></Item>"""


def build_ova(dest: Path, *, name: str = "test-ubuntu", eula: str | None = None, disk_bytes: int = 256 * 1024,
              corrupt_manifest: bool = False, with_options: bool = False, extra_props: str = "") -> Path:
    disk_name = f"{name}-disk1.vmdk"
    disk = (b"KDMV" + b"\0" * 508) + bytes(range(256)) * ((disk_bytes - 512) // 256)
    desc = DESCRIPTOR.format(
        disk=disk_name, size=len(disk), name=name,
        eula=f"<EulaSection><Info>License</Info><License>{eula}</License></EulaSection>" if eula else "",
        options=OPTIONS if with_options else "", large_cpu=LARGE_CPU if with_options else "",
        extra_props=extra_props).encode()
    ovf_name = f"{name}.ovf"
    mf_lines = [f"SHA256({ovf_name})= {hashlib.sha256(desc).hexdigest()}",
                f"SHA256({disk_name})= {('0' * 64) if corrupt_manifest else hashlib.sha256(disk).hexdigest()}"]
    mf = ("\n".join(mf_lines) + "\n").encode()
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dest, "w", format=tarfile.USTAR_FORMAT) as tar:
        for fname, data in ((ovf_name, desc), (f"{name}.mf", mf), (disk_name, disk)):
            info = tarfile.TarInfo(fname)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return dest


# Modelled on Cisco ISE's OVA: one package, several deployment sizes, each with its own CPU, memory and a full
# memory reservation (items tagged ovf:configuration apply only to that size).
APPLIANCE_OPTIONS = """<DeploymentOptionSection><Info>Deployment sizes</Info>
    <Configuration ovf:id="eval" ovf:default="true"><Label>Eval</Label>
      <Description>Evaluation: up to 100 endpoints</Description></Configuration>
    <Configuration ovf:id="small"><Label>Small</Label><Description>Small production node</Description></Configuration>
    <Configuration ovf:id="medium"><Label>Medium</Label><Description>Medium production node</Description></Configuration>
  </DeploymentOptionSection>"""


def _sized(config: str, cpu: int, mem_mb: int, iid: int) -> str:
    return f"""<Item ovf:configuration="{config}"><rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:ElementName>{cpu} virtual CPU(s)</rasd:ElementName><rasd:InstanceID>{iid}</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType><rasd:VirtualQuantity>{cpu}</rasd:VirtualQuantity></Item>
      <Item ovf:configuration="{config}"><rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:ElementName>{mem_mb}MB of memory</rasd:ElementName><rasd:InstanceID>{iid + 1}</rasd:InstanceID>
        <rasd:Reservation>{mem_mb}</rasd:Reservation>
        <rasd:ResourceType>4</rasd:ResourceType><rasd:VirtualQuantity>{mem_mb}</rasd:VirtualQuantity></Item>"""


APPLIANCE_ITEMS = _sized("eval", 4, 4096, 20) + _sized("small", 8, 8192, 22) + _sized("medium", 12, 12288, 24)


def build_appliance_ova(dest: Path, *, name: str = "appliance-vise") -> Path:
    """An ISE-like appliance: deployment sizes, no cloud-init properties."""
    return _build(dest, name=name, options=APPLIANCE_OPTIONS, sized_items=APPLIANCE_ITEMS, no_props=True)


def build_ovf_folder(folder: Path, *, name: str = "loose-ovf") -> Path:
    """An .ovf with its .mf and disk as separate files (as exported by the vSphere Client)."""
    folder.mkdir(parents=True, exist_ok=True)
    files = _files(name=name)
    for fname, data in files:
        (folder / fname).write_bytes(data)
    return folder / f"{name}.ovf"


def _files(*, name: str, options: str = "", sized_items: str = "", no_props: bool = False,
           disk_bytes: int = 256 * 1024) -> list[tuple[str, bytes]]:
    disk_name = f"{name}-disk1.vmdk"
    disk = (b"KDMV" + b"\0" * 508) + bytes(range(256)) * ((disk_bytes - 512) // 256)
    desc = DESCRIPTOR.format(disk=disk_name, size=len(disk), name=name, eula="", options=options,
                             large_cpu=sized_items, extra_props="")
    if no_props:  # an appliance without cloud-init: drop the ProductSection properties
        start, end = desc.index("<Property "), desc.rindex("</Property>") + len("</Property>")
        desc = desc[:start] + desc[end:]
    data = desc.encode()
    mf = (f"SHA256({name}.ovf)= {hashlib.sha256(data).hexdigest()}\n"
          f"SHA256({disk_name})= {hashlib.sha256(disk).hexdigest()}\n").encode()
    return [(f"{name}.ovf", data), (f"{name}.mf", mf), (disk_name, disk)]


def _build(dest: Path, **kw) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dest, "w", format=tarfile.USTAR_FORMAT) as tar:
        for fname, data in _files(**kw):
            info = tarfile.TarInfo(fname)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return dest
