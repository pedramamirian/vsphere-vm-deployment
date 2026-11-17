import pytest
from ovabuilder import build_ova

from vsphere_vm_deployment.errors import ChecksumMismatch, ImageError
from vsphere_vm_deployment.ovf import OvfPackage, parse_descriptor, to_bytes


def test_parse_realistic_descriptor(tmp_path):
    pkg = OvfPackage(build_ova(tmp_path / "a.ova", eula="Be nice."))
    info = pkg.info
    assert info.name == "test-ubuntu"
    assert info.os_type == "ubuntu64Guest"
    assert info.firmware == "efi"
    assert info.networks == ["VM Network"]
    assert len(info.disks) == 1 and info.disks[0].capacity_bytes == 10 * 2**30
    assert info.hardware() == {"cpu": 2, "memory_mb": 1024, "cores_per_socket": None}
    assert {p.key for p in info.properties} >= {"user-data", "hostname", "instance-id", "password"}
    assert info.has_cloud_init_properties
    assert info.eulas == ["Be nice."]
    pkg.close()


def test_deployment_options_change_hardware(tmp_path):
    pkg = OvfPackage(build_ova(tmp_path / "a.ova", with_options=True))
    assert pkg.info.default_option == "small"
    assert pkg.info.hardware("small")["cpu"] == 2
    assert pkg.info.hardware("large")["cpu"] == 8
    pkg.close()


def test_manifest_verification(tmp_path):
    pkg = OvfPackage(build_ova(tmp_path / "ok.ova"))
    seen = []
    assert pkg.verify_manifest(seen.append) == 2
    assert sum(seen) == pkg.manifest_bytes()
    pkg.close()
    bad = OvfPackage(build_ova(tmp_path / "bad.ova", corrupt_manifest=True))
    with pytest.raises(ChecksumMismatch):
        bad.verify_manifest()
    bad.close()


def test_rejects_dtd_and_non_ovf():
    with pytest.raises(ImageError):
        parse_descriptor('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><Envelope/>')
    with pytest.raises(ImageError):
        parse_descriptor("<Foo/>")


def test_rejects_vapp_collections():
    xml = ('<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"><VirtualSystemCollection/></Envelope>')
    with pytest.raises(ImageError, match="Multi-VM"):
        parse_descriptor(xml)


@pytest.mark.parametrize("value,units,expected", [
    ("10", "byte * 2^30", 10 * 2**30), ("1024", "byte * 2^20", 2**30), ("5", None, 5), ("2", "GigaBytes", 2 * 2**30),
])
def test_units(value, units, expected):
    assert to_bytes(value, units) == expected


def test_not_an_ova(tmp_path):
    f = tmp_path / "x.ova"
    f.write_bytes(b"not a tar")
    with pytest.raises(ImageError):
        OvfPackage(f)


def test_manifest_with_utf8_bom_is_still_verified(tmp_path):
    import tarfile

    src = build_ova(tmp_path / "a.ova", corrupt_manifest=True)
    # rewrite the .mf with a BOM: the corrupted first-real entry must still be detected
    with tarfile.open(src) as t:
        members = {m.name: t.extractfile(m).read() for m in t.getmembers()}
    mf = next(n for n in members if n.endswith(".mf"))
    members[mf] = b"\xef\xbb\xbf" + members[mf]
    import io

    out = tmp_path / "bom.ova"
    with tarfile.open(out, "w", format=tarfile.USTAR_FORMAT) as t:
        for n, data in members.items():
            info = tarfile.TarInfo(n)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    pkg = OvfPackage(out)
    assert len(pkg.manifest_entries()) == 2
    with pytest.raises(ChecksumMismatch):
        pkg.verify_manifest()
    pkg.close()


def test_appliance_sizes_are_shown_with_their_hardware(tmp_path):
    from ovabuilder import build_appliance_ova

    pkg = OvfPackage(build_appliance_ova(tmp_path / "vise.ova"))
    info = pkg.info
    assert [o.id for o in info.deployment_options] == ["eval", "small", "medium"]
    assert info.default_option == "eval"
    assert info.option_summary("eval") == "4 vCPU, 4 GB RAM"
    assert info.option_summary("medium") == "12 vCPU, 12 GB RAM"
    assert info.properties == [] and not info.has_cloud_init_properties
    assert info.files == ["appliance-vise-disk1.vmdk"]
    pkg.close()


def test_loose_ovf_folder_is_read_with_its_files(tmp_path):
    from ovabuilder import build_ovf_folder

    pkg = OvfPackage(build_ovf_folder(tmp_path / "pkg"))
    assert pkg.kind == "ovf" and pkg.verify_manifest() == 2
    pkg.close()


# ------------------------------------------------------------------------------------------ property values
def _prop(type_="string", qualifiers="", default=""):
    from vsphere_vm_deployment.ovf import OvfProperty

    return OvfProperty(key="com.cisco.c8000v.x.1", type=type_, default=default, label="X", description="",
                       user_configurable=True, password=False, qualifiers=qualifiers)


def test_booleans_go_to_vcenter_as_True_or_False():
    """vCenter rejected the descriptor's own default: "Invalid value 'false' specified for property
    com.cisco.c8000v.enable-scp-server.1" (Cisco Catalyst 8000V, vCenter 8.0.3)."""
    from vsphere_vm_deployment.ovf import check_value, vcenter_value

    b = _prop("boolean", default="false")
    assert [vcenter_value(b, v) for v in ("false", "true", "False", "yes", "no", True, False, "1", "0")] == \
        ["False", "True", "False", "True", "False", "True", "False", "True", "False"]
    assert vcenter_value(b, "") == "" and check_value(b, "maybe") == "Answer true or false."
    assert vcenter_value(_prop(), " text ") == "text"  # other types: as typed, trimmed


def test_property_values_are_checked_like_vcenter_does():
    from vsphere_vm_deployment.ovf import check_value, value_map

    port = _prop("uint16", 'MinValue(1025) MaxValue(65535)')
    assert check_value(port, "") is None  # empty: vCenter decides whether it is required
    assert check_value(port, "8443") is None
    assert check_value(port, "80") == "Must be between 1025 and 65535."
    assert check_value(port, "http") == "Must be a whole number."
    assert check_value(_prop("uint8"), "300") == "Must be between 0 and 255."
    choice = _prop(qualifiers='ValueMap{"small","large"}')
    assert value_map(choice) == ["small", "large"]
    assert check_value(choice, "huge") == "Must be one of: small, large."
    secret = _prop("password", "MinLen(8) MaxLen(64)")
    assert check_value(secret, "short") == "Must be at least 8 characters."
    assert check_value(secret, "long-enough") is None


def test_descriptions_are_shown_on_one_line_in_full():
    from vsphere_vm_deployment.ovf import one_line

    text = "Password for remote login.\n        WARNING: While this password will be stored securely within IOS,"
    assert one_line(text) == ("Password for remote login. WARNING: While this password will be stored securely "
                              "within IOS,")


SIZED_DISKS = """<?xml version="1.0"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
  xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData">
  <References><File ovf:id="f1" ovf:href="system.vmdk"/></References>
  <DiskSection><Info>Disks</Info>
    <Disk ovf:diskId="system" ovf:fileRef="f1" ovf:capacity="48" ovf:capacityAllocationUnits="byte * 2^30"/>
    <Disk ovf:diskId="disk25GB" ovf:capacity="25" ovf:capacityAllocationUnits="byte * 2^30"/>
    <Disk ovf:diskId="disk1430GB" ovf:capacity="1430" ovf:capacityAllocationUnits="byte * 2^30"/>
  </DiskSection>
  <DeploymentOptionSection><Info>Sizes</Info>
    <Configuration ovf:id="tiny" ovf:default="true"><Label>Tiny</Label></Configuration>
    <Configuration ovf:id="tiny-xlstorage"><Label>Tiny, x-large storage</Label></Configuration>
  </DeploymentOptionSection>
  <VirtualSystem ovf:id="vm"><Info>VM</Info><Name>vcsa-like</Name>
    <VirtualHardwareSection><Info>HW</Info>
      <Item><rasd:InstanceID>1</rasd:InstanceID><rasd:ResourceType>17</rasd:ResourceType>
        <rasd:HostResource>ovf:/disk/system</rasd:HostResource></Item>
      <Item ovf:configuration="tiny"><rasd:InstanceID>2</rasd:InstanceID><rasd:ResourceType>17</rasd:ResourceType>
        <rasd:HostResource>ovf:/disk/disk25GB</rasd:HostResource></Item>
      <Item ovf:configuration="tiny"><rasd:InstanceID>3</rasd:InstanceID><rasd:ResourceType>17</rasd:ResourceType>
        <rasd:HostResource>ovf:/disk/disk25GB</rasd:HostResource></Item>
      <Item ovf:configuration="tiny-xlstorage"><rasd:InstanceID>4</rasd:InstanceID>
        <rasd:ResourceType>17</rasd:ResourceType><rasd:HostResource>ovf:/disk/disk1430GB</rasd:HostResource></Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>"""


def test_each_size_gets_only_its_own_disks():
    """vCenter's OVA: 34 disk definitions, each size picks 17 of them. The image's largest disk (1,430 GB, only for
    the xlstorage sizes) was taken as disk 1, so a tiny vCenter's 48 GB system disk would have grown to 1,430 GB."""
    info = parse_descriptor(SIZED_DISKS)
    gib = 2**30
    assert [(d.disk_id, d.capacity_bytes // gib) for d in info.disks_for("tiny")] == \
        [("system", 48), ("disk25GB", 25), ("disk25GB", 25)]  # a definition used twice counts twice
    assert [d.disk_id for d in info.disks_for("tiny-xlstorage")] == ["system", "disk1430GB"]
    assert [d.disk_id for d in info.disks_for(None)] == ["system", "disk25GB", "disk25GB"]  # the default size
