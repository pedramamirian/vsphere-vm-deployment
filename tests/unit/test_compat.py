"""VM compatibility (virtual hardware version) choices."""

from types import SimpleNamespace as NS

import pytest
from ovabuilder import build_ova

from vsphere_vm_deployment import compat
from vsphere_vm_deployment.compat import Compat
from vsphere_vm_deployment.errors import ConfigError
from vsphere_vm_deployment.ovf import OvfPackage, parse_descriptor

HOST_803 = [f"vmx-{n}" for n in (10, 11, 13, 14, 15, 17, 18, 19, 20, 21)]


def ubuntu_on_803(policy=None, source=""):
    return Compat(image="vmx-10", supported=HOST_803, host_default="vmx-21", policy=policy, policy_source=source)


def test_labels():
    assert compat.describe("vmx-10") == "ESXi 5.5 and later (VM version 10)"
    assert compat.describe("vmx-21") == "ESXi 8.0 U2 and later (VM version 21)"
    assert compat.describe("vmx-99") == "VM version 99"
    assert compat.describe(None) == "host default"


def test_ubuntu_on_esxi_803_offers_keep_or_upgrade():
    c = ubuntu_on_803()
    assert [k for _, k in c.options()] == ["vmx-10", "vmx-21"]  # host default == newest, listed once
    assert c.recommended(prefer_upgrade=True) == "vmx-21"  # presets / ISO installs
    assert c.recommended(prefer_upgrade=False) == "vmx-10"  # vendor appliances keep their tested version


def test_administrator_policy_wins_and_is_warned_about():
    c = ubuntu_on_803(policy="vmx-19", source="cluster Lab")
    assert c.recommended(prefer_upgrade=True) == "vmx-19"
    assert c.recommended(prefer_upgrade=False) == "vmx-19"
    assert any("policy" in label or "administrator" in label for label, k in c.options() if k == "vmx-19")
    assert c.warnings("vmx-19") == []
    assert "differs from the cluster Lab default" in c.warnings("vmx-21")[0]


def test_never_below_the_image():
    c = Compat(image="vmx-19", supported=HOST_803, host_default="vmx-21", policy="vmx-14", policy_source="datacenter DC")
    assert "vmx-14" not in [k for _, k in c.options()]
    with pytest.raises(ConfigError, match="older than the image"):
        c.resolve("vmx-14")


@pytest.mark.parametrize(("value", "expected"), [
    ("keep", "vmx-10"), ("default", "vmx-21"), ("newest", "vmx-21"), ("vmx-19", "vmx-19"), ("VMX-17", "vmx-17"),
])
def test_manifest_values(value, expected):
    assert ubuntu_on_803().resolve(value) == expected


def test_manifest_rejects_unknown_or_unsupported():
    with pytest.raises(ConfigError, match="not valid"):
        ubuntu_on_803().resolve("latest")
    with pytest.raises(ConfigError, match="not supported"):
        ubuntu_on_803().resolve("vmx-22")


def test_image_newer_than_host_is_warned():
    c = Compat(image="vmx-22", supported=HOST_803, host_default="vmx-21")
    assert "newer than this host supports" in c.warnings("vmx-22")[0]


def test_discover_reads_host_and_policy():
    descs = [NS(key=k, createSupported=True, defaultConfigOption=(k == "vmx-21")) for k in HOST_803]
    cluster = type("ClusterComputeResource", (), {})()
    cluster.name = "Lab"
    cluster.environmentBrowser = NS(QueryConfigOptionDescriptor=lambda: descs)
    cluster.configurationEx = NS(defaultHardwareVersionKey="vmx-19")
    dc = NS(name="DC", configuration=NS(defaultHardwareVersionKey=None))
    c = compat.discover(cluster, dc, image="vmx-10")
    assert c.host_default == "vmx-21" and c.newest == "vmx-21"
    assert c.policy == "vmx-19" and c.policy_source == "cluster Lab"


def test_ovf_hardware_version_is_read(tmp_path):
    pkg = OvfPackage(build_ova(tmp_path / "t.ova"))
    assert pkg.info.hardware_version == "vmx-10"


def test_ovf_with_several_versions_uses_the_highest():
    xml = ('<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" '
           'xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData">'
           '<VirtualSystem id="x"><VirtualHardwareSection><System>'
           '<vssd:VirtualSystemType>vmx-10 vmx-13 vmx-11</vssd:VirtualSystemType>'
           '</System></VirtualHardwareSection></VirtualSystem></Envelope>')
    assert parse_descriptor(xml).hardware_version == "vmx-13"
