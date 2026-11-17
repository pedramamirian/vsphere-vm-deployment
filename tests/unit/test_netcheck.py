"""Static IP input checks and IP conflict detection (examples from real-environment testing)."""

import pytest

from vsphere_vm_deployment.manifest import GuestNetwork
from vsphere_vm_deployment.netcheck import (
    IpUse,
    address_error,
    dns_error,
    find_conflicts,
    gateway_error,
    suggested_gateway,
)


@pytest.mark.parametrize(("text", "fragment"), [
    ("192.0.2.300/24", "'300' is too big"),
    ("192.0.02.05/24", "did you mean 192.0.2.5"),
    ("192.0.2.10", "Add the subnet prefix"),
    ("192.0.2.10/33", "from 1 to 32"),
    ("192.0.2.10/255.255.255.0", "192.0.2.10/24"),
    ("192.0.2.0/24", "network address"),
    ("192.0.2.255/24", "broadcast address"),
    ("127.0.0.5/8", "loopback"),
    ("169.254.1.1/16", "link-local"),
    ("198.51.100/24", "not an IPv4 address"),
])
def test_bad_addresses(text, fragment):
    assert fragment in address_error(text)


@pytest.mark.parametrize("text", ["192.0.2.250/24", "198.51.100.214/24", "203.0.113.10/30", "198.51.100.1/31"])
def test_good_addresses(text):
    assert address_error(text) is None


def test_gateway_must_be_in_the_subnet():
    msg = gateway_error("198.51.100.1", "192.0.2.250/24")
    assert "not in the VM's subnet 192.0.2.0/24" in msg and "e.g. 192.0.2.1" in msg
    assert gateway_error("192.0.2.1", "192.0.2.250/24") is None
    assert "own address" in gateway_error("192.0.2.250", "192.0.2.250/24")
    assert "leading zeros" in gateway_error("192.0.2.01", "192.0.2.250/24")
    assert "broadcast" in gateway_error("192.0.2.255", "192.0.2.250/24")


def test_suggested_gateway():
    assert suggested_gateway("192.0.2.250/24") == "192.0.2.1"
    assert suggested_gateway("192.0.2.1/24") == "192.0.2.2"  # the VM itself is .1
    assert suggested_gateway("bad") is None


def test_dns_servers():
    assert dns_error(["1.1.1.1", "192.0.2.1"]) is None
    assert "too big" in dns_error(["8.8.8.800"])


def test_manifest_uses_the_same_checks():
    with pytest.raises(ValueError, match="not in the VM's subnet"):
        GuestNetwork(mode="static", address="192.0.2.250/24", gateway="198.51.100.1")
    with pytest.raises(ValueError, match="too big"):
        GuestNetwork(mode="static", address="192.0.2.300/24")


# ------------------------------------------------------------------------------------------ conflicts
LAB = [
    IpUse("198.51.100.214", 24, "VM 'vmdeploy-test-ubuntu01'", "VM-LAN", "192.0.2.10"),
    IpUse("198.51.100.20", 24, "VM 'dc1'", "VM-LAN", "192.0.2.11"),
    IpUse("203.0.113.214", 24, "VM 'oob-switch'", "OOB-Mgmt", "192.0.2.12"),
    IpUse("192.0.2.10", 24, "ESXi host '192.0.2.10' (vmk0)", "Management Network", "192.0.2.10"),
]


def test_same_address_on_the_same_network_blocks_with_details():
    blockers, warnings = find_conflicts(LAB, "198.51.100.214/24", "VM-LAN")
    assert blockers == ["198.51.100.214 is already used by VM 'vmdeploy-test-ubuntu01' on network VM-LAN "
                        "(host 192.0.2.10)."]
    assert warnings == []


def test_same_address_on_another_network_only_warns():
    blockers, warnings = find_conflicts(LAB, "203.0.113.214/24", "VM-LAN")
    assert blockers == []
    assert any("VM 'oob-switch' on network OOB-Mgmt (host 192.0.2.12)" in w for w in warnings)


def test_esxi_management_address_is_reported():
    blockers, warnings = find_conflicts(LAB, "192.0.2.10/24", "VM-LAN")
    assert any("ESXi host '192.0.2.10' (vmk0)" in w for w in warnings)


def test_wrong_subnet_for_the_network_is_pointed_out():
    # found in testing: VM-LAN uses 198.51.100.0/24, the example address 192.0.2.50/24 was entered
    blockers, warnings = find_conflicts(LAB, "192.0.2.50/24", "VM-LAN")
    assert blockers == []
    assert any("Other VMs on VM-LAN use 198.51.100.0/24" in w and "192.0.2.0/24" in w for w in warnings)


def test_free_address_in_the_right_subnet_is_clean():
    assert find_conflicts(LAB, "198.51.100.50/24", "VM-LAN") == ([], [])


def test_replaced_vm_is_ignored():
    blockers, _ = find_conflicts(LAB, "198.51.100.214/24", "VM-LAN", ignore_vm="vmdeploy-test-ubuntu01")
    assert blockers == []
