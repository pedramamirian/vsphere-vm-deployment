import base64
import gzip

import yaml

from vsphere_vm_deployment import cloudinit as ci
from vsphere_vm_deployment.manifest import GuestNetwork, GuestSpec


def test_sha512_crypt_matches_published_test_vectors():
    # Test vectors from Ulrich Drepper's "Unix crypt using SHA-256 and SHA-512" specification.
    assert ci.sha512_crypt("Hello world!", "saltstring") == (
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1")
    assert ci.sha512_crypt("Hello world!", "saltstringsaltstring", rounds=10000) == (
        "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/"
        "YTBmSK6H9qs/y3RnOaw5v.")


def test_random_salt_differs():
    assert ci.sha512_crypt("pw") != ci.sha512_crypt("pw")


def _parse(user_data: str) -> dict:
    assert user_data.startswith("#cloud-config\n")
    return yaml.safe_load(user_data)


def test_key_only_user_gets_passwordless_sudo_and_no_password_ssh():
    g = GuestSpec(username="alex", ssh_authorized_keys=["ssh-ed25519 AAAA x"])
    cfg = _parse(ci.render_user_data(g, "web01", network_in_userdata=True))
    user = cfg["users"][1]
    assert user["sudo"] == "ALL=(ALL) NOPASSWD:ALL" and user["lock_passwd"] is True
    assert cfg["ssh_pwauth"] is False and cfg["hostname"] == "web01"


def test_password_user_needs_password_for_sudo():
    g = GuestSpec(username="alex", password_hash=ci.sha512_crypt("Sup3rSecret!"))
    cfg = _parse(ci.render_user_data(g, "h", network_in_userdata=True))
    assert cfg["users"][1]["sudo"] == "ALL=(ALL) ALL"
    assert cfg["users"][1]["passwd"].startswith("$6$")
    assert "Sup3rSecret" not in ci.render_user_data(g, "h", network_in_userdata=True)


def test_static_network_written_as_netplan_for_ovf_route():
    g = GuestSpec(username="u", ssh_authorized_keys=["ssh-ed25519 A b"],
                  network=GuestNetwork(mode="static", address="192.0.2.50/24", gateway="192.0.2.1",
                                       dns=["192.0.2.1"]))
    cfg = _parse(ci.render_user_data(g, "h", network_in_userdata=True))
    netplan = yaml.safe_load(cfg["write_files"][0]["content"])["network"]
    eth = netplan["ethernets"]["primary"]
    assert eth["addresses"] == ["192.0.2.50/24"] and eth["dhcp4"] is False
    assert eth["routes"] == [{"to": "default", "via": "192.0.2.1"}]
    # guestinfo route carries the network in metadata instead
    cfg2 = _parse(ci.render_user_data(g, "h", network_in_userdata=False))
    assert "write_files" not in cfg2
    md = yaml.safe_load(ci.render_metadata("h", g))
    assert md["network"]["ethernets"]["primary"]["addresses"] == ["192.0.2.50/24"]
    assert md["redact"] == ["userdata", "vendordata"]


def test_guestinfo_encoding_roundtrip():
    extra = ci.guestinfo_extra_config("#cloud-config\n{}", "instance-id: x\n")
    assert extra["guestinfo.userdata.encoding"] == "gzip+base64"
    assert gzip.decompress(base64.b64decode(extra["guestinfo.userdata"])).decode() == "#cloud-config\n{}"


def test_ovf_property_values_only_sets_known_keys():
    vals = ci.ovf_property_values({"user-data", "hostname", "instance-id", "password"}, "#cloud-config\n", "web01")
    assert set(vals) == {"user-data", "hostname", "instance-id"}
    assert base64.b64decode(vals["user-data"]).decode() == "#cloud-config\n"
