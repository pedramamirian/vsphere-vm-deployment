import hashlib

import pytest

from vsphere_vm_deployment.errors import ChecksumMismatch, ConfigError, ImageError
from vsphere_vm_deployment.images import (
    Preset,
    detect_format,
    load_presets,
    parse_datastore_path,
    resolve,
    resolve_ubuntu_simplestreams,
)
from vsphere_vm_deployment.ui import Prompter


def product(release, version, title, serial, supported=True, ova=True):
    items = {"disk1.img": {"ftype": "disk1.img", "path": f"server/{release}/{serial}/x.img", "sha256": "a" * 64}}
    if ova:
        items["ova"] = {"ftype": "ova", "path": f"releases/{release}/release-{serial}/ubuntu-{version}-server-cloudimg-amd64.ova",
                        "sha256": hashlib.sha256(f"{release}{serial}".encode()).hexdigest(), "size": 1}
    return {"arch": "amd64", "release": release, "version": version, "release_title": title, "supported": supported,
            "versions": {serial: {"items": items}}}


INDEX = {"products": {
    "com.ubuntu.cloud:server:22.04:amd64": product("jammy", "22.04", "22.04 LTS", "20260101"),
    "com.ubuntu.cloud:server:24.04:amd64": product("noble", "24.04", "24.04 LTS", "20261001"),
    "com.ubuntu.cloud:server:25.10:amd64": product("questing", "25.10", "25.10", "20261005"),
    "com.ubuntu.cloud:server:20.04:amd64": product("focal", "20.04", "20.04 LTS", "20250101", supported=False),
}}


def test_presets_load():
    presets = load_presets()
    assert {"ubuntu-lts", "ubuntu-24.04", "ubuntu-22.04"} <= set(presets)
    assert presets["ubuntu-lts"].provisioning == "cloud-init"


def test_simplestreams_picks_newest_supported_lts():
    url, sha, label = resolve_ubuntu_simplestreams(Preset("ubuntu-lts", "", "ubuntu-simplestreams", channel="lts"), INDEX)
    assert url == "https://cloud-images.ubuntu.com/releases/noble/release-20261001/ubuntu-24.04-server-cloudimg-amd64.ova"
    assert sha == hashlib.sha256(b"noble20261001").hexdigest()
    assert "24.04 LTS" in label


def test_simplestreams_specific_release():
    url, _, _ = resolve_ubuntu_simplestreams(Preset("u22", "", "ubuntu-simplestreams", release="jammy"), INDEX)
    assert "/jammy/" in url


def test_simplestreams_no_ova():
    idx = {"products": {"p": product("noble", "24.04", "24.04 LTS", "1", ova=False)}}
    with pytest.raises(ImageError):
        resolve_ubuntu_simplestreams(Preset("x", "", "ubuntu-simplestreams", channel="lts"), idx)


@pytest.mark.parametrize("name,fmt", [("a.ova", "ova"), ("b.OVF", "ovf"), ("https://x/y/z.iso?sig=1", "iso")])
def test_detect_format(name, fmt):
    assert detect_format(name) == fmt


def test_detect_format_rejects_unknown():
    with pytest.raises(ImageError):
        detect_format("disk.vmdk")


def test_datastore_path():
    assert parse_datastore_path("[datastore 1] iso/ubuntu.iso") == ("datastore 1", "iso/ubuntu.iso")
    with pytest.raises(ConfigError):
        parse_datastore_path("iso/ubuntu.iso")


def test_local_image_checksum(isolated_dirs):
    img = isolated_dirs / "images" / "small.iso"
    img.write_bytes(b"hello")
    good = hashlib.sha256(b"hello").hexdigest()
    noop = lambda desc, total: (lambda n: None)  # noqa: E731
    r = resolve("local", "small.iso", sha256=good, prompter=Prompter(False), progress_factory=noop)
    assert r.format == "iso" and r.sha256 == good and "matches" in r.integrity
    with pytest.raises(ChecksumMismatch):
        resolve("local", "small.iso", sha256="0" * 64, prompter=Prompter(False), progress_factory=noop)


def test_local_missing(isolated_dirs):
    with pytest.raises(ConfigError, match="not found"):
        resolve("local", "nope.ova", sha256=None, prompter=Prompter(False), progress_factory=lambda d, t: (lambda n: None))
