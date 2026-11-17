"""Behaviour that must be identical on Windows, macOS and Linux."""

from pathlib import Path

import pytest

from vsphere_vm_deployment import paths
from vsphere_vm_deployment.images import safe_filename


@pytest.mark.parametrize(
    ("url_path", "expected"),
    [
        ("/releases/noble/ubuntu-24.04-server-cloudimg-amd64.ova", "ubuntu-24.04-server-cloudimg-amd64.ova"),
        ("/dl/img:v1*.iso", "img_v1_.iso"),            # ':' would create an NTFS alternate data stream
        ("/dl/my%20image%3F.iso", "my image_.iso"),     # percent-encoding decoded, then sanitised
        ("/dl/a%2Fb.iso", "a_b.iso"),                   # an encoded '/' must not become a sub-directory
        ("/dl/CON.iso", "_CON.iso"),                    # reserved device name on Windows
        ("/dl/image.iso. ", "image.iso"),               # Windows silently strips trailing dots/spaces
        ("/", "download"),
        ("", "download"),
    ],
)
def test_safe_filename(url_path, expected):
    assert safe_filename(url_path) == expected


def test_directory_overrides_expand_home(monkeypatch, tmp_path):
    # PowerShell and cmd.exe do not expand '~', so the tool must.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("VMDEPLOY_CONFIG_DIR", "~/vmd-config")
    monkeypatch.setenv("VMDEPLOY_IMAGES_DIR", "~/vmd-images")
    assert paths.config_dir() == tmp_path / "vmd-config"
    assert paths.images_dir() == Path(tmp_path) / "vmd-images"
