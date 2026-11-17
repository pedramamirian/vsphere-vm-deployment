from pathlib import Path

import pytest

from vsphere_vm_deployment.errors import ConfigError
from vsphere_vm_deployment.manifest import load_manifest

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


@pytest.mark.parametrize("path", sorted(EXAMPLES.glob("*.yaml")), ids=lambda p: p.name)
def test_examples_are_valid(path):
    load_manifest(path)


def _write(tmp_path, text):
    p = tmp_path / "m.yaml"
    p.write_text(text)
    return p


def test_typo_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="resources.memroy_gb"):
        load_manifest(_write(tmp_path, "resources: {memroy_gb: 4}"))


def test_one_image_source_only(tmp_path):
    with pytest.raises(ConfigError, match="choose one source"):
        load_manifest(_write(tmp_path, "image: {preset: ubuntu-lts, url: https://x/y.ova}"))


def test_plain_password_rejected(tmp_path):
    with pytest.raises(ConfigError, match="crypt hash"):
        load_manifest(_write(tmp_path, "guest: {password_hash: hunter2}"))


def test_static_ip_validation(tmp_path):
    with pytest.raises(ConfigError):
        load_manifest(_write(tmp_path, "guest: {network: {mode: static}}"))
    with pytest.raises(ConfigError):
        load_manifest(_write(tmp_path, "guest: {network: {mode: static, address: 300.1.1.1/24}}"))
    m = load_manifest(_write(tmp_path, "guest: {network: {mode: static, address: 203.0.113.5/24, gateway: 203.0.113.1}}"))
    assert m.guest.network.address == "203.0.113.5/24"


def test_vm_name_rules(tmp_path):
    with pytest.raises(ConfigError):
        load_manifest(_write(tmp_path, "vm: {name: 'bad/name'}"))


def test_missing_file():
    with pytest.raises(ConfigError, match="not found"):
        load_manifest("/nonexistent/x.yaml")


def test_empty_manifest_is_fine():
    m = load_manifest(None)
    assert m.vm.name is None and m.post_deploy.power_on is True


def test_ovf_property_values_may_be_written_as_yaml_booleans_and_numbers():
    from vsphere_vm_deployment.manifest import OvfSpec

    spec = OvfSpec(properties={"enable-scp-server": True, "ssh": False, "port": 8443, "name": "r1"})
    assert spec.properties == {"enable-scp-server": "true", "ssh": "false", "port": "8443", "name": "r1"}
