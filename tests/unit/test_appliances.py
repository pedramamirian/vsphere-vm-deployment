import pytest

from vsphere_vm_deployment import appliances


@pytest.mark.parametrize("names,key", [
    (("[datastore1 (3)] eve-pro-prod-bm-7.0.1-21-full.iso",), "eve-ng-7"),
    (("[datastore1 (1)] Cisco-vISE-300-3.4.0.608b.ova (read through this computer)",), "cisco-ise-3.4"),
    (("Cisco-vISE-600-3.3.0.430a.ova",), "cisco-ise-3.3"),
    (("my.ova", "Cisco Identity Services Engine", "", "3.5.0.527"), "cisco-ise-3.5"),
    (("Cisco-vISE-300-3.2.0.542.ova",), None),  # only 3.3 to 3.5 are covered
    (("ubuntu-24.04.1-live-server-amd64.iso",), None),
])
def test_products_are_recognised(names, key):
    app = appliances.detect(*names)
    assert (app.key if app else None) == key


def test_eve_values_follow_the_cookbook():
    eve = appliances.EVE_NG_7
    assert (eve.minimum.cpu, eve.minimum.memory_mb, eve.minimum.disk_gb) == (8, 16384, 120)
    assert (eve.recommended.cpu, eve.recommended.memory_mb, eve.recommended.disk_gb) == (16, 32768, 300)
    assert eve.nested_hv and eve.iommu and eve.secure_boot is False and eve.guest_os == "ubuntu64Guest"
    assert "Cookbook 7.10" in eve.source and eve.url.startswith("https://www.eve-ng.net/")
    # the recommended size only when the host can hold it
    assert appliances.default_size(eve, 48, 256 * 1024) is eve.recommended
    assert appliances.default_size(eve, 12, 256 * 1024) is eve.minimum
    assert appliances.hint(eve, "memory") == " (EVE-NG recommends 32 GB, minimum 16 GB)"
    assert appliances.below_minimum(eve, 2, 2048, 25) == ["2 vCPU (minimum 8)", "2 GB RAM (minimum 16 GB)",
                                                         "25 GB disk (minimum 120 GB)"]


def test_ise_rules():
    ise34, ise33 = appliances.detect("Cisco-vISE-300-3.4.0.608b.ova"), appliances.detect("Cisco-vISE-300-3.3.0.430.ova")
    assert not ise34.snapshots_supported and not ise34.gets_ip_before_setup
    assert ise34.nested_hv is True and ise33.nested_hv is None  # stated from the 3.4 guide on
    assert ise34.url.startswith("https://www.cisco.com/") and "3-4" in ise34.url
