"""Windows ISO installs: guest detection, virtual hardware, key provider checks, datastore ISO paths."""

from types import SimpleNamespace as NS

import pytest
from pyVmomi import vim

from vsphere_vm_deployment import crypto, isolib
from vsphere_vm_deployment.manifest import Provisioning
from vsphere_vm_deployment.vmspec import create_spec, reconfigure_spec


@pytest.mark.parametrize(("name", "guest"), [
    ("en-us_windows_server_2022_updated_oct_2026_x64_dvd_1234.iso", "windows2019srvNext_64Guest"),
    ("SERVER_EVAL_x64FRE_en-us.iso", None),
    ("26100.1742.240906-0331.ge_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso", "windows2022srvNext_64Guest"),
    ("en-us_windows_server_2025_x64_dvd.iso", "windows2022srvNext_64Guest"),
    ("17763.737.190906-2324.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us_1.iso", "windows2019srv_64Guest"),
    ("Win11_24H2_English_x64.iso", "windows11_64Guest"),
    ("22631.2428.231001-0608.23H2_NI_RELEASE_SVC_REFRESH_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso",
     "windows11_64Guest"),
    ("Win10_22H2_English_x64v1.iso", "windows9_64Guest"),
    ("ubuntu-24.04.1-live-server-amd64.iso", "ubuntu64Guest"),
    ("ubuntu-resolute-20261016.iso", "ubuntu64Guest"),  # a date is not a Windows build number
    ("[datastore1] ISO/en-us_windows_server_2022_x64.iso", "windows2019srvNext_64Guest"),
])
def test_guess_guest_from_iso_name(name, guest):
    assert isolib.guess_guest_id(name) == guest


def test_vtpm_rules():
    assert isolib.needs_vtpm("windows11_64Guest")
    assert not isolib.needs_vtpm("windows2022srvNext_64Guest") and isolib.suggests_vtpm("windows2022srvNext_64Guest")
    assert not isolib.suggests_vtpm("windows2019srvNext_64Guest")
    assert isolib.is_windows("windows9_64Guest") and not isolib.is_windows("ubuntu64Guest")


def _spec(**kw):
    net = NS(kind="standard", name="VM-LAN", obj=None)
    args = dict(name="w", guest_id="windows11_64Guest", datastore_name="ds1", cpu=2, cores_per_socket=2,
                memory_mb=4096, disk_gb=64, provisioning=Provisioning.THIN, firmware="efi", secure_boot=True,
                hardware_version="vmx-21", networks=[(net, "e1000e")], iso_path="[ds1] iso/w.iso", annotation="x")
    args.update(kw)
    return create_spec(**args)


def _devices(spec):
    return [c.device for c in spec.deviceChange]


def test_windows_vm_gets_nvme_e1000e_and_vtpm():
    devs = _devices(_spec(disk_controller="nvme", vtpm=True))
    assert any(isinstance(d, vim.vm.device.VirtualNVMEController) for d in devs)
    assert any(isinstance(d, vim.vm.device.VirtualE1000e) for d in devs)
    assert any(isinstance(d, vim.vm.device.VirtualTPM) for d in devs)
    disk = next(d for d in devs if isinstance(d, vim.vm.device.VirtualDisk))
    assert disk.controllerKey == -1000


def test_older_windows_vm_gets_lsi_logic_sas_and_linux_keeps_pvscsi():
    assert any(isinstance(d, vim.vm.device.VirtualLsiLogicSASController)
               for d in _devices(_spec(disk_controller="lsilogicsas")))
    linux = _devices(_spec(guest_id="ubuntu64Guest"))
    assert any(isinstance(d, vim.vm.device.ParaVirtualSCSIController) for d in linux)
    assert not any(isinstance(d, vim.vm.device.VirtualTPM) for d in linux)


def test_extra_disk_on_an_nvme_vm():
    nvme = vim.vm.device.VirtualNVMEController(key=31000, busNumber=0)
    disk = vim.vm.device.VirtualDisk(key=2000, controllerKey=31000, unitNumber=0, capacityInKB=1)
    vm = NS(config=NS(hardware=NS(numCPU=2, numCoresPerSocket=2, memoryMB=4096, device=[nvme, disk])))
    spec, changes = reconfigure_spec(vm, cpu=None, cores_per_socket=None, memory_mb=None, disk_gb=None,
                                     extra_disks=[(20, None)], annotation=None, extra_config=None)
    added = spec.deviceChange[0].device
    assert added.controllerKey == 31000 and added.unitNumber == 1 and "added 20 GB disk" in changes[0]


# ------------------------------------------------------------------------------------------ key provider
def _conn(*, vcenter=True, default=None, providers=(), fail=False):
    def get_default(entity=None, defaultsToParent=None):  # noqa: N803
        if fail:
            raise vim.fault.NoPermission()
        return default

    cm = NS(GetDefaultKmsCluster=get_default, ListKmsClusters=lambda: list(providers))
    return NS(is_vcenter=vcenter, content=NS(cryptoManager=cm))


def test_key_provider_states():
    assert crypto.key_provider(_conn(default=NS(id="nkp-1"))).status == "yes"
    no_default = crypto.key_provider(_conn(providers=[NS(clusterId=NS(id="kms-a"))]))
    assert no_default.status == "no" and "none is set as the default" in no_default.detail
    assert crypto.key_provider(_conn()).status == "no"
    assert crypto.key_provider(_conn(vcenter=False)).status == "no"


def test_restricted_account_falls_back_to_the_hosts_encryption_state():
    host_ready = NS(runtime=NS(cryptoState="safe"))
    assert crypto.key_provider(_conn(fail=True), host_ready).status == "yes"
    assert crypto.key_provider(_conn(fail=True), NS(runtime=NS(cryptoState="incapable"))).status == "unknown"


def test_datastore_paths():
    assert isolib.split("[datastore1] ISO/win.iso") == ("datastore1", "ISO/win.iso")
    assert isolib.copy_target("ds13", "ISO/sub/win.iso") == "[ds13] vmdeploy-iso/win.iso"
    with pytest.raises(ValueError):
        isolib.split("datastore1/ISO/win.iso")


def test_iso_search_reports_datastores_it_could_not_search(monkeypatch):
    def ok_search(datastorePath, searchSpec):  # noqa: N803
        return "task-ok"

    def denied(datastorePath, searchSpec):  # noqa: N803
        raise vim.fault.NoPermission()

    results = {"task-ok": [NS(folderPath="[ds13] ISO", file=[NS(path="win10.iso", fileSize=7 * 1024**3)])]}
    monkeypatch.setattr(isolib, "wait_task", lambda task, what="": results[task])
    dc = NS(hosts={"192.0.2.10": 1, "192.0.2.13": 1}, datastores={
        "ds13": NS(name="ds13", usable=True, hosts={"192.0.2.13"}, obj=NS(browser=NS(SearchDatastoreSubFolders_Task=ok_search))),
        "datastore1": NS(name="datastore1", usable=True, hosts={"192.0.2.10"},
                         obj=NS(browser=NS(SearchDatastoreSubFolders_Task=denied))),
    })
    skipped = []
    found = isolib.find_images(dc, skipped)
    assert [i.full for i in found] == ["[ds13] ISO/win10.iso"] and skipped == ["datastore1"]
    assert found[0].label() == ("192.0.2.13 › [ds13] ISO/win10.iso  (7.0 GB; copied automatically if you deploy "
                                "to another host)")
    shared = isolib.DatastoreIso("nfs", "a.iso", 1, {"h1", "h2"}, 2)
    assert shared.label().startswith("shared (2 hosts) › [nfs] a.iso") and "usable on every host" in shared.label()


@pytest.mark.parametrize("name,first,nested", [
    ("eve-pro-prod-bm-6.5.0-16-full.iso", "ubuntu64Guest", True),
    ("ubuntu-24.04.1-live-server-amd64.iso", "ubuntu64Guest", False),
    ("debian-12.7.0-amd64-netinst.iso", "debian12_64Guest", False),
    ("rhel-9.4-x86_64-dvd.iso", "rhel9_64Guest", False),
    ("Rocky-9.4-x86_64-minimal.iso", "rockylinux_64Guest", False),
    ("VMware-VMvisor-Installer-8.0U3-24022510.x86_64.iso", "vmkernel8Guest", True),
    ("proxmox-ve_8.2-1.iso", "debian12_64Guest", True),
    ("pfSense-CE-2.7.2-RELEASE-amd64.iso", "freebsd14_64Guest", False),
    ("en-us_windows_server_2022_x64.iso", "windows2019srvNext_64Guest", False),
    ("Cisco-vISE-300-3.4.0.608b.ova", None, False),
    ("installer.iso", None, False),
])
def test_installers_are_recognised_from_their_names(name, first, nested):
    from vsphere_vm_deployment import isolib

    assert isolib.guess_guest_id(name) == first
    assert isolib.suggests_nested(name) is nested


def test_older_hosts_fall_back_to_an_older_guest_id():
    from vsphere_vm_deployment import isolib

    ids = isolib.guess_guest_ids("debian-13.0.0-amd64-netinst.iso")
    assert ids[0] == "debian13_64Guest" and "debian12_64Guest" in ids and "debian10_64Guest" in ids
