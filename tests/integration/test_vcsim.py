"""End-to-end tests against govmomi's vcsim vCenter simulator.

They run the real CLI (in-process) against a simulated vCenter 8.0.3 API: certificate pinning, sign-in,
discovery, OVA import through an NFC lease with real HTTP uploads, ISO upload to a datastore, VM creation,
reconfiguration, power-on, snapshots, list and destroy.

vcsim is a partial simulator: it does not boot guests (no IP address), does not model privileges or DVS
uplinks, and returns some enum values empty (handled by tests/vcsim_compat.py). Real-environment testing is
still required; see docs/testing.md.

Run with:  VCSIM_BIN=/path/to/vcsim pytest -m vcsim
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
import vcsim_compat
import yaml
from ovabuilder import build_ova
from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim
from typer.testing import CliRunner

from vsphere_vm_deployment import ANNOTATION_MARKER
from vsphere_vm_deployment.access import inherited_rights as _REAL_INHERITED_RIGHTS
from vsphere_vm_deployment.access import rights_at_top as _REAL_RIGHTS_AT_TOP
from vsphere_vm_deployment.cli import app
from vsphere_vm_deployment.tasks import wait_task
from vsphere_vm_deployment.trust import CertInfo, fetch_peer_cert

pytestmark = pytest.mark.vcsim
USER, PASSWORD = "admin", "Sim-Passw0rd!"


# vSphere API version the simulator reports: 8.0.3.0 by default; VCSIM_API_VERSION=9.0.0.0 checks vSphere 9.
API_VERSION = os.environ.get("VCSIM_API_VERSION", "8.0.3.0")


def _vcsim_bin() -> str | None:
    return os.environ.get("VCSIM_BIN") or shutil.which("vcsim")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def vcsim():
    binary = _vcsim_bin()
    if not binary:
        pytest.skip("vcsim not available (set VCSIM_BIN)")
    vcsim_compat.install()
    port = _free_port()
    proc = subprocess.Popen([binary, "-l", f"127.0.0.1:{port}", "-username", USER, "-password", PASSWORD,
                             "-api-version", API_VERSION], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            break
        except OSError:
            time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail("vcsim did not start")
    fp = CertInfo.from_der(fetch_peer_cert("127.0.0.1", port)).sha256
    yield {"port": port, "fp": fp}
    proc.terminate()
    proc.wait(10)


@pytest.fixture
def cli(vcsim, isolated_dirs, monkeypatch):
    monkeypatch.setenv("VMDEPLOY_PASSWORD", PASSWORD)
    runner = CliRunner()

    def run(*args, ok=True):
        result = runner.invoke(app, list(args), catch_exceptions=False)
        if ok and result.exit_code != 0:
            raise AssertionError(f"exit {result.exit_code}\n{result.output}")
        return result

    run("profile", "add", "--host", "127.0.0.1", "--port", str(vcsim["port"]), "--name", "sim", "--auth",
        "password", "--username", USER, "--no-remember", "--yes")
    run.fp = vcsim["fp"]
    run.images = isolated_dirs / "images"
    run.tmp = isolated_dirs
    return run


@pytest.fixture
def si(vcsim):
    s = SmartConnect(host="127.0.0.1", port=vcsim["port"], user=USER, pwd=PASSWORD, disableSslCertValidation=True)
    yield s
    Disconnect(s)


def find_vm(si, name):
    c = si.RetrieveContent()
    view = c.viewManager.CreateContainerView(c.rootFolder, [vim.VirtualMachine], True)
    try:
        return next((v for v in view.view if v.name == name), None)
    finally:
        view.Destroy()


def manifest(tmp: Path, text: str) -> str:
    p = tmp / f"m{time.time_ns()}.yaml"
    p.write_text(text)
    return str(p)


# ------------------------------------------------------------------------------------------------- tests
def test_doctor_and_inventory(cli):
    r = cli("doctor", "--yes", "--trust-fingerprint", cli.fp)
    assert "Doctor finished" in r.output and "VirtualCenter" in r.output
    assert "in sync with this computer" in r.output  # vcsim runs on this machine
    r = cli("inventory", "--yes", "--trust-fingerprint", cli.fp)
    assert "LocalDS_0" in r.output and "DC0_C0_H0" in r.output
    # Standard and distributed portgroups are both listed; VDS uplink portgroups never are (VMs cannot use them)
    assert "VM Network" in r.output and "DC0_DVPG0" in r.output
    assert "DVUplinks" not in r.output


def test_untrusted_certificate_is_refused_non_interactively(cli):
    r = cli("doctor", "--yes", ok=False)
    assert r.exit_code != 0 and "not trusted" in r.output


def test_ova_deployment_end_to_end(cli, si):
    build_ova(cli.images / "ubuntu-test.ova")
    m = manifest(cli.tmp, """
vm: {name: e2e-ova, notes: integration test}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
resources: {cpu: 4, memory_gb: 2, disk_gb: 20, extra_disks: [{size_gb: 5}]}
networks: [{portgroup: DC0_DVPG0}]
guest:
  hostname: e2e-ova
  username: tester
  ssh_authorized_keys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey tester@ci"]
  network: {mode: static, address: 203.0.113.40/24, gateway: 203.0.113.1, dns: [203.0.113.1]}
post_deploy: {power_on: true, wait_for_ip: false, snapshot: true}
""")
    r = cli("deploy", "-f", m, "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp, "--json")
    summary = json.loads(r.stdout[r.stdout.index("{"):])
    assert summary["vm"] == "e2e-ova" and summary["cpu"] == 4
    assert summary["guest_user"] == "tester" and "The VM is ready" in r.stderr  # --json: stdout is JSON only
    assert {"connect", "upload_disks", "reconfigure"} <= set(summary["timings_s"]) and "plan" not in summary["timings_s"]
    assert "Total time" in r.stderr

    vm = find_vm(si, "e2e-ova")
    assert vm is not None
    hw = vm.config.hardware
    assert hw.numCPU == 4 and hw.memoryMB == 2048
    disks = sorted((d for d in hw.device if isinstance(d, vim.vm.device.VirtualDisk)), key=lambda d: d.unitNumber)
    assert [d.capacityInKB // (1024 * 1024) for d in disks] == [20, 5]
    assert ANNOTATION_MARKER in vm.config.annotation
    assert vm.runtime.powerState == "poweredOn"
    assert vm.snapshot is not None and vm.snapshot.rootSnapshotList[0].name == "clean-baseline"
    nic = next(d for d in hw.device if isinstance(d, vim.vm.device.VirtualEthernetCard))
    assert isinstance(nic.backing, vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo)
    # cloud-init user-data went in through the image's OVF properties
    props = {p.id: p.value for p in vm.config.vAppConfig.property}
    user_data = base64.b64decode(props["user-data"]).decode()
    assert "tester" in user_data and "203.0.113.40/24" in user_data and props["hostname"] == "e2e-ova"

    r = cli("list", "--yes", "--trust-fingerprint", cli.fp)
    assert "e2e-ova" in r.output



def _set_drs(si, cluster_name: str, enabled: bool) -> None:
    c = si.RetrieveContent()
    view = c.viewManager.CreateContainerView(c.rootFolder, [vim.ClusterComputeResource], True)
    try:
        cluster = next(x for x in view.view if x.name == cluster_name)
    finally:
        view.Destroy()
    spec = vim.cluster.ConfigSpecEx(drsConfig=vim.cluster.DrsConfigInfo(enabled=enabled))
    task = cluster.ReconfigureComputeResource_Task(spec=spec, modify=True)
    while task.info.state not in ("success", "error"):
        time.sleep(0.1)
    assert task.info.state == "success", task.info.error


def test_drs_chooses_the_host_for_ova_and_iso_on_a_distributed_portgroup(cli, si):
    """Checklist items 4 and 5 in the simulator: a DRS cluster with no host given (vCenter places the VM), and
    VMs on a distributed portgroup, for an OVA and for an ISO install (whose NIC vmdeploy adds itself)."""
    _set_drs(si, "DC0_C0", True)
    try:
        build_ova(cli.images / "ubuntu-test.ova")
        (cli.images / "drs-installer.iso").write_bytes(os.urandom(1024 * 1024))
        base = """
placement: {cluster: DC0_C0, datastore: LocalDS_0}
resources: {cpu: 2, memory_gb: 2, disk_gb: 20}
networks: [{portgroup: DC0_DVPG0}]
post_deploy: {power_on: true, wait_for_ip: false, snapshot: false}
"""
        cluster_hosts = {"DC0_C0_H0", "DC0_C0_H1", "DC0_C0_H2"}
        r = cli("deploy", "-f", manifest(cli.tmp, "vm: {name: drs-ova}\nguest: {enabled: false}" + base),
                "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp)
        assert "DRS placement" in " ".join(r.output.split())
        r = cli("deploy", "-f", manifest(cli.tmp, "vm: {name: drs-iso}\nhardware: {guest_os: otherGuest64}" + base),
                "--local", "drs-installer.iso", "--yes", "--trust-fingerprint", cli.fp)
        assert "installer is waiting" in r.output
        for name in ("drs-ova", "drs-iso"):
            vm = find_vm(si, name)
            assert vm.runtime.host.name in cluster_hosts and vm.runtime.powerState == "poweredOn"
            nics = [d for d in vm.config.hardware.device if isinstance(d, vim.vm.device.VirtualEthernetCard)]
            assert len(nics) == 1
            assert isinstance(nics[0].backing, vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo)
    finally:
        _set_drs(si, "DC0_C0", False)


def test_duplicate_name_and_replace(cli, si):
    build_ova(cli.images / "ubuntu-test.ova")
    m = manifest(cli.tmp, """
vm: {name: e2e-dup}
placement: {cluster: DC0_C0, host: DC0_C0_H1, datastore: LocalDS_0}
networks: [{portgroup: VM Network}]
guest: {enabled: false}
post_deploy: {power_on: false, snapshot: false}
""")
    args = ["deploy", "-f", m, "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp]
    cli(*args)
    r = cli(*args, ok=False)
    assert r.exit_code != 0 and "already exists" in r.output
    first = find_vm(si, "e2e-dup")._moId
    cli(*args, "--replace")
    assert find_vm(si, "e2e-dup")._moId != first


def test_eula_must_be_accepted(cli, si):
    build_ova(cli.images / "eula.ova", name="eula-appliance", eula="You agree to things.")
    base = """
vm: {name: e2e-eula}
placement: {cluster: DC0_C0, host: DC0_C0_H2, datastore: LocalDS_0}
networks: [{portgroup: VM Network}]
guest: {enabled: false}
post_deploy: {power_on: false}
"""
    r = cli("deploy", "-f", manifest(cli.tmp, base), "--local", "eula.ova", "--yes", "--trust-fingerprint", cli.fp,
            ok=False)
    assert r.exit_code != 0 and "licence agreement" in r.output
    assert find_vm(si, "e2e-eula") is None
    r = cli("deploy", "-f", manifest(cli.tmp, base + "ovf: {accept_eula: true}\n"), "--local", "eula.ova", "--yes",
            "--trust-fingerprint", cli.fp)
    assert find_vm(si, "e2e-eula") is not None
    assert "1 agreement(s) accepted (ovf.accept_eula in the manifest)" in " ".join(r.output.split())  # in the review


def test_corrupted_image_is_never_uploaded(cli, si):
    build_ova(cli.images / "bad.ova", name="bad", corrupt_manifest=True)
    m = manifest(cli.tmp, "vm: {name: e2e-bad}\nplacement: {cluster: DC0_C0, host: DC0_C0_H0}\n")
    r = cli("deploy", "-f", m, "--local", "bad.ova", "--yes", "--trust-fingerprint", cli.fp, ok=False)
    assert r.exit_code != 0 and "Integrity check failed" in r.output
    assert find_vm(si, "e2e-bad") is None


def test_iso_deployment(cli, si):
    (cli.images / "installer.iso").write_bytes(os.urandom(2 * 1024 * 1024))
    m = manifest(cli.tmp, """
vm: {name: e2e-iso}
placement: {cluster: DC0_C0, host: DC0_C0_H1, datastore: LocalDS_0}
resources: {cpu: 2, memory_gb: 2, disk_gb: 30, disk_provisioning: eager-zeroed}
hardware: {guest_os: ubuntu64Guest, firmware: efi, secure_boot: true}
networks: [{portgroup: VM Network}]
""")
    r = cli("deploy", "-f", m, "--local", "installer.iso", "--yes", "--trust-fingerprint", cli.fp)
    assert "installer is waiting in the VM console" in r.output
    vm = find_vm(si, "e2e-iso")
    devs = vm.config.hardware.device
    cd = next(d for d in devs if isinstance(d, vim.vm.device.VirtualCdrom))
    assert cd.backing.fileName == "[LocalDS_0] vmdeploy-iso/installer.iso"
    disk = next(d for d in devs if isinstance(d, vim.vm.device.VirtualDisk))
    assert disk.capacityInKB == 30 * 1024 * 1024 and disk.backing.eagerlyScrub is True
    assert vm.config.firmware == "efi" and vm.config.guestId == "ubuntu64Guest"


def test_missing_answers_fail_cleanly_with_field_names(cli):
    build_ova(cli.images / "ubuntu-test.ova")
    r = cli("deploy", "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp, ok=False)
    assert r.exit_code == 2 and "vm.name" in r.output


def test_destroy_only_own_vms(cli, si):
    r = cli("destroy", "DC0_H0_VM0", "--yes", "--trust-fingerprint", cli.fp, ok=False)
    assert r.exit_code != 0 and "not deployed by this tool" in r.output
    build_ova(cli.images / "ubuntu-test.ova")
    m = manifest(cli.tmp, """
vm: {name: e2e-destroy}
placement: {cluster: DC0_C0, host: DC0_C0_H2, datastore: LocalDS_0}
networks: [{portgroup: VM Network}]
guest: {enabled: false}
post_deploy: {power_on: true, wait_for_ip: false}
""")
    cli("deploy", "-f", m, "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp)
    cli("destroy", "e2e-destroy", "--yes", "--trust-fingerprint", cli.fp)
    assert find_vm(si, "e2e-destroy") is None


# ------------------------------------------------------------------------------------------------- standalone ESXi
@pytest.fixture(scope="module")
def esxsim():
    binary = _vcsim_bin()
    if not binary:
        pytest.skip("vcsim not available (set VCSIM_BIN)")
    vcsim_compat.install()
    port = _free_port()
    proc = subprocess.Popen([binary, "-l", f"127.0.0.1:{port}", "-username", "root", "-password", PASSWORD,
                             "-api-version", API_VERSION, "-esx"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            break
        except OSError:
            time.sleep(0.2)
    yield {"port": port, "fp": CertInfo.from_der(fetch_peer_cert("127.0.0.1", port)).sha256}
    proc.terminate()
    proc.wait(10)


def test_standalone_esxi_ova_and_iso(esxsim, isolated_dirs, monkeypatch):
    monkeypatch.setenv("VMDEPLOY_PASSWORD", PASSWORD)
    runner = CliRunner()

    def run(*args):
        r = runner.invoke(app, list(args), catch_exceptions=False)
        assert r.exit_code == 0, r.output
        return r

    run("profile", "add", "--host", f"127.0.0.1:{esxsim['port']}", "--name", "esx", "--auth", "password",
        "--username", "root", "--no-remember", "--yes")
    images = isolated_dirs / "images"
    build_ova(images / "ubuntu-test.ova")
    (images / "installer.iso").write_bytes(os.urandom(1024 * 1024))
    m = manifest(isolated_dirs, "vm: {name: esx-ova}\nguest: {enabled: false}\n"
                                "post_deploy: {power_on: true, wait_for_ip: false}\n")
    r = run("deploy", "-f", m, "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", esxsim["fp"])
    assert "/ui/#/host/vms/" in r.output  # ESXi Host Client link
    assert "ESXi Host Client" in r.output
    # cloud-init on a host reached directly: guestinfo, because the host drops OVF properties (vCenter delivers them)
    key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEKEYEXAMPLEKEYEXAMPLEKEYEXAMPLEKEYEX test"
    mg = manifest(isolated_dirs, "vm: {name: esx-ci}\n"
                                 "guest: {hostname: esx-ci, username: alex, network: {mode: dhcp}, "
                                 f"ssh_authorized_keys: ['{key}']}}\n"
                                 "post_deploy: {power_on: false, wait_for_ip: false}\n")
    r = run("deploy", "-f", mg, "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", esxsim["fp"])
    out = " ".join(r.output.split())
    assert "cloud-init via guestinfo" in out and "OVF properties" not in out
    m2 = manifest(isolated_dirs, "vm: {name: esx-iso}\nhardware: {guest_os: otherGuest64}\n")
    r = run("deploy", "-f", m2, "--local", "installer.iso", "--yes", "--trust-fingerprint", esxsim["fp"])
    assert "installer is waiting" in r.output

    # A batch on a host reached directly (no vCenter): several VMs on it, each over its own cloned session, with
    # cloud-init through guestinfo and hostnames left to the image.
    mb = manifest(isolated_dirs, f"""
guest: {{username: alex, ssh_authorized_keys: ['{key}']}}
post_deploy: {{power_on: false, wait_for_ip: false}}
batch:
  name: "esx-bt-{{n}}"
  hostname: skip
  targets: [{{hosts_matching: "*", datastore: auto, count: 3}}]
  parallel: {{vms: 3, per_host: 3}}
""")
    r = run("deploy", "-f", mb, "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", esxsim["fp"], "--json")
    doc = json.loads(r.stdout[r.stdout.index("{"):])
    assert doc["exit_code"] == 0 and [v["name"] for v in doc["vms"]] == ["esx-bt-1", "esx-bt-2", "esx-bt-3"]
    assert all(v["hostname"] is None for v in doc["vms"])
    s = SmartConnect(host="127.0.0.1", port=esxsim["port"], user="root", pwd=PASSWORD, disableSslCertValidation=True)
    try:
        vm = find_vm(s, "esx-bt-2")
        extra = {o.key: o.value for o in vm.config.extraConfig}
        user_data = gzip.decompress(base64.b64decode(extra["guestinfo.userdata"])).decode()
        assert "alex" in user_data and "hostname" not in user_data
    finally:
        Disconnect(s)


# ------------------------------------------------------------------------------------------------- access setup
@pytest.fixture(autouse=True)
def _vcsim_knows_every_user(monkeypatch):
    """vcsim's user directory is empty; a real vCenter knows the SSO users these tests name."""
    from vsphere_vm_deployment import access

    monkeypatch.setattr(access, "user_missing", lambda conn, principal: False)
    # vcsim reports every privilege for every user (as if all were administrators); a real vCenter reports the
    # account's own. The refusal itself runs against vcsim's answer below.
    monkeypatch.setattr(access, "inherited_rights", lambda conn, plan: [])
    monkeypatch.setattr(access, "rights_at_top", lambda conn, principal: [])


def _no_permission_for(si, name) -> bool:
    perms = si.RetrieveContent().authorizationManager.RetrieveAllPermissions()
    return not any(p.principal.lower().endswith(name) for p in perms)


def test_access_setup_refuses_an_account_with_rights_before_the_placement_questions(cli, si, monkeypatch):
    """vcsim answers FetchUserPrivilegeOnEntities with every privilege, like an account in vCenter's
    Administrators group: setup stops right after the user is named (no placement questions), changing nothing."""
    from vsphere_vm_deployment import access

    monkeypatch.setattr(access, "rights_at_top", _REAL_RIGHTS_AT_TOP)
    before = _roles(si)
    r = cli("access", "setup", "--yes", "--trust-fingerprint", cli.fp, "--user", "admin2@vsphere.local",
            "--folder", "/", "--compute", "DC0_C0", "--datastore", "LocalDS_0", "--network", "VM Network", ok=False)
    out = " ".join(r.output.split())
    assert r.exit_code != 0 and "already has rights across this vCenter" in out
    assert "Nothing was changed" in out and _roles(si) == before and _no_permission_for(si, "admin2")


def test_access_setup_refuses_rights_on_the_chosen_objects(cli, si, monkeypatch):
    """Rights only lower down (e.g. a group's permission on the cluster): found per object, before the plan."""
    from vsphere_vm_deployment import access

    monkeypatch.setattr(access, "inherited_rights", _REAL_INHERITED_RIGHTS)
    before = _roles(si)
    r = cli("access", "setup", "--yes", "--trust-fingerprint", cli.fp, "--user", "admin3@vsphere.local",
            "--folder", "/", "--compute", "DC0_C0", "--datastore", "LocalDS_0", "--network", "VM Network", ok=False)
    out = " ".join(r.output.split())
    assert r.exit_code != 0 and "already has rights here, through a group" in out and "Cluster DC0_C0" in out
    assert "Nothing was changed" in out and _roles(si) == before and _no_permission_for(si, "admin3")


def test_access_setup_stops_when_the_vcenter_user_does_not_exist(cli, si, monkeypatch):
    """vCenter users cannot be created through the API: say how to create one, before any plan or change."""
    from vsphere_vm_deployment import access

    monkeypatch.setattr(access, "user_missing", lambda conn, principal: True)
    before = _roles(si)
    r = cli("access", "setup", "--yes", "--trust-fingerprint", cli.fp, "--user", "nobody@vsphere.local",
            "--folder", "/", "--compute", "DC0_C0", "--datastore", "LocalDS_0", "--network", "VM Network", ok=False)
    out = " ".join(r.output.split())
    assert r.exit_code != 0 and "does not know the user nobody@vsphere.local" in out
    assert "Users and Groups" in out and "Nothing was changed" in out and _roles(si) == before


def _roles(si) -> dict[str, int]:
    return {r.name: r.roleId for r in si.RetrieveContent().authorizationManager.roleList}


def test_access_setup_and_remove_on_vcenter(cli, si):
    r = cli("access", "setup", "--yes", "--trust-fingerprint", cli.fp, "--user", "svc-deploy@vsphere.local",
            "--folder", "/", "--compute", "DC0_C0", "--compute", "DC0_H0", "--datastore", "LocalDS_0",
            "--network", "VM Network", "--network", "DC0_DVPG0", "--new-profile", "sim-deployer")
    assert "Access created for" in r.output and r"VSPHERE.LOCAL\svc-deploy" in r.output
    roles = _roles(si)
    assert {"vmdeploy-deployer", "vmdeploy-deployer-read"} <= set(roles)
    am = si.RetrieveContent().authorizationManager
    # folder, the cluster and a standalone host (several, for batches: found in real testing, setup allowed one),
    # datastore, standard + distributed portgroup; plus the read role at the top
    deploy_perms = am.RetrieveRolePermissions(roleId=roles["vmdeploy-deployer"])
    assert len(deploy_perms) == 6
    # Only the folder grant applies to objects inside it: VMs also inherit from their resource pool, so the
    # cluster's pool is granted for placement only and existing VMs there stay out of reach
    assert sorted(p.propagate for p in deploy_perms) == [False, False, False, False, False, True]
    assert len(am.RetrieveRolePermissions(roleId=roles["vmdeploy-deployer-read"])) == 1
    assert "sim-deployer" in cli("profile", "list").output
    assert "vmdeploy-deployer" in cli("doctor", "--yes", "--trust-fingerprint", cli.fp).output

    r = cli("access", "remove", "--yes", "--trust-fingerprint", cli.fp)
    assert "Role vmdeploy-deployer" in r.output
    assert "cannot delete vCenter Single Sign-On users" in " ".join(r.output.split())
    assert not {"vmdeploy-deployer", "vmdeploy-deployer-read"} & set(_roles(si))
    # No access left through any existing role. (vcsim neither reports permission entities nor drops a deleted
    # role's permissions, so it may keep an orphan entry pointing at a role that no longer exists; real vCenter
    # removes those. The real-environment checklist covers this on vCenter.)
    live_roles = set(_roles(si).values())
    assert not [p for p in am.RetrieveAllPermissions() if "svc-deploy" in p.principal and p.roleId in live_roles]
    assert "sim-deployer" not in cli("profile", "list").output
    assert "No access created" in cli("access", "remove", "--yes", "--trust-fingerprint", cli.fp).output


def test_access_setup_refuses_to_overwrite_an_existing_permission(cli, si):
    am = si.RetrieveContent().authorizationManager
    root = si.RetrieveContent().rootFolder
    am.SetEntityPermissions(entity=root, permission=[vim.AuthorizationManager.Permission(
        principal="VSPHERE.LOCAL\\boss", group=False, roleId=-1, propagate=True)])
    try:
        r = cli("access", "setup", "--yes", "--trust-fingerprint", cli.fp, "--user", "boss@vsphere.local",
                "--folder", "/", "--compute", "DC0_C0", "--datastore", "LocalDS_0", "--network", "VM Network",
                ok=False)
        assert r.exit_code == 2 and "would overwrite" in r.output
        assert not {"vmdeploy-deployer", "vmdeploy-deployer-read"} & set(_roles(si))  # nothing created
    finally:
        am.RemoveEntityPermission(entity=root, user="VSPHERE.LOCAL\\boss", isGroup=False)


def test_access_setup_and_remove_on_standalone_esxi(esxsim, isolated_dirs, monkeypatch):
    monkeypatch.setenv("VMDEPLOY_PASSWORD", PASSWORD)
    runner = CliRunner()

    def run(*args):
        r = runner.invoke(app, list(args), catch_exceptions=False)
        assert r.exit_code == 0, r.output
        return r

    run("profile", "add", "--host", f"127.0.0.1:{esxsim['port']}", "--name", "esx", "--auth", "password",
        "--username", "root", "--no-remember", "--yes")
    r = run("access", "setup", "-p", "esx", "--yes", "--trust-fingerprint", esxsim["fp"], "--user", "vmdeploy",
            "--new-profile", "esx-deployer", "--no-remember")
    assert "Password for vmdeploy:" in r.output and "Shown once" in r.output
    s = SmartConnect(host="127.0.0.1", port=esxsim["port"], user="root", pwd=PASSWORD, disableSslCertValidation=True)
    try:
        assert "vmdeploy-deployer" in _roles(s)
        users = s.RetrieveContent().userDirectory.RetrieveUserGroups(
            searchStr="vmdeploy", exactMatch=True, findUsers=True, findGroups=False)
        assert [u.principal for u in users] == ["vmdeploy"]
        # vcsim does not return the description setup stored, so the user must be named explicitly
        r = run("access", "remove", "-p", "esx", "--yes", "--trust-fingerprint", esxsim["fp"],
                "--delete-user", "vmdeploy")
        assert "Local user vmdeploy" in r.output
        assert "vmdeploy-deployer" not in _roles(s)
        assert not s.RetrieveContent().userDirectory.RetrieveUserGroups(
            searchStr="vmdeploy", exactMatch=True, findUsers=True, findGroups=False)
    finally:
        Disconnect(s)


def test_bad_profile_names_are_refused_before_anything_changes(cli, si):
    r = cli("access", "setup", "--yes", "--trust-fingerprint", cli.fp, "--user", "svc-deploy@vsphere.local",
            "--folder", "/", "--compute", "DC0_C0", "--datastore", "LocalDS_0", "--network", "VM Network",
            "--new-profile", "bad name", ok=False)
    assert r.exit_code == 2 and "may not contain spaces" in r.output
    r = cli("access", "setup", "--yes", "--trust-fingerprint", cli.fp, "--user", "svc-deploy@vsphere.local",
            "--folder", "/", "--compute", "DC0_C0", "--datastore", "LocalDS_0", "--network", "VM Network",
            "--new-profile", "sim", ok=False)
    assert r.exit_code == 2 and "already exists" in r.output
    assert not {"vmdeploy-deployer", "vmdeploy-deployer-read"} & set(_roles(si))  # vCenter untouched
    r = cli("profile", "add", "--host", "127.0.0.1", "--name", "bad name", "--auth", "password", "--yes", ok=False)
    assert r.exit_code == 2 and "Unexpected error" not in r.output


def test_deploy_scope_uses_the_real_api_shape(vcsim):
    # As administrator everything is in scope; this checks HasPrivilegeOnEntities results are read correctly.
    from vsphere_vm_deployment.connection import Connection
    from vsphere_vm_deployment.inventory import discover
    from vsphere_vm_deployment.privileges import deploy_scope

    s = SmartConnect(host="127.0.0.1", port=vcsim["port"], user=USER, pwd=PASSWORD, disableSslCertValidation=True)
    try:
        conn = Connection(si=s, profile=None, decision=None, trust=None)
        scope = deploy_scope(conn, discover(conn))
        if scope is None:
            pytest.skip("simulator does not report privileges")
        assert "/" in scope["VM folders"] and "LocalDS_0" in scope["Datastores"]
        assert "Cluster DC0_C0" in scope["Hosts / clusters"] and "DC0_DVPG0" in scope["Networks"]
    finally:
        Disconnect(s)


def test_vm_compatibility_upgrade_and_keep(cli, si):
    build_ova(cli.images / "ubuntu-test.ova")  # declares vmx-10, like Ubuntu's cloud images
    m = manifest(cli.tmp, """
vm: {name: compat-newest}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
hardware: {hardware_version: newest}
networks: [{portgroup: VM Network}]
guest: {enabled: false}
post_deploy: {power_on: false}
""")
    r = cli("deploy", "-f", m, "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp, "--json")
    summary = json.loads(r.stdout[r.stdout.index("{"):])
    vm = find_vm(si, "compat-newest")
    assert summary["compatibility"] == vm.config.version and vm.config.version != "vmx-10"

    m2 = manifest(cli.tmp, """
vm: {name: compat-keep}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
hardware: {hardware_version: keep}
networks: [{portgroup: VM Network}]
guest: {enabled: false}
post_deploy: {power_on: false}
""")
    cli("deploy", "-f", m2, "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp)
    assert find_vm(si, "compat-keep").config.version == "vmx-10"


def _vm_folder_child(si, name):
    dc = si.RetrieveContent().rootFolder.childEntity[0]
    return next((c for c in dc.vmFolder.childEntity if isinstance(c, vim.Folder) and c.name == name), None)


def _setup_with_new_folder(cli, folder_name, user):
    # One user per test: vcsim keeps orphaned permissions after a role is deleted (real vCenter does not)
    return cli("access", "setup", "--yes", "--trust-fingerprint", cli.fp, "--user", user,
               "--new-folder", folder_name, "--compute", "DC0_C0", "--datastore", "LocalDS_0",
               "--network", "VM Network", "--new-profile", "sim-" + folder_name)


def test_access_setup_creates_labels_and_removes_its_folder(cli, si):
    r = _setup_with_new_folder(cli, "vmdeploy-svc-folder", "svc-folder@vsphere.local")
    assert "New VM folder" in r.output and "Access created for" in r.output
    folder = _vm_folder_child(si, "vmdeploy-svc-folder")
    assert folder is not None
    cfm = si.RetrieveContent().customFieldsManager
    key = next(f.key for f in cfm.field if f.name == "vmdeploy")
    assert any(cv.key == key and cv.value.startswith("Created by vmdeploy access setup") for cv in folder.customValue)

    r = cli("access", "remove", "--yes", "--trust-fingerprint", cli.fp)
    out = " ".join(r.output.split())
    assert "VM folder vmdeploy-svc-folder (was empty)" in out
    # the plan lists the custom attribute that goes with the last labelled folder (it was removed unannounced)
    plan = " ".join(r.output.replace("│", " ").split())  # table cells wrap at the test's terminal width
    assert "Custom attribute 'vmdeploy' (the label on the folder(s) above; no other folder uses it)" in plan
    assert _vm_folder_child(si, "vmdeploy-svc-folder") is None
    assert not [f for f in si.RetrieveContent().customFieldsManager.field or [] if f.name == "vmdeploy"]


def test_access_remove_keeps_a_folder_that_is_not_empty(cli, si):
    _setup_with_new_folder(cli, "vmdeploy-busy", "svc-busy@vsphere.local")
    folder = _vm_folder_child(si, "vmdeploy-busy")
    folder.CreateFolder(name="something-inside")
    try:
        r = cli("access", "remove", "--yes", "--trust-fingerprint", cli.fp)
        assert "is KEPT" in " ".join(r.output.split())
        assert _vm_folder_child(si, "vmdeploy-busy") is not None
    finally:
        from pyVim.task import WaitForTask

        WaitForTask(_vm_folder_child(si, "vmdeploy-busy").Destroy_Task())


def test_access_setup_needs_a_folder_choice_in_yes_mode(cli, si):
    r = cli("access", "setup", "--yes", "--trust-fingerprint", cli.fp, "--user", "svc-x@vsphere.local",
            "--compute", "DC0_C0", "--datastore", "LocalDS_0", "--network", "VM Network", ok=False)
    assert r.exit_code == 2 and "--new-folder" in r.output


def test_access_setup_new_folder_inside_an_existing_folder(cli, si):
    dc = si.RetrieveContent().rootFolder.childEntity[0]
    parent = dc.vmFolder.CreateFolder(name="Lab")
    try:
        r = cli("access", "setup", "--yes", "--trust-fingerprint", cli.fp, "--user", "svc-nested@vsphere.local",
                "--new-folder", "Lab/vmdeploy-nested", "--compute", "DC0_C0", "--datastore", "LocalDS_0",
                "--network", "VM Network", "--new-profile", "sim-nested")
        assert "/Lab/vmdeploy-nested" in " ".join(r.output.split())
        assert [c.name for c in parent.childEntity] == ["vmdeploy-nested"]
        r = cli("access", "remove", "--yes", "--trust-fingerprint", cli.fp)
        assert not list(parent.childEntity)  # the setup folder is gone, the parent stays
        r = cli("access", "setup", "--yes", "--trust-fingerprint", cli.fp, "--user", "svc-nested2@vsphere.local",
                "--new-folder", "Missing/vmdeploy-x", "--compute", "DC0_C0", "--datastore", "LocalDS_0",
                "--network", "VM Network", ok=False)
        assert r.exit_code == 2 and "does not exist" in r.output
    finally:
        from pyVim.task import WaitForTask

        WaitForTask(parent.Destroy_Task())


def test_ip_uses_reads_the_real_api_shape(vcsim):
    from vsphere_vm_deployment.connection import Connection
    from vsphere_vm_deployment.netcheck import ip_uses

    s = SmartConnect(host="127.0.0.1", port=vcsim["port"], user=USER, pwd=PASSWORD, disableSslCertValidation=True)
    try:
        uses = ip_uses(Connection(si=s, profile=None, decision=None, trust=None))
        assert all(u.ip.count(".") == 3 and u.owner for u in uses)
        # vcsim reports each ESXi host's vmk0 address (its VMs have no guest IPs)
        assert len([u for u in uses if u.owner.startswith("ESXi host") and u.network == "Management Network"]) == 4
    finally:
        Disconnect(s)


def test_access_remove_handles_vms_left_in_the_accounts_folder(cli, si):
    # A real-world sequence: remove the access while VMs are still in the folder, then clean up later.
    _setup_with_new_folder(cli, "vmdeploy-leftovers", "svc-left@vsphere.local")
    build_ova(cli.images / "ubuntu-test.ova")
    m = manifest(cli.tmp, """
vm: {name: left-vm}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0, folder: /vmdeploy-leftovers}
networks: [{portgroup: VM Network}]
guest: {enabled: false}
post_deploy: {power_on: true, wait_for_ip: false}
""")
    cli("deploy", "-f", m, "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp)
    assert find_vm(si, "left-vm") is not None

    r = cli("access", "remove", "--yes", "--trust-fingerprint", cli.fp)  # default: keep the VMs
    out = " ".join(r.output.split())
    assert "are kept" in out and "--delete-vms" in out and "left-vm" in out
    assert find_vm(si, "left-vm") is not None and _vm_folder_child(si, "vmdeploy-leftovers") is not None

    r = cli("access", "remove", "--yes", "--trust-fingerprint", cli.fp, "--delete-vms")  # later clean-up
    out = " ".join(r.output.split())
    assert "VM left-vm (powered off and deleted)" in out and "VM folder vmdeploy-leftovers (was empty)" in out
    assert find_vm(si, "left-vm") is None and _vm_folder_child(si, "vmdeploy-leftovers") is None


def test_access_remove_cleans_up_after_a_folder_deleted_by_hand(cli, si):
    # A real-world sequence: access removed, then the folder deleted in the vSphere Client; only the
    # custom attribute definition is left behind.
    from pyVim.task import WaitForTask

    _setup_with_new_folder(cli, "vmdeploy-by-hand", "svc-hand@vsphere.local")
    cli("access", "remove", "--yes", "--trust-fingerprint", cli.fp, "--delete-vms")
    # recreate the situation: a labelled folder deleted by hand leaves the attribute definition
    cfm = si.RetrieveContent().customFieldsManager
    cfm.AddCustomFieldDef(name="vmdeploy", moType=vim.Folder)
    folder = _vm_folder_child(si, "vmdeploy-by-hand")
    if folder is not None:
        WaitForTask(folder.Destroy_Task())

    r = cli("access", "remove", "--yes", "--trust-fingerprint", cli.fp)
    out = " ".join(r.output.split())
    assert "no folder uses it any more" in out and "Custom attribute 'vmdeploy'" in out
    assert not [f for f in si.RetrieveContent().customFieldsManager.field or [] if f.name == "vmdeploy"]
    assert "No access created" in cli("access", "remove", "--yes", "--trust-fingerprint", cli.fp).output


def test_access_audit_finds_setup_and_confirms_clean_up(cli, si):
    from vsphere_vm_deployment import audit
    from vsphere_vm_deployment.connection import Connection

    def sections():
        return {sec.title: sec for sec in audit.run(Connection(si=si, profile=None, decision=None, trust=None))}

    _setup_with_new_folder(cli, "vmdeploy-audit", "svc-audit@vsphere.local")
    found = sections()
    assert not any(sec.note for sec in found.values()), {t: sec.note for t, sec in found.items() if sec.note}
    assert {"vmdeploy-deployer", "vmdeploy-deployer-read"} <= {row[0] for row in found["Roles"].rows}
    assert any(row[0] == "vmdeploy-audit" and row[1] == "labelled by setup" for row in found["VM folders"].rows)
    assert any("svc-audit" in row[0] for row in found["Permissions"].rows)
    assert "Audit of" in cli("access", "audit", "--yes", "--trust-fingerprint", cli.fp).output  # the command runs

    cli("access", "remove", "--yes", "--trust-fingerprint", cli.fp, "--delete-vms")
    after = sections()
    assert after["Roles"].clean and after["Custom attribute"].clean
    assert not after["Accounts used with vmdeploy"].note  # the directory lookup ran against the real API
    assert not any(row[0] == "vmdeploy-audit" for row in after["VM folders"].rows)
    # vcsim's own VMs are all registered; only the ISO upload folder from the ISO deployment test remains
    files = after["Files on datastores not used by any VM"]
    assert all(row[1].endswith("vmdeploy-iso") for row in files.rows), files.rows


# ------------------------------------------------------------------------------------------------- Windows
def _windows_iso_on_datastore(cli, si, name):
    """Upload a fake ISO through a normal ISO deployment, then copy it to ISO/<name> on the datastore."""
    from vsphere_vm_deployment.tasks import wait_task  # copes with vcsim's FileManager task entity

    (cli.images / "seed.iso").write_bytes(os.urandom(1024 * 1024))
    m = manifest(cli.tmp, f"""
vm: {{name: seed-{time.time_ns()}}}
placement: {{cluster: DC0_C0, host: DC0_C0_H1, datastore: LocalDS_0}}
hardware: {{guest_os: otherGuest64}}
networks: [{{portgroup: VM Network}}]
post_deploy: {{power_on: false}}
""")
    cli("deploy", "-f", m, "--local", "seed.iso", "--yes", "--trust-fingerprint", cli.fp)
    c = si.RetrieveContent()
    dc = c.rootFolder.childEntity[0]
    try:
        c.fileManager.MakeDirectory(name="[LocalDS_0] ISO", datacenter=dc, createParentDirectories=True)
    except vim.fault.FileAlreadyExists:
        pass
    wait_task(c.fileManager.CopyDatastoreFile_Task(
        sourceName="[LocalDS_0] vmdeploy-iso/seed.iso", sourceDatacenter=dc,
        destinationName=f"[LocalDS_0] ISO/{name}", destinationDatacenter=dc, force=True))
    return dc


def test_windows_11_from_a_datastore_iso_gets_nvme_e1000e_secure_boot_and_vtpm(cli, si):
    _windows_iso_on_datastore(cli, si, "Win11_24H2_English_x64.iso")
    m = manifest(cli.tmp, """
vm: {name: win11-test}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
resources: {cpu: 2, memory_gb: 4, disk_gb: 64}
networks: [{portgroup: VM Network}]
""")
    r = cli("deploy", "-f", m, "--datastore-iso", "[LocalDS_0] ISO/Win11_24H2_English_x64.iso", "--yes",
            "--trust-fingerprint", cli.fp)
    assert "Windows Setup is waiting in the VM console" in " ".join(r.output.split())
    vm = find_vm(si, "win11-test")
    devs = vm.config.hardware.device
    assert vm.config.guestId == "windows11_64Guest"  # guessed from the ISO's file name
    assert vm.config.firmware == "efi" and vm.config.bootOptions.efiSecureBootEnabled
    assert any(isinstance(d, vim.vm.device.VirtualNVMEController) for d in devs)
    assert any(isinstance(d, vim.vm.device.VirtualE1000e) for d in devs)
    assert any(isinstance(d, vim.vm.device.VirtualTPM) for d in devs)
    cd = next(d for d in devs if isinstance(d, vim.vm.device.VirtualCdrom))
    assert cd.backing.fileName == "[LocalDS_0] ISO/Win11_24H2_English_x64.iso"  # used in place, no copy needed


def test_windows_11_without_a_key_provider_stops_with_the_command_to_fix_it(cli, si, monkeypatch):
    """No usable key provider: Windows 11 stops before anything is created and says which command fixes it.
    (Interactively, the fix is offered on the spot: tests/unit/test_keyprovider.py.)"""
    from vsphere_vm_deployment import crypto

    monkeypatch.setattr(crypto, "key_provider", lambda conn, host=None: crypto.KeyProvider(
        "no", "no key provider is configured in vCenter"))
    _windows_iso_on_datastore(cli, si, "Win11_nokp.iso")
    base = """
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
resources: {cpu: 2, memory_gb: 4, disk_gb: 64}
networks: [{portgroup: VM Network}]
"""
    r = cli("deploy", "-f", manifest(cli.tmp, "vm: {name: win11-nokp}" + base), "--datastore-iso",
            "[LocalDS_0] ISO/Win11_nokp.iso", "--yes", "--trust-fingerprint", cli.fp, ok=False)
    out = " ".join(r.output.split())
    assert r.exit_code != 0 and find_vm(si, "win11-nokp") is None
    assert "Windows 11 requires a TPM 2.0" in out and "vmdeploy keyprovider add -p sim" in out

    # The one way past it: an explicit `hardware.vtpm: false` (Setup's TPM check bypassed), with a warning.
    r = cli("deploy", "-f", manifest(cli.tmp, "vm: {name: win11-notpm}\nhardware: {vtpm: false}" + base),
            "--datastore-iso", "[LocalDS_0] ISO/Win11_nokp.iso", "--yes", "--trust-fingerprint", cli.fp)
    assert "stops at its requirements check unless that check is bypassed" in " ".join(r.output.split())
    vm = find_vm(si, "win11-notpm")
    assert vm is not None and not any(isinstance(d, vim.vm.device.VirtualTPM) for d in vm.config.hardware.device)



def test_native_key_provider_on_a_standalone_host_is_stopped_before_anything_changes(cli, si, monkeypatch):
    """vCenter: "The host does not support Native Key Provider because it is not in a cluster." Caught in pre-flight
    (before the ISO upload), with the hosts that are in a cluster; a host in a cluster passes."""
    from vsphere_vm_deployment import crypto

    monkeypatch.setattr(crypto, "key_provider", lambda conn, host=None: crypto.KeyProvider(
        "yes", "default key provider 'NKP-01'", "NKP-01", False, True))
    _windows_iso_on_datastore(cli, si, "Win11_nkp.iso")
    rest = "resources: {cpu: 2, memory_gb: 4, disk_gb: 64}\nnetworks: [{portgroup: VM Network}]\n"
    r = cli("deploy", "-f", manifest(cli.tmp, "vm: {name: win11-standalone}\n"
                                              "placement: {host: DC0_H0, datastore: LocalDS_0}\n" + rest),
            "--datastore-iso", "[LocalDS_0] ISO/Win11_nkp.iso", "--yes", "--trust-fingerprint", cli.fp, ok=False)
    out = " ".join(r.output.split())
    assert r.exit_code != 0 and find_vm(si, "win11-standalone") is None
    assert "only supports on hosts in a cluster" in out and "DC0_C0_H0" in out
    cli("deploy", "-f", manifest(cli.tmp, "vm: {name: win11-clustered}\n"
                                          "placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}\n"
                                 + rest),
        "--datastore-iso", "[LocalDS_0] ISO/Win11_nkp.iso", "--yes", "--trust-fingerprint", cli.fp)
    assert find_vm(si, "win11-clustered") is not None

    # No key provider at all, host outside a cluster: adding one would not help, so the cluster is explained
    # instead of `keyprovider add`, and nothing is created.
    monkeypatch.setattr(crypto, "key_provider", lambda conn, host=None: crypto.KeyProvider(
        "no", "no key provider is configured in vCenter"))
    r = cli("deploy", "-f", manifest(cli.tmp, "vm: {name: win11-standalone2}\n"
                                              "placement: {host: DC0_H0, datastore: LocalDS_0}\n" + rest),
            "--datastore-iso", "[LocalDS_0] ISO/Win11_nkp.iso", "--yes", "--trust-fingerprint", cli.fp, ok=False)
    out = " ".join(r.output.split())
    assert r.exit_code != 0 and find_vm(si, "win11-standalone2") is None
    assert "KB 369538" in out and "keyprovider add -p sim" not in out


def test_iso_picker_finds_isos_and_a_copy_is_reused_only_when_verified(cli, si):
    """Security review: an existing vmdeploy-iso/ file is reused only when the caller verified its full SHA-256;
    otherwise the copy goes to an unused name, and nothing is overwritten."""
    from vsphere_vm_deployment import isolib
    from vsphere_vm_deployment.connection import Connection
    from vsphere_vm_deployment.inventory import discover

    dc_obj = _windows_iso_on_datastore(cli, si, "en-us_windows_server_2022_x64.iso")
    conn = Connection(si=si, profile=None, decision=None, trust=None)
    dc = discover(conn).datacenters["DC0"]
    found = [i.full for i in isolib.find_isos(dc)]
    assert "[LocalDS_0] ISO/en-us_windows_server_2022_x64.iso" in found
    ds = dc.datastores["LocalDS_0"].obj
    target = "[LocalDS_0] vmdeploy-iso/en-us_windows_server_2022_x64.iso"
    source = "[LocalDS_0] ISO/en-us_windows_server_2022_x64.iso"
    assert isolib.ensure_copied(conn, dc_obj, source, ds, target) == (target, "copied by vCenter, host to host")
    # Not verified (no checksum to compare with): a new copy under an unused name, the first one untouched.
    second = target.replace(".iso", "-2.iso")
    assert isolib.ensure_copied(conn, dc_obj, source, ds, target) == (second, "copied by vCenter, host to host")
    # Verified by the caller: the existing copy is used.
    assert isolib.ensure_copied(conn, dc_obj, source, ds, target, reuse_if=lambda full: True) == \
        (target, "copied earlier; checked; reused")
    # Only copies of this ISO with the source's size are offered to the caller's check, the plain name first.
    assert isolib.copies_in(ds, target, isolib._size(conn, dc_obj, source)) == [target, second]
    assert isolib.copies_in(ds, target, 1) == []


# ------------------------------------------------------------------------------------------------- datastore files
def _put_on_datastore(si, port, local_path, ds_path):
    """Test helper: upload a file to [LocalDS_0] via the datastore HTTP interface (vcsim)."""
    import ssl
    import urllib.parse
    import urllib.request

    cookie = si._stub.cookie.split(";", 1)[0]
    q = urllib.parse.urlencode({"dcPath": "DC0", "dsName": "LocalDS_0"})
    req = urllib.request.Request(f"https://127.0.0.1:{port}/folder/{urllib.parse.quote(ds_path)}?{q}",
                                 data=Path(local_path).read_bytes(), method="PUT", headers={"Cookie": cookie})
    urllib.request.urlopen(req, context=ssl._create_unverified_context()).read()  # noqa: S323 - test only


def test_ova_already_on_a_datastore_is_read_and_deployed(cli, si, vcsim):
    build_ova(cli.tmp / "appliance.ova")
    _put_on_datastore(si, vcsim["port"], cli.tmp / "appliance.ova", "library/appliance.ova")
    m = manifest(cli.tmp, """
vm: {name: from-ds-ova}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
networks: [{portgroup: VM Network}]
guest: {enabled: false}
post_deploy: {power_on: false}
""")
    r = cli("deploy", "-f", m, "--datastore-file", "[LocalDS_0] library/appliance.ova", "--yes",
            "--trust-fingerprint", cli.fp)
    out = " ".join(r.output.split())
    assert "read through this computer" in out and "Package manifest" in out
    assert find_vm(si, "from-ds-ova") is not None


def test_datastore_iso_checksum_is_verified_when_given(cli, si, vcsim):
    import hashlib

    data = os.urandom(512 * 1024)
    (cli.tmp / "check.iso").write_bytes(data)
    _put_on_datastore(si, vcsim["port"], cli.tmp / "check.iso", "ISO/check.iso")
    good = hashlib.sha256(data).hexdigest()
    base = """
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
hardware: {guest_os: otherGuest64}
networks: [{portgroup: VM Network}]
post_deploy: {power_on: false}
"""
    r = cli("deploy", "-f", manifest(cli.tmp, "vm: {name: iso-sum-bad}" + base), "--datastore-file",
            "[LocalDS_0] ISO/check.iso", "--sha256", "0" * 64, "--yes", "--trust-fingerprint", cli.fp, ok=False)
    assert r.exit_code != 0 and "does not match" in r.output and find_vm(si, "iso-sum-bad") is None
    r = cli("deploy", "-f", manifest(cli.tmp, "vm: {name: iso-sum-ok}" + base), "--datastore-file",
            "[LocalDS_0] ISO/check.iso", "--sha256", good, "--yes", "--trust-fingerprint", cli.fp)
    assert "SHA-256 matches the value you supplied" in " ".join(r.output.split())


def test_second_upload_of_the_same_iso_is_reused(cli, si):
    (cli.images / "reuse-me.iso").write_bytes(os.urandom(256 * 1024))
    base = """
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
hardware: {guest_os: otherGuest64}
networks: [{portgroup: VM Network}]
post_deploy: {power_on: false}
"""
    cli("deploy", "-f", manifest(cli.tmp, "vm: {name: reuse-1}" + base), "--local", "reuse-me.iso", "--yes",
        "--trust-fingerprint", cli.fp)
    r = cli("deploy", "-f", manifest(cli.tmp, "vm: {name: reuse-2}" + base), "--local", "reuse-me.iso", "--yes",
            "--trust-fingerprint", cli.fp)
    out = " ".join(r.output.split())
    # found before the review (contents sampled) or, if ranged reads are unavailable, at upload time
    assert "contents match (sampled); used where it is" in out or \
        "uploaded earlier; same name and size; no upload needed" in out
    cd = next(d for d in find_vm(si, "reuse-2").config.hardware.device if isinstance(d, vim.vm.device.VirtualCdrom))
    assert cd.backing.fileName == "[LocalDS_0] vmdeploy-iso/reuse-me.iso"


def test_a_planted_copy_that_passes_sampling_is_never_used(cli, si, vcsim):
    """Security review: another account with file rights on a datastore could put a different file with the
    image's name and size, even with the bytes vmdeploy samples, into vmdeploy-iso/. Before the VM uses any
    existing copy its full SHA-256 is checked; the genuine ISO is uploaded under an unused name instead, and the
    planted file is left alone."""
    from vsphere_vm_deployment.deploy import Deployment

    size, piece = 16 * 1024 * 1024, 1024 * 1024
    genuine = os.urandom(size)
    (cli.images / "golden.iso").write_bytes(genuine)
    sampled = {min(size - piece, size * i // (Deployment.SAMPLES - 1)) for i in range(Deployment.SAMPLES)}
    hole = next(o for o in range(0, size, piece) if all(not (s <= o < s + piece) for s in sampled))
    planted = bytearray(genuine)
    planted[hole:hole + 16] = b"\x90" * 16  # outside every sampled window
    (cli.tmp / "golden.iso").write_bytes(bytes(planted))
    _put_on_datastore(si, vcsim["port"], cli.tmp / "golden.iso", "vmdeploy-iso/golden.iso")
    base = """
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
hardware: {guest_os: otherGuest64}
networks: [{portgroup: VM Network}]
post_deploy: {power_on: false}
"""
    r = cli("deploy", "-f", manifest(cli.tmp, "vm: {name: golden-vm}" + base), "--local", "golden.iso", "--yes",
            "--trust-fingerprint", cli.fp)
    out = " ".join(r.output.split())
    if "contents match (sampled)" in out:  # ranged reads available: sampling was fooled, the full check was not
        assert "has different content; not used" in out
    cd = next(d for d in find_vm(si, "golden-vm").config.hardware.device if isinstance(d, vim.vm.device.VirtualCdrom))
    assert cd.backing.fileName == "[LocalDS_0] vmdeploy-iso/golden-2.iso"
    from vsphere_vm_deployment import isolib

    ds = next(d for d in si.RetrieveContent().rootFolder.childEntity[0].datastore if d.name == "LocalDS_0")
    assert isolib._size_on(ds, "LocalDS_0", "vmdeploy-iso", "golden.iso") == size  # the planted file untouched


def test_windows_11_below_microsofts_minimum_is_blocked(cli, si):
    _windows_iso_on_datastore(cli, si, "Win11_small.iso")
    m = manifest(cli.tmp, """
vm: {name: win11-small}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
resources: {cpu: 1, memory_gb: 2, disk_gb: 40}
networks: [{portgroup: VM Network}]
""")
    r = cli("deploy", "-f", m, "--datastore-file", "[LocalDS_0] ISO/Win11_small.iso", "--yes",
            "--trust-fingerprint", cli.fp, ok=False)
    out = " ".join(r.output.split())
    assert r.exit_code == 2 and "Below Microsoft's minimum for Windows 11" in out and "refuse to install" in out
    assert find_vm(si, "win11-small") is None  # nothing was created


def test_windows_server_without_sizing_gets_the_suggested_values(cli, si):
    _windows_iso_on_datastore(cli, si, "en-us_windows_server_2022_x64.iso")
    m = manifest(cli.tmp, """
vm: {name: ws2022-defaults}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
networks: [{portgroup: VM Network}]
post_deploy: {power_on: false}
""")
    cli("deploy", "-f", m, "--datastore-file", "[LocalDS_0] ISO/en-us_windows_server_2022_x64.iso", "--yes",
        "--trust-fingerprint", cli.fp)
    vm = find_vm(si, "ws2022-defaults")
    hw = vm.config.hardware
    disk = next(d for d in hw.device if isinstance(d, vim.vm.device.VirtualDisk))
    # never below Microsoft's minimum (1 vCPU, 2 GB, 32 GB); VMware's recommendation when the host reports one
    assert hw.numCPU >= 1 and hw.memoryMB >= 2048 and disk.capacityInKB >= 32 * 1024 * 1024
    assert vm.config.guestId == "windows2019srvNext_64Guest"


# ------------------------------------------------------------------------------------------------- ISO copies
def _iso_vm(cli, name, iso):
    base = """
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
hardware: {guest_os: otherGuest64}
networks: [{portgroup: VM Network}]
post_deploy: {power_on: false}
"""
    cli("deploy", "-f", manifest(cli.tmp, f"vm: {{name: {name}}}" + base), "--local", iso, "--yes",
        "--trust-fingerprint", cli.fp)


def _copy_exists(si, fname):
    from vsphere_vm_deployment import isolib

    ds = si.RetrieveContent().rootFolder.childEntity[0].datastore[0]
    return isolib._size_on(ds, "LocalDS_0", "vmdeploy-iso", fname) is not None


def test_destroy_offers_the_iso_copy_separately(cli, si):
    (cli.images / "shared-copy.iso").write_bytes(os.urandom(128 * 1024))
    _iso_vm(cli, "iso-user-a", "shared-copy.iso")
    _iso_vm(cli, "iso-user-b", "shared-copy.iso")  # reuses the same copy
    r = cli("destroy", "iso-user-a", "--yes", "--trust-fingerprint", cli.fp, "--delete-iso")
    assert "still used by iso-user-b" in " ".join(r.output.split()) and _copy_exists(si, "shared-copy.iso")
    r = cli("destroy", "iso-user-b", "--yes", "--trust-fingerprint", cli.fp)  # --yes alone keeps it
    assert "Kept" in r.output and _copy_exists(si, "shared-copy.iso")


def test_images_prune_lists_and_deletes_only_unused_copies(cli, si):
    (cli.images / "prune-me.iso").write_bytes(os.urandom(128 * 1024))
    (cli.images / "keep-me.iso").write_bytes(os.urandom(128 * 1024))
    _iso_vm(cli, "prune-a", "prune-me.iso")
    _iso_vm(cli, "keep-a", "keep-me.iso")
    cli("destroy", "prune-a", "--yes", "--trust-fingerprint", cli.fp, "--keep-iso")
    r = cli("images", "prune", "--yes", "--trust-fingerprint", cli.fp)
    out = " ".join(r.output.split())
    assert "unused copy(ies)" in out and "--delete-unused" in out  # (file names wrap in the narrow test table)
    assert _copy_exists(si, "prune-me.iso")  # listing only
    cli("images", "prune", "--yes", "--trust-fingerprint", cli.fp, "--delete-unused")
    assert not _copy_exists(si, "prune-me.iso") and _copy_exists(si, "keep-me.iso")
    cli("destroy", "keep-a", "--yes", "--trust-fingerprint", cli.fp, "--delete-iso")  # last copy: folder goes too
    from vsphere_vm_deployment.isocopies import folder_entries

    left = folder_entries(si.RetrieveContent().rootFolder.childEntity[0].datastore[0], "LocalDS_0")
    assert not _copy_exists(si, "keep-me.iso") and left != []  # removed, or still holds other tests' copies


# ------------------------------------------------------------------------------------------------ any ISO / OVA / OVF
def test_appliance_ova_on_a_datastore_offers_its_sizes(cli, si, vcsim):
    from ovabuilder import build_appliance_ova

    build_appliance_ova(cli.tmp / "vise.ova")
    _put_on_datastore(si, vcsim["port"], cli.tmp / "vise.ova", "appliances/vise.ova")
    base = """
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
networks: [{portgroup: VM Network}]
post_deploy: {power_on: false}
"""
    src = ["--datastore-file", "[LocalDS_0] appliances/vise.ova", "--yes", "--trust-fingerprint", cli.fp]
    r = cli("deploy", "-f", manifest(cli.tmp, "vm: {name: vise-bad}\novf: {deployment_option: huge}" + base), *src,
            ok=False)
    assert r.exit_code == 2 and "not defined by the image" in r.output and find_vm(si, "vise-bad") is None

    r = cli("deploy", "-f", manifest(cli.tmp, "vm: {name: vise-medium}\novf: {deployment_option: medium}" + base),
            *src)
    out = " ".join(r.output.split())
    assert "Deployment sizes defined by the image: Eval (4 vCPU, 4 GB RAM); Small (8 vCPU, 8 GB RAM); " \
           "Medium (12 vCPU, 12 GB RAM)" in out
    hw = find_vm(si, "vise-medium").config.hardware
    assert hw.numCPU == 12 and hw.memoryMB == 12288  # the image's own sizing for that size, nothing typed

    # Less memory than the size reserves: the reservation follows, otherwise vCenter refuses the change.
    cli("deploy", "-f", manifest(cli.tmp, "vm: {name: vise-small-2g}\novf: {deployment_option: small}\n"
                                          "resources: {memory_gb: 2}" + base), *src)
    vm = find_vm(si, "vise-small-2g")
    assert vm.config.hardware.numCPU == 8 and vm.config.hardware.memoryMB == 2048
    assert (vm.config.memoryAllocation.reservation or 0) <= 2048


def test_loose_ovf_on_a_datastore_is_read_with_its_files(cli, si, vcsim):
    from ovabuilder import build_ovf_folder

    ovf = build_ovf_folder(cli.tmp / "loose")
    for f in ovf.parent.iterdir():
        _put_on_datastore(si, vcsim["port"], f, f"exports/loose/{f.name}")
    m = manifest(cli.tmp, """
vm: {name: from-ds-ovf}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
networks: [{portgroup: VM Network}]
guest: {enabled: false}
post_deploy: {power_on: false}
""")
    r = cli("deploy", "-f", m, "--datastore-file", "[LocalDS_0] exports/loose/loose-ovf.ovf", "--yes",
            "--trust-fingerprint", cli.fp)
    assert "Package manifest: 2 file(s) verified" in " ".join(r.output.split())
    assert find_vm(si, "from-ds-ovf") is not None


def test_eve_ng_iso_is_recognised_and_gets_nested_virtualisation(cli, si):
    _windows_iso_on_datastore(cli, si, "eve-pro-prod-bm-6.5.0-16-full.iso")  # (any ISO; the name is what counts)
    m = manifest(cli.tmp, """
vm: {name: eve-test}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
networks: [{portgroup: VM Network}]
post_deploy: {power_on: false}
""")
    r = cli("deploy", "-f", m, "--datastore-file", "[LocalDS_0] ISO/eve-pro-prod-bm-6.5.0-16-full.iso", "--yes",
            "--trust-fingerprint", cli.fp)
    assert "nested virtualisation" in " ".join(r.output.split())
    vm = find_vm(si, "eve-test")
    assert vm.config.guestId == "ubuntu64Guest" and vm.config.nestedHVEnabled is True
    assert not vm.config.bootOptions.efiSecureBootEnabled
    assert any(isinstance(d, vim.vm.device.ParaVirtualSCSIController) for d in vm.config.hardware.device)


def test_datastore_ova_needs_free_space_on_this_computer(cli, si, vcsim, monkeypatch):
    import shutil
    from collections import namedtuple

    build_ova(cli.tmp / "toobig.ova")
    _put_on_datastore(si, vcsim["port"], cli.tmp / "toobig.ova", "library/toobig.ova")
    real = shutil.disk_usage
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(shutil, "disk_usage", lambda p: usage(real(p).total, real(p).total, 0))
    m = manifest(cli.tmp, "vm: {name: no-space}\nplacement: {cluster: DC0_C0, host: DC0_C0_H0}\n")
    r = cli("deploy", "-f", m, "--datastore-file", "[LocalDS_0] library/toobig.ova", "--yes",
            "--trust-fingerprint", cli.fp, ok=False)
    out = " ".join(r.output.split())
    assert r.exit_code != 0 and "Not enough free space on this computer" in out and find_vm(si, "no-space") is None


def test_clear_cache_reports_the_space_freed(cli):
    r = cli("images", "clear-cache")
    assert "GB freed" in r.output


def test_vcls_folder_is_not_offered(vcsim, isolated_dirs):
    from vsphere_vm_deployment.deploy import Deployment

    class Dc:
        folders = {"/": object(), "/vCLS": object(), "/Apps": object()}

    seen = {}

    class P:
        def select(self, q, choices, **kw):
            seen["choices"] = [v for _, v in choices]
            return "/"

        def record(self, *a):
            pass

    d = Deployment.__new__(Deployment)
    d.p, d.m = P(), type("M", (), {"placement": type("Pl", (), {"folder": None})()})()
    d._ask_folder(Dc())
    assert seen["choices"] == ["/", "/Apps"]


def test_eve_ng_gets_the_cookbook_settings(cli, si):
    _windows_iso_on_datastore(cli, si, "eve-pro-prod-bm-7.0.1-21-full.iso")
    m = manifest(cli.tmp, """
vm: {name: eve-cookbook}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
networks: [{portgroup: VM Network}]
post_deploy: {power_on: false}
""")
    r = cli("deploy", "-f", m, "--datastore-file", "[LocalDS_0] ISO/eve-pro-prod-bm-7.0.1-21-full.iso", "--yes",
            "--trust-fingerprint", cli.fp)
    out = " ".join(r.output.split())
    assert "Recognised EVE-NG 7: using EVE-NG's recommended settings" in out and "Cookbook" not in out
    vm = find_vm(si, "eve-cookbook")
    hw = vm.config.hardware
    disk = next(d for d in hw.device if isinstance(d, vim.vm.device.VirtualDisk))
    assert hw.numCPU >= 8 and hw.memoryMB >= 16384 and disk.capacityInKB >= 120 * 1024 * 1024  # never below EVE's
    assert hw.numCoresPerSocket == hw.numCPU  # "CPU 1/8": one socket
    assert disk.backing.eagerlyScrub is True  # "Thick Provisioned eagerly" recommended
    assert vm.config.nestedHVEnabled is True and vm.config.flags.vvtdEnabled is True
    assert vm.config.firmware == "efi" and not vm.config.bootOptions.efiSecureBootEnabled


def test_ise_named_ova_follows_ciscos_rules(cli, si, vcsim):
    from ovabuilder import build_appliance_ova

    build_appliance_ova(cli.images / "Cisco-vISE-300-3.4.0.608b.ova", name="Cisco-vISE-300-3.4.0.608")
    m = manifest(cli.tmp, """
vm: {name: ise-rules}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
networks: [{portgroup: VM Network}]
ovf: {deployment_option: small}
resources: {memory_gb: 4}
post_deploy: {power_on: true, snapshot: true}
""")
    r = cli("deploy", "-f", m, "--local", "Cisco-vISE-300-3.4.0.608b.ova", "--yes", "--trust-fingerprint", cli.fp)
    out = " ".join(r.output.split())
    assert "Recognised Cisco ISE 3.4" in out
    assert "Cisco does not support snapshots" in out and "Less CPU or memory than Cisco ISE 3.4" in out
    vm = find_vm(si, "ise-rules")
    assert not vm.rootSnapshot and "clean-baseline" not in out  # no snapshot, as Cisco requires
    assert vm.config.nestedHVEnabled is True  # 3.4 guide: expose hardware-assisted virtualization


def test_failed_host_to_host_copy_falls_back_to_this_computer(cli, si, monkeypatch):
    from vsphere_vm_deployment import isolib
    from vsphere_vm_deployment.deploy import Deployment
    from vsphere_vm_deployment.errors import DeploymentError

    _windows_iso_on_datastore(cli, si, "locked-source.iso")
    original = Deployment._check_iso_on_datastore

    def pretend_other_host(self):  # vcsim's datastores are shared: pretend the target host cannot see the ISO
        original(self)
        self.plan.iso_copy_from = self.plan.iso_datastore_path
        self.plan.iso_datastore_path = "[LocalDS_0] vmdeploy-iso/locked-source.iso"

    def refuse(*a, **k):
        raise DeploymentError("Copy ISO failed: Unable to access file [LocalDS_0] ISO/locked-source.iso")

    monkeypatch.setattr(Deployment, "_check_iso_on_datastore", pretend_other_host)
    monkeypatch.setattr(isolib, "ensure_copied", refuse)
    m = manifest(cli.tmp, """
vm: {name: copy-fallback}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
hardware: {guest_os: otherGuest64}
networks: [{portgroup: VM Network}]
post_deploy: {power_on: false}
""")
    r = cli("deploy", "-f", m, "--datastore-file", "[LocalDS_0] ISO/locked-source.iso", "--yes",
            "--trust-fingerprint", cli.fp)
    out = " ".join(r.output.split())
    assert "vCenter could not copy the ISO" in out
    cd = next(d for d in find_vm(si, "copy-fallback").config.hardware.device if isinstance(d, vim.vm.device.VirtualCdrom))
    assert cd.backing.fileName == "[LocalDS_0] vmdeploy-iso/locked-source.iso"

    r = cli("deploy", "-f", manifest(cli.tmp, "vm: {name: copy-refused}\nimage: {fallback_via_pc: false}\n"
                                              "placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}\n"
                                              "hardware: {guest_os: otherGuest64}\n"
                                              "networks: [{portgroup: VM Network}]\n"),
            "--datastore-file", "[LocalDS_0] ISO/locked-source.iso", "--yes", "--trust-fingerprint", cli.fp, ok=False)
    assert r.exit_code != 0 and find_vm(si, "copy-refused") is None


def test_prune_removes_empty_vmdeploy_iso_folders(cli, si):
    from vsphere_vm_deployment.tasks import wait_task

    (cli.images / "empty-me.iso").write_bytes(os.urandom(64 * 1024))
    _iso_vm(cli, "empty-a", "empty-me.iso")
    cli("destroy", "empty-a", "--yes", "--trust-fingerprint", cli.fp, "--keep-iso")
    c = si.RetrieveContent()
    dc = c.rootFolder.childEntity[0]
    ds = dc.datastore[0]  # delete the copy by hand, as an administrator might, leaving the empty folder
    res = wait_task(ds.browser.SearchDatastore_Task(datastorePath="[LocalDS_0] vmdeploy-iso",
                                                    searchSpec=vim.host.DatastoreBrowser.SearchSpec(matchPattern=["*"])))
    for f in res.file or []:
        wait_task(c.fileManager.DeleteDatastoreFile_Task(name=f"[LocalDS_0] vmdeploy-iso/{f.path}", datacenter=dc))
    r = cli("access", "audit", "--yes", "--trust-fingerprint", cli.fp, ok=False)
    assert "empty vmdeploy-iso folder" in " ".join(r.output.split())
    r = cli("images", "prune", "--yes", "--trust-fingerprint", cli.fp)
    assert "Empty vmdeploy-iso/ folder(s)" in " ".join(r.output.split())
    cli("images", "prune", "--yes", "--trust-fingerprint", cli.fp, "--delete-unused")
    from vsphere_vm_deployment.isocopies import folder_entries

    assert folder_entries(ds, "LocalDS_0") is None  # folder gone


def test_audit_lists_only_the_iso_copies_no_vm_uses(cli, si):
    """Real-environment smoke test: `access audit` listed vmdeploy-iso folders under "Files on datastores not used by
    any VM" by their number of ISO copies, including copies VMs were using; only unused ones are listed now."""
    import re

    def unused():
        r = cli("access", "audit", "--yes", "--trust-fingerprint", cli.fp, ok=False)
        out = " ".join(r.output.replace("│", " ").split())  # table cells wrap at the test's terminal width
        return sum(int(n) for n in re.findall(r"(\d+) of \d+ ISO copies by vmdeploy, used by no VM", out))

    (cli.images / "audit-me.iso").write_bytes(os.urandom(64 * 1024))
    before = unused()
    _iso_vm(cli, "audit-a", "audit-me.iso")
    assert unused() == before  # attached to audit-a: in use, not a leftover
    cli("destroy", "audit-a", "--yes", "--trust-fingerprint", cli.fp, "--keep-iso")
    assert unused() == before + 1


def test_switched_off_first_boot_keeps_cloud_init_defaults(cli, si):
    build_ova(cli.images / "ci-off.ova", name="ci-off",
              extra_props='<Property ovf:key="admin-ip" ovf:type="string" ovf:userConfigurable="true" '
                          'ovf:value="192.0.2.10"><Label>Appliance IP</Label></Property>')
    m = manifest(cli.tmp, """
vm: {name: ci-off}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
networks: [{portgroup: VM Network}]
guest: {enabled: false}
post_deploy: {power_on: false}
""")
    cli("deploy", "-f", m, "--local", "ci-off.ova", "--yes", "--trust-fingerprint", cli.fp)
    # a property nobody set keeps the image's default (vcsim reports it as defaultValue, not value)
    props = {p.id: p.value or p.defaultValue for p in find_vm(si, "ci-off").config.vAppConfig.property}
    assert props.get("instance-id") == "id-ovf" and not props.get("user-data")  # image defaults, nothing generated
    assert props.get("admin-ip") == "192.0.2.10"  # other appliance settings still handled (default in --yes)


def test_boolean_appliance_settings_reach_vcenter_as_True_or_False(cli, si):
    """Like Cisco's Catalyst 8000V: boolean properties whose default is the OVF spelling 'false', which vCenter
    rejects ("Invalid value 'false' specified for property ..."). Sent as True/False, from the image's default
    and from a manifest's YAML boolean alike; a bad value is refused before anything is created."""
    props = ('<Property ovf:key="enable-scp-server" ovf:type="boolean" ovf:userConfigurable="true" '
             'ovf:value="false"><Label>Enable SCP Server</Label></Property>'
             '<Property ovf:key="enable-ssh-server" ovf:type="boolean" ovf:userConfigurable="true" '
             'ovf:value="false"><Label>Enable SSH Server</Label></Property>'
             '<Property ovf:key="agent-port" ovf:type="uint16" ovf:qualifiers="MinValue(1025) MaxValue(65535)" '
             'ovf:userConfigurable="true" ovf:value=""><Label>Agent port</Label></Property>')
    build_ova(cli.images / "bools.ova", name="bools", extra_props=props)
    base = """
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
networks: [{portgroup: VM Network}]
guest: {enabled: false}
post_deploy: {power_on: false}
"""
    bad = manifest(cli.tmp, "vm: {name: bools-bad}\novf: {properties: {agent-port: 80}}" + base)
    r = cli("deploy", "-f", bad, "--local", "bools.ova", "--yes", "--trust-fingerprint", cli.fp, ok=False)
    assert r.exit_code != 0 and "Must be between 1025 and 65535" in r.output and find_vm(si, "bools-bad") is None
    m = manifest(cli.tmp, "vm: {name: bools}\novf: {properties: {enable-ssh-server: true}}" + base)
    cli("deploy", "-f", m, "--local", "bools.ova", "--yes", "--trust-fingerprint", cli.fp)
    props = {p.id: p.value or p.defaultValue for p in find_vm(si, "bools").config.vAppConfig.property}
    assert props["enable-scp-server"] == "False" and props["enable-ssh-server"] == "True"


def test_ctrl_c_during_the_disk_upload_leaves_nothing_behind(cli, si, monkeypatch):
    from vsphere_vm_deployment import deploy as deploy_mod

    def interrupted(*a, progress=None, **k):
        if progress:
            progress(1024)
        raise KeyboardInterrupt

    build_ova(cli.images / "cancel-me.ova", name="cancel-me")
    monkeypatch.setattr(deploy_mod, "upload_stream", interrupted)
    monkeypatch.setattr(deploy_mod.Deployment, "IMPORT_ABORT_WAIT_S", 2)  # vcsim never removes it: vmdeploy does
    m = manifest(cli.tmp, """
vm: {name: cancel-me}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
networks: [{portgroup: VM Network}]
guest: {enabled: false}
post_deploy: {power_on: false}
""")
    r = cli("deploy", "-f", m, "--local", "cancel-me.ova", "--yes", "--trust-fingerprint", cli.fp, ok=False)
    out = " ".join(r.output.split())
    assert r.exit_code == 130 and find_vm(si, "cancel-me") is None
    assert "Nothing is left behind" in out or "Removed the partially created VM" in out
    from vsphere_vm_deployment import isolib

    ds = si.RetrieveContent().rootFolder.childEntity[0].datastore[0]
    assert isolib._size_on(ds, "LocalDS_0", "", "cancel-me") is None  # no folder left on the datastore


def test_aborted_import_folder_is_deleted_when_vcenter_leaves_it(cli, si, monkeypatch):
    """Real vCenter 8.0.3 unregisters an aborted import's VM but leaves its folder: vmdeploy deletes that folder,
    and nothing that is not a top-level VM folder."""
    from types import SimpleNamespace

    from vsphere_vm_deployment import isolib
    from vsphere_vm_deployment.connection import Connection
    from vsphere_vm_deployment.deploy import Deployment

    c = si.RetrieveContent()
    dc = c.rootFolder.childEntity[0]
    ds = dc.datastore[0]
    c.fileManager.MakeDirectory(name="[LocalDS_0] left-by-import", datacenter=dc, createParentDirectories=True)
    d = Deployment.__new__(Deployment)
    d.conn = Connection(si=si, profile=None, decision=None, trust=None)
    d.plan = SimpleNamespace(datastore=SimpleNamespace(obj=ds), dc=SimpleNamespace(obj=dc))
    d.vm_dir = "[LocalDS_0] "  # the datastore root is never deleted
    assert d._delete_import_folder() == "none"
    d.vm_dir = "[LocalDS_0] left-by-import/deeper"  # nor anything below a VM folder
    assert d._delete_import_folder() == "none"
    d.vm_dir = "[LocalDS_0] left-by-import"
    assert d._folder_exists("LocalDS_0", "left-by-import")

    # the host still holds the files right after the abort: the first delete fails, a retry succeeds
    real_fm = c.fileManager
    calls = []

    class BusyOnce:
        def DeleteDatastoreFile_Task(self, **kw):
            calls.append(kw["name"])
            if len(calls) == 1:
                raise RuntimeError("Cannot delete file [LocalDS_0] left-by-import")
            return real_fm.DeleteDatastoreFile_Task(**kw)

    d.conn = SimpleNamespace(content=SimpleNamespace(fileManager=BusyOnce()))
    monkeypatch.setattr("vsphere_vm_deployment.deploy.time.sleep", lambda s: None)
    assert d._delete_import_folder() == "deleted" and len(calls) == 2
    assert not d._folder_exists("LocalDS_0", "left-by-import")
    assert isolib._size_on(ds, "LocalDS_0", "", "left-by-import") is None


def test_local_iso_already_on_a_datastore_is_used_instead_of_uploaded(cli, si, vcsim):
    data = os.urandom(3 * 1024 * 1024)
    (cli.images / "already-there.iso").write_bytes(data)
    (cli.tmp / "already-there.iso").write_bytes(data)
    _put_on_datastore(si, vcsim["port"], cli.tmp / "already-there.iso", "library/already-there.iso")
    base = """
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
hardware: {guest_os: otherGuest64}
networks: [{portgroup: VM Network}]
post_deploy: {power_on: false}
"""
    r = cli("deploy", "-f", manifest(cli.tmp, "vm: {name: same-iso}" + base), "--local", "already-there.iso",
            "--yes", "--trust-fingerprint", cli.fp)
    out = " ".join(r.output.split())
    cd = next(d for d in find_vm(si, "same-iso").config.hardware.device if isinstance(d, vim.vm.device.VirtualCdrom))
    if "contents match" in out:  # the server honours ranged reads: used where it is, nothing uploaded
        assert cd.backing.fileName == "[LocalDS_0] library/already-there.iso"
    else:  # ranges not available: never used unverified in --yes mode; uploaded as usual
        assert cd.backing.fileName == "[LocalDS_0] vmdeploy-iso/already-there.iso"

    # a file with the same name and size but different content is never used
    (cli.images / "already-there.iso").write_bytes(os.urandom(3 * 1024 * 1024))
    r = cli("deploy", "-f", manifest(cli.tmp, "vm: {name: same-name-other-iso}" + base), "--local",
            "already-there.iso", "--yes", "--trust-fingerprint", cli.fp)
    cd = next(d for d in find_vm(si, "same-name-other-iso").config.hardware.device
              if isinstance(d, vim.vm.device.VirtualCdrom))
    assert cd.backing.fileName != "[LocalDS_0] library/already-there.iso"


def test_cancelled_iso_upload_deletes_the_partial_file(cli, si, monkeypatch):
    from vsphere_vm_deployment import deploy as deploy_mod

    real_upload = deploy_mod.upload_stream

    def cut_short(decision, method, path, stream, size, **kw):
        import io

        part = stream.read(64 * 1024)
        real_upload(decision, method, path, io.BytesIO(part), len(part), **{**kw, "progress": None})
        raise KeyboardInterrupt  # Ctrl+C after part of the ISO reached the datastore

    (cli.images / "cut-short.iso").write_bytes(os.urandom(512 * 1024))
    monkeypatch.setattr(deploy_mod, "upload_stream", cut_short)
    m = manifest(cli.tmp, """
vm: {name: cut-short}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
hardware: {guest_os: otherGuest64}
networks: [{portgroup: VM Network}]
post_deploy: {power_on: false}
""")
    r = cli("deploy", "-f", m, "--local", "cut-short.iso", "--yes", "--trust-fingerprint", cli.fp, ok=False)
    assert r.exit_code == 130 and "Deleted the partly uploaded ISO" in " ".join(r.output.split())
    assert not _copy_exists(si, "cut-short.iso") and find_vm(si, "cut-short") is None


def test_keyprovider_backup_reports_a_vcenter_without_one(cli):
    """The simulator has no Native Key Provider (and no crypto REST API): the command must say so plainly."""
    r = cli("keyprovider", "backup", "--yes", "--no-password", "--trust-fingerprint", cli.fp, ok=False)
    out = " ".join(r.output.split())
    assert r.exit_code != 0 and "Unexpected error" not in out
    assert "no Native Key Provider" in out or "Could not list the key providers" in out


# ------------------------------------------------------------------------------------------------- batch
def _batch_doc(r) -> dict:
    return json.loads(r.stdout[r.stdout.index("{"):])


def test_batch_ova_to_several_hosts_with_patterns_and_addresses(cli, si):
    """One OVA to three hosts (one of them twice), names and hostnames from patterns, static addresses from a
    range, built in parallel over cloned sessions; the results file and the summary list every VM."""
    build_ova(cli.images / "ubuntu-test.ova")
    m = manifest(cli.tmp, """
resources: {cpu: 1, memory_gb: 1}
networks: [{portgroup: VM Network}]
guest:
  username: tester
  ssh_authorized_keys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey tester@ci"]
post_deploy: {power_on: true, wait_for_ip: false, snapshot: false}
batch:
  name: "bt-web-{n:02}"
  hostname: "web{n}-{host}"
  targets:
    - {host: DC0_C0_H0, datastore: LocalDS_0}
    - {host: DC0_C0_H1, datastore: auto, count: 2}
    - {host: DC0_H0, datastore: LocalDS_0}
  addresses: {mode: static, range: 203.0.113.60-70, prefix: 24, gateway: 203.0.113.1, dns: [203.0.113.1]}
  parallel: {vms: 3, uploads: 2, per_host: 1}
""")
    r = cli("deploy", "-f", m, "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp, "--json")
    doc = _batch_doc(r)
    assert doc["exit_code"] == 0 and doc["totals"]["deployed"] == 4, r.output
    names = [v["name"] for v in doc["vms"]]
    assert names == ["bt-web-01", "bt-web-02", "bt-web-03", "bt-web-04"]
    assert [v["host"] for v in doc["vms"]] == ["DC0_C0_H0", "DC0_C0_H1", "DC0_C0_H1", "DC0_H0"]
    assert [v["address"] for v in doc["vms"]] == [f"203.0.113.{x}/24" for x in (60, 61, 62, 63)]
    assert Path(doc["results_file"]).is_file() and "Batch finished" in r.stderr
    for v in doc["vms"]:
        vm = find_vm(si, v["name"])
        assert vm is not None and vm.runtime.host.name == v["host"]
        props = {p.id: p.value for p in vm.config.vAppConfig.property}
        user_data = base64.b64decode(props["user-data"]).decode()
        assert v["address"] in user_data and props["hostname"] == v["hostname"]
    assert doc["vms"][1]["hostname"] == "web2-DC0-C0-H1"  # a DNS label: "_" becomes "-"


def _fail_upload_for(monkeypatch, name: str) -> None:
    """The disk upload of VM `name` fails (connection reset); every other VM uploads normally."""
    from vsphere_vm_deployment import deploy as deploy_mod
    from vsphere_vm_deployment.logsetup import _context

    real = deploy_mod.upload_stream

    def upload(*a, **k):
        if getattr(_context, "label", None) == name:
            raise ConnectionResetError("connection reset by the host (test)")
        return real(*a, **k)

    monkeypatch.setattr(deploy_mod, "upload_stream", upload)
    monkeypatch.setattr(deploy_mod.Deployment, "IMPORT_ABORT_WAIT_S", 2)  # vcsim never removes it: vmdeploy does


BATCH_THREE = """
networks: [{portgroup: VM Network}]
guest: {enabled: false}
post_deploy: {power_on: false}
batch:
  name: "NAME-{n}"
  targets:
    - {host: DC0_C0_H0, datastore: LocalDS_0}
    - {host: DC0_C0_H1, datastore: LocalDS_0}
    - {host: DC0_C0_H2, datastore: LocalDS_0}
  parallel: {vms: VMS}
"""


def _three(name: str, vms: int = 3) -> str:
    return BATCH_THREE.replace("NAME", name).replace("VMS", str(vms))


def test_batch_failure_is_isolated_listed_and_retried(cli, si, monkeypatch):
    """One VM's upload fails: only it fails (its partial VM is removed), the others deploy, the exit code is 4, the
    summary names the host, step and reason, and --retry-failed deploys only that VM."""
    build_ova(cli.images / "ubuntu-test.ova")
    m = manifest(cli.tmp, _three("bt-fail"))
    args = ["deploy", "-f", m, "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp]
    # Only the failure is undone afterwards: monkeypatch.undo() would also undo the isolated config folders, and the
    # CLI would then use the real profile of whoever runs the tests.
    with monkeypatch.context() as failing:
        _fail_upload_for(failing, "bt-fail-2")
        r = cli(*args, "--json", ok=False)
    doc = _batch_doc(r)
    assert r.exit_code == 4 and doc["exit_code"] == 4
    by = {v["name"]: v for v in doc["vms"]}
    assert by["bt-fail-1"]["status"] == by["bt-fail-3"]["status"] == "deployed"
    assert by["bt-fail-2"]["status"] == "failed" and by["bt-fail-2"]["host"] == "DC0_C0_H1"
    assert by["bt-fail-2"]["step"] == "Upload disks" and "connection reset" in by["bt-fail-2"]["error"]
    assert find_vm(si, "bt-fail-2") is None and find_vm(si, "bt-fail-1") is not None
    out = " ".join(r.stderr.split())
    assert "Not deployed" in out and "--retry-failed" in out and "Upload disks" in out
    assert "partial" in out and doc["vms"][1]["kept"] is False

    r = cli(*args, "--retry-failed", doc["results_file"], "--json")
    again = _batch_doc(r)
    assert again["exit_code"] == 0 and [v["name"] for v in again["vms"]] == ["bt-fail-2"]
    assert find_vm(si, "bt-fail-2").runtime.host.name == "DC0_C0_H1"

    # destroy --batch with the batch's results file and its retry's: one confirmation for every VM they deployed.
    # A VM renamed since is still found (by its id, the file being from this vCenter); one whose Notes lost the
    # vmdeploy marker is refused and listed, so the exit code is 4.
    wait_task(find_vm(si, "bt-fail-1").Rename_Task(newName="bt-fail-1-renamed"))
    wait_task(find_vm(si, "bt-fail-3").ReconfigVM_Task(spec=vim.vm.ConfigSpec(annotation="someone else's VM")))
    r = cli("destroy", "--batch", doc["results_file"], "--batch", again["results_file"], "--yes",
            "--trust-fingerprint", cli.fp, ok=False)
    out = " ".join(r.output.split())
    assert r.exit_code == 4, out
    assert find_vm(si, "bt-fail-1-renamed") is None and find_vm(si, "bt-fail-2") is None
    assert find_vm(si, "bt-fail-3") is not None and "not deployed by vmdeploy" in out
    assert "bt-fail-1-renamed (was" in out and "Deleted 2 of 2" in out, out  # the cell may wrap
    wait_task(find_vm(si, "bt-fail-3").Destroy_Task())

    # Nothing left: the same files now only list VMs that are gone. `latest` is the newest file (the retry's).
    r = cli("destroy", "--batch", doc["results_file"], "--yes", "--trust-fingerprint", cli.fp)
    assert "Nothing to delete" in " ".join(r.output.split())
    r = cli("destroy", "--batch", "latest", "--yes", "--trust-fingerprint", cli.fp)
    out = " ".join(r.output.split())
    assert "Newest results file" in out and "Nothing to delete" in out
    r = cli("destroy", "bt-fail-1", "--batch", doc["results_file"], "--yes", "--trust-fingerprint", cli.fp, ok=False)
    assert r.exit_code == 2 and "leave out the VM name" in " ".join(r.output.split())


def test_dhcp_identifier_is_set_before_the_first_boot(cli, si):
    """DHCP: the guest identifies itself by NIC 1's MAC address, through a `network-config` OVF property that
    cloud-init reads before the network starts (the image does not declare it: it is added to the VM). With
    `dhcp_identifier: image` nothing is added."""
    build_ova(cli.images / "ubuntu-test.ova")
    guest = """
networks: [{portgroup: VM Network}]
guest:
  username: tester
  ssh_authorized_keys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey tester@ci"]
  DHCPID
post_deploy: {power_on: false}
batch:
  name: "NAME-{n}"
  targets: [{host: DC0_C0_H0, datastore: LocalDS_0, count: 2}]
"""
    for name, setting in (("bt-dhcp-mac", ""), ("bt-dhcp-image", "dhcp_identifier: image")):
        m = manifest(cli.tmp, guest.replace("NAME", name).replace("DHCPID", setting))
        r = cli("deploy", "-f", m, "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp, "--json")
        assert _batch_doc(r)["exit_code"] == 0, r.output
    for k in (1, 2):
        vm = find_vm(si, f"bt-dhcp-mac-{k}")
        props = {p.id: p.value for p in vm.config.vAppConfig.property}
        net = yaml.safe_load(base64.b64decode(props["network-config"]))["network"]
        eth = net["ethernets"]["primary"]
        mac = next(d.macAddress for d in vm.config.hardware.device if isinstance(d, vim.vm.device.VirtualEthernetCard))
        assert eth["dhcp4"] is True and eth["dhcp-identifier"] == "mac" and eth["match"]["macaddress"] == mac.lower()
        assert "network-config" not in {p.id for p in find_vm(si, f"bt-dhcp-image-{k}").config.vAppConfig.property}


def test_batch_stop_on_failure_and_keep_failed(cli, si, monkeypatch):
    """--stop-on-failure: after the first failure no new VM starts (listed as not started). --keep-failed: a VM
    that failed after it was created is kept, and the summary says so."""
    from vsphere_vm_deployment import deploy as deploy_mod
    from vsphere_vm_deployment.errors import DeploymentError
    from vsphere_vm_deployment.logsetup import _context

    build_ova(cli.images / "ubuntu-test.ova")
    real = deploy_mod.reconfigure_spec

    def reconfigure(vm, **k):
        if getattr(_context, "label", None) == "bt-stop-1":
            raise DeploymentError("Reconfigure VM failed: test")
        return real(vm, **k)

    monkeypatch.setattr(deploy_mod, "reconfigure_spec", reconfigure)
    m = manifest(cli.tmp, _three("bt-stop", 1))
    r = cli("deploy", "-f", m, "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp, "--json",
            "--stop-on-failure", "--keep-failed", ok=False)
    doc = _batch_doc(r)
    assert [v["status"] for v in doc["vms"]] == ["failed", "not-started", "not-started"] and r.exit_code == 1
    assert doc["vms"][0]["kept"] is True and find_vm(si, "bt-stop-1") is not None
    assert "kept" in " ".join(r.stderr.split())  # "failed (VM kept)", possibly wrapped in the narrow test terminal
    assert find_vm(si, "bt-stop-2") is None


def test_batch_name_clash_is_listed_with_where_the_vm_is(cli, si):
    """An existing name: the review says where that VM is (folder, host); --yes skips that VM and deploys the rest;
    `on_check_failure: cancel` changes nothing (exit code 2)."""
    build_ova(cli.images / "ubuntu-test.ova")
    cli("deploy", "-f", manifest(cli.tmp, """
vm: {name: bt-clash-2}
placement: {cluster: DC0_C0, host: DC0_C0_H2, datastore: LocalDS_0}
networks: [{portgroup: VM Network}]
guest: {enabled: false}
post_deploy: {power_on: false}
"""), "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp)
    cancel = manifest(cli.tmp, _three("bt-clash", 2) + "  on_check_failure: cancel\n")
    r = cli("deploy", "-f", cancel, "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp, ok=False)
    out = " ".join(r.output.split())
    assert r.exit_code == 2 and "already exists (folder /, host DC0_C0_H2)" in out
    assert find_vm(si, "bt-clash-1") is None
    r = cli("deploy", "-f", manifest(cli.tmp, _three("bt-clash", 2)), "--local", "ubuntu-test.ova", "--yes",
            "--trust-fingerprint", cli.fp, "--json", ok=False)
    doc = _batch_doc(r)
    assert r.exit_code == 4 and [v["status"] for v in doc["vms"]] == ["deployed", "skipped", "deployed"]
    assert "already exists (folder /, host DC0_C0_H2)" in doc["vms"][1]["error"]


def test_batch_iso_is_uploaded_once_and_drs_places_the_vms(cli, si):
    """An ISO batch: uploaded once, then used by every VM; a DRS cluster target places its VMs itself."""
    (cli.images / "batch.iso").write_bytes(os.urandom(1024 * 1024))
    _set_drs(si, "DC0_C0", True)
    try:
        m = manifest(cli.tmp, """
resources: {cpu: 1, memory_gb: 1, disk_gb: 8}
hardware: {guest_os: ubuntu64Guest, firmware: efi, secure_boot: false}
networks: [{portgroup: VM Network}]
post_deploy: {power_on: false}
batch:
  name: "bt-drs-{n}"
  targets:
    - {cluster: DC0_C0, drs: true, count: 2, datastore: LocalDS_0}
    - {host: DC0_H0, datastore: LocalDS_0}
""")
        r = cli("deploy", "-f", m, "--local", "batch.iso", "--yes", "--trust-fingerprint", cli.fp, "--json")
    finally:
        _set_drs(si, "DC0_C0", False)
    doc = _batch_doc(r)
    assert doc["exit_code"] == 0 and [v["host"] for v in doc["vms"]] == ["DC0_C0 (DRS)"] * 2 + ["DC0_H0"]
    for v in doc["vms"]:
        vm = find_vm(si, v["name"])
        cd = next(d for d in vm.config.hardware.device if isinstance(d, vim.vm.device.VirtualCdrom))
        assert cd.backing.fileName == "[LocalDS_0] vmdeploy-iso/batch.iso"
    assert r.stderr.count("Uploading batch.iso") <= 1


def test_batch_limits_and_impossible_batches_change_nothing(cli, si):
    build_ova(cli.images / "ubuntu-test.ova")
    base = ["--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp]
    r = cli("deploy", "-f", manifest(cli.tmp, _three("bt-limit", 2)), *base, "--per-host", "9", ok=False)
    assert r.exit_code == 2 and "at most 8" in " ".join(r.output.split())
    big = manifest(cli.tmp, "resources: {disk_gb: 900000, disk_provisioning: thick}\n" + _three("bt-big", 2))
    r = cli("deploy", "-f", big, *base, ok=False)
    assert r.exit_code == 2 and "None of the batch's VMs can be deployed" in " ".join(r.output.split())
    assert find_vm(si, "bt-big-1") is None
    r = cli("deploy", "--batch", *base, ok=False)
    assert r.exit_code == 2 and "batch.targets" in r.output
    r = cli("deploy", "--parallel", "3", *base, ok=False)
    assert r.exit_code == 2 and "only work(s) for a batch" in r.output


def _scripted_prompter(monkeypatch, answers: dict[str, object]) -> list[str]:
    """Answer the interactive questions without a terminal: the first `answers` key found in a question gives its
    answer; any other question takes its default (or its first choice). Returns the questions asked."""
    from vsphere_vm_deployment import ui

    asked: list[str] = []
    real_init = ui.Prompter.__init__

    def init(self, interactive, view=None):
        real_init(self, interactive, view)
        self.interactive = interactive  # as if stdin were a terminal

    def pick(question, default, fallback):
        asked.append(question)
        for key, value in answers.items():
            if key in question:
                return value
        return default if default is not None else fallback

    def kept(self, k, value):  # remembered like a real answer (results files save them for --retry-failed)
        return self._keep(k.get("answer_key") or k.get("field_name", ""), value)

    monkeypatch.setattr(ui.Prompter, "__init__", init)
    monkeypatch.setattr(ui.Prompter, "select", lambda self, q, choices, default=None, **k:
                        kept(self, k, pick(q, default, choices[0][1])))
    monkeypatch.setattr(ui.Prompter, "checkbox", lambda self, q, choices, **k:
                        kept(self, k, pick(q, None, [choices[0][1]])))
    monkeypatch.setattr(ui.Prompter, "text", lambda self, q, default=None, **k: kept(self, k, pick(q, default, "")))
    monkeypatch.setattr(ui.Prompter, "integer", lambda self, q, default=None, **k: kept(self, k, pick(q, default, 1)))
    monkeypatch.setattr(ui.Prompter, "confirm", lambda self, q, default=False, **k:
                        kept(self, k, pick(q, default, default)))
    return asked


def test_batch_interactive_questions(cli, si, monkeypatch):
    """The interactive batch: hosts from a checklist (an unusable host greyed out), the number of VMs, a name
    pattern, one datastore choice for all hosts, hostnames, static addresses, the review, then the build."""
    build_ova(cli.images / "ubuntu-test.ova")
    m = manifest(cli.tmp, """
resources: {cpu: 1, memory_gb: 1}
networks: [{portgroup: VM Network}]
guest: {username: tester, ssh_authorized_keys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey tester@ci"]}
post_deploy: {power_on: false, snapshot: false}
""")
    asked = _scripted_prompter(monkeypatch, {
        "Deploy to": [("host", "DC0_C0_H1"), ("host", "DC0_H0")],
        "How many VMs?": "per_host", "VMs on each": 2,
        "VM name pattern": "bt-int-{host}-{i}",
        "Datastores:": "auto",
        "Hostnames:": "{name}",
        "Guest IP addresses": "static",
        "Addresses: a range": "198.51.100.20-198.51.100.40", "Prefix length": 24,
        "Default gateway": "198.51.100.1", "DNS servers": "198.51.100.1",
        "What next?": "deploy",
    })
    r = cli("deploy", "--batch", "-f", m, "--local", "ubuntu-test.ova", "--trust-fingerprint", cli.fp, "--json")
    doc = _batch_doc(r)
    assert doc["exit_code"] == 0, r.output
    assert [v["name"] for v in doc["vms"]] == ["bt-int-DC0_C0_H1-1", "bt-int-DC0_C0_H1-2", "bt-int-DC0_H0-1",
                                               "bt-int-DC0_H0-2"]
    assert [v["address"] for v in doc["vms"]] == [f"198.51.100.{x}/24" for x in (20, 21, 22, 23)]
    assert doc["vms"][0]["hostname"] == "bt-int-DC0-C0-H1-1"
    assert any("Deploy to" in q for q in asked) and any("What next?" in q for q in asked)
    assert not any("Datastore on" in q for q in asked)  # one choice ("the most free space") for every host


def test_a_session_that_expired_during_the_review_is_renewed(cli, si, monkeypatch):
    """Found in real testing: with the review left open past vCenter's idle timeout, every VM failed with
    NotAuthenticated (shown as pyVmomi's dump of the fault). The session is now checked after the review and
    renewed over the same connection, so the objects read before it keep working; a single VM and a batch."""
    from vsphere_vm_deployment import batch as batch_mod
    from vsphere_vm_deployment import deploy as deploy_mod

    def expire_after(cls):
        real = cls._plan_and_review

        def review_then_expire(self, inv):
            real(self, inv)
            self.conn.content.sessionManager.Logout()  # as vCenter does after 30 idle minutes
        monkeypatch.setattr(cls, "_plan_and_review", review_then_expire)

    build_ova(cli.images / "ubuntu-test.ova")
    expire_after(deploy_mod.Deployment)
    r = cli("deploy", "-f", manifest(cli.tmp, """
vm: {name: bt-expired-single}
placement: {cluster: DC0_C0, host: DC0_C0_H0, datastore: LocalDS_0}
networks: [{portgroup: VM Network}]
guest: {enabled: false}
post_deploy: {power_on: false}
"""), "--local", "ubuntu-test.ova", "--yes", "--trust-fingerprint", cli.fp)
    assert "signed in again" in " ".join(r.output.split())
    assert find_vm(si, "bt-expired-single") is not None

    expire_after(batch_mod.BatchDeployment)
    r = cli("deploy", "-f", manifest(cli.tmp, _three("bt-expired", 1)), "--local", "ubuntu-test.ova", "--yes",
            "--trust-fingerprint", cli.fp, "--json")
    doc = _batch_doc(r)
    assert doc["exit_code"] == 0 and all(v["status"] == "deployed" for v in doc["vms"])
    assert "signed in again" in " ".join(r.stderr.split())
    for name in ("bt-expired-single", "bt-expired-1", "bt-expired-2", "bt-expired-3"):
        wait_task(find_vm(si, name).Destroy_Task())


def test_a_retry_reuses_the_first_runs_answers_and_destroy_takes_both_runs(cli, si, monkeypatch):
    """Found in real testing: --retry-failed asked every question again, and a changed answer (hosts, VMs per
    host, sizing) would silently have deployed different VMs. Now the results file keeps the answers (never a
    password) and the retry reuses them: here with --yes and no answers in the manifest at all. `destroy --batch`
    on the retry's file also deletes the first run's VMs."""
    from vsphere_vm_deployment import deploy as deploy_mod
    from vsphere_vm_deployment.errors import DeploymentError
    from vsphere_vm_deployment.logsetup import _context

    build_ova(cli.images / "ubuntu-test.ova")
    m = manifest(cli.tmp, """
resources: {cpu: 1, memory_gb: 1}
networks: [{portgroup: VM Network}]
guest: {enabled: false}
post_deploy: {power_on: false, snapshot: false}
""")
    with monkeypatch.context() as first:  # not monkeypatch.undo(): it would drop the isolated config folders
        _scripted_prompter(first, {
            "Deploy to": [("host", "DC0_C0_H1"), ("host", "DC0_H0")],
            "How many VMs?": "per_host", "VMs on each": 2,
            "VM name pattern": "bt-rep-{host}-{i}",
            "Datastores:": "auto",
            "What next?": "deploy",
        })
        real = deploy_mod.reconfigure_spec

        def reconfigure(vm, **k):
            if getattr(_context, "label", None) == "bt-rep-DC0_H0-2":
                raise DeploymentError("Reconfigure VM failed: test")
            return real(vm, **k)
        first.setattr(deploy_mod, "reconfigure_spec", reconfigure)
        r = cli("deploy", "--batch", "-f", m, "--local", "ubuntu-test.ova", "--trust-fingerprint", cli.fp,
                "--json", ok=False)
    doc = _batch_doc(r)
    assert r.exit_code == 4 and [v["status"] for v in doc["vms"]].count("failed") == 1
    assert doc["answers"]["batch.name"] == "bt-rep-{host}-{i}" and doc["answers"]["batch.count"] == 2
    assert doc["answers"]["batch.targets"] == [["host", "DC0_C0_H1"], ["host", "DC0_H0"]]

    # Nothing but the results file: the manifest, the image and the answers are that run's.
    r = cli("deploy", "--retry-failed", "latest", "--yes", "--trust-fingerprint", cli.fp, "--json")
    again = _batch_doc(r)
    out = " ".join(r.stderr.split())
    assert "As that run: manifest" in out and "image --local" in out and "profile sim" in out, out
    assert again["exit_code"] == 0 and [v["name"] for v in again["vms"]] == ["bt-rep-DC0_H0-2"], out
    assert again["vms"][0]["host"] == "DC0_H0" and "(as in the first run)" in out
    assert again["retry_of"] == str(Path(doc["results_file"]).resolve())

    r = cli("destroy", "--batch", "latest", "--yes", "--trust-fingerprint", cli.fp)
    out = " ".join(r.output.split())
    assert "Also the run it retried" in out and "Deleted 4 of 4" in out, out
    assert not [n for n in ("bt-rep-DC0_C0_H1-1", "bt-rep-DC0_C0_H1-2", "bt-rep-DC0_H0-1", "bt-rep-DC0_H0-2")
                if find_vm(si, n)]
