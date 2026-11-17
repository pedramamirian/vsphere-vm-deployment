"""`vmdeploy keyprovider backup`: the vSphere Automation API calls, with the HTTPS layer replaced."""

import json
from types import SimpleNamespace

import pytest

from vsphere_vm_deployment import keyprovider as kp
from vsphere_vm_deployment.errors import AuthError, DeploymentError

DECISION = SimpleNamespace(host="192.0.2.5", port=443)


class FakeVcenter:
    """Answers like vCenter 8.0 whose own host name is "localhost" (the case the command exists for)."""

    def __init__(self, export_status=200, login_status=200):
        self.calls = []
        self.export_status, self.login_status = export_status, login_status

    def __call__(self, decision, method, path, *, headers=None, body=None, timeout=60):
        self.calls.append((method, path, dict(headers or {}), body))
        if path == kp.SESSION_PATH and method == "POST":
            if self.login_status != 200:
                return self.login_status, json.dumps({"error_type": "UNAUTHENTICATED", "messages": [
                    {"default_message": "Authentication required."}]}).encode()
            return 201, json.dumps("session-123").encode()
        if path == kp.SESSION_PATH and method == "DELETE":
            return 204, b""
        if path == kp.EXPORT_PATH:
            if self.export_status != 200:
                return self.export_status, json.dumps({"error_type": "UNAUTHORIZED", "messages": [
                    {"default_message": "Permission denied."}]}).encode()
            return 200, json.dumps({"type": "LOCATION", "location": {
                "url": "https://localhost/cryptomanager/kms/abc123?x=1",
                "download_token": {"token": "tok-456", "expiry": "2026-11-11T10:00:00Z"}}}).encode()
        if path == "/cryptomanager/kms/abc123?x=1":
            return 200, b"PKCS12-BYTES"
        return 404, b""


def test_backup_downloads_from_the_connected_vcenter_not_localhost(monkeypatch):
    fake = FakeVcenter()
    secrets = []
    monkeypatch.setattr(kp, "_request", fake)
    monkeypatch.setattr(kp, "register_secret", secrets.append)
    with kp.RestSession(DECISION, "administrator@vsphere.local", "pw") as sid:
        data = kp.export(DECISION, sid, "NKP-01", "backup-pw")
    assert data == b"PKCS12-BYTES"
    login, export, download, logout = fake.calls
    assert login[2]["Authorization"].startswith("Basic ")
    assert json.loads(export[3]) == {"provider": "NKP-01", "password": "backup-pw"}
    assert export[2]["vmware-api-session-id"] == "session-123"
    # the link named "localhost": only its path is used, on the connection to 192.0.2.5
    assert download[:2] == ("POST", "/cryptomanager/kms/abc123?x=1")
    assert download[2]["Authorization"] == "Bearer tok-456"
    assert logout[:2] == ("DELETE", kp.SESSION_PATH)
    assert {"session-123", "tok-456"} <= set(secrets)  # never logged


def test_backup_without_a_password_sends_none(monkeypatch):
    fake = FakeVcenter()
    monkeypatch.setattr(kp, "_request", fake)
    kp.export(DECISION, "session-123", "NKP", None)
    assert json.loads(fake.calls[0][3]) == {"provider": "NKP"}


def test_refused_backup_names_the_privilege(monkeypatch):
    monkeypatch.setattr(kp, "_request", FakeVcenter(export_status=403))
    with pytest.raises(DeploymentError) as e:
        kp.export(DECISION, "session-123", "NKP", "pw")
    assert "Permission denied" in str(e.value) and kp.PRIVILEGE in e.value.hint


def test_rejected_api_sign_in(monkeypatch):
    monkeypatch.setattr(kp, "_request", FakeVcenter(login_status=401))
    with pytest.raises(AuthError, match="Authentication required"), kp.RestSession(DECISION, "u", "p"):
        pass


def test_native_providers_and_doctor_see_a_provider_that_is_not_backed_up():
    from vsphere_vm_deployment.crypto import key_provider

    nkp = SimpleNamespace(clusterId=SimpleNamespace(id="NKP-01"), managementType="nativeProvider",
                          hasBackup=False, useAsDefault=True)
    kmip = SimpleNamespace(clusterId=SimpleNamespace(id="KMS"), managementType="vCenter", hasBackup=None,
                           useAsDefault=False)
    cm = SimpleNamespace(ListKmsClusters=lambda **kw: [nkp, kmip],
                         GetDefaultKmsCluster=lambda **kw: SimpleNamespace(id="NKP-01"))
    conn = SimpleNamespace(is_vcenter=True, content=SimpleNamespace(cryptoManager=cm))
    nkp.tpmRequired, kmip.tpmRequired = False, None
    assert kp.native_providers(conn) == [kp.Provider("NKP-01", False, True, "Native", False)]
    assert [p.kind for p in kp.providers(conn)] == ["Native", "Standard (KMS)"]
    assert kp.providers(conn)[1].backed_up is None  # backup state only applies to Native Key Providers
    kpv = key_provider(conn)
    assert not kpv.available and "keyprovider backup" in kpv.detail
    nkp.hasBackup = True
    assert key_provider(conn).available


def test_create_and_delete_native_key_provider(monkeypatch):
    calls = []

    def fake(decision, method, path, *, headers=None, body=None, timeout=60):
        calls.append((method, path, json.loads(body) if body else None, headers))
        return 204, b""

    monkeypatch.setattr(kp, "_request", fake)
    kp.create(DECISION, "sid", "NKP-01")
    kp.delete(DECISION, "sid", "NKP Home/Lab")
    (m1, p1, b1, h1), (m2, p2, _b2, h2) = calls
    assert (m1, p1) == ("POST", kp.PROVIDERS_PATH)
    assert b1 == {"provider": "NKP-01", "native_spec": {}, "constraints": {"tpm_required": False}}
    assert h1["vmware-api-session-id"] == "sid" and h2["vmware-api-session-id"] == "sid"
    assert (m2, p2) == ("DELETE", kp.PROVIDERS_PATH + "/NKP%20Home%2FLab")  # the name is URL-encoded


def test_create_reports_vcenters_reason(monkeypatch):
    monkeypatch.setattr(kp, "_request", lambda *a, **k: (400, json.dumps({"error_type": "ALREADY_EXISTS", "messages": [
        {"default_message": "Provider already exists."}]}).encode()))
    with pytest.raises(DeploymentError, match="Provider already exists"):
        kp.create(DECISION, "sid", "NKP")


def test_vms_using_a_key_provider(monkeypatch):
    from pyVmomi import vim

    from vsphere_vm_deployment import inventory

    def vm(name, provider, readable=True):
        props = {"name": name}  # an unencrypted VM's config.keyId is unset: the bulk read leaves it out
        if readable:  # an inaccessible VM (its storage is down) has no configuration at all
            props["config.template"] = False
        if provider:
            props["config.keyId"] = vim.encryption.CryptoKeyId(
                keyId="k", providerId=vim.encryption.KeyProviderId(id=provider))
        return None, props

    reads = []
    monkeypatch.setattr(inventory, "vm_properties", lambda conn, paths, root=None: (reads.append(paths), [
        vm("win11", "NKP"), vm("plain", None), vm("other", "KMS"), vm("win11b", "NKP"),
        vm("on-a-lost-datastore", None, readable=False)])[1])
    assert kp.vms_using(SimpleNamespace(), "NKP") == (["win11", "win11b"], ["on-a-lost-datastore"])
    assert kp.vm_keys(SimpleNamespace()) == ({"NKP": ["win11", "win11b"], "KMS": ["other"]}, ["on-a-lost-datastore"])
    assert reads == [["name", "config.template", "config.keyId"]] * 2  # one bulk read each, never VM by VM


def test_key_provider_users_that_cannot_be_read_are_an_error_never_none(monkeypatch):
    """`keyprovider remove` refuses while VMs use the provider: an unreadable inventory must not read as "none"."""
    from vsphere_vm_deployment import inventory

    def fail(conn, paths, root=None):
        raise DeploymentError("Could not read the VMs: session expired")

    monkeypatch.setattr(inventory, "vm_properties", fail)
    with pytest.raises(DeploymentError, match="Could not read the VMs"):
        kp.vms_using(SimpleNamespace(), "NKP")


def _win11_deployment(monkeypatch, provs, answers, rest=True, interactive=True, host=None, dc=None):
    """A Deployment stand-in for `_key_provider_for_windows_11`, with the user's answers scripted."""
    from vsphere_vm_deployment import crypto
    from vsphere_vm_deployment import deploy as d

    done, state = [], {"usable": False}
    monkeypatch.setattr(kp, "providers", lambda conn: provs)
    monkeypatch.setattr(kp, "show_table", lambda provs: None)
    monkeypatch.setattr(kp, "backup_flow", lambda conn, p, name, *a, **k: (done.append(("backup", name)),
                                                                          state.update(usable=True)))
    monkeypatch.setattr(kp, "add_flow", lambda conn, p, **k: (done.append(("add",)), state.update(usable=True)))
    monkeypatch.setattr(kp, "set_default", lambda conn, name: done.append(("default", name)))
    monkeypatch.setattr(crypto, "key_provider", lambda conn, host=None: crypto.KeyProvider(
        "yes" if state["usable"] else "no", "default key provider 'X'" if state["usable"] else "not usable"))
    it = iter(answers)
    p = SimpleNamespace(interactive=interactive, section=lambda h: __import__("contextlib").nullcontext(),
                        select=lambda q, choices, **k: next(it), confirm=lambda q, **k: next(it),
                        record=lambda *a: None)
    conn = SimpleNamespace(is_vcenter=True, rest_credentials=("u", "p") if rest else None,
                           profile=SimpleNamespace(name="vCenter"))
    fake = SimpleNamespace(conn=conn, p=p)
    plan = SimpleNamespace(key_provider=crypto.KeyProvider("no", "not usable"), host=host, cluster=None, dc=dc,
                           guest_id="windows11_64Guest")
    return (lambda: d.Deployment._key_provider_for_windows_11(fake, plan)), done, plan


def test_windows_11_offers_to_back_up_the_existing_native_key_provider(monkeypatch):
    provs = [kp.Provider("NKP-01", False, True)]
    run, done, plan = _win11_deployment(monkeypatch, provs, ["backup"])
    run()
    assert done == [("backup", "NKP-01")] and plan.key_provider.available


def test_windows_11_offers_to_add_one_and_cancel_changes_nothing(monkeypatch):
    from vsphere_vm_deployment.errors import PreflightError, UserAborted

    run, done, _ = _win11_deployment(monkeypatch, [], ["add"])
    run()
    assert done == [("add",)]
    run, done, _ = _win11_deployment(monkeypatch, [], ["cancel"])
    with pytest.raises(UserAborted) as e:
        run()
    assert done == [] and "vmdeploy keyprovider add -p vCenter" in e.value.hint
    # --yes (or a federated sign-in): no offer, a stop with the command to run
    run, done, _ = _win11_deployment(monkeypatch, [kp.Provider("NKP", False, True)], [], interactive=False)
    with pytest.raises(PreflightError) as e:
        run()
    assert done == [] and "vmdeploy keyprovider backup -p vCenter --provider NKP" in e.value.hint


def test_windows_11_on_a_host_outside_a_cluster_is_told_about_the_cluster_not_offered_a_provider(monkeypatch):
    """A Native Key Provider would not help a host outside a cluster: explain it and stop; vmdeploy never creates a
    cluster or moves the host."""
    from vsphere_vm_deployment.errors import PreflightError

    h11 = SimpleNamespace(name="192.0.2.11", cluster=None, usable=True, obj=None)
    h20 = SimpleNamespace(name="192.0.2.20", cluster="Lab", usable=True, obj=None)
    dc = SimpleNamespace(hosts={h.name: h for h in (h11, h20)})
    for provs in ([], [kp.Provider("NKP", False, True)], [kp.Provider("NKP", True, False)]):
        run, done, _ = _win11_deployment(monkeypatch, provs, [], host=h11, dc=dc)
        with pytest.raises(PreflightError) as e:
            run()
        hint = " ".join(e.value.hint.split())
        assert done == [] and "192.0.2.11 is not in a cluster" in str(e.value)
        assert "KB 369538" in hint and "Choose a host that is in a cluster (192.0.2.20)" in hint
        assert "does not change your clusters" in hint
    # An External KMS (Standard Key Provider) is not refused: Broadcom's product docs do not state a cluster rule.
    run, done, _ = _win11_deployment(monkeypatch, [kp.Provider("KMS", None, False, kind="Standard (KMS)")], ["default", True],
                                     host=h11, dc=dc)
    with pytest.raises(PreflightError, match="still has no usable"):  # the fake default changes nothing
        run()
    assert done == [("default", "KMS")]  # offered, not stopped by the cluster rule


def test_a_host_reached_directly_names_the_supported_route():
    from vsphere_vm_deployment import crypto

    assert "KB 414781" in crypto.no_vtpm_on_esxi(SimpleNamespace(managed_by=None))
    managed = crypto.no_vtpm_on_esxi(SimpleNamespace(managed_by="192.0.2.5"))
    assert "managed by vCenter 192.0.2.5" in managed and "profile for the vCenter" in managed


def test_host_tpm_state():
    from vsphere_vm_deployment.crypto import host_tpm

    def host(supported, version, att=None):
        return SimpleNamespace(capability=SimpleNamespace(tpmSupported=supported, tpmVersion=version),
                               summary=SimpleNamespace(tpmAttestation=SimpleNamespace(status=att) if att else None))

    assert host_tpm(host(True, "2.0", "accepted")) == (True, "TPM 2.0, attestation accepted")
    assert host_tpm(host(False, None)) == (False, "no TPM 2.0")
    assert host_tpm(host(True, "1.2")) == (False, "no TPM 2.0 (TPM 1.2)")
    assert host_tpm(SimpleNamespace(capability=None)) == (None, "unknown")


def test_tpm_required_key_provider_blocks_a_host_without_a_tpm(monkeypatch):
    from vsphere_vm_deployment import crypto
    from vsphere_vm_deployment import deploy as d

    tpm = {"h10": (False, "no TPM 2.0"), "h12": (True, "TPM 2.0"), "h13": (False, "no TPM 2.0")}
    monkeypatch.setattr(crypto, "host_tpm", lambda obj: tpm[obj])
    hosts = {n: SimpleNamespace(name=n, obj=n, usable=True) for n in tpm}
    kpv = crypto.KeyProvider("yes", "default key provider 'NKP'", "NKP", True)

    def run(host=None, cluster=None):
        plan = SimpleNamespace(host=hosts.get(host), cluster=cluster, blockers=[], warnings=[],
                               dc=SimpleNamespace(hosts=hosts))
        notes = []
        d.Deployment._check_host_tpm(SimpleNamespace(plan=plan, view=SimpleNamespace(
            note=lambda *a, **k: notes.append(a[1]))), kpv)
        return plan, notes

    plan, _ = run("h10")
    assert plan.blockers and "host h10 has none" in plan.blockers[0] and "(h12)" in plan.blockers[0]
    plan, notes = run("h12")
    assert not plan.blockers and not plan.warnings and "h12: TPM 2.0" in notes[0]
    plan, _ = run(cluster=SimpleNamespace(hosts=["h10", "h12"]))  # DRS: may land without a TPM
    assert not plan.blockers and "DRS may place the VM" in plan.warnings[0]
    plan, _ = run(cluster=SimpleNamespace(hosts=["h10", "h13"]))
    assert "no host in the cluster has one" in plan.blockers[0]


def test_fault_message_prefers_vcenters_explanation_over_a_summary_placeholder():
    from vsphere_vm_deployment.tasks import fault_message

    real = ("Key provider NKP-01 is not compatible with the host 192.0.2.11. Reason: The host does not "
            "support Native Key Provider because it is not in a cluster.")
    err = SimpleNamespace(msg="RuntimeFault.summary", faultMessage=[SimpleNamespace(message=real)])
    assert fault_message(err) == real
    assert fault_message(SimpleNamespace(msg="Disk full", faultMessage=[])) == "Disk full"


class _VcenterConnection:
    is_vcenter = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _keyprovider_cli(monkeypatch, provs, keys):
    """`vmdeploy keyprovider ...` with the connection and vCenter's answers replaced; returns the run and what was
    deleted."""
    from typer.testing import CliRunner

    from vsphere_vm_deployment import cli
    from vsphere_vm_deployment.ui import Prompter

    deleted = []
    monkeypatch.setattr(cli, "_connect", lambda *a: (_VcenterConnection(), Prompter(interactive=False)))
    monkeypatch.setattr(kp, "require_manageable", lambda conn: None)
    monkeypatch.setattr(kp, "providers", lambda conn: provs)
    monkeypatch.setattr(kp, "show_table", lambda provs: None)
    monkeypatch.setattr(kp, "host_tpms", lambda conn: [])
    monkeypatch.setattr(kp, "vm_keys", keys)
    monkeypatch.setattr(kp, "delete", lambda *a: deleted.append(a))
    return (lambda *args: CliRunner().invoke(cli.app, ["keyprovider", *args])), deleted


def test_a_key_provider_is_not_removed_while_some_vms_cannot_be_checked(monkeypatch):
    """Code review: an encrypted VM whose storage is down has no readable configuration; it counted as "not using
    the key provider", which was then removed, leaving the VM unable to get its keys once its storage is back."""
    run, deleted = _keyprovider_cli(monkeypatch, [kp.Provider("NKP", True, True)],
                                    lambda conn: ({}, ["vmdeploy-test-on-a-lost-datastore"]))
    r = run("remove", "--provider", "NKP", "--yes")
    out = " ".join(r.output.split())
    assert r.exit_code != 0 and deleted == []
    assert "1 VM(s) could not be checked: vmdeploy-test-on-a-lost-datastore. Nothing was removed." in out


def test_keyprovider_list_still_shows_the_providers_when_the_vms_cannot_be_read(monkeypatch):
    def fail(conn):
        raise DeploymentError("Could not read the VMs: session expired")

    run, _deleted = _keyprovider_cli(monkeypatch, [kp.Provider("NKP", False, True)], fail)
    r = run("list", "--yes")
    out = " ".join(r.output.split())
    assert r.exit_code == 0, r.output
    assert "Could not read the VMs: session expired Which VMs use each key provider is not shown." in out
    assert "Back up a Native Key Provider" in out  # the rest of the advice is still given
