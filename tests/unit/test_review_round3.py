"""Regression tests for the third pre-release review (a code review and a security review of the second round
of fixes, and a code review of those fixes in turn): one test (or two) per finding."""

import contextlib
import hashlib
import ipaddress
import os
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace as NS

import pytest
import typer
from typer.testing import CliRunner

from vsphere_vm_deployment.errors import ConfigError, DeploymentError, TrustError, UserAborted
from vsphere_vm_deployment.trust import TrustDecision


def _flat(text: str) -> str:
    return " ".join(text.split())


# ------------------------------------------------------------------------------------------ IPv6 endpoints
def test_an_ipv6_endpoint_keeps_its_brackets_in_profile_list_audit_and_messages(isolated_dirs, monkeypatch, capsys):
    """Rich read '[fd00::10]' as a markup tag: `profile list`, the `access audit` header and a cancelled connection
    showed ':443' instead of the server."""
    from vsphere_vm_deployment import audit, cli
    from vsphere_vm_deployment.profiles import Profile, ProfileStore

    v6 = Profile(name="v6", host="fd00::10")
    ProfileStore().save(v6)
    r = CliRunner().invoke(cli.app, ["profile", "list"])
    assert r.exit_code == 0 and "[fd00::10]:443" in r.output

    class _Conn(contextlib.nullcontext):
        profile, user = v6, "VSPHERE.LOCAL\\ops"

    monkeypatch.setattr(cli, "_connect", lambda *a: (_Conn(), None))
    monkeypatch.setattr(audit, "run", lambda conn: [])
    r = CliRunner().invoke(cli.app, ["access", "audit", "--yes"])
    assert "Audit of [fd00::10]:443" in r.output

    def cancelled():
        raise UserAborted("Connection to [fd00::10]:443 cancelled.", hint="Run [b]trust add[/b] first.")

    with pytest.raises(typer.Exit):
        cli._run(cancelled)
    out = capsys.readouterr()
    assert "[fd00::10]:443" in out.err + out.out and "[b]trust add[/b]" in out.err + out.out


def test_a_bracketed_ipv6_host_without_a_port_is_saved_without_its_brackets(isolated_dirs):
    """'[fd00::10]' was saved as typed, so the URL host became '[[fd00::10]]' and the profile never connected."""
    from vsphere_vm_deployment import cli
    from vsphere_vm_deployment.profiles import Profile, ProfileStore
    from vsphere_vm_deployment.ui import Prompter

    assert Profile(name="a", host=" [fd00::10] ").host == "fd00::10"
    prof = cli._profile_wizard(Prompter(interactive=False), ProfileStore(), host="[fd00::10]", name="v6",
                               username="ops", remember=False)
    assert prof.host == "fd00::10" and prof.endpoint == "[fd00::10]:443" and prof.url_host == "[fd00::10]"


def test_trust_remove_accepts_the_endpoint_as_profile_list_shows_it(tmp_path):
    """Pins are stored as host:port; `trust remove [fd00::10]:443` (as `profile list` shows it) matched nothing."""
    from vsphere_vm_deployment.trust import TrustStore

    store = TrustStore(tmp_path / "trust.json")
    store.add_pin("fd00::10:443", NS(sha256="aa" * 32, subject="CN=vc", not_after=datetime.now(UTC), pem="PEM"))
    assert store.remove("[fd00::10]:443") and store.pin("fd00::10:443") is None
    assert not store.remove("[fd00::10]:443")


# ------------------------------------------------------------------------------------------ certificates
def _cert(sha):
    from vsphere_vm_deployment.trust import CertInfo

    now = datetime.now(UTC)
    return CertInfo(der=b"x", subject="vc", issuer="vc", not_before=now - timedelta(days=30),
                    not_after=now + timedelta(days=30), sans=["vc.example.com"], sha256=sha, sha1="00" * 20,
                    subject_dn="CN=vc", issuer_dn="CN=vc")


def test_trust_add_vcenter_ca_never_downloads_over_an_unchecked_certificate(monkeypatch, tmp_path):
    """Security review: on a server whose certificate validates, the CA bundle was downloaded over a connection
    pinned to a certificate read without any check, so anyone on the network path could have their own root CA
    saved into the bundle that every later connection trusts."""
    from vsphere_vm_deployment import trust

    real, forged = _cert("aa" * 32), _cert("bb" * 32)
    monkeypatch.setattr(trust, "validates", lambda *a, **k: (True, "valid"))
    monkeypatch.setattr(trust, "validated_peer_cert", lambda *a, **k: b"real")
    monkeypatch.setattr(trust, "fetch_peer_cert", lambda *a, **k: b"forged")  # an unchecked connection
    monkeypatch.setattr(trust, "lists_name", lambda *a, **k: None)  # no network in unit tests; cannot tell
    monkeypatch.setattr(trust.CertInfo, "from_der", classmethod(lambda cls, der: real if der == b"real" else forged))
    monkeypatch.setattr(trust.CertInfo, "from_pem", classmethod(lambda cls, pem: real))
    used = []
    monkeypatch.setattr(trust, "download_vcenter_ca",
                        lambda decision: used.append(decision) or ["-----BEGIN CERTIFICATE-----\nX\n"])
    tm = trust.TrustManager(store=trust.TrustStore(tmp_path / "t.json"))
    assert tm.trust_vcenter_ca("vc.example.com") == 1
    assert used[0].mode == "validated" and used[0].cert is real  # chain and hostname are checked again
    assert tm.vouch("esx01.example.com", 443, None).cert is real  # an ESXi host's validated certificate too


def _ca_and_ip_leaf():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(UTC)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test CA")])
    usage = {k: False for k in ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
                                "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only")}
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
          .not_valid_after(now + timedelta(days=9))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(**{**usage, "digital_signature": True, "key_cert_sign": True,
                                          "crl_sign": True}), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=9))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return ca, leaf, key


def test_a_validated_servers_certificate_is_read_over_a_validated_connection(tmp_path):
    from cryptography.hazmat.primitives import serialization as ser

    from vsphere_vm_deployment import trust

    ca, leaf, key = _ca_and_ip_leaf()
    (tmp_path / "srv.pem").write_bytes(leaf.public_bytes(ser.Encoding.PEM))
    (tmp_path / "srv.key").write_bytes(key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                                         ser.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "srv.pem", tmp_path / "srv.key")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(1)
            except (ssl.SSLError, OSError):
                pass

    threading.Thread(target=serve, daemon=True).start()
    ca_pem = ca.public_bytes(ser.Encoding.PEM).decode()
    try:
        assert trust.validated_peer_cert("127.0.0.1", port, ca_pem) == leaf.public_bytes(ser.Encoding.DER)
        with pytest.raises(TrustError, match="validated on one connection but not on the next"):
            trust.validated_peer_cert("127.0.0.1", port, None)  # not trusted without the test CA
    finally:
        with contextlib.suppress(OSError):
            srv.shutdown(socket.SHUT_RDWR)  # wakes the accept() on Linux, where close() alone does not
        srv.close()
    # A network problem is not called interception. Checked on a port that is bound but never listens, so it always
    # refuses: on Linux the closed server's port could still answer (CI on Ubuntu, a race with the accept() above).
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        with pytest.raises(TrustError, match="Could not connect"):
            trust.validated_peer_cert("127.0.0.1", unused.getsockname()[1], ca_pem, timeout=5)


# ------------------------------------------------------------------------------------------ datastore images
def test_a_file_picked_from_the_list_is_used_in_its_own_datacenter(monkeypatch):
    """The picker listed every datacenter's files but kept only "[datastore1] iso/x.iso": with the VM placed in
    another datacenter, that datacenter's own file at the same path was booted instead."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib

    def dc(name):
        return NS(name=name, datastores={"datastore1": NS(name="datastore1")}, obj=name)

    dc1, dc2 = dc("DC1"), dc("DC2")
    found = {n: [isolib.DatastoreIso("datastore1", "iso/x.iso", 10, {f"h-{n}"}, 1, n)] for n in ("DC1", "DC2")}
    monkeypatch.setattr(isolib, "find_images", lambda dc, skipped=None: found[dc.name])
    asked, offered = [], []

    def select(question, choices, **k):
        asked.append(question)
        offered.extend(choices)
        return ("DC2", "[datastore1] iso/x.iso") if question == "Which file?" else "DC1"

    fake = NS(inv=NS(datacenters={"DC1": dc1, "DC2": dc2}), p=NS(select=select))
    assert d.Deployment._pick_datastore_iso(fake) == "[datastore1] iso/x.iso"
    assert fake.image_dc == "DC2" and asked == ["Which file?"]  # each entry names its datacenter: no 2nd question
    assert [label.split(" › ")[0] for label, _ in offered[:2]] == ["DC1", "DC2"]
    assert d.Deployment._datacenter_of(fake, "datastore1") is dc2  # read and checked there before placement
    fake.image = NS(source_kind="datastore_iso")
    asked.clear()
    assert d.Deployment._choose_datacenter(fake, [dc1, dc2]) == (dc2, True) and asked == []  # the VM goes there
    fake.image = NS(source_kind="datastore_ova")  # read through this computer: the VM may go anywhere
    assert d.Deployment._choose_datacenter(fake, [dc1, dc2]) == ("DC1", False) and asked == ["Datacenter:"]


def test_files_read_from_datastores_are_cached_per_datacenter(isolated_dirs):
    """The local cache was keyed on the path only: another datacenter's file at the same path, with the same size
    and time, was taken for the copy read earlier."""
    from vsphere_vm_deployment import deploy as d

    def fake(dc):
        return NS(conn=NS(profile=NS(endpoint="vc.example.com:443")), _datacenter_of=lambda ds: NS(name=dc))

    a = d.Deployment._datastore_cache(fake("DC1"), "[datastore1] app.ova")
    assert a == d.Deployment._datastore_cache(fake("DC1"), "[datastore1] app.ova")
    assert a != d.Deployment._datastore_cache(fake("DC2"), "[datastore1] app.ova")


def test_datastore_names_are_matched_to_datacenters_in_one_place():
    from vsphere_vm_deployment import isolib

    a, b = NS(name="A", datastores={"ds": 1}), NS(name="B", datastores={"ds": 1, "x": 2})
    inv = NS(datacenters={"A": a, "B": b})
    assert isolib.datacenters_with(inv, "ds") == [a, b] and isolib.datacenters_with(inv, "ds", "B") == [b]
    assert isolib.datacenters_with(inv, "x") == [b] and isolib.datacenters_with(inv, "nope") == []


def _same_iso_fake(monkeypatch, tmp_path, verdicts):
    from vsphere_vm_deployment import isolib

    iso = tmp_path / "x.iso"
    iso.write_bytes(b"x" * 10)
    cands = [isolib.DatastoreIso(f"ds{i + 1}", "iso/x.iso", 10, {"h1"}, 1, "DC") for i in range(len(verdicts))]
    monkeypatch.setattr(isolib, "find_isos", lambda dc: list(cands))
    records = []
    plan = NS(dc=None, datastore=NS(name="ds1"), host_names={"h1"}, iso_rejected=set(),
              iso_datastore_path=None, iso_copy_from=None, iso_found_on_datastore=False)
    p = NS(interactive=False, section=lambda header: contextlib.nullcontext(), confirm=lambda q, **k: k["assume"],
           record=lambda label, value: records.append(value))
    fake = NS(plan=plan, image=NS(path=iso), view=NS(note=lambda *a, **k: None),
              m=NS(image=NS(reuse_datastore_copy=None)), p=p,
              _same_content=lambda local, cand: verdicts[cands.index(cand)])
    return fake, cands, records


def test_with_yes_the_record_says_which_copy_was_used_or_why_none(monkeypatch, tmp_path):
    """A copy skipped with --yes (contents not comparable) was recorded as 'uploaded from this computer' before
    the next copy was used; and when every copy was skipped, nothing was recorded at all."""
    from vsphere_vm_deployment import deploy as d

    fake, cands, records = _same_iso_fake(monkeypatch, tmp_path, [None, True])
    d.Deployment._find_same_iso_on_datastores(fake)
    assert fake.plan.iso_datastore_path == cands[1].full
    assert records == [f"{cands[1].full} (contents match (sampled); used where it is)"]
    fake, cands, records = _same_iso_fake(monkeypatch, tmp_path, [None, None])
    d.Deployment._find_same_iso_on_datastores(fake)
    assert fake.plan.iso_datastore_path is None and len(records) == 1 and "could not be compared" in records[0]


def test_an_earlier_upload_under_a_dash_n_name_is_offered_before_other_copies(monkeypatch, tmp_path):
    """Found in the real-environment re-test: after an upload had to use x-2.iso (x.iso was taken by another
    file), the next deployment offered only an unrelated x.iso elsewhere; a "No" to it then ruled out reusing the
    verified x-2.iso, so the ISO was uploaded again."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib

    fake, _, records = _same_iso_fake(monkeypatch, tmp_path, [])
    other = isolib.DatastoreIso("ds1", "x.iso", 10, {"h1"}, 1, "DC")  # same name and size, outside vmdeploy-iso
    dash2 = isolib.DatastoreIso("ds1", "vmdeploy-iso/x-2.iso", 10, {"h1"}, 1, "DC")
    unrelated = isolib.DatastoreIso("ds1", "isos/x-2.iso", 10, {"h1"}, 1, "DC")  # not vmdeploy's: never offered
    monkeypatch.setattr(isolib, "find_isos", lambda dc: [other, unrelated, dash2])
    offered = []
    fake._same_content = lambda local, cand: offered.append(cand.full) or True
    d.Deployment._find_same_iso_on_datastores(fake)
    assert offered == [dash2.full] and fake.plan.iso_datastore_path == dash2.full


def test_deleting_iso_copies_names_the_datacenter_when_a_path_is_in_two(monkeypatch):
    from vsphere_vm_deployment import cli, inventory, isocopies

    monkeypatch.setattr(isocopies, "iso_users", lambda conn: {})
    monkeypatch.setattr(inventory, "discover", lambda conn: "inv")
    asked = []
    p = NS(confirm=lambda q, **k: asked.append(q) or False, record=lambda *a: None)
    path = "[vsanDatastore] vmdeploy-iso/a.iso"
    cli._offer_iso_cleanup(None, p, [("Site-A", path), ("Site-B", path)], None)
    assert len(asked) == 2 and "Site-A" in asked[0] and "Site-B" in asked[1]


# ------------------------------------------------------------------------------------------ ISO copies and uploads
def test_a_copy_refused_as_it_starts_is_retried_or_reported_and_cleans_up_nothing(monkeypatch):
    """CopyDatastoreFile_Task was called outside the try: a fault raised as the copy starts skipped the retry with
    another name and left as a raw vSphere fault. A copy that never started wrote nothing: the file at that name
    belongs to someone else and is never deleted."""
    from pyVmomi import vim

    from vsphere_vm_deployment import isolib

    names, deleted = {"a.iso": 5}, []
    monkeypatch.setattr(isolib, "list_folder", lambda ds_obj, ds, folder: dict(names))
    monkeypatch.setattr(isolib, "_size", lambda conn, dc, full: 5)
    monkeypatch.setattr(isolib, "_size_on", lambda *a: 3)  # another deployment's half-written file is there
    monkeypatch.setattr(isolib, "wait_task", lambda task, **k: None)

    def copy(**k):
        if k["destinationName"].endswith("/a-2.iso"):  # taken by another deployment just after the listing
            names["a-2.iso"] = 5
            raise vim.fault.FileAlreadyExists()
        return "task"

    fm = NS(MakeDirectory=lambda **k: None, CopyDatastoreFile_Task=copy,
            DeleteDatastoreFile_Task=lambda **k: deleted.append(k["name"]) or "task")
    conn = NS(content=NS(fileManager=fm))
    assert isolib.ensure_copied(conn, None, "[nfs] a.iso", None, "[ds1] vmdeploy-iso/a.iso") == \
        ("[ds1] vmdeploy-iso/a-3.iso", "copied by vCenter, host to host")

    def refused(**k):
        raise vim.fault.NoPermission(privilegeId="Datastore.FileManagement")

    fm.CopyDatastoreFile_Task = refused
    with pytest.raises(DeploymentError, match="Copy ISO failed"):
        isolib.ensure_copied(conn, None, "[nfs] a.iso", None, "[ds1] vmdeploy-iso/a.iso")
    assert deleted == []

    def dropped(**k):  # not a vSphere fault (e.g. the connection dropped): not taken for a refused copy
        raise ConnectionResetError("connection reset")

    fm.CopyDatastoreFile_Task = dropped
    with pytest.raises(ConnectionResetError):
        isolib.ensure_copied(conn, None, "[nfs] a.iso", None, "[ds1] vmdeploy-iso/a.iso")


def test_a_folder_that_cannot_be_listed_does_not_start_a_copy_through_this_computer(monkeypatch):
    """A failed listing of the VM's datastore was taken for a failed copy: the ISO was read through this computer
    (possibly many GB) and the upload then failed on the same listing."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib

    assert issubclass(isolib.FolderListError, DeploymentError)

    def cannot_list(*a, **k):
        raise isolib.FolderListError("Could not list [ds1] vmdeploy-iso: no permission")

    monkeypatch.setattr(isolib, "ensure_copied", cannot_list)
    monkeypatch.setattr(isolib, "list_folder", cannot_list)
    monkeypatch.setattr(isolib, "_size", lambda conn, dc, full: None)  # even when the source size is unknown
    plan = NS(iso_found_on_datastore=False, iso_copy_from="[nfs] iso/x.iso", iso_copy_via_pc=False,
              iso_datastore_path="[ds1] vmdeploy-iso/x.iso", dc=NS(obj=None), datastore=NS(obj=None))
    view = NS(skip=lambda *a: None, start=lambda *a: None, update=lambda *a, **k: None, done=lambda *a: None)
    fake = NS(plan=plan, view=view, conn=None, _copy_matches=None,
              _copy_through_pc_after=lambda e: pytest.fail("offered to copy through this computer"))
    with pytest.raises(isolib.FolderListError):
        d.Deployment._deploy_iso(fake)
    with pytest.raises(isolib.FolderListError):  # before reading the ISO through this computer
        d.Deployment._reuse_uploaded_iso_named(fake, plan.iso_datastore_path)


def _upload_fake(tmp_path, fm, deleted, notes):
    local = tmp_path / "x.iso"
    local.write_bytes(b"abc")
    plan = NS(datastore=NS(name="ds1", obj=None), dc=NS(obj=None, name="DC"), iso_datastore_path=None)
    view = NS(steps={"upload_iso": NS(weight=1)}, start=lambda *a: None, begin_transfer=lambda *a: (lambda n: None),
              done=lambda *a: None, note=lambda step, text, **k: notes.append(text))
    conn = NS(content=NS(fileManager=fm, rootFolder=None), is_vcenter=False, decision=None, session_cookie="c")
    return NS(plan=plan, view=view, conn=conn, image=NS(path=local),
              _delete_partial_upload=lambda full: deleted.append(full))


def test_an_upload_gets_its_name_by_a_move_that_never_replaces_a_file(monkeypatch, tmp_path):
    """A datastore upload (HTTP PUT) replaces a file of the same name: two deployments uploading the same ISO at
    once could overwrite each other's copy while a VM was being created from it."""
    from pyVmomi import vim

    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib

    names, puts, moves, deleted, notes = {}, [], [], [], []
    monkeypatch.setattr(isolib, "list_folder", lambda ds_obj, ds, folder: dict(names))
    monkeypatch.setattr(isolib, "wait_task", lambda task, **k: None)
    monkeypatch.setattr(d, "upload_stream", lambda decision, method, path, f, size, **k: puts.append(path))

    def move(**k):
        if not moves:  # another deployment gave its upload the name x.iso after our listing
            names["x.iso"] = 3
            moves.append(None)
            raise vim.fault.FileAlreadyExists()
        moves.append((k["sourceName"], k["destinationName"], k["force"]))
        return "task"

    fm = NS(MakeDirectory=lambda **k: None, MoveDatastoreFile_Task=move)
    fake = _upload_fake(tmp_path, fm, deleted, notes)
    d.Deployment._upload_iso(fake, reuse=False)
    assert fake.plan.iso_datastore_path == "[ds1] vmdeploy-iso/x-2.iso" and deleted == [] and notes == []
    source, dest, force = moves[-1]
    assert dest == "[ds1] vmdeploy-iso/x-2.iso" and force is False
    # Its own name is still an .iso (so `images prune` sees it if a run is cut off), never taken for a copy.
    own = source.rpartition("/")[2]
    assert own.startswith("x.vmdeploy-upload-") and own.endswith(".iso") and own in puts[0]
    assert not isolib.copy_variant("x.iso", own)

    def locked(**k):  # the name cannot be given (not "taken"): the complete upload is used as it is
        raise vim.fault.FileLocked()

    fm.MoveDatastoreFile_Task = locked
    fake = _upload_fake(tmp_path, fm, deleted, notes)
    d.Deployment._upload_iso(fake, reuse=False)
    assert "vmdeploy-upload-" in fake.plan.iso_datastore_path and deleted == [] and len(notes) == 1

    def broken(*a, **k):
        raise OSError("connection reset")

    monkeypatch.setattr(d, "upload_stream", broken)
    fake = _upload_fake(tmp_path, fm, deleted, notes)
    with pytest.raises(OSError):
        d.Deployment._upload_iso(fake, reuse=False)
    assert len(deleted) == 1 and "vmdeploy-upload-" in deleted[0]  # only this run's own partial upload


# ------------------------------------------------------------------------------------------ key provider backup
def test_a_key_provider_backup_is_kept_when_its_file_cannot_be_written(monkeypatch, tmp_path):
    """vCenter counts the export as the backup; a failed write deleted the file and dropped the exported bytes.
    Saved elsewhere, it is still an error: a script must not take the backup to be where it asked for it."""
    from vsphere_vm_deployment import keyprovider
    from vsphere_vm_deployment.paths import config_dir

    monkeypatch.setenv("VMDEPLOY_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setattr(keyprovider, "export", lambda *a: b"P12-BYTES")
    monkeypatch.setattr(keyprovider, "RestSession", lambda *a: contextlib.nullcontext("sid"))
    monkeypatch.setattr(keyprovider, "native_providers", lambda conn: [])
    conn = NS(rest_credentials=("admin", "pw"), decision=None)
    p = NS(text=lambda *a, **k: "", password=lambda *a, **k: "")
    real_fsync, calls = os.fsync, []

    def first_fails(fd):
        calls.append(fd)
        if len(calls) == 1:
            raise OSError(28, "No space left on device")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", first_fails)
    target = tmp_path / "out" / "nkp.p12"
    with pytest.raises(DeploymentError, match="saved to .* instead"):
        keyprovider.backup_flow(conn, p, "nkp", out=target, no_password=True)
    assert not target.exists()
    saved = list((config_dir() / "keyprovider-backups").glob("nkp-*.p12"))
    assert len(saved) == 1 and saved[0].read_bytes() == b"P12-BYTES"

    def always_fails(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", always_fails)
    target = tmp_path / "out" / "nkp2.p12"
    with pytest.raises(DeploymentError, match="no backup file exists"):
        keyprovider.backup_flow(conn, p, "nkp", out=target, no_password=True)
    assert not target.exists() and len(list((config_dir() / "keyprovider-backups").glob("*.p12"))) == 1


# ------------------------------------------------------------------------------------------ disks
def test_extra_disks_are_checked_against_the_controllers_free_units_for_its_hardware_version():
    """Only SCSI units were counted (NVMe overflow was found by vCenter), and the limits did not follow the
    hardware version: an NVMe controller takes 64 namespaces from version 21, a paravirtual SCSI one 64 disks
    from version 14."""
    from pyVmomi import vim

    from vsphere_vm_deployment.vmspec import reconfigure_spec

    def vm(controller, version):
        disks = [vim.vm.device.VirtualDisk(key=2000 + i, controllerKey=controller.key, unitNumber=i, capacityInKB=1)
                 for i in range(2)]
        return NS(config=NS(version=version, hardware=NS(device=[controller, *disks], numCPU=2, numCoresPerSocket=1,
                                                         memoryMB=1024)))

    common = {"cpu": None, "cores_per_socket": None, "memory_mb": None, "disk_gb": None, "annotation": None,
              "extra_config": None}
    nvme = vim.vm.device.VirtualNVMEController(key=31000, busNumber=0)
    with pytest.raises(DeploymentError, match="no free slot"):
        reconfigure_spec(vm(nvme, "vmx-19"), extra_disks=[(5, None)] * 14, **common)
    spec, _ = reconfigure_spec(vm(nvme, "vmx-19"), extra_disks=[(5, None)] * 13, **common)
    assert max(c.device.unitNumber for c in spec.deviceChange) == 14
    spec, _ = reconfigure_spec(vm(nvme, "vmx-21"), extra_disks=[(5, None)] * 14, **common)
    assert max(c.device.unitNumber for c in spec.deviceChange) == 15
    lsi = vim.vm.device.VirtualLsiLogicSASController(key=1000, busNumber=0)
    pvscsi = vim.vm.device.ParaVirtualSCSIController(key=1000, busNumber=0)
    spec, _ = reconfigure_spec(vm(lsi, "vmx-21"), extra_disks=[(5, None)] * 13, **common)
    assert max(c.device.unitNumber for c in spec.deviceChange) == 15  # 0-15, with 7 reserved
    spec, _ = reconfigure_spec(vm(pvscsi, "vmx-14"), extra_disks=[(5, None)] * 14, **common)
    assert max(c.device.unitNumber for c in spec.deviceChange) == 16


# ------------------------------------------------------------------------------------------ checksums
def test_a_sha256_is_checked_and_compared_in_one_form_on_the_command_line_and_in_manifests(tmp_path, isolated_dirs):
    """--sha256 was never validated, a pasted value with spaces matched in one code path but not another, and a
    manifest and the command line treated the same value differently."""
    from vsphere_vm_deployment import images
    from vsphere_vm_deployment.cli import app
    from vsphere_vm_deployment.manifest import ImageSpec
    from vsphere_vm_deployment.transfer import check_sha256

    f = tmp_path / "a.iso"
    f.write_bytes(b"abc")
    sha = hashlib.sha256(b"abc").hexdigest()
    pasted = f"  {':'.join(sha[i:i + 2] for i in range(0, 64, 2)).upper()} \n"
    assert check_sha256(pasted) == sha and check_sha256(None) is None and check_sha256("  ") is None
    with pytest.raises(ConfigError, match="64 hexadecimal"):
        check_sha256("abc123")
    assert ImageSpec(local="a.iso", sha256=pasted).sha256 == sha and ImageSpec(local="a.iso", sha256="  ").sha256 is None
    with pytest.raises(ValueError, match="image.sha256 must be a SHA-256"):
        ImageSpec(local="a.iso", sha256="abc123")
    img = images.resolve("local", str(f), sha256=pasted, prompter=None, progress_factory=lambda d, t: (lambda n: None))
    assert img.sha256 == sha
    r = CliRunner().invoke(app, ["deploy", "--local", str(f), "--sha256", "not-a-hash", "--yes"])
    assert r.exit_code == 2 and "64 hexadecimal" in _flat(r.output)


def test_a_datastore_ova_is_hashed_once(monkeypatch, tmp_path):
    """The OVA read from a datastore was hashed while it was read, then hashed again in full."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import images, isolib, transfer

    monkeypatch.setattr(isolib, "_stat", lambda conn, dc, full: (3, "t1"))
    monkeypatch.setattr(transfer, "read_stream", lambda decision, url, sink, **k: sink(b"abc"))
    fake = NS(conn=None, view=NS(note=lambda *a, **k: None), _datacenter_of=lambda ds: NS(obj=None),
              _datastore_cache=lambda full: tmp_path, _datastore_http=lambda full: (None, "/folder/a.ova", {}))
    local = d.Deployment._read_datastore_file(fake, "[ds1] a.ova", None)
    known = fake._fresh_sha[str(local)]
    assert known == hashlib.sha256(b"abc").hexdigest()
    monkeypatch.setattr(images, "sha256_file", lambda *a, **k: pytest.fail("hashed again"))
    img = images.resolve("local", str(local), sha256=None, known_sha256=known, prompter=None,
                         progress_factory=lambda d, t: (lambda n: None))
    assert img.sha256 == known


def test_notes_about_reading_an_iso_go_to_the_upload_step(monkeypatch, tmp_path):
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import images, isolib

    dest = tmp_path / "x.iso"
    dest.write_bytes(b"abc")
    images._write_meta(dest, source="[ds1] iso/x.iso", size=3, modified="t1")
    monkeypatch.setattr(isolib, "_stat", lambda conn, dc, full: (3, "t1"))
    notes = []
    fake = NS(conn=None, view=NS(note=lambda step, text, **k: notes.append(step)),
              _datacenter_of=lambda ds: NS(obj=None))
    assert d.Deployment._read_datastore_file(fake, "[ds1] iso/x.iso", None, dest=dest, step="upload_iso") == dest
    assert notes == ["upload_iso"]


def test_both_comparisons_sample_the_same_places_and_read_the_source_size_once(monkeypatch):
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib, transfer

    mib = 1024 * 1024
    piece, offsets = d._sample_offsets(8 * mib)
    assert piece == mib and offsets[0] == 0 and offsets[-1] == 7 * mib and len(offsets) == d.Deployment.SAMPLES
    assert d._sample_offsets(10) == (10, [0])
    sizes, answers = [], [None, 4 * mib]  # the first read fails: not remembered, so the next comparison tries again
    monkeypatch.setattr(isolib, "_size", lambda conn, dc, full: sizes.append(full) or answers[min(len(sizes), 2) - 1])
    monkeypatch.setattr(transfer, "read_range", lambda decision, url, off, n, **k: b"x" * n)
    fake = NS(conn=None, _datacenter_of=lambda ds: NS(obj=None), _datastore_http=lambda full: (None, full, {}))
    assert d.Deployment._same_remote(fake, "[nfs] iso/x.iso", "[ds1] vmdeploy-iso/x.iso") is None
    assert d.Deployment._same_remote(fake, "[nfs] iso/x.iso", "[ds1] vmdeploy-iso/x-2.iso")
    assert d.Deployment._same_remote(fake, "[nfs] iso/x.iso", "[ds1] vmdeploy-iso/x-3.iso")
    assert sizes == ["[nfs] iso/x.iso"] * 2


# ------------------------------------------------------------------------------------------ command line
def test_the_one_image_source_hint_names_every_source(isolated_dirs):
    from vsphere_vm_deployment.cli import app

    r = CliRunner().invoke(app, ["deploy", "--datastore-iso", "[a] x.iso", "--url", "https://example.com/x.iso",
                                 "--yes"])
    assert r.exit_code == 2 and "--preset, --datastore-iso, --datastore-file" in _flat(r.output)


# ------------------------------------------------------------------------------------------ found in real-environment re-tests
def test_an_ip_address_host_suggests_the_whole_address_as_profile_name():
    """For a vCenter reached by IP, the suggested profile name was its first number (for 192.0.2.5: "192"), as for
    an FQDN's first label. IPv6 keeps every group: '2001:db8::1' and '2001:db8:1::' both became '2001-db8-1', and
    `profile add --yes` would have replaced the other server's profile (and its saved password)."""
    from vsphere_vm_deployment.cli import _default_profile_name
    from vsphere_vm_deployment.profiles import profile_name_error

    assert _default_profile_name("192.0.2.5") == "192-0-2-5"
    assert _default_profile_name("vcsa.example.com") == "vcsa"
    assert _default_profile_name("fd00::10") == "fd00-0-0-0-0-0-0-10"
    a, b = _default_profile_name("2001:db8::1"), _default_profile_name("2001:db8:1::")
    assert a == "2001-db8-0-0-0-0-0-1" and b == "2001-db8-1-0-0-0-0-0" and a != b
    assert _default_profile_name("::") == "0-0-0-0-0-0-0-0"
    assert _default_profile_name("2001:DB8::1") == a  # the same address, written differently: the same name
    for host in ("::", "fe80::1%eth0", "2001:db8::1", "192.0.2.5"):
        assert profile_name_error(_default_profile_name(host)) is None


def test_ctrl_c_at_a_prompt_is_reported_once(monkeypatch):
    """questionary's ask() printed its own "Cancelled by user" before vmdeploy's message."""
    from vsphere_vm_deployment import ui

    class Interrupted:
        def unsafe_ask(self):
            raise KeyboardInterrupt

    monkeypatch.setattr(ui.questionary, "confirm", lambda *a, **k: Interrupted())
    p = ui.Prompter(interactive=False)
    p.interactive = True  # pytest has no terminal
    with pytest.raises(UserAborted, match="Cancelled by user"):
        p.confirm("Continue?")


def test_progress_bars_show_sizes_in_the_same_units_as_the_rest_of_vmdeploy():
    """The question said 'uploading 3.2 GB' while the progress bar showed '0.9/3.4 GB' for the same file: Rich's
    columns are 1000-based, vmdeploy (like vSphere and Windows) is 1024-based."""
    from vsphere_vm_deployment.ui import SizeColumn, SpeedColumn
    from vsphere_vm_deployment.units import human_size

    iso = 3_405_469_696
    assert human_size(iso) == f"{iso / 1024**3:.1f} GB" == "3.2 GB"
    assert human_size(824_268_800) == "786.1 MB" and human_size(512) == "512 bytes"
    # just under a boundary: the next unit, never '1024.0 MB'
    assert human_size(1024**3 - 1) == "1.0 GB" and human_size(1024**2 - 1) == "1.0 MB"
    assert human_size(1023) == "1023 bytes" and human_size(1024) == "1.0 KB"
    assert SizeColumn().render(NS(total=iso, completed=iso // 4)).plain == "0.8/3.2 GB"
    assert SizeColumn().render(NS(total=None, completed=2048)).plain == "2.0 KB"
    assert SpeedColumn().render(NS(finished_speed=None, speed=58_800_000)).plain == "56.1 MB/s"
    assert SpeedColumn().render(NS(finished_speed=None, speed=None)).plain == "?"


def test_vm_notes_name_a_local_image_by_its_file_name_only(tmp_path):
    """The VM's Notes held the image's full local path (user name and folders), readable by anyone who can see the
    VM in vCenter."""
    from vsphere_vm_deployment import deploy as d

    iso = tmp_path / "private-folder" / "x.iso"
    fake = NS(m=NS(vm=NS(notes="")), image=NS(source_kind="local", path=iso, display=str(iso), sha256="ab" * 32))
    notes = d.Deployment._annotation(fake)
    assert "image: x.iso (local file)" in notes and "private-folder" not in notes and str(tmp_path) not in notes
    fake.image = NS(source_kind="url", path=iso, display="https://example.com/x.iso", sha256=None)
    assert "image: https://example.com/x.iso" in d.Deployment._annotation(fake)


def test_a_refused_sample_read_says_why_in_the_log(monkeypatch, caplog):
    """'The contents could not be compared' left nothing in the log to tell a 403 from a server ignoring ranges."""
    import http.client
    import logging

    from vsphere_vm_deployment import transfer

    class FakeConn:
        def __init__(self, *a, **k):
            self.sock = NS(getpeercert=lambda binary_form: b"")

        def connect(self):
            pass

        def request(self, *a, **k):
            pass

        def getresponse(self):
            return NS(status=403, reason="Forbidden")

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPSConnection", FakeConn)
    decision = TrustDecision("vc.example.com", 443, "validated", None)  # validated: no pin to compare
    with caplog.at_level(logging.INFO, logger="vsphere_vm_deployment.transfer"):
        assert transfer.read_range(decision, "/folder/x.iso?dcPath=DC&dsName=ds1", 0, 10) is None
    assert "HTTP 403 Forbidden" in caplog.text and "/folder/x.iso" in caplog.text and "dsName" not in caplog.text


def test_access_remove_plan_does_not_promise_to_keep_a_folder_its_vms_may_empty():
    """With --delete-vms (or that answer to the question after the plan), the account's folder is deleted once its
    VMs are gone, but the plan said it 'is KEPT'. Names are escaped: '[' is allowed in folder names, and
    'vmdeploy-[/]' made Rich raise before the plan was shown."""
    from rich.text import Text

    from vsphere_vm_deployment.cli import _folder_plan_row

    assert _folder_plan_row("vmdeploy-x", 0, False) == "vmdeploy-x (created by setup)"
    assert "is KEPT: it still holds 2 item(s)" in _folder_plan_row("vmdeploy-x", 2, False)
    row = _folder_plan_row("vmdeploy-x", 6, True)
    assert "deleted after its VMs, if they are deleted" in row and "is KEPT" not in row
    for name in ("vmdeploy-[/]", "vmdeploy-[lab]"):
        assert Text.from_markup(_folder_plan_row(name, 0, False)).plain == f"{name} (created by setup)"


def test_a_folder_is_emptied_by_deleting_vms_only_when_nothing_else_is_in_it():
    """The plan said a folder 'may be deleted' when it held a VM vmdeploy never deletes, or a subfolder."""
    from pyVmomi import vim

    from vsphere_vm_deployment import access

    ours, theirs, sub = vim.VirtualMachine("vm-1"), vim.VirtualMachine("vm-2"), vim.Folder("group-v9")

    def is_ours(vm):
        return vm is ours

    assert access.emptied_by_deleting_vms(NS(childEntity=[ours]), is_ours) is True
    assert access.emptied_by_deleting_vms(NS(childEntity=[ours, theirs]), is_ours) is False
    assert access.emptied_by_deleting_vms(NS(childEntity=[ours, sub]), is_ours) is False
    assert access.emptied_by_deleting_vms(NS(childEntity=[]), is_ours) is False


def test_iso_lists_show_small_files_in_a_readable_unit():
    """`images prune` listed a 1 MB file in vmdeploy-iso/ as '0.0 GB'."""
    from vsphere_vm_deployment import isolib

    iso = isolib.DatastoreIso("ds1", "vmdeploy-iso/x.iso", 1_048_576, {"h1"}, 1, "DC")
    assert "(1.0 MB;" in iso.label()
    assert "(3.2 GB;" in isolib.DatastoreIso("ds1", "iso/y.iso", 3_405_469_696, {"h1"}, 1, "DC").label()


def test_access_remove_plan_lists_the_folder_label_when_its_last_folder_goes():
    """Real-environment re-test: `access remove` deleted the 'vmdeploy' custom attribute along with the last folder
    that carried it, but the plan listed it only when no folder used it any more."""
    from vsphere_vm_deployment.access import label_plan

    assert label_plan([], False, True) == "no folder uses it any more"
    assert label_plan([(0, False)], False, False) == "the label on the folder(s) above; no other folder uses it"
    assert "removed too if they are deleted" in label_plan([(0, False), (6, True)], False, False)
    assert label_plan([(0, False)], True, False) is None  # another setup's folder keeps it
    assert label_plan([(2, False)], False, False) is None  # this folder is kept, and so is its label
    assert label_plan([], False, False) is None


# ------------------------------------------------------------------ fourth review (changes after the re-tests)


def _iso_choice_fake(monkeypatch, tmp_path, cands, verdicts, answer=True, reuse=None):
    from vsphere_vm_deployment import isolib

    iso = tmp_path / "x.iso"
    iso.write_bytes(b"x" * 10)
    monkeypatch.setattr(isolib, "find_isos", lambda dc: list(cands))
    asked, records = [], []
    plan = NS(dc=None, datastore=NS(name="ds1"), host_names={"h1"}, iso_rejected=set(),
              iso_datastore_path=None, iso_copy_from=None, iso_found_on_datastore=False)
    p = NS(interactive=True, section=lambda header: contextlib.nullcontext(),
           confirm=lambda q, **k: asked.append(q) or answer, record=lambda label, value: records.append(value))
    fake = NS(plan=plan, image=NS(path=iso, sha256="ab" * 32), view=NS(note=lambda *a, **k: None),
              m=NS(image=NS(reuse_datastore_copy=reuse)), p=p, _same_content=lambda local, cand: verdicts[cand.full])
    return fake, asked, records


def test_vmdeploys_earlier_upload_is_offered_before_another_file_of_that_name(monkeypatch, tmp_path):
    """An unrelated x.iso on the VM's own datastore was offered before vmdeploy's x-2.iso on a datastore the host
    also sees; a "No" to it ruled out the earlier upload too. Both are usable where they are: ours first."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib

    other = isolib.DatastoreIso("ds1", "isos/x.iso", 10, {"h1"}, 1, "DC")
    ours = isolib.DatastoreIso("ds2", "vmdeploy-iso/x-2.iso", 10, {"h1"}, 1, "DC")
    fake, asked, _ = _iso_choice_fake(monkeypatch, tmp_path, [other, ours], {other.full: True, ours.full: True})
    d.Deployment._find_same_iso_on_datastores(fake)
    assert len(asked) == 1 and ours.full in asked[0] and fake.plan.iso_datastore_path == ours.full


def test_a_copy_usable_where_it_is_comes_before_one_that_needs_copying(monkeypatch, tmp_path):
    """Fourth review: ranking vmdeploy's uploads above placement offered a host-to-host copy of x-2.iso before an
    identical file already on the VM's datastore."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib

    other = isolib.DatastoreIso("ds1", "isos/x.iso", 10, {"h1"}, 2, "DC")
    ours = isolib.DatastoreIso("esx2-local", "vmdeploy-iso/x-2.iso", 10, {"h2"}, 2, "DC")
    fake, asked, _ = _iso_choice_fake(monkeypatch, tmp_path, [ours, other], {other.full: True, ours.full: True})
    d.Deployment._find_same_iso_on_datastores(fake)
    assert len(asked) == 1 and other.full in asked[0] and fake.plan.iso_datastore_path == other.full
    assert fake.plan.iso_copy_from is None


def test_a_file_whose_contents_cannot_be_compared_is_offered_only_when_reuse_is_asked_for(monkeypatch, tmp_path):
    """Its question defaulted to No, and Enter ruled out every copy, including vmdeploy's earlier upload whose full
    SHA-256 the upload step checks anyway. A matching file further down the list is still offered, and with
    reuse_datastore_copy: true a file that cannot be sampled is used once its full SHA-256 matches."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib

    ours = isolib.DatastoreIso("ds1", "vmdeploy-iso/x-2.iso", 10, {"h1"}, 1, "DC")
    other = isolib.DatastoreIso("ds2", "isos/x.iso", 10, {"h1"}, 1, "DC")
    fake, asked, records = _iso_choice_fake(monkeypatch, tmp_path, [ours, other], {ours.full: None, other.full: None},
                                            answer=False)
    d.Deployment._find_same_iso_on_datastores(fake)
    assert asked == [] and not fake.plan.iso_rejected and fake.plan.iso_datastore_path is None
    assert "could not be compared" in records[-1] and "still used if its full SHA-256 matches" in records[-1]

    # the earlier upload cannot be sampled (e.g. HTTP 403); a matching file the host sees is still offered
    fake, asked, _ = _iso_choice_fake(monkeypatch, tmp_path, [ours, other], {ours.full: None, other.full: True})
    d.Deployment._find_same_iso_on_datastores(fake)
    assert len(asked) == 1 and other.full in asked[0] and fake.plan.iso_datastore_path == other.full

    # opted in (the server does not honour ranged reads): offered anyway, its full SHA-256 checked before use
    lib = isolib.DatastoreIso("lib", "iso/x.iso", 10, {"h1"}, 1, "DC")
    fake, asked, records = _iso_choice_fake(monkeypatch, tmp_path, [lib], {lib.full: None}, reuse=True)
    d.Deployment._find_same_iso_on_datastores(fake)
    assert "could not be compared" in asked[0] and fake.plan.iso_datastore_path == lib.full
    assert "checked in full first" in records[-1]


def test_no_rules_out_that_file_only(monkeypatch, tmp_path):
    """Decided in the fourth review: "No" to an offered copy is "not this file". A No to another file no longer rules
    out vmdeploy's own earlier upload (the upload step uses it once its full SHA-256 matches), and the question says
    what happens instead."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib

    other = isolib.DatastoreIso("shared", "isos/x.iso", 10, {"h1"}, 2, "DC")  # usable where it is: asked first
    ours = isolib.DatastoreIso("esx2-local", "vmdeploy-iso/x-2.iso", 10, {"h2"}, 2, "DC")  # would be copied
    fake, asked, records = _iso_choice_fake(monkeypatch, tmp_path, [ours, other], {ours.full: True, other.full: True},
                                            answer=False)
    d.Deployment._find_same_iso_on_datastores(fake)
    assert len(asked) == 1 and other.full in asked[0] and "an earlier upload in vmdeploy-iso/ is used" in asked[0]
    assert fake.plan.iso_rejected == {other.full} and fake.plan.iso_datastore_path is None
    assert records == [f"not {other.full}: an earlier upload in vmdeploy-iso/ is used if its full SHA-256 matches, "
                       "otherwise the ISO is uploaded from this computer"]

    # the only copy: No means the ISO is uploaded, and that file is never used at the upload step either
    only = isolib.DatastoreIso("ds1", "vmdeploy-iso/x.iso", 10, {"h1"}, 1, "DC")
    fake, asked, records = _iso_choice_fake(monkeypatch, tmp_path, [only], {only.full: True}, answer=False)
    d.Deployment._find_same_iso_on_datastores(fake)
    assert fake.plan.iso_rejected == {only.full} and records == [f"not {only.full}: the ISO is uploaded from this "
                                                                 "computer"]


def test_a_copy_of_an_earlier_dash_n_upload_gets_the_images_own_name(monkeypatch, tmp_path):
    """Copied to the VM's datastore under the candidate's name, a copy of x-2.iso became x-2.iso (or x-2-2.iso if
    taken), which later runs do not recognise as a copy of x.iso."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib

    ours = isolib.DatastoreIso("ds2", "vmdeploy-iso/x-2.iso", 10, {"h2"}, 2, "DC")  # another host's datastore
    fake, _, _ = _iso_choice_fake(monkeypatch, tmp_path, [ours], {ours.full: True})
    d.Deployment._find_same_iso_on_datastores(fake)
    assert fake.plan.iso_copy_from == ours.full and fake.plan.iso_datastore_path == "[ds1] vmdeploy-iso/x.iso"


def test_vmdeploys_copies_are_recognised_in_one_place():
    from vsphere_vm_deployment import isolib

    assert isolib.is_vmdeploy_copy("x.iso", "vmdeploy-iso/x.iso")
    assert isolib.is_vmdeploy_copy("x.iso", "vmdeploy-iso/x-2.iso")
    assert not isolib.is_vmdeploy_copy("x.iso", "isos/x-2.iso")
    assert not isolib.is_vmdeploy_copy("x.iso", "vmdeploy-iso/x-2-2.iso")
    assert not isolib.is_vmdeploy_copy("x.iso", "vmdeploy-iso/x.vmdeploy-upload-0a1b2c3d.iso")


def test_a_certificate_failure_while_sampling_stops_with_a_trust_error(monkeypatch):
    """A certificate that no longer validated was treated as 'the contents could not be compared'."""
    import http.client
    import ssl

    from vsphere_vm_deployment import transfer

    class FakeConn:
        def __init__(self, *a, **k):
            pass

        def connect(self):
            raise ssl.SSLCertVerificationError("certificate verify failed")

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPSConnection", FakeConn)
    decision = TrustDecision("vc.example.com", 443, "validated", None)  # validated: no pin to compare
    with pytest.raises(TrustError):
        transfer.read_range(decision, "/folder/x.iso?dcPath=DC&dsName=ds1", 0, 10)


@pytest.mark.parametrize("call", ["upload", "read", "range"])
def test_every_transfer_connects_through_one_trust_check(monkeypatch, call):
    """Fourth review: the certificate-failure handling was copied into each transfer function (and missing from
    one). A failing certificate is a TrustError for every transfer; a network failure is still 'interrupted' (or,
    for a sample, 'could not be compared'); the connection is closed either way."""
    import http.client
    import io
    import ssl

    from vsphere_vm_deployment import transfer

    closed, failure = [], {}

    class FakeConn:
        def __init__(self, *a, **k):
            pass

        def connect(self):
            raise failure["e"]

        def close(self):
            closed.append(True)

    monkeypatch.setattr(http.client, "HTTPSConnection", FakeConn)
    decision = TrustDecision("vc.example.com", 443, "validated", None)  # validated: no pin to compare
    run = {"upload": lambda: transfer.upload_stream(decision, "PUT", "/folder/x.iso", io.BytesIO(b"x"), 1),
           "read": lambda: transfer.read_stream(decision, "/folder/x.iso", lambda b: None),
           "range": lambda: transfer.read_range(decision, "/folder/x.iso", 0, 1)}[call]
    failure["e"] = ssl.SSLCertVerificationError("certificate verify failed")
    with pytest.raises(TrustError, match="not the trusted one"):
        run()
    failure["e"] = ConnectionResetError("reset")
    if call == "range":
        assert run() is None
    else:
        with pytest.raises(DeploymentError, match="interrupted"):
            run()
    assert len(closed) == 2


def test_the_full_check_of_a_datastore_copy_stops_on_a_certificate_failure(monkeypatch):
    """Fourth review: _datastore_sha256 turned a TrustError from read_stream into 'could not be read; not used',
    and the run went on with a server whose certificate no longer validated."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import transfer

    def refuse(*a, **k):
        raise TrustError("vc.example.com:443 presented a certificate that is not the trusted one; reading stopped.")

    monkeypatch.setattr(transfer, "read_stream", refuse)
    fake = NS(view=NS(begin_transfer=lambda *a: None, end_transfer=lambda: None),
              _datastore_http=lambda full: (None, "/folder/x.iso", {}))
    with pytest.raises(TrustError):
        d.Deployment._datastore_sha256(fake, "[ds1] vmdeploy-iso/x.iso", "upload_iso")


def test_profile_add_with_yes_never_replaces_another_servers_profile_by_a_default_name(monkeypatch):
    """Fourth review: vcsa.site-a.example and vcsa.site-b.example both get the default name 'vcsa'; with --yes the
    second replaced the first and deleted its saved password. The same goes for another account on the same server,
    and the host's letter case does not make it another server. An explicit --name still replaces."""
    from vsphere_vm_deployment import cli, credentials
    from vsphere_vm_deployment.profiles import ProfileStore
    from vsphere_vm_deployment.ui import Prompter

    deleted = []
    monkeypatch.setattr(credentials, "delete_secret", lambda profile, kind="password": deleted.append(kind) or True)
    store, p = ProfileStore(), Prompter(interactive=False)
    cli._profile_wizard(p, store, host="vcsa.site-a.example", username="ops", remember=True)
    for host, user in (("vcsa.site-b.example", "ops"), ("vcsa.site-a.example", "ops2")):
        with pytest.raises(ConfigError, match="another server or account"):
            cli._profile_wizard(p, store, host=host, username=user, remember=True)
    assert store.get("vcsa").host == "vcsa.site-a.example" and store.get("vcsa").username == "ops" and not deleted
    # the same server in other letters: the default name is "vcsa" too, the same target, so the password is kept
    cli._profile_wizard(p, store, host="VCSA.site-a.example", username="ops", remember=True)
    assert [pr.name for pr in store.list()] == ["vcsa"] and not deleted
    cli._profile_wizard(p, store, host="vcsa.site-b.example", name="vcsa", username="ops", remember=True)
    assert store.get("vcsa").host == "vcsa.site-b.example" and deleted  # asked for by name: replaced


def test_profile_add_with_yes_may_add_a_user_to_a_profile_that_had_none(monkeypatch):
    """Final review: a profile saved without a user (so without a saved password) could not be updated with --yes
    once the guard compared users exactly; a user name in other letters is the same account."""
    from vsphere_vm_deployment import cli, credentials
    from vsphere_vm_deployment.profiles import ProfileStore
    from vsphere_vm_deployment.ui import Prompter

    monkeypatch.setattr(credentials, "delete_secret", lambda profile, kind="password": True)
    store, p = ProfileStore(), Prompter(interactive=False)
    cli._profile_wizard(p, store, host="vcsa.example.com", remember=False)
    cli._profile_wizard(p, store, host="vcsa.example.com", username="ops", remember=False)
    cli._profile_wizard(p, store, host="vcsa.example.com", username="OPS", remember=False)
    assert [(pr.name, pr.username) for pr in store.list()] == [("vcsa", "OPS")]


def test_a_certificate_failure_while_checking_an_earlier_upload_stops_the_run(monkeypatch):
    """Fourth review: the TrustError from the full check must reach the top, both for a copy used where it is and
    for one copied host to host (where a DeploymentError means 'upload instead')."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib

    for hosts in ({"h1"}, {"h2"}):  # usable where it is; on another host's datastore (copied)
        cand = isolib.DatastoreIso("ds2", "vmdeploy-iso/win.iso", 10, hosts, 2, "DC")

        def refuse(full, step="upload_iso", c=cand, copied=hosts == {"h2"}):
            if copied and full == c.full:
                return True  # the source passes; the check of the copy already at the target fails (inside the copy)
            raise TrustError("vc.example.com:443 presented a certificate that is not the trusted one; reading stopped.")

        monkeypatch.setattr(isolib, "find_isos", lambda dc, c=cand: [c])
        monkeypatch.setattr(isolib, "ensure_copied", lambda conn, dc, src, ds, target, **k: k["reuse_if"](target))
        plan = NS(dc=NS(obj=None), datastore=NS(name="ds1", obj=None), host_names={"h1"},
                  iso_datastore_path=None, iso_rejected=set())
        fake = NS(plan=plan, view=NS(done=lambda *a, **k: None, update=lambda *a, **k: None,
                                     note=lambda *a, **k: None),
                  image=NS(path=NS(name="win.iso"), sha256="ab" * 32), m=NS(image=NS(reuse_datastore_copy=None)),
                  conn=NS(is_vcenter=True), _copy_is_genuine=refuse)
        with pytest.raises(TrustError):
            d.Deployment._reuse_uploaded_iso(fake, 10)


def test_vmdeploys_vms_are_read_in_one_go_per_folder(monkeypatch):
    """Fourth review: every VM's whole configuration was fetched on its own (several times) to read its Notes, and
    its name one request at a time (twice). Names and markers now come from one request per folder."""
    from vsphere_vm_deployment import access, inventory

    calls = []
    vm1, vm2, vm3 = NS(_moId="vm-1"), NS(_moId="vm-2"), NS(_moId="vm-3")

    def collect(conn, vimtype, paths, root=None, strict=False):
        calls.append((paths, root.name, strict))
        return [(vm2, {"name": "b", "config.annotation": "x\n[deployed-by: vsphere-vm-deployment]"}),
                (vm1, {"name": "c", "config.annotation": "someone else's VM"}), (vm3, {"name": "a"})]

    monkeypatch.setattr(inventory, "collect", collect)
    [(folder, recs)] = access.vms_in_folders(None, [NS(name="vmdeploy-x", _moId="group-v1")])
    assert folder == "vmdeploy-x" and [(r.name, r.ours) for r in recs] == [("a", False), ("b", True), ("c", False)]
    assert calls == [(["name", "config.annotation"], "vmdeploy-x", True)]


def test_a_copy_failing_its_full_check_falls_back_to_earlier_uploads_before_uploading(monkeypatch):
    """Final review: when the offered copy failed its full SHA-256 check, the upload skipped vmdeploy's other
    verified earlier uploads (reuse=False). The failed file is in iso_rejected, so reuse is safe."""
    from vsphere_vm_deployment import deploy as d

    class Stop(Exception):
        pass

    def start(step, *a, **k):
        if step == "create":
            raise Stop

    uploads = []
    plan = NS(iso_found_on_datastore=True, iso_copy_from=None, iso_copy_via_pc=False,
              iso_datastore_path="[shared] isos/x.iso")
    fake = NS(plan=plan, view=NS(skip=lambda *a, **k: None, start=start), _copy_is_genuine=lambda full: False,
              _upload_iso=lambda *a, **k: uploads.append(k))
    with pytest.raises(Stop):
        d.Deployment._deploy_iso(fake)
    assert uploads == [{}] and plan.iso_datastore_path is None and not plan.iso_found_on_datastore


def test_change_my_answers_does_not_carry_a_no_over_to_another_file(monkeypatch, tmp_path):
    """Final review: "No" now means "not this file", but on "Change my answers" a No about one file became the
    default answer for a different file."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib, ui

    seen = []
    monkeypatch.setattr(ui.questionary, "confirm", lambda q, default: NS(unsafe_ask=lambda: seen.append(default)
                                                                         or default))
    iso = tmp_path / "x.iso"
    iso.write_bytes(b"x" * 10)
    a = isolib.DatastoreIso("dsA", "isos/x.iso", 10, {"h1"}, 1, "DC")
    b = isolib.DatastoreIso("dsB", "vmdeploy-iso/x.iso", 10, {"h1"}, 1, "DC")
    for cand, expected in ((b, True), (a, False)):  # another file: the default is Yes again; the same file: No
        p = ui.Prompter(interactive=False)
        p.interactive = True  # pytest has no terminal
        p.previous = {"image.reuse_datastore_copy": False, "_iso_copy_offered": a.full}
        plan = NS(datastore=NS(name="ds1"), host_names={"h1"}, iso_rejected=set(), iso_datastore_path=None,
                  iso_copy_from=None, iso_found_on_datastore=False)
        dep = NS(plan=plan, image=NS(path=iso), m=NS(image=NS(reuse_datastore_copy=None)), p=p)
        d._offer_iso_copy(dep, cand, 10, [a, b], {a.full: False, b.full: True}, sampled=True)
        assert seen[-1] is expected and p.answers["_iso_copy_offered"] == cand.full


def test_an_iso_on_the_vms_own_datastore_is_always_usable_where_it_is():
    """Final review: in a cluster where not every host mounts the VM's datastore, a copy on that datastore was
    ranked as needing a host-to-host copy (onto the same datastore)."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib

    plan = NS(datastore=NS(name="ds1"), host_names={"h1", "h2"})
    assert d._iso_in_place(plan, isolib.DatastoreIso("ds1", "vmdeploy-iso/x.iso", 10, {"h1"}, 2, "DC"))
    assert not d._iso_in_place(plan, isolib.DatastoreIso("ds9", "isos/x.iso", 10, {"h1"}, 2, "DC"))


def test_access_remove_lists_each_vm_once_with_nested_folders(monkeypatch):
    """Final review: with a permission on a parent of setup's folder, the child's VMs were listed twice; the second
    deletion attempt failed on the VM just deleted, before the permissions and roles were removed."""
    from vsphere_vm_deployment import access, inventory

    vm1, vm2 = NS(_moId="vm-1"), NS(_moId="vm-2")
    inside = {"Lab": [(vm1, {"name": "a"}), (vm2, {"name": "b"})], "vmdeploy-x": [(vm2, {"name": "b"})]}
    monkeypatch.setattr(inventory, "collect", lambda conn, t, paths, root=None, strict=False: inside[root.name])
    folders = [NS(name="Lab", _moId="group-v1"), NS(name="vmdeploy-x", _moId="group-v2")]
    [(folder, recs)] = access.vms_in_folders(None, folders)
    assert folder == "Lab" and [r.vm for r in recs] == [vm1, vm2]


def test_access_remove_stops_when_the_vms_cannot_be_read(monkeypatch):
    """Final review: a failed read showed every VM as 'not deployed by vmdeploy' in the plan. Now nothing is
    removed and the error says why, also when the folder's own name cannot be read any more."""
    from vsphere_vm_deployment import access, inventory

    def fail(conn, vimtype, paths, root=None, strict=False):
        assert strict
        raise RuntimeError("timed out")

    monkeypatch.setattr(inventory, "collect", fail)
    with pytest.raises(DeploymentError, match=r"Could not read the VMs: timed out \(folder vmdeploy-x\)\. Nothing"):
        access.vms_in_folders(None, [NS(name="vmdeploy-x", _moId="group-v1")])

    class Gone:  # the session expired: reading the folder's name fails as well
        _moId = "group-v1"

        @property
        def name(self):
            raise ConnectionResetError("connection reset")

    with pytest.raises(DeploymentError, match=r"Could not read the VMs: connection reset \(folder group-v1\)"):
        access.vms_in_folders(None, [Gone()])


# ------------------------------------------------------------------ bulk VM reads and the Notes block


def test_the_notes_block_is_written_and_read_in_one_place():
    """The marker check was written out in six places (and --replace crashed on a VM whose configuration could not
    be read); vmnotes owns it now."""
    from vsphere_vm_deployment import ANNOTATION_MARKER, vmnotes

    text = vmnotes.build("My notes\ndeployed: by hand", "x.iso (local file)", "ab" * 32)
    assert text.startswith("My notes\ndeployed: by hand\n\n" + ANNOTATION_MARKER + "\nversion: ")
    assert vmnotes.is_marked(text) and not vmnotes.is_marked("someone else's VM") and not vmnotes.is_marked(None)
    assert vmnotes.field(text, "image") == "x.iso (local file)" and vmnotes.field(text, "image-sha256") == "ab" * 32
    assert vmnotes.field(text, "deployed") != "by hand"  # read from vmdeploy's block, not from the user's notes
    assert vmnotes.field("no marker", "deployed") == ""
    # notes copied from another vmdeploy VM into the manifest: the newest block (always the last) is the one read
    copied = vmnotes.build(f"{ANNOTATION_MARKER}\ndeployed: 2023-01-01T00:00:00+00:00", "x.iso", None)
    assert vmnotes.field(copied, "deployed") != "2023-01-01T00:00:00+00:00" and vmnotes.field(copied, "image")


def test_one_vm_is_read_in_one_small_request():
    """The check right before `access remove` deletes a VM read its whole configuration (twice); a deleted VM or a
    fault is a clear error, never 'not marked'."""
    from pyVmomi import vim

    from vsphere_vm_deployment import inventory

    vm = vim.VirtualMachine("vm-7")
    sent = []

    def conn(result=None, fail=None):
        def retrieve(specSet, options):
            sent.append([p.pathSet for p in specSet[0].propSet] + [[o.obj._moId for o in specSet[0].objectSet]])
            if fail:
                raise fail
            return result

        return NS(content=NS(propertyCollector=NS(RetrievePropertiesEx=retrieve)))

    one = NS(objects=[NS(propSet=[NS(name="config.annotation", val="notes")])])
    assert inventory.vm_properties_of(conn(one), vm, ["config.annotation", "config.hardware.device"]) == {
        "config.annotation": "notes"}  # a property the server left out is simply missing
    assert sent == [[["config.annotation", "config.hardware.device"], ["vm-7"]]]
    with pytest.raises(DeploymentError, match="deleted or moved meanwhile"):
        inventory.vm_properties_of(conn(NS(objects=[])), vm, ["config.annotation"])
    with pytest.raises(DeploymentError, match="Could not read the VM: The object has already been deleted"):
        inventory.vm_properties_of(conn(fail=RuntimeError("The object has already been deleted")), vm, ["name"])


def test_finding_a_vm_by_name_reads_all_names_in_one_request(monkeypatch):
    """`destroy <name>` and `deploy --replace` read the name of every VM in the datacenter, one request each."""
    from vsphere_vm_deployment import inventory

    calls = []
    a, b = NS(_moId="vm-1"), NS(_moId="vm-2")

    def collect(conn, t, paths, root=None, strict=False):
        calls.append((paths, root, strict))
        return [(a, {"name": "web01"}), (b, {"name": "db01"})]

    monkeypatch.setattr(inventory, "collect", collect)
    assert inventory.find_vm(None, "db01", root="dc-vm-folder") is b and inventory.find_vm(None, "nope") is None
    assert calls == [(["name"], "dc-vm-folder", True), (["name"], None, True)]

    def fail(conn, t, paths, root=None, strict=False):
        raise RuntimeError("NotAuthenticated")

    monkeypatch.setattr(inventory, "collect", fail)  # never "no VM named ..." when the names could not be read
    with pytest.raises(DeploymentError, match="Could not read the VMs"):
        inventory.find_vm(None, "db01")


def test_list_reads_every_vm_in_one_request(monkeypatch):
    """`vmdeploy list` downloaded every VM's whole configuration to read its Notes, then made three more requests
    per VM of vmdeploy's."""
    from vsphere_vm_deployment import cli, inventory, vmnotes

    calls = []

    def collect(conn, t, paths, root=None, strict=False):
        calls.append(paths)
        ours = vmnotes.build(None, "x.iso", None)
        edited = "[deployed-by: vsphere-vm-deployment]\ndeployed: 2026 [/] by hand"  # anyone may edit Notes
        return [(NS(), {"name": "web02", "config.annotation": ours, "runtime.powerState": "poweredOff"}),
                (NS(), {"name": "dc01", "config.annotation": "domain controller", "runtime.powerState": "poweredOn"}),
                (NS(), {"name": "web01", "config.annotation": ours, "runtime.powerState": "poweredOn",
                        "guest.ipAddress": "192.0.2.10"}),
                (NS(), {"name": "web03", "config.annotation": edited, "runtime.powerState": "poweredOff"})]

    monkeypatch.setattr(inventory, "collect", collect)
    monkeypatch.setattr(cli, "_connect", lambda *a: (contextlib.nullcontext(), None))
    r = CliRunner().invoke(cli.app, ["list"], env={"COLUMNS": "200"})
    assert r.exit_code == 0, r.output  # a '[/]' typed into the Notes made Rich fail on the whole list
    assert calls == [["name", "config.annotation", "runtime.powerState", "guest.ipAddress"]]
    assert "dc01" not in r.output and r.output.index("web01") < r.output.index("web02") and "192.0.2.10" in r.output
    assert "2026 [/] by hand" in r.output


def test_access_remove_deletes_only_vms_the_plan_listed_and_that_are_still_marked(monkeypatch, caplog):
    """The delete loop: a VM is deleted only if the plan said it was deployed by vmdeploy AND its Notes still say
    so when read right before its own deletion (one small request, not its whole configuration, twice). A VM that
    cannot be read then, or is no longer marked, is kept with the reason; its ISO copies are passed on only when it
    is deleted, with its own datacenter. Smoke test: the deletions and the reasons were not in the log file."""
    import logging

    from pyVmomi import vim

    caplog.set_level(logging.INFO, logger="vsphere_vm_deployment.access")

    from vsphere_vm_deployment import access, inventory, isocopies, vmnotes

    iso = vim.vm.device.VirtualCdrom(backing=vim.vm.device.VirtualCdrom.IsoBackingInfo(
        fileName="[ds1] vmdeploy-iso/x.iso"))
    other_iso = vim.vm.device.VirtualCdrom(backing=vim.vm.device.VirtualCdrom.IsoBackingInfo(
        fileName="[ds1] isos/y.iso"))  # not one of vmdeploy's copies
    ours = vmnotes.build(None, "x.iso", None)
    fresh = {"vm-1": {"config.annotation": ours, "config.hardware.device": [iso, other_iso]},
             "vm-2": {"config.annotation": "marker removed since the plan"},
             "vm-4": DeploymentError("Could not read the VM: it may have been deleted or moved meanwhile.")}
    read, deleted, warnings, walked = [], [], [], []

    def props_of(conn, vm, paths):
        read.append(vm._moId)
        got = fresh[vm._moId]
        if isinstance(got, Exception):
            raise got
        return got

    monkeypatch.setattr(inventory, "vm_properties_of", props_of)
    monkeypatch.setattr(access, "delete_vm", lambda vm, label=None: deleted.append((vm._moId, label)))
    monkeypatch.setattr(isocopies, "datacenter_of", lambda vm: walked.append(vm._moId) or "DC")
    recs = [access.FolderVM(NS(_moId=f"vm-{n}"), f"web0{n}", n != 3) for n in (1, 2, 3, 4)]
    shown = []
    done, isos = access.delete_planned(None, [("vmdeploy-x", recs)], warnings.append, on_removed=shown.append)
    assert deleted == [("vm-1", "web01")] and done == shown == ["VM web01 (powered off and deleted)"]
    assert isos == [("DC", "[ds1] vmdeploy-iso/x.iso")] and walked == ["vm-1"]
    assert read == ["vm-1", "vm-2", "vm-4"]  # the VM the plan listed as not vmdeploy's is never read or deleted
    assert warnings == ["Kept VM 'web02': its Notes no longer mark it as deployed by vmdeploy.",
                        "Kept VM 'web03': it was not deployed by vmdeploy.",
                        "Kept VM 'web04': Could not read the VM: it may have been deleted or moved meanwhile."]
    logged = [r.getMessage() for r in caplog.records]  # the deletion itself is logged by delete_vm
    assert all(w in logged for w in warnings)


# ------------------------------------------------------------------ minor suggestions 1-5 (before the first push)


def test_host_names_in_other_letter_cases_are_one_server(tmp_path):
    """Host names are case-insensitive (DNS), but profiles and saved certificates compared them as typed: a second
    trust prompt for VCSA.example.com (which --yes refuses), and `access remove` missed a deploy profile saved with
    other letters. Entries saved before keys were lower case are still found."""
    import json

    from vsphere_vm_deployment.profiles import Profile
    from vsphere_vm_deployment.trust import TrustStore

    assert Profile(name="a", host=" VCSA.Example.COM ").host == "vcsa.example.com"
    assert Profile(name="b", host="[FD00::10]").host == "fd00::10"
    store = TrustStore(tmp_path / "trusted_hosts.json")
    store.path.write_text(json.dumps({"pins": {"VCSA.Example.COM:443": {"sha256": "ab"}},
                                      "cas": {"VC2.example.com:443": {"pems": ["x"]}}}), encoding="utf-8")
    assert store.pin("vcsa.example.com:443") == {"sha256": "ab"} and store.ca_bundle() == "x"
    assert store.remove("VC2.EXAMPLE.COM:443") and store.ca_bundle() is None


@pytest.mark.parametrize("call", ["key provider", "token exchange", "CA download"])
def test_every_raw_https_request_turns_a_certificate_failure_into_a_trust_error(monkeypatch, call):
    """Key provider requests, the token exchange and the vCenter CA download each had their own certificate
    handling; the CA download let a raw SSL error through ("Unexpected error"). All use TrustDecision.connect."""
    import http.client

    from vsphere_vm_deployment import auth, keyprovider, trust

    closed = []

    class FakeConn:
        def __init__(self, *a, **k):
            pass

        def connect(self):
            raise ssl.SSLCertVerificationError("certificate verify failed")

        def close(self):
            closed.append(True)

    monkeypatch.setattr(http.client, "HTTPSConnection", FakeConn)
    decision = TrustDecision("vc.example.com", 443, "validated", None)
    run = {"key provider": lambda: keyprovider._request(decision, "GET", "/api/vcenter/crypto-manager/kms/providers"),
           "token exchange": lambda: auth.exchange_for_saml(decision, "access-token", None),
           "CA download": lambda: trust.download_vcenter_ca(decision)}[call]
    with pytest.raises(TrustError, match="vc.example.com:443 presented a certificate that is not the trusted one"):
        run()
    assert closed == [True]


def test_only_the_trust_module_opens_https_connections():
    """Every raw HTTPS request goes through TrustDecision.connect (validated or pinned context, peer check, a
    certificate failure is a TrustError); a new copy of that logic elsewhere is how one of them went missing."""
    from pathlib import Path

    import vsphere_vm_deployment

    src = Path(vsphere_vm_deployment.__file__).parent
    found = sorted(p.name for p in src.glob("*.py") if "HTTPSConnection(" in p.read_text(encoding="utf-8"))
    assert found == ["trust.py"]


class _FakeKeychain:
    """An OS keychain in memory: `locked` makes every call fail the way a locked keychain does; `sticky` makes a
    delete report success while the entry stays (seen with some backends)."""

    def __init__(self, monkeypatch):
        import keyring

        self.saved, self.locked, self.sticky = {}, False, False
        monkeypatch.setattr(keyring, "get_password", self.get)
        monkeypatch.setattr(keyring, "set_password", self.set)
        monkeypatch.setattr(keyring, "delete_password", self.delete)

    def _check(self):
        from keyring.errors import KeyringLocked

        if self.locked:
            raise KeyringLocked("locked")

    def get(self, service, key):
        self._check()
        return self.saved.get((service, key))

    def set(self, service, key, value):
        self._check()
        self.saved[(service, key)] = value

    def delete(self, service, key):
        from keyring.errors import PasswordDeleteError

        self._check()
        if (service, key) not in self.saved:
            raise PasswordDeleteError("not found")
        if not self.sticky:
            del self.saved[(service, key)]


def test_a_saved_secret_is_never_read_for_another_server_or_account(monkeypatch):
    """Security review: secrets were saved per profile name. When the keychain could not be changed (locked), the
    secret of a replaced profile stayed under the reused name and was sent to the new server. A secret is now bound
    to its server, port, account, sign-in method and token endpoint: a leftover is never even found."""
    from vsphere_vm_deployment import credentials
    from vsphere_vm_deployment.profiles import OAuthSettings, Profile

    def variant(profile, **changes):  # validated like a saved profile (host names in lower case)
        return Profile(**{**profile.model_dump(), **changes})

    keychain = _FakeKeychain(monkeypatch)
    lab = Profile(name="lab", host="vc1.example.com", username="ops", remember_secret=True)
    assert credentials.set_secret(lab, "s3cret") and credentials.get_secret(lab) == "s3cret"
    assert credentials.get_secret(variant(lab, host="VC1.Example.com")) == "s3cret"  # the same server
    for other in ({"host": "vc2.example.com"}, {"port": 8443}, {"username": "ops2"}, {"auth": "oauth-password"},
                  {"oauth": OAuthSettings(token_url="https://idp.example.com/token", client_id="vmdeploy")}):
        assert credentials.get_secret(variant(lab, **other)) is None, other
    sso = Profile(name="sso", host="vc1.example.com", auth="oauth-client-credentials", remember_secret=True,
                  oauth=OAuthSettings(token_url="https://idp.example.com/token", client_id="vmdeploy"))
    assert credentials.set_secret(sso, "client-s3cret", "client_secret")
    assert credentials.get_secret(sso, "client_secret") == "client-s3cret"
    for oauth in (OAuthSettings(token_url="https://other.example.net/token", client_id="vmdeploy"),
                  OAuthSettings(token_url="https://idp.example.com/token", client_id="someone-else")):
        assert credentials.get_secret(variant(sso, oauth=oauth), "client_secret") is None

    # deleting: True deleted, False nothing saved, None could not be changed or checked (the secret may be there)
    assert credentials.delete_secret(lab) is True and credentials.get_secret(lab) is None
    assert credentials.delete_secret(lab) is False
    credentials.set_secret(lab, "s3cret")
    keychain.sticky = True
    assert credentials.delete_secret(lab) is None
    keychain.sticky, keychain.locked = False, True
    assert credentials.delete_secret(lab) is None and credentials.delete_secrets(lab) == ([], False)
    keychain.locked = False
    assert credentials.delete_secrets(lab) == (["password"], True)


def test_a_locked_keychain_never_leaves_an_old_secret_for_a_new_server(monkeypatch):
    """Replacing a profile for another server while the keychain is locked: the old password cannot be deleted.
    The new profile keeps its keychain setting (it can never read the old entry) and the user is told."""
    from vsphere_vm_deployment import cli, credentials
    from vsphere_vm_deployment.profiles import ProfileStore
    from vsphere_vm_deployment.ui import Prompter

    keychain = _FakeKeychain(monkeypatch)
    warnings = []
    monkeypatch.setattr(cli, "warn", lambda text: warnings.append(text))
    monkeypatch.setattr(credentials, "keychain_available", lambda: True)
    store, p = ProfileStore(), Prompter(interactive=False)
    old = cli._profile_wizard(p, store, host="vc1.example.com", name="lab", username="ops", remember=True)
    credentials.set_secret(old, "old-s3cret")
    keychain.locked = True
    new = cli._profile_wizard(p, store, host="vc2.example.com", name="lab", username="ops", remember=True)
    assert store.get("lab").host == "vc2.example.com" and store.get("lab").remember_secret
    [warning] = warnings  # names the entry to delete by hand: `forget-secret lab` now means the new server
    assert "could not be removed from the OS keychain" in warning and credentials.entry_name(old, "password") in warning
    keychain.locked = False
    assert credentials.get_secret(old) == "old-s3cret"  # still there, under the old server's entry...
    assert credentials.get_secret(new) is None  # ...and never sent to the new server


def test_the_iso_on_a_cd_drive_rule_is_written_once():
    """iso_users and copies_attached each had their own loop over CD/DVD ISO backings (and differed slightly)."""
    from pyVmomi import vim

    from vsphere_vm_deployment import isocopies

    def cd(path):
        return vim.vm.device.VirtualCdrom(backing=vim.vm.device.VirtualCdrom.IsoBackingInfo(fileName=path))

    devices = [cd("[ds1]  vmdeploy-iso/x.iso"), cd("[ds1] isos/y.iso"), cd(""),
               vim.vm.device.VirtualCdrom(backing=vim.vm.device.VirtualCdrom.RemotePassthroughBackingInfo()),
               vim.vm.device.VirtualDisk()]
    assert isocopies.iso_paths(devices) == ["[ds1] vmdeploy-iso/x.iso", "[ds1] isos/y.iso"]
    assert isocopies.copies_attached(devices, "DC") == [("DC", "[ds1] vmdeploy-iso/x.iso")]
    # connected_only: the files a running VM keeps locked (deploy's "copy it from another host" check)
    devices[1].connectable = vim.vm.device.VirtualDevice.ConnectInfo(connected=True)
    devices[0].connectable = vim.vm.device.VirtualDevice.ConnectInfo(connected=False)
    assert isocopies.iso_paths(devices, connected_only=True) == ["[ds1] isos/y.iso"]


def test_running_vms_using_an_iso_reads_every_vm_once_and_counts_only_connected_drives(monkeypatch):
    """deploy had its own loop over CD/DVD backings; it now uses isocopies.iso_paths(connected_only=True)."""
    from pyVmomi import vim

    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import inventory

    def vm(name, power, path, connected):
        cd = vim.vm.device.VirtualCdrom(backing=vim.vm.device.VirtualCdrom.IsoBackingInfo(fileName=path),
                                        connectable=vim.vm.device.VirtualDevice.ConnectInfo(connected=connected))
        return None, {"name": name, "runtime.powerState": power, "config.hardware.device": [cd]}

    vms = [vm("a", "poweredOn", "[ds1]  isos/x.iso", True), vm("b", "poweredOn", "[ds1] isos/x.iso", False),
           vm("c", "poweredOff", "[ds1] isos/x.iso", True), vm("d", "poweredOn", "[ds1] isos/y.iso", True)]
    monkeypatch.setattr(inventory, "collect", lambda conn, t, paths, **k: vms)
    fake = NS(conn=NS())
    assert d.Deployment._running_vms_using(fake, "[ds1] isos/x.iso") == ["a"]


def test_bulk_reads_have_one_home():
    """The bulk property reader lived in netcheck as a private helper used by five modules."""
    from vsphere_vm_deployment import inventory, netcheck

    assert callable(inventory.collect) and not hasattr(netcheck, "_collect")


def test_a_certificate_that_fails_at_sign_in_is_a_trust_error(monkeypatch):
    """A certificate renewed (or intercepted) since it was trusted failed inside pyVmomi's sign-in and was reported
    as an unexpected error ("a bug") at the API version check, and as "Could not connect" (or a rejected SAML token)
    at the sign-in itself, where pyVmomi wraps it in a HostConnectFault. Other connection faults pass unchanged."""
    from pyVmomi import vim

    from vsphere_vm_deployment import connection
    from vsphere_vm_deployment.profiles import Profile

    profile = Profile(name="lab", host="vc.example.com")
    decision = TrustDecision("vc.example.com", 443, "pinned", None)
    decision.ssl_context = lambda: ssl.create_default_context()
    failure = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
    failure.verify_message = "certificate has expired"

    def fail(*a, **k):
        raise failure

    def wrapped(**k):  # what pyVim.connect.__Login does with any error that is not a vSphere fault
        try:
            raise failure
        except ssl.SSLCertVerificationError as e:
            raise vim.fault.HostConnectFault(msg=str(e))  # noqa: B904 - as pyVmomi does

    monkeypatch.setattr(connection, "_supported_version", fail)
    with pytest.raises(TrustError, match="vc.example.com:443 presented a certificate that is not the trusted one"):
        connection._raw_connect(profile, decision, user="ops", pwd="x")
    monkeypatch.setattr(connection, "_supported_version", lambda *a: "vim.version.v8_0_3_0")
    monkeypatch.setattr(connection.pyvim_connect, "Connect", wrapped)
    with pytest.raises(TrustError, match=r"\(certificate has expired\); sign-in stopped") as e:
        connection._raw_connect(profile, decision, user="ops", pwd="x")
    assert "CHANGED" in e.value.hint and "trust remove" not in e.value.hint  # the old pin keeps that warning
    monkeypatch.setattr(connection.pyvim_connect, "Connect",
                        lambda **k: (_ for _ in ()).throw(vim.fault.HostConnectFault(msg="connection refused")))
    with pytest.raises(vim.fault.HostConnectFault):
        connection._raw_connect(profile, decision, user="ops", pwd="x")
    # a validated (not pinned) certificate: there is no pin to remove
    validated = TrustDecision("fd00::10", 443, "validated", None)
    err = validated.refused(failure, "the upload")
    assert err.message.startswith("[fd00::10]:443 presented") and "trust remove" not in err.hint


def test_a_bulk_read_whose_view_cannot_be_created_follows_the_strict_rule(monkeypatch):
    """Creating the container view sat outside the try: an expired session was an unexpected error even for
    informational reads, which must return nothing instead."""
    from pyVmomi import vim

    from vsphere_vm_deployment import inventory

    def fail(*a):
        raise RuntimeError("session expired")

    conn = NS(content=NS(rootFolder=None, viewManager=NS(CreateContainerView=fail)))
    assert inventory.collect(conn, vim.VirtualMachine, ["name"]) == []
    with pytest.raises(RuntimeError, match="session expired"):
        inventory.collect(conn, vim.VirtualMachine, ["name"], strict=True)
    with pytest.raises(DeploymentError, match="Could not read the VMs: session expired"):
        inventory.vm_properties(conn, ["name"])


def test_host_letter_case_is_one_server_but_an_ipv6_zone_keeps_its_letters():
    from vsphere_vm_deployment.profiles import Profile
    from vsphere_vm_deployment.trust import endpoint_key

    assert Profile(name="a", host="VCSA.Example.COM").host == "vcsa.example.com"
    assert Profile(name="a", host="[FE80::1%Eth0]").host == "fe80::1%Eth0"  # a Linux interface name: case-sensitive
    assert endpoint_key("VCSA.Example.COM:443") == "vcsa.example.com:443"
    assert endpoint_key("[FE80::1%Eth0]:443") == "[fe80::1%Eth0]:443"
    assert endpoint_key("FD00::AB:443") == "fd00::ab:443"  # trust entries store an IPv6 host without brackets
    # without a port, all of it is the host
    assert endpoint_key("VCSA.Example.COM") == "vcsa.example.com"
    assert endpoint_key("[FD00::AB]") == "[fd00::ab]"
    assert endpoint_key("FE80::AB%Eth0") == "fe80::ab%Eth0"


def test_trust_entries_that_differ_only_in_letter_case_keep_the_newest(isolated_dirs):
    """Pins saved before keys were lower case are merged on load: the newest one wins whatever the file order, so
    a certificate trusted again after a renewal is not replaced by the old one (a 'certificate changed' prompt)."""
    import json

    from vsphere_vm_deployment.trust import TrustStore

    store = TrustStore()
    old = {"sha256": "aa" * 32, "added": "2026-01-01T00:00:00+00:00"}
    new = {"sha256": "bb" * 32, "added": "2026-06-01T00:00:00+00:00"}
    for order in (("vc.example.com:443", new, "VC.example.com:443", old),
                  ("VC.example.com:443", old, "vc.example.com:443", new)):
        store.path.write_text(json.dumps({"pins": {order[0]: order[1], order[2]: order[3]}, "cas": {}}),
                              encoding="utf-8")
        assert store.pin("Vc.Example.com:443")["sha256"] == "bb" * 32
        assert list(store.entries()["pins"]) == ["vc.example.com:443"]


def test_the_account_history_matches_a_server_however_its_name_was_typed(isolated_dirs):
    """Entries recorded before host names were stored in lower case were not found by `access remove` (the account
    stayed "still set up") or by `access audit`."""
    from vsphere_vm_deployment import access

    access.record_setup("VCSA.example.com:443", r"VSPHERE.LOCAL\svc-deploy")
    access.record_removed("vcsa.example.com:443", [r"vsphere.local\SVC-DEPLOY"])
    [e] = access.load_history()
    assert e["removed"]
    access.record_setup("vcsa.example.com:443", r"VSPHERE.LOCAL\svc-deploy")  # replaces the entry, not a second
    assert len(access.load_history()) == 1
    access.forget_account("VCSA.EXAMPLE.COM:443", r"vsphere.local\svc-deploy")
    assert access.load_history() == []
    assert access.same_endpoint("[FD00::10]:443", "[fd00::10]:443")
    assert not access.same_endpoint("vcsa.example.com:443", "vcsa.example.com:8443")


def test_turning_the_keychain_off_for_a_profile_deletes_its_saved_secret(monkeypatch):
    """Code review: a password saved for a profile stayed in the keychain when the profile was saved again for the
    same server and account with the keychain turned off, and was out of reach of every command afterwards."""
    from vsphere_vm_deployment import cli, credentials
    from vsphere_vm_deployment.profiles import ProfileStore
    from vsphere_vm_deployment.ui import Prompter

    _FakeKeychain(monkeypatch)
    store, p = ProfileStore(), Prompter(interactive=False)
    old = cli._profile_wizard(p, store, host="vc1.example.com", name="lab", username="ops", remember=True)
    credentials.set_secret(old, "s3cret")
    cli._profile_wizard(p, store, host="vc1.example.com", name="lab", username="ops", remember=True)
    assert credentials.get_secret(old) == "s3cret"  # kept: same server, account and setting
    cli._profile_wizard(p, store, host="vc1.example.com", name="lab", username="ops", remember=False)
    assert credentials.get_secret(old) is None


def test_a_profile_that_cannot_be_read_can_still_be_removed(isolated_dirs):
    """Code review: `profile remove` read the profile (to find its keychain entry) before removing it, so one that
    no longer validates (hand-edited, or from another version) could not be removed at all."""
    from vsphere_vm_deployment import cli
    from vsphere_vm_deployment.profiles import ProfileStore

    store = ProfileStore()
    store.path.write_text("default: lab\nprofiles:\n  lab: {host: vc.example.com, auth: oauth-device}\n",
                          encoding="utf-8")
    r = CliRunner().invoke(cli.app, ["profile", "remove", "lab"])
    assert r.exit_code == 0, r.output
    assert "Removed profile 'lab'" in r.output and "could not be read" in _flat(r.output)
    assert store.list() == []


# ------------------------------------------------------------------ found in the real-environment smoke test
def test_access_remove_logs_each_removal_as_it_happens(caplog):
    """The removals were written to the log only after all of them had succeeded: a failure part-way left none of
    the completed ones in the log."""
    import logging

    from vsphere_vm_deployment import access

    def refuse(roleId, failIfUsed):  # noqa: N803 - the vSphere API's names
        raise RuntimeError("vCenter refused")

    am = NS(RemoveEntityPermission=lambda entity, user, isGroup: None, RemoveAuthorizationRole=refuse)
    perms = [NS(entity=NS(name="vmdeploy-ops"), principal=r"VSPHERE.LOCAL\svc-deploy", group=False),
             NS(entity=None, principal=r"VSPHERE.LOCAL\svc-deploy", group=False)]  # removed with its role
    found = access.ExistingAccess(roles={"vmdeploy-deployer": 7}, permissions=perms, local_users=[])
    caplog.set_level(logging.INFO, logger="vsphere_vm_deployment.access")
    shown = []
    with pytest.raises(RuntimeError, match="vCenter refused"):
        access.remove(NS(content=NS(authorizationManager=am)), found, on_removed=shown.append)
    named = rf"Permission for VSPHERE.LOCAL\svc-deploy on {access.entity_label(perms[0].entity)}"
    assert [r.getMessage() for r in caplog.records] == [f"Removed: {named}"] and shown == [named]
    # the role went: so did the permission on the object the server did not name, and only now is it reported
    shown.clear()
    am.RemoveAuthorizationRole = lambda roleId, failIfUsed: None
    access.remove(NS(content=NS(authorizationManager=am)), found, on_removed=shown.append)
    assert shown == [named, "Role vmdeploy-deployer",
                     r"Permission for VSPHERE.LOCAL\svc-deploy on an object the server did not name (with its role)"]


def test_account_history_dates_are_shown_in_local_time():
    """`access audit` showed the UTC date of a setup: on an evening west of UTC, the next day's."""
    from datetime import timedelta, timezone

    from vsphere_vm_deployment.units import local_date as _local_date

    eastern = timezone(timedelta(hours=-5))
    assert _local_date("2026-11-16T01:52:20+00:00", eastern) == "2026-11-15"
    assert _local_date("2026-11-16T12:00:00+00:00", eastern) == "2026-11-16"
    assert _local_date("not a date") == "not a date"


def test_the_audit_counts_iso_copies_the_way_images_prune_does():
    """Code review: every entry in vmdeploy-iso/ counted as an "ISO copy" for `images prune` to delete, though prune
    only finds *.iso files: a file or folder put there by hand stayed reported, and prune could never remove it."""
    from vsphere_vm_deployment.audit import iso_folder_report

    used = {"[ds1] vmdeploy-iso/a.iso"}
    assert iso_folder_report("ds1", None, used) == "vmdeploy-iso folder (its contents could not be listed)"
    assert iso_folder_report("ds1", [], used).startswith("empty vmdeploy-iso folder")
    assert iso_folder_report("ds1", ["a.iso"], used) is None  # attached to a VM: in use, not a leftover
    assert iso_folder_report("ds1", ["a.iso", "b.ISO"], used).startswith("1 of 2 ISO copies by vmdeploy, used by no VM")
    other = iso_folder_report("ds1", ["a.iso", "notes.txt", "old"], used)
    assert other == "2 other file(s) or folder(s), not ISO copies (check them in the vSphere Client)"
    assert iso_folder_report("ds2", ["a.iso"], used).startswith("1 of 1 ISO copies")  # another datastore's file
    # code review of that change: an ISO in any letter case is an ISO (deploy takes Win11.Iso), never "other";
    # whatever a VM uses is in use; files the storage keeps for itself (an NFS lock of an open ISO) are left out
    assert iso_folder_report("ds1", ["Win11.Iso"], {"[ds1] vmdeploy-iso/Win11.Iso"}) is None
    assert iso_folder_report("ds1", ["Win11.Iso"], set()).startswith("1 of 1 ISO copies by vmdeploy, used by no VM")
    assert iso_folder_report("ds1", ["a.iso", ".lck-00a1", "@eaDir"], used) is None


def test_one_rule_for_what_an_iso_is():
    """Code review: deploy took Win11.Iso for an ISO, `images prune` searched for *.iso and *.ISO only (so it never
    saw such a copy), and the audit had a third rule."""
    from vsphere_vm_deployment import isolib

    assert isolib.is_iso_name("Win11.Iso") and isolib.is_iso_name("a.iso") and not isolib.is_iso_name("a.iso.txt")
    assert len(isolib.ISO_PATTERNS) == 8 and {"*.iso", "*.Iso", "*.ISO"} <= set(isolib.ISO_PATTERNS)
    assert isolib.find_isos.__defaults__[0] == isolib.ISO_PATTERNS
