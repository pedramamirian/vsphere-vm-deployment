import datetime as dt
import hashlib
import io
import ssl
import zipfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from vsphere_vm_deployment.errors import TrustError, UserAborted
from vsphere_vm_deployment.trust import (
    CertInfo,
    TrustDecision,
    TrustManager,
    TrustStore,
    extract_ca_pems,
    normalize_fingerprint,
)


def make_cert(cn="vcsa.example.com", sans=("vcsa.example.com",)):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert


def test_certinfo_fields():
    cert = make_cert()
    der = cert.public_bytes(serialization.Encoding.DER)
    info = CertInfo.from_der(der)
    assert info.subject == "vcsa.example.com" and info.self_signed and not info.expired
    assert info.sans == ["vcsa.example.com"]
    assert info.sha256 == hashlib.sha256(der).hexdigest()
    assert CertInfo.from_pem(info.pem).sha256 == info.sha256
    assert CertInfo.pretty("abcd") == "AB:CD"


def test_normalize_fingerprint():
    assert normalize_fingerprint("AB:CD:ef") == "abcdef"


def test_extract_ca_pems_from_vcenter_style_zip():
    c1, c2 = make_cert("CA"), make_cert("CA2")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("certs/lin/1a2b3c4d.0", c1.public_bytes(serialization.Encoding.PEM))
        zf.writestr("certs/lin/1a2b3c4d.r0", b"crl-data")
        zf.writestr("certs/win/1a2b3c4d.0.crt", c1.public_bytes(serialization.Encoding.PEM))  # duplicate
        zf.writestr("certs/mac/5e6f.1", c2.public_bytes(serialization.Encoding.DER))
    pems = extract_ca_pems(buf.getvalue())
    assert len(pems) == 2


def test_store_pins_and_cas(tmp_path):
    store = TrustStore(tmp_path / "t.json")
    info = CertInfo.from_der(make_cert().public_bytes(serialization.Encoding.DER))
    store.add_pin("vc:443", info)
    assert store.pin("vc:443")["sha256"] == info.sha256
    store.add_cas("vc:443", [info.pem])
    assert info.pem in store.ca_bundle()
    assert store.remove("vc:443") and store.pin("vc:443") is None and store.ca_bundle() is None


def test_pinned_decision_checks_exact_certificate():
    der = make_cert().public_bytes(serialization.Encoding.DER)
    d = TrustDecision("h", 443, "pinned", CertInfo.from_der(der))
    d.check_peer(der)
    with pytest.raises(TrustError):
        d.check_peer(make_cert().public_bytes(serialization.Encoding.DER))
    assert d.ssl_context().verify_mode == ssl.CERT_REQUIRED  # trusts only the pinned certificate
    assert TrustDecision("h", 443, "validated", CertInfo.from_der(der)).ssl_context().verify_mode == ssl.CERT_REQUIRED


def test_untrusted_certificate_fails_non_interactively(monkeypatch):
    der = make_cert().public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr("vsphere_vm_deployment.trust.validates", lambda *a, **k: (False, "self-signed certificate"))
    monkeypatch.setattr("vsphere_vm_deployment.trust.fetch_peer_cert", lambda *a, **k: der)
    from vsphere_vm_deployment.ui import Prompter

    tm = TrustManager(prompter=Prompter(interactive=False))
    with pytest.raises(TrustError) as e:
        tm.decision("vc.lab", 443)
    assert "--trust-fingerprint" in e.value.hint
    # ...but a fingerprint passed explicitly is accepted
    tm2 = TrustManager(prompter=Prompter(False), assume_fingerprints=[CertInfo.pretty(hashlib.sha256(der).hexdigest())])
    assert tm2.decision("vc.lab", 443).mode == "pinned"


def test_vouch_uses_vcenter_reported_thumbprint(monkeypatch):
    der = make_cert("esx01").public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr("vsphere_vm_deployment.trust.validates", lambda *a, **k: (False, "self-signed"))
    monkeypatch.setattr("vsphere_vm_deployment.trust.fetch_peer_cert", lambda *a, **k: der)
    from vsphere_vm_deployment.ui import Prompter

    tm = TrustManager(prompter=Prompter(False))
    sha1 = CertInfo.pretty(hashlib.sha1(der).hexdigest())
    assert tm.vouch("esx01", 443, sha1).mode == "pinned"
    with pytest.raises(TrustError):
        TrustManager(prompter=Prompter(False)).vouch("esx01", 443, "00" * 20)


# ------------------------------------------------------------------- pinning on real TLS handshakes
def _tls_server(tmp_path, leaf, key, chain=()):
    import socket
    import threading

    from cryptography.hazmat.primitives import serialization as ser

    cert_file = tmp_path / f"srv{leaf.serial_number}.pem"
    cert_file.write_bytes(b"".join(c.public_bytes(ser.Encoding.PEM) for c in (leaf, *chain)))
    key_file = tmp_path / f"srv{leaf.serial_number}.key"
    key_file.write_bytes(key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

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
    return srv


def _ca_and_leaf(cn):
    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{cn}-VMCA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + dt.timedelta(days=9))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=9))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return ca, leaf, key


def test_pinned_leaf_issued_by_untrusted_ca_is_accepted_and_others_rejected(tmp_path):
    from vsphere_vm_deployment.trust import pinned_handshake_ok

    ca, leaf, key = _ca_and_leaf("esx01.example.com")
    _, other_leaf, other_key = _ca_and_leaf("esx01.example.com")  # attacker: same name, different cert
    good = _tls_server(tmp_path, leaf, key, chain=(ca,))
    evil = _tls_server(tmp_path, other_leaf, other_key)
    pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
    try:
        # every connection is verified, not only the first one
        for _ in range(3):
            assert pinned_handshake_ok("127.0.0.1", good.getsockname()[1], pem)
            assert not pinned_handshake_ok("127.0.0.1", evil.getsockname()[1], pem)
    finally:
        good.close()
        evil.close()


def test_cert_details_layout():
    from vsphere_vm_deployment.trust import cert_details

    info = CertInfo.from_der(make_cert("vcsa.example.com").public_bytes(serialization.Encoding.DER))
    text = cert_details(info, "self-signed certificate")
    lines = text.splitlines()
    assert lines[0] == 'Subject: "CN=vcsa.example.com"'
    assert lines[2] == 'Names/IPs: ["vcsa.example.com"]'
    assert lines[3].startswith("Valid from: ") and lines[4].startswith("Expires: ")
    assert lines[5] == f"SHA-256 fingerprint: {CertInfo.pretty(info.sha256)}"


def test_numbered_prompt(monkeypatch):
    from vsphere_vm_deployment import ui

    p = ui.Prompter(interactive=False)
    p.interactive = True
    answers = iter(["9", "", "2"])
    monkeypatch.setattr(ui.console, "input", lambda prompt="": next(answers))
    opts = [("Trust for this session", "once"), ("Trust and remember", "always"), ("Cancel", "decline")]
    assert p.numbered("Certificate trust choice:", opts, default="decline") == "decline"  # "9" rejected, "" = default
    assert p.numbered("Certificate trust choice:", opts, default="decline") == "always"


# ------------------------------------------------------------------- interactive trust choices
class _FakePrompter:
    """Answers the certificate menu with a fixed choice and records which options were offered."""

    interactive = True

    def __init__(self, answer):
        self.answer, self.offered = answer, []

    def section(self, _title):
        import contextlib
        return contextlib.nullcontext()

    def numbered(self, _question, options, default=None):
        self.offered = [value for _label, value in options]
        return self.answer


def _untrusted(monkeypatch, der, *, ca_validates, is_vcenter=True):
    """The server is untrusted by the OS; with the vCenter CA bundle loaded it validates only if `ca_validates`.
    Only a vCenter publishes /certs/download.zip; a standalone ESXi host does not."""
    monkeypatch.setattr("vsphere_vm_deployment.trust.fetch_peer_cert", lambda *a, **k: der)
    monkeypatch.setattr("vsphere_vm_deployment.trust.validated_peer_cert", lambda *a, **k: der)
    monkeypatch.setattr("vsphere_vm_deployment.trust.publishes_ca_bundle", lambda *a, **k: is_vcenter)
    monkeypatch.setattr("vsphere_vm_deployment.trust.lists_name", lambda *a, **k: None)  # no network: cannot tell
    monkeypatch.setattr("vsphere_vm_deployment.trust.validates",
                        lambda h, p, cadata=None, **k: (bool(cadata) and ca_validates, "unable to get local issuer certificate"))


def test_trust_vcenter_root_ca_saves_bundle_after_validating(monkeypatch, tmp_path):
    der = make_cert().public_bytes(serialization.Encoding.DER)
    ca_pem = CertInfo.from_der(make_cert("CA").public_bytes(serialization.Encoding.DER)).pem
    _untrusted(monkeypatch, der, ca_validates=True)
    monkeypatch.setattr("vsphere_vm_deployment.trust.download_vcenter_ca", lambda d: [ca_pem])
    store, prompter = TrustStore(tmp_path / "t.json"), _FakePrompter("vcenter-ca")

    d = TrustManager(store=store, prompter=prompter).decision("vc.lab", 443)

    assert "vcenter-ca" in prompter.offered
    assert d.mode == "validated" and "root CA" in d.describe()
    assert store.ca_bundle() == ca_pem and store.pin("vc.lab:443") is None


def test_trust_vcenter_root_ca_saves_nothing_if_it_does_not_validate(monkeypatch, tmp_path):
    der = make_cert().public_bytes(serialization.Encoding.DER)
    ca_pem = CertInfo.from_der(make_cert("Other CA").public_bytes(serialization.Encoding.DER)).pem
    _untrusted(monkeypatch, der, ca_validates=False)
    monkeypatch.setattr("vsphere_vm_deployment.trust.download_vcenter_ca", lambda d: [ca_pem])
    store = TrustStore(tmp_path / "t.json")

    with pytest.raises(TrustError) as e:
        TrustManager(store=store, prompter=_FakePrompter("vcenter-ca")).decision("vc.lab", 443)

    assert "Nothing was saved" in str(e.value)
    assert store.ca_bundle() is None and store.pin("vc.lab:443") is None


def test_session_trust_is_reported_as_session_only(monkeypatch, tmp_path):
    der = make_cert().public_bytes(serialization.Encoding.DER)
    _untrusted(monkeypatch, der, ca_validates=False)
    store = TrustStore(tmp_path / "t.json")

    d = TrustManager(store=store, prompter=_FakePrompter("once")).decision("vc.lab", 443)

    assert d.describe() == "pinned, this session only"
    assert store.pin("vc.lab:443") is None


def test_root_ca_not_offered_for_esxi_or_changed_certificate(monkeypatch, tmp_path):
    der = make_cert().public_bytes(serialization.Encoding.DER)
    _untrusted(monkeypatch, der, ca_validates=False)
    store = TrustStore(tmp_path / "t.json")
    store.add_pin("vc.lab:443", CertInfo.from_der(make_cert().public_bytes(serialization.Encoding.DER)))  # old cert

    changed = _FakePrompter("once")
    TrustManager(store=store, prompter=changed).decision("vc.lab", 443)
    esxi = _FakePrompter("once")
    TrustManager(store=store, prompter=esxi).vouch("esx01", 443, None)

    assert "vcenter-ca" not in changed.offered and "vcenter-ca" not in esxi.offered


def test_root_ca_not_offered_when_connecting_straight_to_standalone_esxi(monkeypatch, tmp_path):
    der = make_cert("esxi01.lab").public_bytes(serialization.Encoding.DER)
    _untrusted(monkeypatch, der, ca_validates=False, is_vcenter=False)
    prompter = _FakePrompter("once")

    d = TrustManager(store=TrustStore(tmp_path / "t.json"), prompter=prompter).decision("esxi01.lab", 443)

    assert prompter.offered == ["once", "always", "decline"]
    assert d.describe() == "pinned, this session only"


def test_trust_decision_is_logged_with_fingerprint(monkeypatch, tmp_path, caplog):
    der = make_cert().public_bytes(serialization.Encoding.DER)
    _untrusted(monkeypatch, der, ca_validates=False)
    with caplog.at_level("INFO", logger="vsphere_vm_deployment.trust"):
        TrustManager(store=TrustStore(tmp_path / "t.json"), prompter=_FakePrompter("once")).decision("vc.lab", 443)
    assert CertInfo.pretty(hashlib.sha256(der).hexdigest()) in caplog.text and "'once'" in caplog.text


def test_a_name_mismatch_does_not_offer_the_root_ca(monkeypatch, tmp_path, capsys):
    """Real-environment smoke test: a vCenter whose certificate lists only its IP address, reached by its host name.
    No CA can make a certificate valid for a name it does not list: "Trust this vCenter's root CA" could only fail
    ("does not validate ... Nothing was saved"). It is not offered. The prompt says what avoids the question without
    saying the server is genuine (reviews: a forged certificate can fail the same way, and the names it lists are
    the server's own choice). With --yes, the hint says the same."""
    der = make_cert().public_bytes(serialization.Encoding.DER)
    _untrusted(monkeypatch, der, ca_validates=False)
    monkeypatch.setattr("vsphere_vm_deployment.trust.validates",
                        lambda h, p, cadata=None, **k: (False, f"Hostname mismatch, certificate is not valid for '{h}'."))
    prompter = _FakePrompter("once")

    d = TrustManager(store=TrustStore(tmp_path / "t.json"), prompter=prompter).decision("vc.lab", 443)

    assert prompter.offered == ["once", "always", "decline"] and d.scope == "this session only"
    err = " ".join(capsys.readouterr().err.split())
    assert ("The certificate does not list vc.lab. If you know one of the names or addresses it lists to be this "
            "server, use that one instead (in the connection profile too: `vmdeploy profile add`). If you do not, be "
            "careful: this may not be the server you meant.") in err
    assert "trusted already" not in err

    with pytest.raises(TrustError) as e:  # --yes: no prompt; the hint says the same first
        TrustManager(store=TrustStore(tmp_path / "t.json"), prompter=None).decision("vc.lab", 443)
    assert e.value.hint.startswith("The certificate does not list vc.lab.") and "--trust-fingerprint" in e.value.hint

    # an ESXi host reached at the address vCenter reports: the user cannot choose another name, so no such advice
    TrustManager(store=TrustStore(tmp_path / "t.json"), prompter=_FakePrompter("once")).vouch("esx.lab", 443, None)
    assert "does not list" not in capsys.readouterr().err


def test_lists_name_uses_openssls_own_name_rules(tmp_path):
    """Code review: `trust add --vcenter-ca` needs to know, before any question, whether the certificate lists the
    name it was given. OpenSSL decides, on a handshake whose only trust anchor is the certificate itself."""
    import ipaddress

    from vsphere_vm_deployment.trust import lists_name

    now = dt.datetime.now(dt.UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vcsa.example.com")])
    leaf = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + dt.timedelta(days=9))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    _ca, dns_only, dns_key = _ca_and_leaf("esx01.example.com")
    by_ip, by_dns = _tls_server(tmp_path, leaf, key), _tls_server(tmp_path, dns_only, dns_key)
    info = CertInfo.from_der(leaf.public_bytes(serialization.Encoding.DER))
    try:
        assert lists_name("127.0.0.1", by_ip.getsockname()[1], info) is True
        assert lists_name("127.0.0.1", by_dns.getsockname()[1],  # an address it does not list
                          CertInfo.from_der(dns_only.public_bytes(serialization.Encoding.DER))) is False
        assert lists_name("127.0.0.1", by_dns.getsockname()[1], info) is None  # another certificate: cannot tell
    finally:
        by_ip.close()
        by_dns.close()


def test_trust_add_vcenter_ca_refuses_a_name_the_certificate_does_not_list(monkeypatch, tmp_path):
    """Code review: by a name the certificate does not list, `trust add --vcenter-ca` asked to trust the certificate
    first (a "Trust and remember" answer saved a pin) and only then failed at the CA step. It now stops before."""
    der = make_cert().public_bytes(serialization.Encoding.DER)  # lists vcsa.example.com only
    monkeypatch.setattr("vsphere_vm_deployment.trust.validates", lambda *a, **k: (False, "self-signed certificate"))
    monkeypatch.setattr("vsphere_vm_deployment.trust.fetch_peer_cert", lambda *a, **k: der)
    monkeypatch.setattr("vsphere_vm_deployment.trust.lists_name", lambda *a, **k: False)
    store, prompter = TrustStore(tmp_path / "t.json"), _FakePrompter("always")
    with pytest.raises(TrustError) as e:
        TrustManager(store=store, prompter=prompter).trust_vcenter_ca("vc.lab", 443)
    assert "does not list vc.lab (it lists vcsa.example.com), so no root CA can make it valid" in e.value.message
    assert "Nothing was changed" in e.value.message and "you know" in e.value.hint
    assert prompter.offered == [] and store.pin("vc.lab:443") is None and store.ca_bundle() is None


def test_a_name_mismatch_behind_an_untrusted_chain_does_not_offer_the_root_ca(monkeypatch, tmp_path, capsys):
    """Code review: on a first connection the vCenter's VMCA is not trusted yet, so OpenSSL reports the chain, not
    the name, and "Trust this vCenter's root CA" was still offered when the certificate does not list the name used:
    it could only fail. The name is checked on its own (lists_name)."""
    der = make_cert().public_bytes(serialization.Encoding.DER)
    _untrusted(monkeypatch, der, ca_validates=True)  # the chain is what fails
    monkeypatch.setattr("vsphere_vm_deployment.trust.lists_name", lambda *a, **k: False)  # ...and the name
    prompter = _FakePrompter("decline")
    with pytest.raises(UserAborted):
        TrustManager(store=TrustStore(tmp_path / "t.json"), prompter=prompter).decision("vc.lab", 443)
    assert prompter.offered == ["once", "always", "decline"]
    assert "The certificate does not list vc.lab." in " ".join(capsys.readouterr().err.split())


def test_trust_add_vcenter_ca_never_leaves_a_pin_behind(monkeypatch, tmp_path):
    """Code review: "Trust and remember" in `trust add --vcenter-ca` saved a pin before the CA step, which could then
    fail ("Nothing was saved") and leave the pin behind. The server's certificate is trusted for the session only."""
    der = make_cert().public_bytes(serialization.Encoding.DER)
    ca_pem = CertInfo.from_der(make_cert("CA").public_bytes(serialization.Encoding.DER)).pem
    monkeypatch.setattr("vsphere_vm_deployment.trust.download_vcenter_ca", lambda d: [ca_pem])
    for ca_validates in (False, True):
        _untrusted(monkeypatch, der, ca_validates=ca_validates)
        store, prompter = TrustStore(tmp_path / f"t{ca_validates}.json"), _FakePrompter("once")
        tm = TrustManager(store=store, prompter=prompter)
        if ca_validates:
            assert tm.trust_vcenter_ca("vc.lab", 443) == 1 and store.ca_bundle() == ca_pem
        else:
            with pytest.raises(TrustError, match="Nothing was saved"):
                tm.trust_vcenter_ca("vc.lab", 443)
        assert prompter.offered == ["once", "decline"] and store.pin("vc.lab:443") is None
