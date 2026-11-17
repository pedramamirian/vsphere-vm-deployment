"""Federated sign-in: IdP token request and vCenter token exchange against local fake servers."""

import base64
import datetime as dt
import json
import ssl
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from vsphere_vm_deployment.auth import TOKEN_EXCHANGE_PATH, exchange_for_saml, idp_token
from vsphere_vm_deployment.errors import AuthError
from vsphere_vm_deployment.trust import CertInfo, TrustDecision

SAML = "<saml2:Assertion xmlns:saml2='urn:oasis:names:tc:SAML:2.0:assertion'>ok</saml2:Assertion>"
seen: dict = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = urllib.parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        seen[self.path] = (body, dict(self.headers))
        if self.path == "/idp/token":
            if body.get("password") == ["wrong"]:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error":"invalid_grant"}')
                return
            payload = {"access_token": "AT-123", "id_token": "IDT-456", "token_type": "Bearer"}
        elif self.path == TOKEN_EXCHANGE_PATH:
            payload = {"access_token": base64.b64encode(SAML.encode()).decode(), "token_type": "SAML2"}
        else:
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture(scope="module")
def servers(tmp_path_factory):
    d = tmp_path_factory.mktemp("tls")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    (d / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
    class QuietServer(HTTPServer):
        def handle_error(self, request, client_address):  # handshake aborted on purpose in one test
            pass

    plain = QuietServer(("127.0.0.1", 0), Handler)
    tls = QuietServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "c.pem", d / "k.pem")
    tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
    for s in (plain, tls):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    yield plain.server_address[1], tls.server_address[1], cert.public_bytes(serialization.Encoding.DER)
    plain.shutdown()
    tls.shutdown()


def test_password_grant_and_exchange(servers):
    http_port, https_port, der = servers
    access, idt = idp_token(f"http://127.0.0.1:{http_port}/idp/token", "vcenter-client", grant="password",
                            username="svc@contoso.com", password="pw")
    assert (access, idt) == ("AT-123", "IDT-456")
    body, _ = seen["/idp/token"]
    assert body["grant_type"] == ["password"] and body["scope"] == ["openid"]

    decision = TrustDecision("127.0.0.1", https_port, "pinned", CertInfo.from_der(der))
    assert exchange_for_saml(decision, access, idt) == SAML
    body, headers = seen[TOKEN_EXCHANGE_PATH]
    assert body["grant_type"] == ["urn:ietf:params:oauth:grant-type:token-exchange"]
    assert body["requested_token_type"] == ["urn:ietf:params:oauth:token-type:saml2"]
    assert body["actor_token"] == ["IDT-456"]
    assert headers["Authorization"] == "Bearer AT-123"


def test_idp_rejection_is_explained(servers):
    http_port, _, _ = servers
    with pytest.raises(AuthError) as e:
        idp_token(f"http://127.0.0.1:{http_port}/idp/token", "c", grant="password", username="u", password="wrong")
    assert "invalid_grant" in e.value.hint


def test_exchange_refuses_wrong_certificate(servers):
    _, https_port, _ = servers
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil")])
    now = dt.datetime.now(dt.UTC)
    fake = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(2).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1)).sign(key, hashes.SHA256()))
    decision = TrustDecision("127.0.0.1", https_port, "pinned",
                             CertInfo.from_der(fake.public_bytes(serialization.Encoding.DER)))
    from vsphere_vm_deployment.errors import TrustError

    with pytest.raises(TrustError):
        exchange_for_saml(decision, "AT", None)
