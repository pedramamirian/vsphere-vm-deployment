"""TLS certificate trust: validate normally, otherwise let the user trust once / trust always / decline.

Order of checks for every host the tool talks to (vCenter, standalone ESXi, and the ESXi hosts that
receive disk uploads during an OVA import):

1. The certificate validates against the OS trust store, or against a vCenter root CA the user chose to
   trust earlier (downloaded from https://<vcenter>/certs/download.zip). -> connect normally.
2. The exact certificate was pinned earlier ("trust always"), or during this run ("trust once"). -> connect,
   and verify on every connection that the server still presents that exact certificate.
3. During an OVA import vCenter hands out the SHA-1 thumbprint of each ESXi host certificate over the
   already-trusted vCenter session. If the host presents a matching certificate it is trusted for this run
   ("vouched for by vCenter").
4. Otherwise the user is shown the certificate details and asked. A *changed* certificate for a pinned
   host triggers a loud warning, like SSH's "REMOTE HOST IDENTIFICATION HAS CHANGED".

Certificate validation is never switched off globally.
"""

from __future__ import annotations

import hashlib
import http.client
import io
import json
import logging
import re
import socket
import ssl
import unicodedata
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, NameOID

from .errors import TrustError, UserAborted
from .paths import config_dir

log = logging.getLogger(__name__)

_SPACES = re.compile(r" {2,}")
TRUST_ONCE = "once"
TRUST_ALWAYS = "always"
TRUST_CA = "vcenter-ca"
DECLINE = "decline"


# ------------------------------------------------------------------------------------------ certificate info
@dataclass
class CertInfo:
    der: bytes
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    sans: list[str]
    sha256: str  # lower-case hex, no separators
    sha1: str
    subject_dn: str = ""  # full distinguished name, RFC 4514
    issuer_dn: str = ""

    @property
    def pem(self) -> str:
        return ssl.DER_cert_to_PEM_cert(self.der)

    @property
    def self_signed(self) -> bool:
        return self.subject == self.issuer

    @property
    def expired(self) -> bool:
        return self.not_after < datetime.now(UTC)

    def validity_problem(self) -> str | None:
        """Why TLS will refuse this certificate whatever the user decides (dates are checked even for a pinned
        certificate), or None."""
        now = datetime.now(UTC)
        if self.not_after < now:
            return f"expired on {self.not_after:%Y-%m-%d}"
        if self.not_before > now:
            return f"is not valid before {self.not_before:%Y-%m-%d %H:%M} UTC"
        return None

    @staticmethod
    def pretty(hexdigest: str) -> str:
        return ":".join(hexdigest[i:i + 2] for i in range(0, len(hexdigest), 2)).upper()

    @classmethod
    def from_der(cls, der: bytes) -> CertInfo:
        cert = x509.load_der_x509_certificate(der)

        def name(n: x509.Name) -> str:
            cn = n.get_attributes_for_oid(NameOID.COMMON_NAME)
            return cn[0].value if cn else n.rfc4514_string()

        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            sans = [str(v) for v in san.get_values_for_type(x509.DNSName)] + \
                   [str(v) for v in san.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound:
            sans = []
        return cls(
            der=der,
            subject=name(cert.subject),
            issuer=name(cert.issuer),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            sans=sans,
            sha256=hashlib.sha256(der).hexdigest(),
            sha1=hashlib.sha1(der, usedforsecurity=False).hexdigest(),
            subject_dn=cert.subject.rfc4514_string(),
            issuer_dn=cert.issuer.rfc4514_string(),
        )

    @classmethod
    def from_pem(cls, pem: str) -> CertInfo:
        return cls.from_der(ssl.PEM_cert_to_DER_cert(pem))


def normalize_fingerprint(fp: str) -> str:
    return fp.replace(":", "").replace(" ", "").lower()


# ------------------------------------------------------------------------------------------ network helpers
def fetch_peer_cert(host: str, port: int = 443, timeout: float = 15.0) -> bytes:
    """Return the server's leaf certificate (DER) without validating it. Used only to *show* it."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we only read the certificate here; nothing sensitive is sent
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock, \
                ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    except OSError as e:
        raise TrustError(f"Could not open a TLS connection to {host}:{port}: {e}",
                         hint="Check the hostname/IP, port, DNS and firewall.") from e
    if not der:
        raise TrustError(f"{host}:{port} did not present a certificate.")
    return der


def _validating_context(cadata: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if cadata:
        ctx.load_verify_locations(cadata=cadata)
    return ctx


def validates(host: str, port: int, cadata: str | None = None, timeout: float = 15.0, *,
              os_store: bool = True) -> tuple[bool, str]:
    """Does the certificate chain + hostname validate (against the OS store, plus optional extra CAs)? With
    os_store=False, against `cadata` alone."""
    ctx = _validating_context(cadata) if os_store else ssl.create_default_context(cadata=cadata)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock, \
                ctx.wrap_socket(sock, server_hostname=host):
            return True, "valid"
    except ssl.SSLCertVerificationError as e:
        return False, e.verify_message or str(e)
    except ssl.SSLError as e:
        return False, str(e)
    except OSError as e:
        raise TrustError(f"Could not connect to {host}:{port}: {e}") from e


def validated_peer_cert(host: str, port: int, cadata: str | None = None, timeout: float = 15.0) -> bytes:
    """The server's certificate (DER), read over a connection that validates it like validates() (chain and
    hostname). A validated decision records this one: a certificate read without checks (fetch_peer_cert) could
    come from anyone on the network path."""
    ctx = _validating_context(cadata)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock, \
                ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    except ssl.SSLError as e:  # it validated a moment ago: the certificate on the way changed
        raise TrustError(f"The certificate of {host}:{port} validated on one connection but not on the next ({e}); "
                         "refusing to continue.",
                         hint="Check for a proxy or device that intercepts TLS on the way to this server, then try "
                              "again.") from e
    except OSError as e:  # timeouts, resets, DNS: a network problem, not a certificate one
        raise TrustError(f"Could not connect to {host}:{port}: {e}") from e
    if not der:
        raise TrustError(f"{host}:{port} did not present a certificate.")
    return der


def pinned_context(pem: str) -> ssl.SSLContext:
    """TLS context whose only trust anchor is one specific certificate.

    * VERIFY_X509_PARTIAL_CHAIN lets OpenSSL accept a trusted *leaf* (e.g. an ESXi certificate issued by an
      untrusted VMCA) as the anchor, so the chain does not need to be complete.
    * VERIFY_X509_STRICT is cleared because some ESXi/VMCA certificates lack extensions strict mode demands.
    * Hostname checking is off because the user explicitly accepted this certificate for this endpoint
      (commonly reached by IP). Any other certificate fails the handshake.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=pem)
    flags = ctx.verify_flags | getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
    flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    ctx.verify_flags = flags
    return ctx


def _pinned_handshake(host: str, port: int, pem: str, timeout: float, *,
                      check_hostname: bool = False) -> BaseException | None:
    """One TLS handshake whose only trust anchor is `pem`: None if it succeeded, otherwise the error."""
    try:
        ctx = pinned_context(pem)
        ctx.check_hostname = check_hostname
        with socket.create_connection((host, port), timeout=timeout) as sock, \
                ctx.wrap_socket(sock, server_hostname=host):
            return None
    except (ssl.SSLError, OSError) as e:
        return e


def pinned_handshake_ok(host: str, port: int, pem: str, timeout: float = 15.0) -> bool:
    return _pinned_handshake(host, port, pem, timeout) is None


_NAME_MISMATCH = (62, 64)  # OpenSSL's X509_V_ERR_HOSTNAME_MISMATCH and X509_V_ERR_IP_ADDRESS_MISMATCH


def lists_name(host: str, port: int, cert: CertInfo, timeout: float = 10.0) -> bool | None:
    """Does this certificate list `host`, by OpenSSL's own rules (wildcards, IP addresses)? Checked on a handshake
    whose only trust anchor is this certificate, so the name is the only thing that can fail. None when that cannot
    be told (e.g. the server presented another certificate, or could not be reached)."""
    error = _pinned_handshake(host, port, cert.pem, timeout, check_hostname=True)
    if error is None:
        return True
    return False if getattr(error, "verify_code", None) in _NAME_MISMATCH else None


def other_name_advice(what: str = "server") -> str:
    """What to do about a certificate that does not list the name used. The names it lists are the server's own
    choice (an interception lists the interceptor's): never advice to use them without knowing they are this one."""
    return (f"If you know one of the names or addresses it lists to be this {what}, use that one instead (in the "
            "connection profile too: `vmdeploy profile add`). If you do not, be careful: this may not be the server "
            "you meant.")


def visible(text: object) -> str:
    r"""Text taken from a certificate (or anything else a server chose), safe to show: control characters
    (newline, ESC, ...), invisible Unicode formatting characters (e.g. right-to-left overrides) and unusual
    spaces are shown as \x.. / \u.... codes instead of acting on the terminal, and runs of spaces are shown as
    one (padding could otherwise push text to the start of a wrapped line)."""
    out = []
    for ch in str(text):
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Zl", "Zp") or (cat == "Zs" and ch != " "):
            out.append(f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return _SPACES.sub(" ", "".join(out))


def shown(text: object) -> str:
    r"""Server-supplied text for a Rich markup string: visible() plus markup escaping. Security review: an
    unescaped Subject Alternative Name such as `x"]\nSHA-256 fingerprint: <the real server's>[conceal black]`
    could add a fake fingerprint line to the trust prompt and hide the real one."""
    from rich.markup import escape

    return escape(visible(text))


def cert_detail_lines(cert: CertInfo, reason: str = "") -> list[tuple[str, bool]]:
    """(Rich markup line, chosen by the server?) in the fixed layout shown at the trust prompt. Every certificate
    field goes through shown(), so it is displayed as text, never as markup or terminal control codes."""
    lines = [
        (f'Subject: "{shown(cert.subject_dn or cert.subject)}"', True),
        (f'Issuer: "{shown(cert.issuer_dn or cert.issuer)}"' + ("  (self-signed)" if cert.self_signed else ""), True),
        ("Names/IPs: [" + ", ".join(f'"{shown(n)}"' for n in cert.sans) + "]", True),
        (f"Valid from: {cert.not_before.isoformat()}", False),
        (f"Expires: {cert.not_after.isoformat()}" + ("  [red](EXPIRED)[/]" if cert.expired else ""), False),
        (f"SHA-256 fingerprint: {CertInfo.pretty(cert.sha256)}", False),
    ]
    if reason:
        lines.append((f"[dim]Validation result: {shown(reason)}[/]", True))
    return lines


def cert_details(cert: CertInfo, reason: str = "") -> str:
    return "\n".join(text for text, _ in cert_detail_lines(cert, reason))


def print_cert_details(console, cert: CertInfo, reason: str = "") -> None:
    """Each line the server chose (subject, issuer, names) is printed on exactly one terminal line, cut with "..."
    if too long: it can never wrap so that its own text starts a line that looks like the real fingerprint."""
    for text, from_server in cert_detail_lines(cert, reason):
        console.print(text, markup=True, highlight=False, emoji=False, no_wrap=from_server,
                      overflow="ellipsis" if from_server else "fold")


# ------------------------------------------------------------------------------------------ persistent store
def host_key(host: str) -> str:
    """A host name or address as vmdeploy stores and compares it: lower case, because host names are
    case-insensitive (DNS), so VCSA.example.com and vcsa.example.com are one server. An IPv6 zone (fe80::1%eth0)
    is a network interface name and keeps its letters."""
    address, pct, zone = host.partition("%")
    return address.lower() + pct + zone


def endpoint_key(endpoint: str) -> str:
    """host:port as trust entries (and the account history) are keyed, the host as host_key: one server has one
    saved certificate, not a second trust prompt. Without a port, all of it is the host."""
    text = endpoint.strip()
    host, colon, port = text.rpartition(":")
    if not colon or not port.isdigit():  # "vcsa.example.com", "[fd00::ab]", "fe80::1%eth0"
        return host_key(text)
    return host_key(host) + colon + port


def certificate_failure(e: BaseException | None) -> ssl.SSLCertVerificationError | None:
    """The failed certificate check behind an error: the error itself, or the one it was raised from or while
    handling (pyVmomi's sign-in wraps it in a HostConnectFault). None when a certificate check is not the cause."""
    seen: set[int] = set()
    while e is not None and id(e) not in seen:
        if isinstance(e, ssl.SSLCertVerificationError):
            return e
        seen.add(id(e))
        e = e.__cause__ or e.__context__
    return None


def _added(entry) -> str:
    """When a trust entry was saved (ISO 8601 UTC, so the text sorts by time); "" if unknown."""
    return str(entry.get("added") or "") if isinstance(entry, dict) else ""


class TrustStore:
    """trusted_hosts.json: pinned leaf certificates and trusted vCenter root CAs, keyed by endpoint_key."""

    def __init__(self, path: Path | None = None):
        self.path = path or (config_dir() / "trusted_hosts.json")

    def _load(self) -> dict:
        if not self.path.exists():
            return {"pins": {}, "cas": {}}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        for kind in ("pins", "cas"):  # entries saved before keys were lower case are found too; of two that differ
            merged: dict = {}         # only in letter case, the newest is kept (the next save drops the other)
            for k, v in (data.get(kind) or {}).items():
                key = endpoint_key(k)
                if key not in merged or _added(v) >= _added(merged[key]):
                    merged[key] = v
            data[kind] = merged
        return data

    def _save(self, data: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def pin(self, endpoint: str) -> dict | None:
        return self._load()["pins"].get(endpoint_key(endpoint))

    def add_pin(self, endpoint: str, cert: CertInfo) -> None:
        data = self._load()
        data["pins"][endpoint_key(endpoint)] = {
            "sha256": cert.sha256,
            "subject": cert.subject,
            "not_after": cert.not_after.isoformat(),
            "pem": cert.pem,
            "added": datetime.now(UTC).isoformat(timespec="seconds"),
        }
        self._save(data)

    def remove(self, endpoint_or_ca: str) -> bool:
        """Forget a pin or a saved CA bundle. An IPv6 endpoint may be given as `profile list` shows it
        ([fd00::10]:443); entries are stored as host:port."""
        data = self._load()
        keys = {endpoint_key(endpoint_or_ca)}
        if m := re.fullmatch(r"\[([^\]]+)\]:(\d+)", endpoint_or_ca.strip()):
            keys.add(endpoint_key(f"{m.group(1)}:{m.group(2)}"))
        removed = False
        for key in keys:
            removed = (data["pins"].pop(key, None) is not None) or removed
            removed = (data["cas"].pop(key, None) is not None) or removed
        self._save(data)
        return removed

    def add_cas(self, source: str, pems: list[str]) -> None:
        data = self._load()
        data["cas"][endpoint_key(source)] = {"pems": pems, "added": datetime.now(UTC).isoformat(timespec="seconds")}
        self._save(data)

    def ca_bundle(self) -> str | None:
        pems = [p for entry in self._load()["cas"].values() for p in entry["pems"]]
        return "\n".join(pems) if pems else None

    def entries(self) -> dict:
        return self._load()


# ------------------------------------------------------------------------------------------ decisions
def _validated_scope(host: str, port: int, cadata: str | None) -> str:
    """What a validated chain was checked against (no extra network round-trip to tell the two apart)."""
    return "OS trust store + saved vCenter root CAs" if cadata else "OS trust store"


@dataclass
class TrustDecision:
    host: str
    port: int
    mode: str  # "validated" | "pinned"
    cert: CertInfo
    cadata: str | None = None
    scope: str = ""  # how the trust was established, shown by `doctor`, e.g. "this session only"

    def describe(self) -> str:
        return f"{self.mode}, {self.scope}" if self.scope else self.mode

    @property
    def endpoint(self) -> str:
        """host:port, with an IPv6 address in brackets."""
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"

    def refused(self, e: ssl.SSLCertVerificationError, action: str) -> TrustError:
        """The error for a certificate that failed this decision's check (renewed or intercepted since it was
        trusted, expired, issued for another name): a TrustError with the reason, never a network error that a
        caller could retry or take for an interrupted transfer. The one wording for every connection; raise it
        `from e`."""
        reason = getattr(e, "verify_message", None) or getattr(e, "reason", None) or str(e)
        # Not `trust remove`: with the old pin kept, the next connection warns that the certificate CHANGED and
        # shows the fingerprint that was trusted (security review).
        hint = ("Run the command again to see the certificate the server presents now (vmdeploy warns that it CHANGED "
                "if you had saved the old one). Trust it only if you expected a change, e.g. a renewal."
                if self.mode == "pinned" else
                "Check the server's certificate: renewed, expired, or issued for another name?")
        return TrustError(f"{self.endpoint} presented a certificate that is not the trusted one ({reason}); "
                          f"{action} stopped.", hint=hint)

    def ssl_context(self) -> ssl.SSLContext:
        """A verifying TLS context. For pinned hosts the *only* trust anchor is the exact certificate the user
        accepted, so every handshake on every connection (including pooled / reconnected ones) is checked
        against it by OpenSSL itself; `check_peer()` is an additional exact-match check on raw connections."""
        if self.mode == "validated":
            return _validating_context(self.cadata)
        return pinned_context(self.cert.pem)

    def check_peer(self, der: bytes | None) -> None:
        if self.mode != "pinned":
            return
        if not der or hashlib.sha256(der).hexdigest() != self.cert.sha256:
            raise TrustError(f"The certificate presented by {self.host}:{self.port} changed during the session; "
                             "refusing to continue.")

    def connect(self, timeout: float, action: str) -> http.client.HTTPSConnection:
        """An HTTPS connection to this server over ssl_context(), its certificate checked again by check_peer()
        before anything is sent. A certificate that does not validate is a TrustError ("... `action` stopped"),
        never a network error that a caller could take for an interrupted transfer, retry or work around. Every raw
        HTTPS request vmdeploy makes goes through here (pyVmomi's own connection is given ssl_context())."""
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=timeout, context=self.ssl_context())
        try:
            conn.connect()
            self.check_peer(conn.sock.getpeercert(binary_form=True))
        except ssl.SSLCertVerificationError as e:
            conn.close()
            raise self.refused(e, action) from e
        except BaseException:
            conn.close()
            raise
        return conn


class TrustManager:
    """Per-run trust decisions, backed by the persistent TrustStore."""

    def __init__(self, store: TrustStore | None = None, prompter=None, assume_fingerprints: list[str] | None = None):
        self.store = store or TrustStore()
        self.prompter = prompter
        self._session: dict[str, TrustDecision] = {}
        self._assume = {normalize_fingerprint(f) for f in (assume_fingerprints or [])}

    def decision(self, host: str, port: int = 443, *, is_vcenter_candidate: bool = True,
                 remember: bool = True) -> TrustDecision:
        """How to trust host:port: validated, a saved pin, --trust-fingerprint, or the user's answer. `remember`:
        whether "Trust and remember" is offered."""
        endpoint = f"{host}:{port}"
        if (known := self._session.get(endpoint_key(endpoint))) is not None:
            return known

        cadata = self.store.ca_bundle()
        ok, reason = validates(host, port, cadata)
        if ok:
            # Recorded from a connection validated the same way, never from an unchecked one: `trust add
            # --vcenter-ca` downloads the CA bundle over this decision (security review).
            cert = CertInfo.from_der(validated_peer_cert(host, port, cadata))
            log.info("Certificate for %s validated (%s)", endpoint, cert.subject)
            return self._remember(TrustDecision(host, port, "validated", cert, cadata,
                                                scope=_validated_scope(host, port, cadata)))

        cert = CertInfo.from_der(fetch_peer_cert(host, port))  # compared with a pin, or shown to the user
        pinned = self.store.pin(endpoint)
        if pinned and pinned["sha256"] == cert.sha256:
            log.info("Certificate for %s matches the pinned certificate", endpoint)
            _refuse_out_of_date(endpoint, cert)
            return self._remember(TrustDecision(host, port, "pinned", cert, scope="remembered"))

        if cert.sha256 in self._assume:
            log.info("Certificate for %s matches a fingerprint passed with --trust-fingerprint", endpoint)
            _refuse_out_of_date(endpoint, cert)
            return self._remember(TrustDecision(host, port, "pinned", cert, scope="--trust-fingerprint"))

        return self._ask(host, port, cert, reason, changed_from=pinned, offer_ca=is_vcenter_candidate,
                         remember=remember)

    def vouch(self, host: str, port: int, sha1_thumbprint: str | None) -> TrustDecision:
        """Trust an ESXi host because vCenter (already trusted) reported this exact thumbprint for it."""
        endpoint = f"{host}:{port}"
        if (known := self._session.get(endpoint_key(endpoint))) is not None:
            return known
        cadata = self.store.ca_bundle()
        ok, reason = validates(host, port, cadata)
        if ok:
            cert = CertInfo.from_der(validated_peer_cert(host, port, cadata))
            return self._remember(TrustDecision(host, port, "validated", cert, cadata,
                                                scope=_validated_scope(host, port, cadata)))
        cert = CertInfo.from_der(fetch_peer_cert(host, port))  # compared with vCenter's thumbprint or a pin
        if sha1_thumbprint and normalize_fingerprint(sha1_thumbprint) == cert.sha1:
            log.info("ESXi host %s certificate matches the thumbprint reported by vCenter", endpoint)
            _refuse_out_of_date(endpoint, cert)
            return self._remember(TrustDecision(host, port, "pinned", cert, scope="thumbprint reported by vCenter"))
        pinned = self.store.pin(endpoint)
        if pinned and pinned["sha256"] == cert.sha256:
            _refuse_out_of_date(endpoint, cert)
            return self._remember(TrustDecision(host, port, "pinned", cert, scope="remembered"))
        return self._ask(host, port, cert, reason, changed_from=pinned, offer_ca=False)

    def _remember(self, d: TrustDecision) -> TrustDecision:
        self._session[endpoint_key(f"{d.host}:{d.port}")] = d
        return d

    def _ask(self, host: str, port: int, cert: CertInfo, reason: str, *, changed_from: dict | None,
             offer_ca: bool, remember: bool = True) -> TrustDecision:
        from .ui import console

        endpoint = f"{host}:{port}"
        p = self.prompter
        if problem := cert.validity_problem():
            # TLS refuses it whatever the user chooses: say so, instead of offering a trust that cannot work.
            if p is not None and p.interactive:
                with p.section(f"Certificate check: {endpoint}"):
                    print_cert_details(console, cert, reason)
            _refuse_out_of_date(endpoint, cert, problem)
        # A name mismatch: no CA can make a certificate valid for a name it does not list, so trusting vCenter's root
        # CA cannot help. OpenSSL reports it once the chain reaches a CA this computer trusts (it checks the name
        # before the signatures, so a forged certificate can look the same: nothing here says the server is genuine).
        name_only = "Hostname mismatch" in reason or "IP address mismatch" in reason
        # Only for a connection the user chose by name (not an ESXi host at the address vCenter reports).
        other_name = f"The certificate does not list {host}. {other_name_advice()}" if name_only and offer_ca else None
        if p is None or not p.interactive:
            hint = (f"Run `vmdeploy trust add {host} --port {port}` interactively once, or pass --trust-fingerprint "
                    f"{CertInfo.pretty(cert.sha256)} after verifying it out-of-band.")
            raise TrustError(f"The certificate presented by {endpoint} is not trusted ({reason}).",
                             hint=f"{other_name} {hint}" if other_name else hint)
        with p.section(f"Certificate check: {endpoint}"):
            if changed_from:
                console.print(
                    "[bold red]WARNING: the certificate for this server has CHANGED since you chose to remember it.[/]\n"
                    "This is expected after a certificate renewal, but it can also mean the connection is being "
                    "intercepted.\n"
                    f"Previously trusted SHA-256 fingerprint: {CertInfo.pretty(changed_from['sha256'])}")
            else:
                console.print("This server certificate is not yet trusted.")
            print_cert_details(console, cert, reason)
            # Not offered for a changed certificate (the user must look at that change, not trust a whole CA), for a
            # name mismatch (see above), nor by a standalone ESXi host, which has no CA bundle to download.
            root_ca = offer_ca and not changed_from and not name_only and publishes_ca_bundle(host, port, cert)
            if root_ca and lists_name(host, port, cert) is False:
                # e.g. its VMCA is not trusted yet, so the reason names the chain; the name does not match either
                root_ca = False
                other_name = f"The certificate does not list {host}. {other_name_advice()}"
            if other_name:
                console.print(other_name, markup=False)
            console.print("[yellow]First-use trust does not independently establish server identity. Compare the "
                          "fingerprint with a trusted administrative view.[/]")
            options = [("Trust for this session", TRUST_ONCE)]
            if remember:
                options.append(("Trust and remember", TRUST_ALWAYS))
            if root_ca:
                options.append(("Trust this vCenter's root CA (also covers its ESXi hosts and certificate renewals)",
                                TRUST_CA))
            options.append(("Cancel", DECLINE))
            answer = p.numbered("Certificate trust choice:", options, default=DECLINE)

        log.info("Trust prompt for %s: user chose %r for certificate %s (SHA-256 %s)", endpoint, answer,
                 cert.subject, CertInfo.pretty(cert.sha256))
        if answer == DECLINE:
            raise UserAborted(f"Connection to {endpoint} cancelled: the certificate was not trusted. Nothing was sent.")
        if answer == TRUST_CA:
            decision = self._adopt_vcenter_ca(host, port, cert)
            console.print(f"vCenter's root CA trusted and remembered ({decision.scope}). Certificates it issues to "
                          "this vCenter and its ESXi hosts will be accepted without asking.")
            return self._remember(decision)
        if answer == TRUST_ALWAYS:
            self.store.add_pin(endpoint, cert)
            console.print("Certificate trusted and remembered. Future connections to this server will be accepted "
                          "without asking while it presents this exact certificate.")
            return self._remember(TrustDecision(host, port, "pinned", cert, scope="remembered"))
        console.print("Certificate trusted for this session only. Saved trust was not changed.")
        return self._remember(TrustDecision(host, port, "pinned", cert, scope="this session only"))

    def _save_vcenter_ca(self, decision: TrustDecision) -> list[str]:
        """Download vCenter's root CA bundle over `decision`'s own connection rules: a validated server's chain and
        hostname are checked again, a pinned one must present the certificate that was remembered or that the user
        accepted. A certificate read without checks is never the anchor of this download (security review). The
        bundle is saved only if it validates the server's certificate on its own (chain and hostname, normal TLS
        rules; not with the help of the OS trust store). Otherwise nothing is saved, so a CA that does not apply
        to this server never ends up in the trust store that every connection is checked against."""
        host, port = decision.host, decision.port
        endpoint = f"{host}:{port}"
        pems = download_vcenter_ca(decision)
        if not pems:
            raise TrustError(f"{endpoint} did not provide any root CA certificates at /certs/download.zip. "
                             "Nothing was saved.",
                             hint="Check that this is a vCenter Server, or choose 'Trust and remember' instead.")
        ok, reason = validates(host, port, "\n".join(pems), os_store=False)
        if not ok:
            raise TrustError(f"vCenter's root CA does not validate the certificate of {endpoint} ({reason}). "
                             "Nothing was saved.",
                             hint="Choose 'Trust and remember' to pin this exact certificate instead. If you connect "
                                  "by IP, check that the IP is in the certificate's Names/IPs.")
        self.store.add_cas(endpoint, pems)
        log.info("Saved %d vCenter root CA certificate(s) from %s: %s", len(pems), endpoint,
                 ", ".join(CertInfo.from_pem(p).subject for p in pems))
        return pems

    def _adopt_vcenter_ca(self, host: str, port: int, cert: CertInfo) -> TrustDecision:
        pems = self._save_vcenter_ca(TrustDecision(host, port, "pinned", cert))  # the certificate the user accepted
        return TrustDecision(host, port, "validated", cert, self.store.ca_bundle(),
                             scope=f"vCenter root CA from {host}:{port}, {len(pems)} certificate(s)")

    def trust_vcenter_ca(self, host: str, port: int = 443) -> int:
        """`vmdeploy trust add --vcenter-ca`: trust vCenter's root CA bundle (covers its ESXi hosts too), after the
        server's own certificate is trusted for this session (asked like at first use, never remembered: a pin saved
        before a CA step that then failed stayed behind, though the message said nothing was saved). Refused before
        any question when the certificate does not list `host`: no CA can make it valid for that name."""
        if not validates(host, port, self.store.ca_bundle())[0]:  # a certificate that validates lists the name
            cert = CertInfo.from_der(fetch_peer_cert(host, port))
            if lists_name(host, port, cert) is False:
                names = ", ".join(visible(n) for n in cert.sans[:5]) + (", ..." if len(cert.sans) > 5 else "")
                raise TrustError(f"The certificate of {host}:{port} does not list {host}"
                                 + (f" (it lists {names})" if names else "") + ", so no root CA can make it valid "
                                 "for that name. Nothing was changed.", hint=other_name_advice("vCenter"))
        decision = self.decision(host, port, is_vcenter_candidate=False, remember=False)
        return len(self._save_vcenter_ca(decision))


def _refuse_out_of_date(endpoint: str, cert: CertInfo, problem: str | None = None) -> None:
    problem = problem or cert.validity_problem()
    if problem:
        raise TrustError(f"The certificate of {endpoint} {problem}. TLS refuses a certificate outside its validity "
                         "dates, even a trusted one, so this server cannot be used until it is renewed.",
                         hint="Renew the server's certificate (in the vSphere Client: the host's Configure > "
                              "Certificate; for vCenter: Administration > Certificate Management), or check this "
                              "computer's date and time. Then connect again.")


def download_vcenter_ca(decision: TrustDecision) -> list[str]:
    """Fetch vCenter's trusted root CA bundle over the decision's connection: validated (chain and hostname), or
    pinned to the certificate that was remembered or that the user accepted. Documented in Broadcom KB 330833
    (https://<vcenter>/certs/download.zip)."""

    conn = decision.connect(30, "the CA bundle download")  # a failing certificate is a TrustError, not an SSL error
    try:
        conn.request("GET", "/certs/download.zip")
        resp = conn.getresponse()
        if resp.status != 200:
            log.warning("/certs/download.zip returned HTTP %s", resp.status)
            return []
        blob = resp.read()
    finally:
        conn.close()
    return extract_ca_pems(blob)


def publishes_ca_bundle(host: str, port: int, cert: CertInfo) -> bool:
    """Does this server publish vCenter's CA bundle? Decides whether "Trust this vCenter's root CA" is offered.

    The trust prompt comes before sign-in, so the server type (vCenter or standalone ESXi) is not known yet.
    ESXi has no /certs/download.zip. The request is anonymous and uses a TLS connection pinned to the exact
    certificate being shown, so nothing is sent to any other server; the body is not read.
    """
    decision = TrustDecision(host, port, "pinned", cert)
    conn = None
    try:
        conn = decision.connect(10, "the CA bundle check")
        conn.request("GET", "/certs/download.zip")
        return conn.getresponse().status == 200
    except (OSError, http.client.HTTPException, TrustError) as e:
        log.debug("CA bundle probe on %s:%s failed: %s", host, port, e)
        return False
    finally:
        if conn is not None:
            conn.close()


def extract_ca_pems(zip_bytes: bytes) -> list[str]:
    """The zip contains certs/lin/*.0 (PEM), certs/win/*.crt and *.r0 / *.crl revocation lists."""
    pems: list[str] = []
    seen: set[str] = set()
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            base = name.rsplit("/", 1)[-1]
            if not (base.endswith(".crt") or (base.rsplit(".", 1)[-1].isdigit())):
                continue
            raw = zf.read(name)
            try:
                cert = x509.load_pem_x509_certificate(raw)
            except ValueError:
                try:
                    cert = x509.load_der_x509_certificate(raw)
                except ValueError:
                    continue
            pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
            if fp not in seen:
                seen.add(fp)
                pems.append(pem)
    return pems
