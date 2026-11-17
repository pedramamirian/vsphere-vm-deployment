"""Connecting to vCenter Server / ESXi: certificate trust, sign-in, licence check and guaranteed logout."""

from __future__ import annotations

import logging
import os
import ssl
from dataclasses import dataclass, field

from pyVim import connect as pyvim_connect
from pyVmomi import vim, vmodl

from . import credentials
from .auth import exchange_for_saml, idp_token
from .errors import AuthError, LicenseRestricted, VmDeployError
from .logsetup import register_secret
from .profiles import AUTH_DESCRIPTIONS, AuthMethod, Profile
from .trust import TrustDecision, TrustManager, certificate_failure
from .ui import Prompter, warn

log = logging.getLogger(__name__)

TESTED_MAJOR_VERSIONS = (8, 9)


@dataclass
class Connection:
    si: vim.ServiceInstance
    profile: Profile
    decision: TrustDecision
    trust: TrustManager
    user: str = ""
    warnings: list[str] = field(default_factory=list)
    managed_by: str | None = None  # direct ESXi connection to a host that vCenter (this address) manages
    # (user, password) of a password sign-in, kept in memory only (already registered as a secret, so never
    # logged) for the few vCenter features that exist only in the REST API (e.g. `keyprovider backup`).
    rest_credentials: tuple[str, str] | None = field(default=None, repr=False, compare=False)
    _content: vim.ServiceInstanceContent | None = field(default=None, init=False, repr=False, compare=False)

    @property
    def content(self) -> vim.ServiceInstanceContent:
        """The ServiceContent, read once: it does not change during a session, and every read is a round trip."""
        if self._content is None:
            self._content = self.si.RetrieveContent()
        return self._content

    @property
    def about(self) -> vim.AboutInfo:
        return self.content.about

    @property
    def is_vcenter(self) -> bool:
        return self.about.apiType == "VirtualCenter"

    @property
    def product(self) -> str:
        return f"{self.about.fullName}"

    @property
    def session_cookie(self) -> str:
        """vmware_soap_session cookie value, needed for datastore HTTP access and NFC uploads."""
        cookie = self.si._stub.cookie  # noqa: SLF001 - pyVmomi exposes no public accessor
        return cookie.split(";", 1)[0] if cookie else ""

    def close(self) -> None:
        """Always log out, so sessions do not pile up on vCenter."""
        try:
            pyvim_connect.Disconnect(self.si)
            log.info("Logged out of %s", self.profile.endpoint)
        except Exception as e:  # noqa: BLE001
            log.debug("Logout failed (session may already be gone): %s", e)

    def __enter__(self) -> Connection:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# ---------------------------------------------------------------------------------------------- helpers
def _supported_version(host: str, port: int, ssl_context: ssl.SSLContext) -> str:
    """Negotiate the vim25 API version (/sdk/vimServiceVersions.xml) over the same verified or pinned connection
    as the sign-in: TLS validation is never switched off, not even for this public metadata."""
    find = getattr(pyvim_connect, "__FindSupportedVersion")
    version = find("https", host, port, "/sdk", pyvim_connect.GetServiceVersions("vim25"), ssl_context,
                   None, 80, None)
    if version is None:
        raise VmDeployError(f"{host}:{port} does not look like a vCenter Server or ESXi host (no vim25 API).")
    return version


def _raw_connect(profile: Profile, decision: TrustDecision, *, user: str | None = None, pwd: str | None = None,
                 saml: str | None = None) -> vim.ServiceInstance:
    kwargs: dict = {"host": profile.host, "port": profile.port}
    if saml:
        kwargs.update(token=saml, tokenType=pyvim_connect.TOKEN_TYPE_SAML)
    else:
        kwargs.update(user=user, pwd=pwd)
    # Always a verifying context. For pinned hosts it trusts only the accepted certificate (trust.pinned_context).
    # pyVmomi's own serverPemCert fallback is deliberately NOT used: it switches the shared SSL context to
    # CERT_NONE after the first connection, so later pooled connections would no longer be checked.
    kwargs["sslContext"] = decision.ssl_context()
    try:
        kwargs["version"] = _supported_version(profile.host, profile.port, kwargs["sslContext"])
        return pyvim_connect.Connect(**kwargs)
    except (ssl.SSLCertVerificationError, vim.fault.HostConnectFault) as e:
        # e.g. renewed or intercepted since it was trusted: a trust error, never "a bug" or "could not connect".
        # pyVmomi's sign-in wraps the certificate failure in a HostConnectFault.
        if (failed := certificate_failure(e)) is None:
            raise
        raise decision.refused(failed, "sign-in") from e


ENV_SECRETS = {"password": "VMDEPLOY_PASSWORD", "client_secret": "VMDEPLOY_CLIENT_SECRET"}


def uses_keychain(profile: Profile, kind: str) -> bool:
    """Is this secret saved in / read from the OS keychain? A saved secret belongs to one account: a password only
    when the profile names the username. Otherwise one person's saved password would be sent for whichever
    username is typed next (and deleted when that sign-in fails)."""
    return profile.remember_secret and (kind != "password" or bool(profile.username))


def _get_secret(profile: Profile, prompter: Prompter, kind: str, question: str) -> tuple[str, str]:
    """Return (secret, source) with source "env", "keychain" or "prompt".
    Order: environment variable (automation/CI), OS keychain, interactive prompt."""
    env = os.environ.get(ENV_SECRETS.get(kind, ""))
    if env:
        return env, "env"
    if uses_keychain(profile, kind):
        stored = credentials.get_secret(profile, kind)  # saved for exactly this server and account, or None
        if stored:
            return stored, "keychain"
    if not prompter.interactive:
        raise AuthError(f"No {kind.replace('_', ' ')} available for profile '{profile.name}' in non-interactive mode.",
                        hint=f"Run once interactively with the keychain enabled (and a username in the profile), "
                             f"or set {ENV_SECRETS.get(kind)} in the environment of the automation job.")
    return prompter.password(question, field_name=""), "prompt"


def _maybe_store(profile: Profile, prompter: Prompter, kind: str, value: str, source: str) -> None:
    if source != "prompt" or not uses_keychain(profile, kind):
        return
    if credentials.set_secret(profile, value, kind):
        prompter.record("Keychain", f"{kind} saved to the OS keychain for profile '{profile.name}'")


def connect(profile: Profile, prompter: Prompter, trust: TrustManager, *, max_attempts: int = 3) -> Connection:
    decision = trust.decision(profile.host, profile.port)
    rest_credentials = None
    if profile.auth == AuthMethod.PASSWORD:
        si, user, pwd = _password_login(profile, prompter, decision, max_attempts)
        rest_credentials = (user, pwd)
    else:
        si, user = _federated_login(profile, prompter, decision)
    conn = Connection(si=si, profile=profile, decision=decision, trust=trust, user=user,
                      rest_credentials=rest_credentials)
    try:
        check_environment(conn)
    except Exception:
        conn.close()
        raise
    return conn


def _password_login(profile: Profile, prompter: Prompter, decision: TrustDecision,
                    max_attempts: int) -> tuple[vim.ServiceInstance, str, str]:
    with prompter.section(f"Sign in to {profile.endpoint}"):
        prompter.record("Method", AUTH_DESCRIPTIONS[profile.auth])
        user = profile.username or prompter.text("Username (e.g. administrator@vsphere.local, user@domain, root):",
                                                 field_name="profile.username")
        for attempt in range(1, max_attempts + 1):
            pwd, source = _get_secret(profile, prompter, "password", f"Password for {user}:")
            register_secret(pwd)
            try:
                si = _raw_connect(profile, decision, user=user, pwd=pwd)
            except vim.fault.InvalidLogin:
                if source == "keychain":
                    if credentials.delete_secret(profile, "password") is None:  # could not be changed or checked
                        warn("The password saved in the keychain was rejected. It could not be removed from the "
                             f"keychain (is it locked?); run `vmdeploy forget-secret {profile.name}` later.")
                    else:
                        warn("The password saved in the keychain was rejected and has been removed.")
                elif source == "prompt" and attempt < max_attempts and prompter.interactive:
                    warn("Incorrect username or password, try again.")
                    continue
                raise AuthError(f"Sign-in failed for {user}.",
                                hint="For Active Directory accounts use user@domain (UPN). Federated (SSO) "
                                     "identity sources need an oauth-* sign-in method on the profile.") from None
            except vim.fault.HostConnectFault as e:
                raise AuthError(f"Could not connect to {profile.endpoint}: {e.msg}") from e
            _maybe_store(profile, prompter, "password", pwd, source)
            prompter.record("Signed in as", user)
            return si, user, pwd
    raise AuthError("Sign-in failed.")  # pragma: no cover


def _federated_login(profile: Profile, prompter: Prompter,
                     decision: TrustDecision) -> tuple[vim.ServiceInstance, str]:
    with prompter.section(f"Federated sign in to {profile.endpoint}"):
        prompter.record("Method", AUTH_DESCRIPTIONS[profile.auth])
        if profile.auth == AuthMethod.OAUTH_TOKEN:
            access = os.environ.get("VMDEPLOY_ACCESS_TOKEN") or \
                prompter.password("Paste the access token from your identity provider:",
                                  field_name="VMDEPLOY_ACCESS_TOKEN")
            id_tok = os.environ.get("VMDEPLOY_ID_TOKEN") or prompter.text(
                "Paste the ID token (optional, press Enter to skip):", default="", assume_default=True) or None
            register_secret(access)
            register_secret(id_tok)
            user = "(token)"
        else:
            if not profile.oauth:
                raise AuthError(f"Profile '{profile.name}' uses {profile.auth.value} but has no OAuth settings.",
                                hint="Re-create it with `vmdeploy profile add` and choose federated sign-in.")
            secret, secret_src = (None, "prompt")
            if profile.auth == AuthMethod.OAUTH_CLIENT_CREDENTIALS:
                secret, secret_src = _get_secret(profile, prompter, "client_secret", "OAuth client secret:")
                register_secret(secret)
                access, id_tok = idp_token(profile.oauth.token_url, profile.oauth.client_id,
                                           grant="client_credentials", scope=profile.oauth.scope,
                                           client_secret=secret)
                user = profile.oauth.client_id
            else:
                user = profile.username or prompter.text("Username (UPN, e.g. user@contoso.com):",
                                                         field_name="profile.username")
                pwd, pwd_src = _get_secret(profile, prompter, "password", f"Password for {user}:")
                register_secret(pwd)
                access, id_tok = idp_token(profile.oauth.token_url, profile.oauth.client_id, grant="password",
                                           scope=profile.oauth.scope, username=user, password=pwd)
                _maybe_store(profile, prompter, "password", pwd, pwd_src)
            if secret:
                _maybe_store(profile, prompter, "client_secret", secret, secret_src)
        saml = exchange_for_saml(decision, access, id_tok)
        try:
            si = _raw_connect(profile, decision, saml=saml)
        except (vim.fault.InvalidLogin, vmodl.MethodFault) as e:
            raise AuthError(f"vCenter rejected the SAML token: {getattr(e, 'msg', e)}") from e
        prompter.record("Signed in as", user)
        return si, user


# ---------------------------------------------------------------------------------------------- checks
def is_free_hypervisor_license(licenses) -> bool:
    """The free 'vSphere Hypervisor' edition makes the API read-only for every write operation
    (William Lam, 'The Dreaded fault.RestrictedVersion.summary Error'). Detected by edition name."""
    for lic in licenses or []:
        name = (getattr(lic, "name", "") or "").lower()
        key = (getattr(lic, "editionKey", "") or "").lower()
        if "hypervisor" in name or key == "esxbasic":
            return True
    return False


def check_environment(conn: Connection) -> None:
    about = conn.about
    major = int((about.version or "0").split(".")[0] or 0)
    if major not in TESTED_MAJOR_VERSIONS:
        msg = f"{about.fullName} is not a version this tool supports (supported: vSphere 8.x and 9.x)."
        conn.warnings.append(msg)
        warn(msg)
    if not conn.is_vcenter:
        lm = conn.content.licenseManager
        if lm and is_free_hypervisor_license(lm.licenses):
            raise LicenseRestricted(
                f"{conn.profile.host} is licensed with the free vSphere Hypervisor edition.",
                hint="With that licence the vSphere API is read-only, so VMs cannot be created through it. "
                     "A paid licence, a VMUG Advantage licence, or the 60-day evaluation mode is required.",
            )
        host = _first_host(conn)
        mgmt_ip = getattr(getattr(host, "summary", None), "managementServerIp", None) if host else None
        if mgmt_ip:
            conn.managed_by = mgmt_ip
            msg = (f"This ESXi host is managed by vCenter Server {mgmt_ip}. Deploying directly to the host works, "
                   "but connecting to vCenter instead keeps vCenter's inventory and DRS in charge.")
            conn.warnings.append(msg)
            warn(msg)


def _first_host(conn: Connection):
    view = conn.content.viewManager.CreateContainerView(conn.content.rootFolder, [vim.HostSystem], True)
    try:
        return view.view[0] if view.view else None
    finally:
        view.Destroy()


def license_fault_to_error(e: Exception) -> Exception:
    if isinstance(e, vim.fault.RestrictedVersion):
        return LicenseRestricted("The host refused a write operation because of its licence (RestrictedVersion).",
                                 hint="The free vSphere Hypervisor licence makes the API read-only.")
    return e
