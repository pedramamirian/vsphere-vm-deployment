"""Federated (SSO) sign-in helpers.

Flow for vCenter Server configured with an external identity provider (ADFS, Entra ID, Okta, PingFederate):

1. Obtain an OAuth 2.0 access token (and, with the `openid` scope, an ID token) from the identity provider
   using the password grant, the client-credentials grant, or a token the user obtained elsewhere.
2. Exchange it at vCenter for a SAML token:
       POST https://<vcenter>/api/vcenter/authentication/token
       grant_type=urn:ietf:params:oauth:grant-type:token-exchange
       subject_token_type=urn:ietf:params:oauth:token-type:access_token
       actor_token_type=urn:ietf:params:oauth:token-type:id_token
       requested_token_type=urn:ietf:params:oauth:token-type:saml2
   (Broadcom vSphere Automation SDKs Programming Guide 8.0, "Exchange JWT Tokens for a SAML Token and
   Obtain a Session Identifier".)
3. Log in to the vSphere Web Services (vim25) API with the SAML token (pyVmomi token/tokenType="saml",
   which calls SessionManager.LoginByToken).

The identity provider must allow the chosen grant for the vCenter OAuth client. Broadcom recommends the
password grant only for low-privilege service users because it exposes the credentials to the client.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import ssl
import urllib.parse
import urllib.request

from .errors import AuthError
from .logsetup import register_secret
from .trust import TrustDecision

log = logging.getLogger(__name__)

TOKEN_EXCHANGE_PATH = "/api/vcenter/authentication/token"


def _idp_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    extra = os.environ.get("VMDEPLOY_IDP_CA_BUNDLE")  # for identity providers signed by a private CA
    if extra:
        ctx.load_verify_locations(cafile=extra)
    return ctx


def idp_token(token_url: str, client_id: str, *, grant: str, scope: str = "openid",
              username: str | None = None, password: str | None = None,
              client_secret: str | None = None, timeout: float = 30) -> tuple[str, str | None]:
    """Return (access_token, id_token or None) from the identity provider's token endpoint."""
    parsed = urllib.parse.urlparse(token_url)
    if parsed.scheme != "https" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise AuthError("The OAuth token URL must use https:// (credentials would otherwise be sent in clear text).")
    form: dict[str, str] = {"grant_type": grant, "client_id": client_id}
    if scope:
        form["scope"] = scope
    if grant == "password":
        if not (username and password):
            raise AuthError("The OAuth password grant needs a username and password.")
        form.update(username=username, password=password)
    if client_secret:
        form["client_secret"] = client_secret
    req = urllib.request.Request(token_url, data=urllib.parse.urlencode(form).encode(), method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_idp_ssl_context()) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:500]
        raise AuthError(f"The identity provider rejected the token request (HTTP {e.code}).",
                        hint=f"Check the token URL, client ID and that the '{grant}' grant is enabled for this "
                             f"client. Provider said: {detail}") from e
    except urllib.error.URLError as e:
        raise AuthError(f"Could not reach the identity provider at {token_url}: {e.reason}") from e
    access = body.get("access_token")
    if not access:
        raise AuthError("The identity provider response did not contain an access_token.")
    register_secret(access)
    idt = body.get("id_token")
    register_secret(idt)
    return access, idt


def exchange_for_saml(decision: TrustDecision, access_token: str, id_token: str | None,
                      timeout: float = 30) -> str:
    """Exchange an IdP access token for a vCenter SAML token. Returns the SAML assertion XML."""
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_token": access_token,
        "requested_token_type": "urn:ietf:params:oauth:token-type:saml2",
    }
    if id_token:
        form.update(actor_token_type="urn:ietf:params:oauth:token-type:id_token", actor_token=id_token)
    conn = decision.connect(timeout, "the token exchange")  # the certificate is checked before the token is sent
    try:
        conn.request("POST", TOKEN_EXCHANGE_PATH, body=urllib.parse.urlencode(form),
                     headers={"Content-Type": "application/x-www-form-urlencoded",
                              "Authorization": f"Bearer {access_token}", "Accept": "application/json"})
        resp = conn.getresponse()
        raw = resp.read().decode(errors="replace")
    finally:
        conn.close()
    if resp.status != 200 and resp.status != 201:
        raise AuthError(f"vCenter refused the token exchange (HTTP {resp.status}).",
                        hint="Confirm vCenter is federated with this identity provider and that the user has "
                             f"permissions in vCenter. Response: {raw[:300]}")
    try:
        token = json.loads(raw).get("access_token")
    except json.JSONDecodeError as e:
        raise AuthError("Unexpected token exchange response from vCenter.") from e
    if not token:
        raise AuthError("vCenter's token exchange response did not include a token.")
    register_secret(token)
    return decode_saml(token)


def decode_saml(token: str) -> str:
    """vCenter returns the SAML assertion base64-encoded; pyVmomi needs the XML."""
    t = token.strip()
    if t.startswith("<"):
        return t
    padded = t + "=" * (-len(t) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            xml = decoder(padded).decode()
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if xml.lstrip().startswith("<"):
            register_secret(xml)
            return xml
    raise AuthError("Could not decode the SAML token returned by vCenter.")
