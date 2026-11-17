"""Connection profiles: one per vCenter Server or standalone ESXi host.

Stored in <config dir>/profiles.yaml. Profiles never contain passwords or client secrets; those live in
the OS keychain (see credentials.py) or are asked for at run time.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from .errors import ConfigError
from .paths import config_dir
from .trust import host_key


class AuthMethod(StrEnum):
    PASSWORD = "password"  # vsphere.local / local ESXi accounts, AD over LDAP(S), Integrated Windows Auth identity sources
    OAUTH_PASSWORD = "oauth-password"  # federated IdP (ADFS, Entra ID, Okta, PingFederate) via OAuth password grant
    OAUTH_CLIENT_CREDENTIALS = "oauth-client-credentials"  # federated IdP, service principal / app registration
    OAUTH_TOKEN = "oauth-token"  # federated IdP, access token obtained outside the tool (e.g. browser + MFA)


AUTH_DESCRIPTIONS = {
    AuthMethod.PASSWORD: "Username + password (vsphere.local, ESXi local, Active Directory over LDAP or IWA)",
    AuthMethod.OAUTH_PASSWORD: "Federated SSO, OAuth password grant (ADFS / Entra ID / Okta / PingFederate)",
    AuthMethod.OAUTH_CLIENT_CREDENTIALS: "Federated SSO, OAuth client credentials (service principal)",
    AuthMethod.OAUTH_TOKEN: "Federated SSO, paste an access token you obtained yourself (works with MFA)",
}


class OAuthSettings(BaseModel):
    token_url: str = Field(..., description="The identity provider's OAuth 2.0 token endpoint")
    client_id: str
    scope: str = "openid"
    # The client secret is never stored here; it is kept in the OS keychain.


def profile_name_error(name: str) -> str | None:
    """Why a profile name is not allowed, or None. Used by prompts (checked as you type) and the model."""
    if not name:
        return "A profile name is required"
    if len(name) > 64:
        return "Profile names can be at most 64 characters"
    if any(c.isspace() or c in "/\\:" for c in name):
        return "Profile names may not contain spaces, slashes or colons"
    return None


class Profile(BaseModel):
    name: str
    host: str
    port: int = 443
    auth: AuthMethod = AuthMethod.PASSWORD
    username: str | None = None
    oauth: OAuthSettings | None = None
    remember_secret: bool = False  # keep password / client secret in the OS keychain
    default_datacenter: str | None = None

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        problem = profile_name_error(v)
        if problem:
            raise ValueError(problem)
        return v

    @field_validator("host")
    @classmethod
    def _plain_host(cls, v: str) -> str:
        """An IPv6 address is kept without brackets, however it was typed ("[fd00::10]"): url_host and endpoint
        add them where they are needed. Lower case: host names are case-insensitive (DNS), so VCSA.example.com and
        vcsa.example.com are one server, with one saved certificate, and `access remove` matches their profiles."""
        v = v.strip()
        return host_key(v[1:-1] if v.startswith("[") and v.endswith("]") else v)  # keeps an IPv6 zone's letters

    @property
    def endpoint(self) -> str:
        """host:port, with an IPv6 address in brackets ([fd00::10]:443) so the port cannot be mistaken for part
        of the address."""
        return f"{self.url_host}:{self.port}"

    @property
    def url_host(self) -> str:
        """The host as written in a URL: an IPv6 address in brackets."""
        return f"[{self.host}]" if ":" in self.host else self.host


class ProfileStore:
    def __init__(self, path: Path | None = None):
        self.path = path or (config_dir() / "profiles.yaml")

    def _load_raw(self) -> dict:
        if not self.path.exists():
            return {"default": None, "profiles": {}}
        try:
            data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            raise ConfigError(f"{self.path} is not valid YAML: {e}") from e
        data.setdefault("profiles", {})
        data.setdefault("default", None)
        return data

    def list(self) -> list[Profile]:
        raw = self._load_raw()
        return [Profile(name=n, **p) for n, p in sorted(raw["profiles"].items())]

    def default_name(self) -> str | None:
        return self._load_raw().get("default")

    def get(self, name: str) -> Profile:
        raw = self._load_raw()
        if name not in raw["profiles"]:
            existing = ", ".join(sorted(raw["profiles"])) or "none yet (create one with `vmdeploy profile add`)"
            raise ConfigError(f"No profile named '{name}'.",
                              hint=f"Existing profiles: {existing}. (`vmdeploy access remove` deletes the deploy "
                                   "account's profile; use an administrator profile then.)")
        return Profile(name=name, **raw["profiles"][name])

    def save(self, profile: Profile, make_default: bool = False) -> None:
        raw = self._load_raw()
        raw["profiles"][profile.name] = profile.model_dump(mode="json", exclude={"name"}, exclude_none=True)
        if make_default or not raw.get("default"):
            raw["default"] = profile.name
        self._write(raw)

    def remove(self, name: str) -> None:
        raw = self._load_raw()
        if raw["profiles"].pop(name, None) is None:
            raise ConfigError(f"No profile named '{name}'.")
        if raw.get("default") == name:
            raw["default"] = next(iter(raw["profiles"]), None)
        self._write(raw)

    def set_default(self, name: str) -> None:
        raw = self._load_raw()
        if name not in raw["profiles"]:
            raise ConfigError(f"No profile named '{name}'.")
        raw["default"] = name
        self._write(raw)

    def _write(self, raw: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
        tmp.replace(self.path)
