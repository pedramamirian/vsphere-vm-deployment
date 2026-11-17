"""Secret storage in the operating system keychain.

Windows Credential Manager, macOS Keychain and the Secret Service API on Linux are used through the
`keyring` library. If no keychain backend is available the tool simply asks every time.

A saved secret is bound to what it was saved for: the keychain entry's name holds the profile name and a
fingerprint of the profile's server, port, account, sign-in method and token endpoint. A secret is only ever read
for that exact target, so one left under a reused profile name (an earlier server or account, kept because the
keychain was locked when it should have been deleted) is never found, let alone sent somewhere else.
"""

from __future__ import annotations

import hashlib
import logging

import keyring
from keyring.errors import NoKeyringError

log = logging.getLogger(__name__)
SERVICE = "vsphere-vm-deployment"
KINDS = ("password", "client_secret")


def binding(profile) -> str:
    """Fingerprint of what a profile's secrets belong to: server, port, account, sign-in method and token endpoint
    (host names are stored in lower case). Two profiles with the same binding are the same target."""
    o = profile.oauth
    auth = getattr(profile.auth, "value", profile.auth)
    parts = (profile.host, str(profile.port), profile.username or "", str(auth),
             (o.token_url or "") if o else "", (o.client_id or "") if o else "")
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]


def entry_name(profile, kind: str) -> str:
    """The keychain entry (under service SERVICE) that holds this profile's secret of this kind."""
    return f"{profile.name}:{kind}:{binding(profile)}"



def keychain_available() -> bool:
    try:
        backend = keyring.get_keyring()
    except Exception:  # noqa: BLE001
        return False
    name = f"{type(backend).__module__}.{type(backend).__name__}".lower()
    if "fail" in name or "null" in name:
        return False
    try:
        return float(getattr(backend, "priority", 1)) > 0
    except Exception:  # noqa: BLE001
        return True


def get_secret(profile, kind: str = "password") -> str | None:
    """The secret saved for this profile's exact target, or None."""
    try:
        return keyring.get_password(SERVICE, entry_name(profile, kind))
    except Exception as e:  # noqa: BLE001 - locked, denied, no keychain, or a backend error: ask instead
        log.debug("keychain read failed: %s", e)
        return None


def set_secret(profile, value: str, kind: str = "password") -> bool:
    try:
        keyring.set_password(SERVICE, entry_name(profile, kind), value)
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("Could not save to the OS keychain: %s", e)
        return False


def delete_secret(profile, kind: str = "password") -> bool | None:
    """True: deleted. False: nothing was saved (or there is no keychain). None: the keychain could not be changed or
    checked (e.g. locked or access denied), so the secret may still be there: bound to this profile's target, so no
    other profile can use it. Checked by reading it back: some backends (macOS, KWallet) report a locked keychain as
    "not found", and some raise errors that are not KeyringErrors (Windows without a logon session)."""
    key = entry_name(profile, kind)
    try:
        if keyring.get_password(SERVICE, key) is None:
            return False
        keyring.delete_password(SERVICE, key)
        gone = keyring.get_password(SERVICE, key) is None
    except NoKeyringError:
        return False
    except Exception as e:  # noqa: BLE001 - locked, denied, or a backend error: the secret may still be there
        log.warning("Could not delete the saved %s of profile %s from the OS keychain: %s", kind, profile.name, e)
        return None
    if not gone:
        log.warning("The saved %s of profile %s is still in the OS keychain after deleting it", kind, profile.name)
        return None
    return True


def delete_secrets(profile) -> tuple[list[str], bool]:
    """Delete every secret saved for a profile's target: (the kinds deleted, whether the keychain could be changed
    and checked for all of them; False means one may still be there, unusable by any other target)."""
    results = {kind: delete_secret(profile, kind) for kind in KINDS}
    return [kind for kind, r in results.items() if r], None not in results.values()
