"""vCenter key providers: list, add, back up and remove a Native Key Provider (needed for a virtual TPM).

The vSphere Client's "Back up" builds its download link from vCenter's own host name. When vCenter was installed
with an IP address as its system name (PNID) and has no proper host name, that link points at "localhost" and
the backup fails (Broadcom KB 312030, KB 404088). Common in small and test installations.

This does the same backup through the documented vSphere Automation API (Broadcom: "Export and Import vSphere
Native Key Provider Configuration"):
  1. POST /api/vcenter/crypto-manager/kms/providers?action=export {provider, password} -> a download URL and a
     one-time token;
  2. POST that URL with "Authorization: Bearer <token>" -> the backup file (.p12).
The download goes to the address vmdeploy is connected to, whatever host name vCenter put in the URL, over the
same trusted (validated or pinned) TLS connection as everything else. An export counts as the backup vCenter
requires. Needs Cryptographer.ManageKeyServers (an administrator).
"""

from __future__ import annotations

import base64
import http.client
import json
import logging
import re
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

from .errors import AuthError, DeploymentError
from .logsetup import register_secret
from .transfer import USER_AGENT

log = logging.getLogger(__name__)

SESSION_PATH = "/api/session"
EXPORT_PATH = "/api/vcenter/crypto-manager/kms/providers?action=export"
PRIVILEGE = "Cryptographer.ManageKeyServers"


PROVIDERS_PATH = "/api/vcenter/crypto-manager/kms/providers"
KINDS = {"nativeProvider": "Native", "vCenter": "Standard (KMS)", "trustAuthority": "Trusted"}
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}")


@dataclass
class Provider:
    name: str
    backed_up: bool | None  # None: vCenter did not say (or not a Native Key Provider)
    default: bool
    kind: str = "Native"
    tpm_required: bool | None = None

    @property
    def native(self) -> bool:
        return self.kind == "Native"


def providers(conn) -> list[Provider]:
    """All key providers of the vCenter (SOAP: CryptoManagerKmip.ListKmsClusters)."""
    cm = getattr(conn.content, "cryptoManager", None)
    if cm is None or not hasattr(cm, "ListKmsClusters"):
        return []
    try:
        clusters = cm.ListKmsClusters(includeKmsServers=False) or []
    except Exception as e:  # noqa: BLE001 - NoPermission for accounts without Cryptographer.ManageKeyServers
        raise DeploymentError(f"Could not list the key providers: {getattr(e, 'msg', e)}",
                              hint=f"This needs an administrator (privilege {PRIVILEGE}).") from e
    out = []
    for c in clusters:
        kind = KINDS.get(str(getattr(c, "managementType", "")), str(getattr(c, "managementType", "")) or "unknown")
        out.append(Provider(c.clusterId.id, getattr(c, "hasBackup", None) if kind == "Native" else None,
                            bool(getattr(c, "useAsDefault", False)), kind, getattr(c, "tpmRequired", None)))
    return out


def native_providers(conn) -> list[Provider]:
    return [p for p in providers(conn) if p.native]


def host_tpms(conn) -> list[tuple[str, str | None, bool | None, str]]:
    """(host, its cluster or None, has a TPM 2.0, TPM description) for every ESXi host. A Native Key Provider only
    works on hosts in a cluster; one with "Hosts need a TPM" also needs a TPM 2.0 there."""
    from pyVmomi import vim

    from .crypto import host_tpm

    content = conn.content
    view = content.viewManager.CreateContainerView(content.rootFolder, [vim.HostSystem], True)
    try:
        out = []
        for h in view.view:
            parent = h.parent
            cluster = parent.name if isinstance(parent, vim.ClusterComputeResource) else None
            out.append((h.name, cluster, *host_tpm(h)))
        return sorted(out)
    finally:
        view.Destroy()


def set_default(conn, name: str) -> None:
    """Make `name` vCenter's default key provider (used for new virtual TPMs)."""
    from pyVmomi import vim

    conn.content.cryptoManager.SetDefaultKmsCluster(entity=None, clusterId=vim.encryption.KeyProviderId(id=name))


def vm_keys(conn) -> tuple[dict[str, list[str]], list[str]]:
    """(key provider name -> names of the VMs whose keys (virtual TPM or encryption) come from it, names of the VMs
    whose configuration could not be read, e.g. inaccessible because their storage is down: they may use any key
    provider). One bulk read of every VM; read-only. Raises DeploymentError when the VMs cannot be read at all:
    `keyprovider remove` relies on "no VM uses it", which must never be a guess."""
    from .inventory import vm_properties

    used: dict[str, list[str]] = {}
    unchecked: list[str] = []
    for _vm, props in vm_properties(conn, ["name", "config.template", "config.keyId"]):
        if "config.template" not in props:  # always set in a configuration that could be read
            unchecked.append(props.get("name", "?"))
            continue
        key = props.get("config.keyId")
        if key is not None and getattr(key, "providerId", None) is not None:
            used.setdefault(key.providerId.id, []).append(props.get("name", "?"))
    return {k: sorted(v) for k, v in used.items()}, sorted(unchecked)


def vms_using(conn, name: str) -> tuple[list[str], list[str]]:
    """(names of the VMs whose keys come from key provider `name`, names of the VMs that could not be checked)."""
    used, unchecked = vm_keys(conn)
    return used.get(name, []), unchecked


def _request(decision, method: str, path: str, *, headers: dict[str, str] | None = None,
             body: bytes | None = None, timeout: float = 60) -> tuple[int, bytes]:
    """One HTTPS request to the connected server over the trusted (validated or pinned) connection."""
    conn = None
    try:
        conn = decision.connect(timeout, "the key provider request")  # a failing certificate is a TrustError
        hdrs = {"User-Agent": USER_AGENT, "Connection": "close", "Accept": "application/json"}
        hdrs.update(headers or {})
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        return resp.status, resp.read()
    except (OSError, http.client.HTTPException) as e:
        raise DeploymentError(f"The request to {decision.host} failed: {e}") from e
    finally:
        if conn is not None:
            conn.close()


def _api_message(data: bytes) -> str:
    """The text of a vSphere Automation API error ({"error_type": ..., "messages": [{"default_message": ...}]})."""
    try:
        err = json.loads(data or b"{}")
    except ValueError:
        return (data or b"").decode("utf-8", "replace")[:200]
    if not isinstance(err, dict):
        return str(err)[:200]
    msgs = "; ".join(m.get("default_message", "") for m in err.get("messages") or [] if isinstance(m, dict))
    return msgs or str(err.get("error_type") or "")


class RestSession:
    """A vSphere Automation API session (POST /api/session with the user's password), logged out on exit."""

    def __init__(self, decision, user: str, password: str):
        self.decision, self.user, self.password = decision, user, password
        self.id: str | None = None

    def __enter__(self) -> str:
        basic = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        register_secret(basic)
        status, data = _request(self.decision, "POST", SESSION_PATH, headers={"Authorization": f"Basic {basic}"})
        if status in (401, 403):
            raise AuthError(f"vCenter's API refused the sign-in for {self.user}: {_api_message(data)}")
        if status >= 300:
            raise DeploymentError(f"Could not open an API session: HTTP {status} {_api_message(data)}")
        self.id = json.loads(data)
        register_secret(self.id)
        return self.id

    def __exit__(self, *exc) -> None:
        if self.id:
            try:
                _request(self.decision, "DELETE", SESSION_PATH, headers={"vmware-api-session-id": self.id})
            except Exception as e:  # noqa: BLE001 - the session expires on its own
                log.debug("API session logout failed: %s", e)


def _check(status: int, data: bytes, what: str) -> None:
    if status in (401, 403):
        raise DeploymentError(f"vCenter refused to {what}: {_api_message(data)}",
                              hint=f"This needs an administrator (privilege {PRIVILEGE}).")
    if status >= 300:
        raise DeploymentError(f"vCenter could not {what}: HTTP {status} {_api_message(data)}")


def create(decision, session_id: str, name: str, *, tpm_required: bool = False) -> None:
    """Add a Native Key Provider (vSphere Automation API, Providers.create with a native_spec)."""
    body = {"provider": name, "native_spec": {}, "constraints": {"tpm_required": tpm_required}}
    status, data = _request(decision, "POST", PROVIDERS_PATH, body=json.dumps(body).encode(),
                            headers={"vmware-api-session-id": session_id, "Content-Type": "application/json"})
    _check(status, data, f"add the Native Key Provider '{name}'")


def delete(decision, session_id: str, name: str) -> None:
    """Remove a key provider (vSphere Automation API, Providers.delete)."""
    status, data = _request(decision, "DELETE", f"{PROVIDERS_PATH}/{quote(name, safe='')}",
                            headers={"vmware-api-session-id": session_id})
    _check(status, data, f"remove the key provider '{name}'")


def export(decision, session_id: str, provider: str, password: str | None) -> bytes:
    """The backup file of a Native Key Provider. `password` protects the file (recommended)."""
    body: dict[str, str] = {"provider": provider}
    if password:
        body["password"] = password
    status, data = _request(decision, "POST", EXPORT_PATH, body=json.dumps(body).encode(),
                            headers={"vmware-api-session-id": session_id, "Content-Type": "application/json"})
    if status in (401, 403):
        raise DeploymentError(f"vCenter refused the backup: {_api_message(data)}",
                              hint=f"This needs an administrator (privilege {PRIVILEGE}).")
    if status >= 300:
        raise DeploymentError(f"vCenter could not back up '{provider}': HTTP {status} {_api_message(data)}")
    result = json.loads(data)
    location = (result or {}).get("location") if isinstance(result, dict) else None
    if not location or not location.get("url"):
        log.debug("unexpected export response keys: %s", list(result) if isinstance(result, dict) else type(result))
        raise DeploymentError("vCenter's answer to the backup request had no download location.",
                              hint="Please report this with the log file (`-v`); it lists what vCenter sent.")
    token = ((location.get("download_token") or {}).get("token")) or ""
    if token:
        register_secret(token)
    url = urlsplit(location["url"])
    if url.hostname and url.hostname.lower() != decision.host.lower():
        # The case this command exists for: vCenter named its own download link after "localhost" (or another
        # name this computer may not reach). The file is on the vCenter we are connected to, so ask that.
        log.info("vCenter's download link names %s; downloading from %s instead", url.hostname, decision.host)
    path = url.path + (f"?{url.query}" if url.query else "")
    headers = {"Authorization": f"Bearer {token}"} if token else {"vmware-api-session-id": session_id}
    status, data = _request(decision, "POST", path, headers={**headers, "Accept": "*/*"}, timeout=120)
    if status >= 300:
        raise DeploymentError(f"Downloading the backup failed: HTTP {status} {_api_message(data)}")
    if not data:
        raise DeploymentError("vCenter returned an empty backup file.")
    return data



# ---------------------------------------------------------------------------- interactive flows (CLI and deploy)
def require_manageable(conn) -> None:
    """Key provider changes need vCenter and a password sign-in (for the API session)."""
    from .errors import ConfigError

    if not conn.is_vcenter:
        from .crypto import no_vtpm_on_esxi

        raise ConfigError("Key providers belong to vCenter; this is an ESXi host.", hint=no_vtpm_on_esxi(conn))
    if not conn.rest_credentials:
        raise AuthError("This needs a profile that signs in with a password.",
                        hint="It opens a vCenter API session with the same user and password; federated sign-in "
                             "is not supported for it yet.")


def show_table(provs: list[Provider]) -> None:
    from rich.markup import escape as esc
    from rich.table import Table

    from .ui import console

    t = Table("Key provider", "Type", "Default", "Backed up", "Hosts need a TPM")
    for k in provs:
        backed = {True: "yes", False: "[yellow]NO: vCenter does not use it yet[/]", None: "-"}[k.backed_up]
        tpm = {True: "yes", False: "no", None: "-"}[k.tpm_required]
        t.add_row(esc(k.name), k.kind, "yes" if k.default else "", backed, tpm)
    console.print(t)


def backup_flow(conn, p, name: str, out=None, no_password: bool = False) -> None:
    """Export `name` to a .p12 file (vCenter only uses a Native Key Provider after this)."""
    import os
    from datetime import date
    from pathlib import Path

    from rich.markup import escape as esc

    from .errors import ConfigError
    from .ui import console, warn

    default_target = Path.cwd() / f"{name}-{date.today().isoformat()}.p12"
    target = Path(out) if out else Path(p.text("Save the backup file to:", default=str(default_target),
                                              field_name="--out", assume_default=True)).expanduser()
    if target.exists():
        raise ConfigError(f"{target} already exists; nothing was overwritten.", hint="Choose another file with --out.")
    password = None
    if not no_password:
        password = os.environ.get("VMDEPLOY_BACKUP_PASSWORD")
        if password is None:
            console.print("The backup file is protected with a password. Without the file and its password, VMs "
                          "with a virtual TPM cannot be recovered if vCenter is lost.")
            while True:
                password = p.password("Password for the backup file:",
                                      field_name="VMDEPLOY_BACKUP_PASSWORD (or --no-password)")
                if p.password("Repeat it:") == password:
                    break
                warn("The passwords do not match; try again.")
        register_secret(password)
    # The file is created (empty, readable by this user only) before the export: vCenter counts the export as
    # the backup, so if the file could not be written afterwards, the only copy of the backup would be lost.
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise ConfigError(f"Cannot create the folder {target.parent}: {e.strerror or e}. Nothing was exported.",
                          hint="Choose a file in a folder you can write to with --out.") from e
    try:
        fd = _create_private(target)
    except FileExistsError:
        raise ConfigError(f"{target} already exists; nothing was overwritten.",
                          hint="Choose another file with --out.") from None
    except OSError as e:
        raise ConfigError(f"Cannot create {target}: {e.strerror or e}. Nothing was exported.",
                          hint="Choose a file in a folder you can write to with --out.") from e
    data: bytes | None = None
    try:
        with os.fdopen(fd, "wb") as f:
            user, pwd = conn.rest_credentials
            with console.status(f"Backing up {name}..."), RestSession(conn.decision, user, pwd) as sid:
                data = export(conn.decision, sid, name, password)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException as e:
        target.unlink(missing_ok=True)  # nothing, or not all of it, was written: no empty or partial file is left
        if data is None:  # not exported: nothing was lost
            raise
        # vCenter already counts this export as the backup: its bytes must not be lost with the file.
        rescued = _rescue_backup(data, name)
        if rescued is None:
            raise DeploymentError(
                f"vCenter exported the backup of {name}, but it could not be written to {target} ({e}). vCenter now "
                "lists the key provider as backed up, although no backup file exists.",
                hint="Make room or choose another folder, then run `vmdeploy keyprovider backup` again (a key provider "
                     "can be exported again), or back it up in the vSphere Client: Configure > Security > Key "
                     "Providers > Back up.") from e
        if not isinstance(e, Exception):
            raise  # e.g. Ctrl+C while writing: the backup is safe (logged); stop as asked
        # Not where it was asked for: an error (a script must not take the backup to be at --out), but saved.
        raise DeploymentError(
            f"The backup of {name} could not be written to {target} ({e}). It was saved to {rescued} instead "
            f"({len(data):,} bytes{', password-protected' if password else ''}), and vCenter counts it as backed up.",
            hint="Move that file to where you keep backups, outside this vCenter, together with its password.") from e
    console.print(f"[green]Saved the backup of {esc(name)} to {esc(str(target))} "
                  f"({len(data):,} bytes{', password-protected' if password else ''}).[/]")
    now = next((k for k in native_providers(conn) if k.name == name), None)
    if now and now.backed_up:
        console.print("[green]vCenter now shows it as backed up: it can be used (e.g. for a virtual TPM).[/]")
    else:
        console.print("[yellow]vCenter does not show it as backed up yet. Refresh Configure > Security > Key Providers "
                      "in the vSphere Client in a minute.[/]")
    console.print("Keep this file and its password outside this vCenter (e.g. in your password manager). To restore: "
                  "vSphere Client > Configure > Security > Key Providers > Restore.")


def _create_private(path) -> int:
    """Create `path` for writing, readable by this user only. An existing file (or a link planted there) is never
    opened: FileExistsError."""
    import os

    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)


def _rescue_backup(data: bytes, name: str):
    """Save an exported backup that could not be written where asked into vmdeploy's own folder, readable by this
    user only: vCenter already counts the export as the backup, so its only copy must not be lost. Returns the path,
    or None when it cannot be written there either."""
    import os
    from datetime import datetime

    from .paths import config_dir

    path = None
    try:
        folder = config_dir() / "keyprovider-backups"
        folder.mkdir(parents=True, exist_ok=True)
        stem = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.")[:60] or "key-provider"
        path = folder / f"{stem}-{datetime.now():%Y%m%d-%H%M%S-%f}.p12"
        fd = _create_private(path)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        log.warning("Key provider backup of %s saved to %s (it could not be written where asked)", name, path)
        return path
    except OSError as e:
        log.warning("Could not save the key provider backup to %s either: %s", path or "vmdeploy's folder", e)
        return None


def add_flow(conn, p, *, name: str | None = None, tpm_required: bool = False, make_default: bool | None = None,
             backup: bool | None = None, out=None, no_password: bool = False) -> str:
    """Plan, confirm, add a Native Key Provider, make it the default, back it up. Returns its name."""
    from rich.markup import escape as esc

    from .errors import ConfigError, UserAborted
    from .ui import console

    provs = providers(conn)
    if provs:
        show_table(provs)
    taken = {k.name for k in provs}
    new = name or p.text("Name of the new Native Key Provider:", default="vmdeploy-nkp", field_name="--name",
                         assume_default=True,
                         validate=lambda s: ("letters, digits, . _ -" if not NAME_RE.fullmatch(s)
                                             else "that name is taken" if s in taken else True))
    if not NAME_RE.fullmatch(new):
        raise ConfigError(f"'{new}' is not a valid name (letters, digits, '.', '_' and '-').")
    if new in taken:
        raise ConfigError(f"A key provider named '{new}' already exists.",
                          hint="Back it up with `vmdeploy keyprovider backup` if it is not backed up yet.")
    hosts = host_tpms(conn)
    if hosts and not any(cluster for _h, cluster, _t, _d in hosts):
        from .crypto import NEEDS_CLUSTER
        from .ui import warn

        warn("None of this vCenter's hosts is in a cluster, so no VM can use a Native Key Provider until one is. "
             + NEEDS_CLUSTER)
    make_default = make_default if make_default is not None else not any(k.default for k in provs)
    console.print("[bold]Plan: nothing has been changed yet[/]")
    console.print(f"  Add Native Key Provider [bold]{esc(new)}[/] "
                  f"({'only hosts with a physical TPM 2.0' if tpm_required else 'usable on every host'})")
    if make_default:
        console.print("  Make it vCenter's default key provider (new virtual TPMs get their keys from it)")
    if backup is not False:
        console.print("  Back it up to a file on this computer (vCenter only uses it after a backup)")
    if not p.confirm("Add it?", default=True, assume=True):
        raise UserAborted("Nothing was changed.")
    user, pwd = conn.rest_credentials
    with console.status(f"Adding {new}..."), RestSession(conn.decision, user, pwd) as sid:
        create(conn.decision, sid, new, tpm_required=tpm_required)
    console.print(f"[green]Added the Native Key Provider {esc(new)}.[/]")
    if make_default:
        set_default(conn, new)
        console.print(f"[green]{esc(new)} is now the default key provider.[/]")
    if backup is not False:
        backup_flow(conn, p, new, out, no_password)
    else:
        console.print(f"[yellow]Not backed up yet: vCenter does not use it until you run "
                      f"`vmdeploy keyprovider backup --provider {esc(new)}`.[/]")
    return new
