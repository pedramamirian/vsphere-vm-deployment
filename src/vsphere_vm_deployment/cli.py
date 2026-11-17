"""Command-line interface (`vmdeploy`)."""

from __future__ import annotations

import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.markup import escape as esc
from rich.table import Table
from rich.text import Text

from . import __version__, credentials, crypto
from .errors import ConfigError, DeploymentError, UserAborted, VmDeployError
from .logsetup import FILE_ONLY, current_log_file, setup_logging
from .profiles import AUTH_DESCRIPTIONS, AuthMethod, OAuthSettings, Profile, ProfileStore, profile_name_error
from .ui import Prompter, console, error, warn
from .units import local_date

log = logging.getLogger(__name__)

app = typer.Typer(no_args_is_help=True, rich_markup_mode="rich", add_completion=False,
                  help="Deploy VMs to vCenter Server / ESXi from OVA, OVF or ISO images, entirely from the terminal.")
profile_app = typer.Typer(no_args_is_help=True, help="Manage connection profiles (one per vCenter / ESXi host).")
trust_app = typer.Typer(no_args_is_help=True, help="Manage trusted TLS certificates.")
images_app = typer.Typer(no_args_is_help=True, help="Local images, presets and the download cache.")
app.add_typer(profile_app, name="profile")
app.add_typer(trust_app, name="trust")
app.add_typer(images_app, name="images")
access_app = typer.Typer(no_args_is_help=True, help="Create or remove a least-privilege deploy account "
                                                    "(run by an administrator).")
app.add_typer(access_app, name="access")
keyprovider_app = typer.Typer(no_args_is_help=True, help="vCenter key providers (needed for a virtual TPM, "
                                                         "e.g. Windows 11).")
app.add_typer(keyprovider_app, name="keyprovider")

_state = {"verbose": 0, "json": False}

ProfileOpt = Annotated[str | None, typer.Option("--profile", "-p", help="Connection profile to use.")]
YesOpt = Annotated[bool, typer.Option("--yes", "-y", help="Non-interactive: take answers from the manifest/flags, "
                                                          "fail if anything is missing.")]
FingerprintOpt = Annotated[list[str] | None, typer.Option(
    "--trust-fingerprint", help="Accept a certificate with this SHA-256 fingerprint (verify it out-of-band first).")]


def _version_cb(value: bool) -> None:
    if value:
        console.print(f"vsphere-vm-deployment {__version__}")
        raise typer.Exit()


@app.callback()
def _main(verbose: Annotated[int, typer.Option("--verbose", "-v", count=True,
                                               help="-v shows each step's details, -vv adds API debug output.")] = 0,
          version: Annotated[bool, typer.Option("--version", help="Show the version and exit.", is_eager=True,
                                                callback=_version_cb)] = False) -> None:
    _state["verbose"] = verbose
    setup_logging(verbose)
    log.info("vsphere-vm-deployment %s, Python %s, args %s", __version__, sys.version.split()[0], sys.argv[1:])


# ------------------------------------------------------------------------------------------------ helpers
def _resolve_profile(name: str | None, prompter: Prompter, manifest_profile: str | None = None) -> Profile:
    store = ProfileStore()
    name = name or manifest_profile or store.default_name()
    if name:
        return store.get(name)
    if not prompter.interactive:
        raise ConfigError("No connection profile configured.",
                          hint="Create one with `vmdeploy profile add` or pass --profile.")
    console.print("[bold]No connection profile yet - let's create one.[/]")
    return _profile_wizard(prompter, store)


def _default_profile_name(host: str) -> str:
    """The suggested profile name: a host name's first label (vcsa.example.com -> vcsa), or a whole IP address
    with '-' separators (192.0.2.5 -> 192-0-2-5; its first part alone, "192", would say nothing). IPv6 keeps all
    eight groups (2001:db8::1 -> 2001-db8-0-0-0-0-0-1): two addresses never share a name, which `profile add
    --yes` would take as replacing the other server's profile."""
    import ipaddress

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:  # lower case: VCSA.example.com is the same server as vcsa.example.com, and so its profile
        return re.sub(r"[^a-z0-9_-]", "-", host.split(".")[0].lower())
    if ip.version == 4:
        return str(ip).replace(".", "-")
    groups = "-".join(f"{int(g, 16):x}" for g in ipaddress.IPv6Address(int(ip)).exploded.split(":"))
    scope = getattr(ip, "scope_id", None)
    return groups + (f"-{re.sub(r'[^a-z0-9]', '-', scope.lower())}" if scope else "")


def _profile_wizard(p: Prompter, store: ProfileStore, **given) -> Profile:
    with p.section("New connection profile"):
        host = given.get("host") or p.text("vCenter Server or ESXi host (FQDN or IP):", field_name="--host",
                                           validate=lambda s: bool(s.strip()) or "Required")
        host = host.strip()
        port = given.get("port") or 443
        m = re.fullmatch(r"(\[[^\]]+\]|[^:\[\]]+):(\d+)", host)  # host:port or [ipv6]:port
        if m:
            host, port = m.group(1).strip("[]"), int(m.group(2))
        elif re.fullmatch(r"\[[^\]]+\]", host):  # [ipv6] without a port: stripped here too for the default
            host = host[1:-1]                    # profile name below (Profile strips them as well)
        name = given.get("name") or p.text("Profile name:", default=_default_profile_name(host),
                                           field_name="--name", assume_default=True,
                                           validate=lambda s: profile_name_error(s.strip()) or True)
        name = name.strip()
        if profile_name_error(name):
            raise ConfigError(f"Invalid profile name '{name}': {profile_name_error(name)}.")
        auth = given.get("auth") or p.select("Sign-in method:", [(AUTH_DESCRIPTIONS[m], m) for m in AuthMethod],
                                             default=AuthMethod.PASSWORD, field_name="--auth", assume_default=True)
        auth = AuthMethod(auth)
        oauth = None
        if auth in (AuthMethod.OAUTH_PASSWORD, AuthMethod.OAUTH_CLIENT_CREDENTIALS):
            console.print("[dim]Federated sign-in needs your identity provider's OAuth token endpoint and the client ID "
                          "registered for vCenter. See docs/authentication.md.[/]")
            oauth = OAuthSettings(
                token_url=given.get("token_url") or p.text("OAuth token endpoint URL:", field_name="--token-url"),
                client_id=given.get("client_id") or p.text("OAuth client ID:", field_name="--client-id"),
                scope=given.get("scope") or p.text("Scope:", default="openid", assume_default=True))
        username = given.get("username")
        if username is None and auth in (AuthMethod.PASSWORD, AuthMethod.OAUTH_PASSWORD):
            username = p.text("Username (leave empty to be asked every time):", default="", assume_default=True) or None
        remember = given.get("remember")
        if auth in (AuthMethod.PASSWORD, AuthMethod.OAUTH_PASSWORD) and not username:
            # A saved password belongs to one account; with the username asked each time there is none to save.
            if remember:
                warn("A password is saved only for a profile with a username; it will be asked for every time.")
            remember = False
        if remember is None and auth != AuthMethod.OAUTH_TOKEN:
            if credentials.keychain_available():
                remember = p.confirm("Save the password / client secret in the OS keychain after the first "
                                     "successful sign-in?", default=False, assume=False)
            else:
                remember = False
                warn("No OS keychain is available, so the password will be asked for every time.")
        profile = Profile(name=name, host=host, port=port, auth=auth, username=username, oauth=oauth,
                          remember_secret=bool(remember))
        old = next((pr for pr in store.list() if pr.name == name), None)
        if old is not None:
            another = ((old.host, old.port) != (profile.host, profile.port)
                       or bool(old.username and profile.username and old.username.lower() != profile.username.lower()))
            if another and not p.interactive and not given.get("name"):
                # --yes chose this name by default (vcsa.site-a and vcsa.site-b are both "vcsa"): never replace the
                # profile of another server or account, and delete its saved password, without --name asking for it.
                # Adding a user to a profile that had none, or changing how one signs in, is an update.
                raise ConfigError(f"A profile named '{name}' already exists for another server or account "
                                  f"({old.username or 'no user'} at {old.endpoint}).",
                                  hint="Choose a name for this one with --name.")
            if not p.confirm(f"A profile named '{name}' already exists ({old.endpoint}). Replace it?", default=False,
                             assume=True, field_name="--name"):
                raise UserAborted("Nothing was changed.", hint="Choose another name with --name.")
        if old is not None and old.remember_secret and (
                not profile.remember_secret or credentials.binding(old) != credentials.binding(profile)):
            # A saved secret is bound to its server, account and token endpoint (credentials.binding): a profile
            # for another target can never read it. Deleted when the target changes or the keychain is turned off.
            dropped, ok = credentials.delete_secrets(old)
            if dropped:
                p.record("Keychain", f"deleted the {' and '.join(dropped)} saved for the old '{name}'")
            if not ok:
                _warn_secret_left(old)
        store.save(profile, make_default=given.get("make_default", False))
        p.record("Profile saved", f"{profile.name} -> {profile.endpoint} ({auth.value})")
    return profile


def _run(fn):
    """Run a command body with consistent error reporting and exit codes."""
    try:
        return fn()
    # Every outcome is also written to the log file, so a log attached to a bug report shows how the run ended.
    except UserAborted as e:
        log.warning("Stopped: %s", e.message, extra=FILE_ONLY)
        # As text: messages name "[datastore] paths" and [IPv6] servers, which Rich markup would swallow.
        console.print(Text(e.message, style="yellow"))
        if e.hint:
            console.print(Text(f"  hint: {e.hint}"))
        raise typer.Exit(e.exit_code) from None
    except ValidationError as e:
        details = "; ".join(f"{'.'.join(str(x) for x in err['loc']) or 'value'}: {err['msg']}" for err in e.errors())
        log.error("Invalid value: %s", details, extra=FILE_ONLY)
        error(f"Invalid value: {details}")
        raise typer.Exit(2) from None
    except VmDeployError as e:
        log.error("%s%s", e.message, f" (hint: {e.hint})" if e.hint else "", extra=FILE_ONLY)
        error(e.message, e.hint)
        lf = current_log_file()
        if lf:
            console.print(f"[dim]Log: {lf}[/]")
        raise typer.Exit(e.exit_code) from None
    except KeyboardInterrupt:
        log.warning("Cancelled with Ctrl-C", extra=FILE_ONLY)
        console.print("[yellow]Cancelled.[/]")
        raise typer.Exit(130) from None
    except typer.Exit:
        raise
    except Exception as e:  # noqa: BLE001
        log.exception("Unexpected error")
        error(f"Unexpected error: {e}", "This is probably a bug. Please open an issue and attach the log file "
                                         "(secrets are removed from it automatically).")
        lf = current_log_file()
        if lf:
            console.print(f"[dim]Log: {lf}[/]")
        raise typer.Exit(1) from None


def _connect(profile_name: str | None, yes: bool, fingerprints: list[str] | None):
    from .connection import connect
    from .trust import TrustManager

    p = Prompter(interactive=not yes)
    profile = _resolve_profile(profile_name, p)
    trust = TrustManager(prompter=p, assume_fingerprints=fingerprints or [])
    return connect(profile, p, trust), p


# ------------------------------------------------------------------------------------------------ deploy
@app.command()
def deploy(
    manifest: Annotated[Path | None, typer.Option("--file", "-f", help="Deployment manifest (YAML).")] = None,
    local: Annotated[str | None, typer.Option("--local", help="Image file in the images/ folder (or a path).",
                                              show_default=False)] = None,
    local_pick: Annotated[bool, typer.Option("--pick-local", help="Choose from the files in images/.")] = False,
    url: Annotated[str | None, typer.Option("--url", help="Download an .ova or .iso from this URL.")] = None,
    preset: Annotated[str | None, typer.Option("--preset", help="Named image, e.g. ubuntu-lts.")] = None,
    datastore_file: Annotated[str | None, typer.Option("--datastore-file", help='ISO, OVA or OVF already on a datastore: '
                                                       '"[datastore1] folder/file.iso".')] = None,
    datastore_iso: Annotated[str | None, typer.Option("--datastore-iso",
                                                      help='ISO already on a datastore: "\\[datastore1] iso/x.iso".')] = None,
    sha256: Annotated[str | None, typer.Option("--sha256", help="Expected SHA-256 of the image.")] = None,
    profile: ProfileOpt = None,
    yes: YesOpt = False,
    replace: Annotated[bool, typer.Option("--replace", help="Delete and re-create a VM with the same name.")] = False,
    trust_fingerprint: FingerprintOpt = None,
    json_out: Annotated[bool, typer.Option("--json", help="Print a JSON summary on stdout when done.")] = False,
) -> None:
    """Deploy a VM: sign in, discover, pick the image, answer what is missing, review, deploy."""
    from .deploy import Deployment, DeployOptions
    from .manifest import load_manifest
    from .transfer import check_sha256

    def body():
        sha = check_sha256(sha256)  # a typo is refused before anything is read or downloaded
        sources = [(flag, kind, v) for flag, kind, v in (
            ("--local", "local", local), ("--url", "url", url), ("--preset", "preset", preset),
            ("--datastore-iso", "datastore", datastore_iso), ("--datastore-file", "datastore", datastore_file)) if v]
        if local_pick:
            sources.append(("--pick-local", "local", ""))
        if len(sources) > 1:
            raise ConfigError(f"Use only one image source; given: {', '.join(f for f, _, _ in sources)}.",
                              hint="Choose one of --local, --pick-local, --url, --preset, --datastore-iso, "
                                   "--datastore-file.")
        m = load_manifest(manifest)
        kind, value = (sources[0][1], sources[0][2]) if sources else (None, None)
        p = Prompter(interactive=not yes)
        prof = _resolve_profile(profile, p, m.profile)
        result = Deployment(DeployOptions(profile=prof, manifest=m, image_kind=kind, image_value=value or None,
                                          sha256=sha, interactive=not yes, replace=replace,
                                          trust_fingerprints=trust_fingerprint or [])).run()
        _print_result(result, json_out)

    _run(body)


def _print_result(result: dict, json_out: bool) -> None:
    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_row("[bold]VM", esc(f"{result['vm']} ({result['moid']})"))
    t.add_row("[bold]Where", esc(f"{result['datacenter']}, {result['target']}, datastore {result['datastore']}"))
    if result.get("ip"):
        t.add_row("[bold]IP address", esc(result["ip"]))
    console.print(t)
    if result.get("iso_install") and result.get("powered_on") and result.get("windows"):
        console.print("\n[bold green]Deployment complete.[/] Windows Setup is waiting in the VM console (press a key "
                      "when it says 'Press any key to boot from CD or DVD'). Open the console to install Windows and "
                      "enter your product key or activate it later. Afterwards install VMware Tools "
                      "(VM > Guest OS > Install VMware Tools) for the best drivers:")
    elif result.get("iso_install") and result.get("powered_on"):
        console.print("\n[bold green]Deployment complete.[/] The VM has booted from the ISO and the operating system "
                      "installer is waiting in the VM console. Open the console to install the OS:")
    elif not result.get("powered_on"):
        console.print("\n[bold green]Deployment complete.[/] The VM is powered off. Power it on and open its console "
                      "when you are ready:")
    elif result.get("guest_user"):  # cloud-init set it up: ready to use
        console.print("\n[bold green]Deployment complete.[/] The VM is ready. Its console:")
    else:
        console.print("\n[bold green]Deployment complete.[/] Next step: open the VM's console to finish setting it "
                      "up or to use it:")
    console.print(f"  {esc(result['console_url'])}")  # an IPv6 host is in [brackets]: not markup
    client = ("In the ESXi Host Client choose 'Console' on that page" if result.get("on_esxi") else
              "In the vSphere Client choose 'Launch Web Console' on that page")
    console.print(f"  [dim]({client}. If the link does not open the VM directly, search for "
                  f"'{esc(result['vm'])}'.)[/]")
    if result.get("ip"):
        console.print(f"  Or connect with SSH: [bold]ssh {esc(result.get('guest_user') or '<user>')}@"
                      f"{esc(result['ip'])}[/]")
    lf = current_log_file()
    if lf:
        console.print(f"[dim]Log: {lf}[/]")
    if json_out:
        sys.stdout.write(json.dumps(result, indent=2) + "\n")


# ------------------------------------------------------------------------------------------------ profiles
@profile_app.command("add")
def profile_add(
    host: Annotated[str | None, typer.Option(help="vCenter / ESXi FQDN or IP.")] = None,
    name: Annotated[str | None, typer.Option(help="Profile name.")] = None,
    port: Annotated[int, typer.Option(help="HTTPS port.")] = 443,
    auth: Annotated[AuthMethod | None, typer.Option(help="Sign-in method.")] = None,
    username: Annotated[str | None, typer.Option(help="Username (optional).")] = None,
    token_url: Annotated[str | None, typer.Option(help="OAuth token endpoint (federated sign-in).")] = None,
    client_id: Annotated[str | None, typer.Option(help="OAuth client ID (federated sign-in).")] = None,
    remember: Annotated[bool | None, typer.Option("--remember/--no-remember",
                                                  help="Save the secret in the OS keychain.")] = None,
    default: Annotated[bool, typer.Option("--default", help="Make this the default profile.")] = False,
    yes: YesOpt = False,
) -> None:
    """Create a connection profile."""
    _run(lambda: _profile_wizard(Prompter(not yes), ProfileStore(), host=host, name=name, port=port, auth=auth,
                                 username=username, token_url=token_url, client_id=client_id, remember=remember,
                                 make_default=default))


@profile_app.command("list")
def profile_list() -> None:
    """Show all profiles."""
    def body():
        store = ProfileStore()
        default = store.default_name()
        t = Table("", "Name", "Endpoint", "Sign-in", "User", "Keychain")
        for pr in store.list():  # as text: "[fd00::10]:443" is not a style tag
            t.add_row("*" if pr.name == default else "", esc(pr.name), esc(pr.endpoint), pr.auth.value,
                      esc(pr.username or ""), "yes" if pr.remember_secret else "no")
        console.print(t if store.list() else "No profiles yet. Create one with `vmdeploy profile add`.")
    _run(body)


@profile_app.command("remove")
def profile_remove(name: str) -> None:
    """Delete a profile and its saved secrets."""
    def body():
        store = ProfileStore()
        try:
            profile = store.get(name)  # "No profile named ..." with the list of profiles
        except ValidationError:  # hand-edited, or written by another version: removed all the same
            profile = None
        ok = credentials.delete_secrets(profile)[1] if profile is not None else True
        store.remove(name)
        console.print(f"Removed profile '{name}'.")
        if profile is None:
            warn(f"The profile could not be read, so a password or client secret saved for it was not looked up. "
                 f"If one was saved, delete it in the OS keychain: service '{credentials.SERVICE}', an entry "
                 f"starting with '{name}:'.")
        elif not ok:
            _warn_secret_left(profile)
    _run(body)


def _warn_secret_left(profile: Profile) -> None:
    """A saved secret could not be deleted (keychain locked or unavailable). It is bound to the profile's server and
    account, so no profile for another server or account can read it; say where it is, to delete by hand."""
    entries = " and ".join(f"'{credentials.entry_name(profile, kind)}'" for kind in credentials.KINDS)
    warn(f"A password or client secret saved for '{profile.name}' ({profile.endpoint}) could not be removed from the "
         f"OS keychain (is it locked?). It is bound to that server and account: no profile for another server or "
         f"account can read it. Delete it later in the keychain: service '{credentials.SERVICE}', entry {entries}.")


@profile_app.command("default")
def profile_default(name: str) -> None:
    """Set the default profile."""
    _run(lambda: (ProfileStore().set_default(name), console.print(f"Default profile: {name}")))


@app.command("forget-secret")
def forget_secret(name: Annotated[str, typer.Argument(help="Profile name")]) -> None:
    """Remove a saved password / client secret from the OS keychain."""
    def body():
        profile = ProfileStore().get(name)  # secrets are saved for a profile's server and account
        removed, ok = credentials.delete_secrets(profile)
        if removed:
            console.print(f"Removed: {', '.join(removed)}")
        if not ok:
            warn("The OS keychain could not be changed (is it locked?): a saved secret may still be there. Unlock "
                 "it and run this command again.")
        elif not removed:
            console.print("Nothing saved for that profile.")
    _run(body)


# ------------------------------------------------------------------------------------------------ trust
@trust_app.command("list")
def trust_list() -> None:
    """Show pinned certificates and trusted vCenter root CAs."""
    from .trust import CertInfo, TrustStore, shown

    data = TrustStore().entries()
    t = Table("Endpoint", "Subject", "SHA-256", "Expires", title="Pinned certificates")
    for ep, e in data["pins"].items():
        t.add_row(esc(ep), shown(e["subject"]), CertInfo.pretty(e["sha256"])[:47] + "...", e["not_after"][:10])
    console.print(t)
    t2 = Table("Source", "Certificates", "Added", title="Trusted vCenter root CAs")
    for src, e in data["cas"].items():
        t2.add_row(src, str(len(e["pems"])), local_date(e["added"]))
    console.print(t2)


@trust_app.command("add")
def trust_add(host: str, port: Annotated[int, typer.Option(help="HTTPS port.")] = 443,
              vcenter_ca: Annotated[bool, typer.Option("--vcenter-ca", help="Also trust vCenter's root CA bundle "
                                                       "(from /certs/download.zip); covers its ESXi hosts.")] = False) -> None:
    """Optional: check and trust a certificate ahead of time. Normally you are asked during the first run."""
    from .trust import TrustManager, shown

    def body():
        tm = TrustManager(prompter=Prompter(True))
        if vcenter_ca:
            n = tm.trust_vcenter_ca(host, port)
            console.print(f"Trusted {n} root CA certificate(s) from {host}:{port}.")
        else:
            d = tm.decision(host, port)
            console.print(f"{host}:{port}: {'trusted by your system' if d.mode == 'validated' else 'pinned'} "
                          f"({shown(d.cert.subject)})")
    _run(body)


@trust_app.command("remove")
def trust_remove(endpoint: Annotated[str, typer.Argument(help="host:port, or the source of a trusted CA")]) -> None:
    """Forget a pinned certificate or trusted CA."""
    from .trust import TrustStore

    console.print("Removed." if TrustStore().remove(endpoint) else "Nothing matched.")


# ------------------------------------------------------------------------------------------------ inventory / doctor
def _clock_check(conn) -> str | None:
    """Compare the server's clock with this computer's. Sign-in tokens (SSO, federation) fail when clocks
    drift too far apart, and task times in vCenter no longer match local logs."""
    from datetime import UTC, datetime

    try:
        server = conn.si.CurrentTime()
    except Exception:  # noqa: BLE001
        return None
    if server.tzinfo is None:
        server = server.replace(tzinfo=UTC)
    skew = (server - datetime.now(UTC)).total_seconds()
    if abs(skew) < 60:
        return "in sync with this computer"
    direction = "behind" if skew < 0 else "ahead of"
    amount = f"{abs(skew) / 60:.0f} min" if abs(skew) >= 90 else f"{abs(skew):.0f} s"
    warn(f"The server's clock is {amount} {direction} this computer's. Check NTP on the server (and this "
         "computer): large differences break single sign-on and make vCenter task times disagree with logs.")
    return f"[yellow]{amount} {direction} this computer[/]"


# ------------------------------------------------------------------------------------------------ access
def _check_admin(conn) -> None:
    """Stop early, before any question, if the signed-in account cannot manage roles and permissions."""
    from . import privileges

    missing = privileges.check(conn, {"access_admin": conn.content.rootFolder})
    if missing is None:
        warn("This server cannot report privileges; continuing, and the server will refuse what is not allowed.")
        return
    ids = [i for i in missing.get("access_admin", []) if not (conn.is_vcenter and i.startswith("Host.Local."))]
    if ids:
        raise ConfigError(f"The signed-in account ({conn.user}) cannot manage roles, permissions or users "
                          f"(missing: {', '.join(ids)}).",
                          hint="Run this with an administrator's profile, e.g. -p <admin-profile>. The deploy account "
                               "itself never needs these privileges.")


def _check_folder_admin(conn, vm_folder) -> None:
    """Creating and labelling a folder needs a few more administrator privileges; check before the plan."""
    from . import privileges

    missing = privileges.check(conn, {"access_admin_folder": vm_folder,
                                      "access_admin_label": conn.content.rootFolder}) or {}
    ids = [i for group in missing.values() for i in group]
    if ids:
        raise ConfigError(f"The signed-in account cannot create and label folders (missing: {', '.join(ids)}).",
                          hint="Choose an existing folder with --folder instead, or sign in as an administrator.")


def _ask_image_datastores(p: Prompter, conn, dc, ds_names: list[str], given: list[str] | None):
    """(copy-rights datastores, see-only datastores) for the deploy account's image picker.

    Default ("all"): the account sees every datastore (Browse), and gets copy rights (Browse + Low level file
    operations) only where ISO/OVA files are found now. Images added elsewhere later are still visible and are
    then copied through the deploying computer."""
    from . import isolib

    total = len(dc.hosts)
    others = sorted((d for d in dc.datastores.values() if d.usable and d.name not in ds_names),
                    key=lambda d: (d.where(total), d.display_name.lower()))
    if not others:
        return [], []
    with console.status("Looking for ISO and OVA files on all datastores..."):
        holding = sorted({i.datastore for i in isolib.find_images(dc) if i.datastore not in ds_names})
    if holding:
        console.print("ISO/OVA files found on: " + ", ".join(dc.datastores[n].host_label(total).split("  (")[0]
                                                            for n in holding))
    else:
        console.print("[dim]No ISO/OVA files found on the other datastores right now.[/]")
    console.print("[dim]Already included as deploy datastore(s): "
                  f"{', '.join(dc.datastores[n].display_name for n in ds_names)}.[/]")
    every = [d.name for d in others]
    choice = None
    names = list(given or [])
    if names and [n.lower() for n in names] == ["all"]:
        choice = "all"
    elif names and [n.lower() for n in names] == ["none"]:
        choice = "none"
    elif names:
        by_display = {d.display_name: d.name for d in dc.datastores.values()}
        names = [by_display.get(n, n) for n in names]
        unknown = [n for n in names if n not in dc.datastores]
        if unknown:
            raise ConfigError(f"--image-datastore not found: {', '.join(unknown)}",
                              hint=f"Use all, none, or datastore names: {', '.join(sorted(dc.datastores))}")
        return [n for n in names if n not in ds_names], []
    if choice is None:
        choice = p.select("Which datastores may the account find images on?", [
            (f"All {len(every)} datastores: see every image; copy rights only where images are now "
             f"({len(holding)}) (recommended)", "all"),
            ("Choose datastores (copy rights on the ones you tick)", "choose"),
            (f"None: only the datastore(s) it deploys to "
             f"({', '.join(dc.datastores[n].display_name for n in ds_names)}); images on other datastores won't be "
             "visible", "none"),
        ], default="all", field_name="--image-datastore", assume_default=True, auto_single=False)
    if choice == "all":
        return holding, [n for n in every if n not in holding]
    if choice == "none":
        return [], []
    picked = p.checkbox("Datastores the account may find and copy images from:",
                        [(d.host_label(total) + ("  [has images]" if d.name in holding else ""), d.name)
                         for d in others], field_name="--image-datastore", minimum=0)
    return picked, []


def _pick(p: Prompter, given: str | None, question: str, choices: list[tuple[str, str]], flag: str) -> str:
    """Use a value from the command line if given (checked against the choices), otherwise ask."""
    if given is not None:
        values = [v for _, v in choices]
        if given not in values:
            raise ConfigError(f"{flag} '{given}' not found.", hint=f"Available: {', '.join(values) or 'none'}")
        return given
    return p.select(question, choices, field_name=flag)


def _pick_many(p: Prompter, given: list[str] | None, question: str, choices: list[tuple[str, str]],
               flag: str) -> list[str]:
    if given:
        values = [v for _, v in choices]
        unknown = [g for g in given if g not in values]
        if unknown:
            raise ConfigError(f"{flag} not found or not usable from the chosen cluster/host: {', '.join(unknown)}",
                              hint=f"Available: {', '.join(values) or 'none'}")
        return list(given)
    if len(choices) == 1:  # taken without asking: say so
        p.record(question.rstrip(":"), f"{choices[0][0]} (the only one available)")
    return p.checkbox(question, choices, field_name=flag)


def _upn(user: str) -> str:
    """The sign-in name for a profile: user@domain, whichever form was typed."""
    if "\\" in user:
        domain, name = user.split("\\", 1)
        return f"{name}@{domain.lower()}"
    return user


@access_app.command("setup")
def access_setup(
    profile: ProfileOpt = None, yes: YesOpt = False, trust_fingerprint: FingerprintOpt = None,
    user: Annotated[str | None, typer.Option(
        help="vCenter: an existing user to give deploy access (user@domain). ESXi: the local user to create.")] = None,
    datacenter: Annotated[str | None, typer.Option(help="vCenter: datacenter.")] = None,
    folder: Annotated[str | None, typer.Option(help="vCenter: an existing VM folder, e.g. /Lab ('/' = the "
                                                    "datacenter's top VM folder).")] = None,
    new_folder: Annotated[str | None, typer.Option("--new-folder", help="vCenter: create this VM folder for the "
                                                   "account (recommended), e.g. vmdeploy-ops or Lab/vmdeploy-ops "
                                                   "inside an existing folder; `access remove` deletes it when "
                                                   "empty.")]
    = None,
    compute: Annotated[str | None, typer.Option(help="vCenter: cluster or standalone host to deploy to.")] = None,
    datastore: Annotated[list[str] | None, typer.Option(help="vCenter: datastore the account may use "
                                                             "(repeat for more).")] = None,
    network: Annotated[list[str] | None, typer.Option(help="vCenter: network the account may use "
                                                           "(repeat for more).")] = None,
    image_datastore: Annotated[list[str] | None, typer.Option(
        "--image-datastore", help="vCenter: which datastores the account may find images on. 'all' (default): see "
                                  "every datastore, copy rights where images are; 'none'; or datastore names "
                                  "(repeatable) for copy rights only there.")] = None,
    role_name: Annotated[str, typer.Option(help="Name of the role to create.")] = "vmdeploy-deployer",
    new_profile: Annotated[str | None, typer.Option(help="Name of the connection profile to create for the deploy "
                                                         "account (default: <profile>-deployer).")] = None,
    remember: Annotated[bool | None, typer.Option("--remember/--no-remember", help="ESXi: save the generated "
                                                  "password in the OS keychain (default: show it once).")] = None,
) -> None:
    """Create a least-privilege deploy account. Sign in as an administrator; nothing changes until you confirm."""
    from . import access
    from .inventory import discover
    from .logsetup import register_secret

    def body():
        conn, p = _connect(profile, yes, trust_fingerprint)
        with conn:
            console.print(
                "[bold]Least-privilege deploy account[/]\n"
                "You are signed in as an administrator. vmdeploy will prepare an account that can only deploy VMs "
                "where you allow it, so day-to-day deployments never use administrator credentials. You will see "
                "the full plan before anything is created; `vmdeploy access remove` deletes it all again.")
            _check_admin(conn)
            if conn.is_vcenter:
                inv = discover(conn)
                with p.section("Who and where"):
                    dc_name = _pick(p, datacenter, "Datacenter:", [(n, n) for n in sorted(inv.datacenters)],
                                    "--datacenter")
                    dc = inv.datacenters[dc_name]
                    principal = user or p.text(
                        "Existing vCenter user who will deploy VMs (user@domain):", field_name="--user",
                        validate=lambda s: ("@" in s or "\\" in s) or "Use user@domain")
                    # Validate early, and check the user exists before any plan: vCenter users cannot be created
                    # through the vSphere API, so a missing one is the administrator's step, explained here.
                    if access.user_missing(conn, access.normalize_principal(principal)):
                        raise ConfigError(
                            f"vCenter does not know the user {principal}. vmdeploy gives an existing user deploy "
                            "access; it cannot create vCenter users (the vSphere API does not allow it).",
                            hint="Create it first in the vSphere Client: Administration > Single Sign On > Users and "
                                 "Groups > Users, choose the domain (for example vsphere.local), Add, enter a user "
                                 "name and password, Add. Do not add it to any group (vmdeploy grants exactly the "
                                 "rights it needs). Then run `vmdeploy access setup` again. An Active Directory user "
                                 "works too, if vCenter is joined to the domain. Nothing was changed.")
                    top = access.rights_at_top(conn, access.normalize_principal(principal))
                    if top:
                        sample = ", ".join(top[:3]) + (f" and {len(top) - 3} more" if len(top) > 3 else "")
                        raise ConfigError(
                            f"{principal} already has rights across this vCenter ({len(top)} privilege(s), e.g. "
                            f"{sample}), from its own permission, a group (for example Administrators) or a global "
                            "permission. Setup would replace them with read-only access at the top of the "
                            "inventory, so this account cannot be used.",
                            hint="Use a dedicated account that is in no group and has no other permissions (README, "
                                 "Step 4: how to create one). Nothing was changed.")
                    create_name = None
                    create_parent = "/"
                    chosen_folder = folder  # local copy: `folder` is the command-line option
                    if chosen_folder is not None and new_folder is not None:
                        raise ConfigError("Use either --folder (an existing folder) or --new-folder, not both.")
                    if new_folder is not None:
                        create_parent, create_name = access.split_folder_path(new_folder)
                        if create_parent not in dc.folders:
                            raise ConfigError(f"--new-folder: the folder {create_parent} does not exist.",
                                              hint="Existing folders: " + ", ".join(sorted(dc.folders)))
                    elif chosen_folder is None:
                        if not p.interactive:
                            raise ConfigError("Where may the account create VMs?",
                                              hint="Pass --new-folder NAME (recommended: a folder just for this "
                                                   "account) or --folder PATH (an existing folder).")
                        console.print(
                            "[bold]Where may this account create VMs?[/] Its deploy rights (create, change, power on/off "
                            "and delete VMs) apply only inside the folder you choose, including its subfolders. "
                            "Everywhere else it can only look. A new folder just for it keeps your existing VMs out of "
                            "its reach. You can rename or move the folder later in the vSphere Client: the rights "
                            "belong to the folder and move with it. (VMs moved out of the folder are no longer managed "
                            "by this account.)")
                        pick = p.select("VM folder the account may create VMs in:",
                                        [("Create a new folder for this account (recommended)", "__new__")]
                                        + [(path, path) for path in sorted(dc.folders)],
                                        default="__new__", field_name="--folder", auto_single=False)
                        if pick == "__new__":
                            if len(dc.folders) > 1:
                                create_parent = p.select(
                                    "Where should the new folder go?",
                                    [("At the top of the datacenter (recommended)", "/")]
                                    + [(f"Inside {path}", path) for path in sorted(dc.folders) if path != "/"],
                                    default="/", auto_single=False)
                            siblings = access.child_names(dc.folders, create_parent)
                            create_name = p.text(
                                "Name of the new folder:",
                                default=access.suggest_folder_name(principal, siblings), assume_default=True,
                                validate=lambda s: access.folder_name_error(s.strip(), siblings) or True).strip()
                        else:
                            chosen_folder = pick
                    if create_name is not None:
                        problem = access.folder_name_error(create_name, access.child_names(dc.folders, create_parent))
                        if problem:
                            raise ConfigError(f"--new-folder '{create_name}': {problem}.")
                        _check_folder_admin(conn, dc.folders[create_parent])
                        folder_path = (create_parent.rstrip("/") + "/" + create_name)
                    else:
                        folder_path = _pick(p, chosen_folder, "VM folder the account may create VMs in:",
                                            [(path, path) for path in sorted(dc.folders)], "--folder")
                    existing_vms = [] if create_name else access.vms_in_folder(conn, dc.folders[folder_path])
                    if existing_vms:
                        shown = ", ".join(existing_vms[:5]) + (" ..." if len(existing_vms) > 5 else "")
                        warn(f"{folder_path} already holds {len(existing_vms)} VM(s) ({shown}). The account will be "
                             "able to change, power off and delete them too. A dedicated, empty folder is safer.")
                    computes = [(f"Cluster {c}", c) for c in sorted(dc.clusters)] + \
                               [(f"Host {h}", h) for h, hi in sorted(dc.hosts.items()) if not hi.cluster]
                    target = _pick(p, compute, "Cluster or host the account may deploy to:", computes, "--compute")
                    # The cluster, or the standalone host's compute resource, granted without propagation (see
                    # access.py). Not the root resource pool: vCenter refuses permissions on that sub-entity.
                    if target in dc.clusters:
                        hosts, obj = set(dc.clusters[target].hosts), dc.clusters[target].obj
                        label = f"Cluster {target}"
                    else:
                        hosts, obj, label = {target}, dc.hosts[target].obj.parent, f"Host {target}"
                    total = len(dc.hosts)
                    ds_names = _pick_many(p, datastore, "Datastores the account may use:",
                                          [(d.host_label(total), d.name) for d in dc.datastores_for(hosts) if d.usable],
                                          "--datastore")
                    net_names = _pick_many(p, network, "Networks the account may connect VMs to:",
                                           [(n.label(), n.name) for n in dc.usable_networks(hosts)], "--network")
                    image_names, browse_names = _ask_image_datastores(p, conn, dc, ds_names, image_datastore)
                plan = access.build_vcenter_plan(
                    conn, principal=principal, role_name=role_name,
                    folder=(folder_path, None if create_name else dc.folders[folder_path]),
                    new_folder=(dc.folders[create_parent], create_name) if create_name else None,
                    compute=(label, obj), datastores=[(n, dc.datastores[n].obj) for n in ds_names],
                    networks=[(n, dc.networks[n].obj) for n in net_names],
                    image_datastores=[(n, dc.datastores[n].obj) for n in image_names],
                    browse_datastores=[(n, dc.datastores[n].obj) for n in browse_names])
            else:
                with p.section("Deploy account"):
                    principal = user or p.text("Name of the local ESXi user to create:", default="vmdeploy",
                                               field_name="--user", assume_default=True)
                plan = access.build_esxi_plan(conn, username=principal, role_name=role_name)
                existing_vms = access.vms_in_folder(conn, conn.content.rootFolder)
                if existing_vms:
                    warn(f"This host already runs {len(existing_vms)} VM(s). A standalone ESXi host has no VM folders "
                         "to limit access with, so the account will be able to change, power off and delete them "
                         "too.")
                register_secret(plan.password)
                if access.local_user_exists(conn, plan.principal):
                    raise ConfigError(f"A local user '{plan.principal}' already exists on this host.",
                                      hint="Choose another name with --user, or remove the existing access with "
                                           "`vmdeploy access remove`.")

            # Every question is asked before the plan, so nothing is asked after vCenter/ESXi has been changed.
            store = ProfileStore()
            existing_names = {pr.name for pr in store.list()}

            def _name_check(s: str):
                s = s.strip()
                if not s:
                    return True  # empty = skip
                if s in existing_names:
                    return f"A profile named '{s}' already exists"
                return profile_name_error(s) or True

            if new_profile is not None:
                name = new_profile.strip()
                if (problem := _name_check(name)) is not True:
                    raise ConfigError(f"--new-profile '{name}': {problem}.")
            else:
                default_name = f"{conn.profile.name}-deployer"
                while default_name in existing_names:
                    default_name += "-2"
                name = p.text("Connection profile to create for this account (empty to skip):",
                              default=default_name, assume_default=True, validate=_name_check).strip()
            keep = False
            if plan.password and name:
                keep = remember if remember is not None else (credentials.keychain_available() and p.confirm(
                    "Save the generated password in the OS keychain? (No = it is shown once at the end)",
                    default=False, assume=False))

            clash = access.conflicts(conn, plan)
            if clash:
                raise ConfigError(f"{plan.principal} already has permissions that setup would overwrite:\n  "
                                  + "\n  ".join(clash),
                                  hint="Use a dedicated account that is only used for deployments (README, Step 4). "
                                       "Nothing was changed.")
            inherited = access.inherited_rights(conn, plan)
            if inherited:
                raise ConfigError(
                    f"{plan.principal} already has rights here, through a group (for example vCenter's "
                    "Administrators) or a permission higher up. vSphere lets a permission set on an object replace "
                    "those, so setup would reduce what this account can do on:\n  " + "\n  ".join(inherited),
                    hint="Use a dedicated account that is in no group and has no other permissions (README, Step 4: "
                         "how to create one). Nothing was changed.")
            if inherited is None:
                warn(f"Could not check whether {plan.principal} already has rights through a group or a permission "
                     "higher up (vCenter did not say). If it does, setup's permissions would replace them on the "
                     "objects below: use a dedicated account.")

            with p.section("Plan: nothing has been changed yet"):
                who = (f"{plan.principal} (new local user, password generated)" if plan.create_local_user
                       else plan.principal)
                console.print(f"Account: [bold]{who}[/]")
                console.print(f"Role [bold]{plan.role_name}[/]: {len(plan.privileges)} deploy privileges "
                              "(docs/least-privilege.md lists them)")
                t = Table("Granted on", "Role", "Also applies to objects inside")
                for g in plan.grants:
                    t.add_row(esc(g.label), g.role, "yes" if g.propagate else "no")
                console.print(t)
                if plan.new_folder:
                    console.print(f"New VM folder: [bold]{folder_path}[/], labelled in the vSphere Client "
                                  f"(Custom Attributes: {access.FOLDER_MARKER_FIELD} = \"Created by vmdeploy access "
                                  "setup\"). `vmdeploy access remove` deletes it again once it is empty.")
                if any(g.role == plan.browse_role_name for g in plan.grants):
                    console.print("Datastores marked 'see image files': the account can list and read the files there "
                                  "(Browse datastore), so every ISO/OVA in vCenter shows up when it deploys. It cannot "
                                  "change anything there.")
                if any(g.role == plan.images_role_name for g in plan.grants):
                    console.print("Image datastores: the account can also copy ISO/OVA files from there to its own "
                                  "datastores (fast, host to host). 'Low level file operations', which copying needs, "
                                  "also lets it rename or delete files on those datastores.")
                if conn.is_vcenter:
                    console.print(f"Deploy rights apply only to VMs in [bold]{folder_path}[/] and its subfolders; the "
                                  "account can look at, but not change, everything else. You can rename or move the "
                                  "folder later: the rights move with it.")
                console.print(f"Local profile: [bold]{name}[/]" + (" (password in the OS keychain)" if keep else "")
                              if name else "Local profile: none")
                if not p.confirm("Create this access?", default=False, assume=True):
                    raise UserAborted("Cancelled. Nothing was changed.")
            access.apply(conn, plan)
            p.record("Access created for", plan.principal)
            access.record_setup(conn.profile.endpoint, plan.principal, created_local_user=plan.create_local_user)
            dropped = access.missing_from_role(conn, plan.role_name)
            if dropped:
                warn(f"The server stored role {plan.role_name} without: {', '.join(dropped)}. Deployments that need "
                     "these will fail; please report this with the log file.")

            login = _upn(plan.principal) if conn.is_vcenter else plan.principal
            if not name:
                if plan.password:
                    console.print(f"[bold]Password for {plan.principal}:[/] {plan.password}\n"
                                  "[yellow]Shown once. It is not saved anywhere.[/]")
                return
            try:
                deploy_profile = Profile(name=name, host=conn.profile.host, port=conn.profile.port,
                                         auth=AuthMethod.PASSWORD, username=login, remember_secret=keep)
                if keep and not credentials.set_secret(deploy_profile, plan.password):  # bound to this profile
                    keep = False  # not saved: the password is shown once below instead
                    deploy_profile = deploy_profile.model_copy(update={"remember_secret": False})
                store.save(deploy_profile)
            except Exception as e:  # noqa: BLE001 - vSphere was already changed; say so and how to finish
                if plan.password:
                    console.print(f"[bold]Password for {plan.principal}:[/] {plan.password}  [yellow](shown once)[/]")
                raise VmDeployError(
                    f"The access was created, but the local profile '{name}' could not be saved: {e}",
                    hint=f"Create it yourself: vmdeploy profile add --name <name> --host {conn.profile.host} "
                         f"--port {conn.profile.port} --auth password --username {login} --no-remember") from e
            p.record("Profile saved", f"{name} (keychain: {'yes' if keep else 'no'})")
            if plan.password and not keep:
                console.print(f"[bold]Password for {plan.principal}:[/] {plan.password}\n"
                              "[yellow]Shown once. It is not saved anywhere; you will be asked for it when you deploy."
                              "[/]")
            console.print(f"Deploy with this account: [bold]vmdeploy deploy -p {name}[/]   "
                          f"Remove it again: [bold]vmdeploy access remove -p {conn.profile.name}[/]")
    _run(body)


@access_app.command("audit")
def access_audit(profile: ProfileOpt = None, yes: YesOpt = False, trust_fingerprint: FingerprintOpt = None) -> None:
    """Read-only report of everything vmdeploy created and any leftovers (roles, permissions, folders, VMs, files)."""
    from . import audit

    def body():
        conn, _p = _connect(profile, yes, trust_fingerprint)
        with conn:
            console.print(f"[bold]Audit of {esc(conn.profile.endpoint)}[/] as {esc(conn.user)}. "
                          "Read-only: nothing is changed.")
            with console.status("Reading roles, permissions, folders, VMs and datastore files..."):
                sections = audit.run(conn)
            for s in sections:
                if s.clean:
                    console.print(f"[green]  ✔ {s.title}: nothing found[/]")
                    continue
                console.print(f"[bold cyan]  ℹ {s.title}[/]" if s.reminder else f"[bold yellow]  ! {s.title}[/]")
                if s.rows:
                    t = Table(*s.columns)
                    for row in s.rows:
                        t.add_row(*(esc(str(c)) for c in row))  # "[datastore] path" is not a style tag
                    console.print(t)
                    if s.advice:
                        console.print(f"    [dim]{s.advice}[/]")
                if s.note:
                    console.print(f"    [yellow]{s.note}[/]")
            found = [s.title for s in sections if s.rows and not s.reminder]
            unchecked = [s.title for s in sections if s.note]
            reminders = [s for s in sections if s.reminder and s.rows]
            if not found and not unchecked:
                console.print("[bold green]Nothing created by vmdeploy is left, and no orphaned VM files were found.[/]")
            else:
                if found:
                    console.print(f"[bold]Found something in: {', '.join(found)}.[/]")
                if unchecked:
                    console.print(f"[yellow]Not checked (see above): {', '.join(unchecked)}.[/]")
            if reminders:
                console.print("[cyan]Reminder: check the account(s) listed under "
                              f"'{reminders[0].title}' and delete any that are no longer needed.[/]")
    _run(body)


# ------------------------------------------------------------------------------------------------ key provider
NoPasswordOpt = Annotated[bool, typer.Option("--no-password", help="Do not protect the backup file with a password "
                                             "(not recommended).")]
OutOpt = Annotated[Path | None, typer.Option("--out", "-o", help="Where to save the backup (.p12). Default: "
                                             "<provider>-<date>.p12 in the current folder.")]


@keyprovider_app.command("list")
def keyprovider_list(profile: ProfileOpt = None, yes: YesOpt = False, trust_fingerprint: FingerprintOpt = None) -> None:
    """List vCenter's key providers: type, default, and whether a Native Key Provider is backed up."""
    from . import keyprovider as kp

    def body():
        conn, _p = _connect(profile, yes, trust_fingerprint)
        with conn:
            if not conn.is_vcenter:
                raise ConfigError("Key providers belong to vCenter; this is an ESXi host.",
                                  hint=crypto.no_vtpm_on_esxi(conn))
            provs = kp.providers(conn)
            if not provs:
                console.print("No key provider is configured. Add one with [bold]vmdeploy keyprovider add[/].")
                return
            kp.show_table(provs)
            try:
                used, unchecked = kp.vm_keys(conn)
            except DeploymentError as e:  # informational here: the rest of the list still helps
                warn(f"{e.message} Which VMs use each key provider is not shown.")
                used, unchecked = None, []
            for k in provs if used is not None else []:
                vms = used.get(k.name, [])
                console.print(f"VMs using {esc(k.name)}'s keys (virtual TPM or encryption): "
                              + (esc(", ".join(vms)) if vms else "none"))
            for name in sorted(set(used or ()) - {k.name for k in provs}):
                console.print(f"[yellow]VMs using keys from '{esc(name)}', which is not configured in vCenter:[/] "
                              f"{esc(', '.join(used[name]))} (vCenter cannot give them their keys until it is restored from its backup).")
            if unchecked:
                console.print("[yellow]VMs whose keys could not be checked (vCenter cannot read their configuration, "
                              f"e.g. their storage is unavailable):[/] {esc(', '.join(unchecked))}")
            if any(k.native and k.backed_up is False for k in provs):
                console.print("Back up a Native Key Provider with [bold]vmdeploy keyprovider backup[/]; vCenter only "
                              "uses it after that.")
            if not any(k.default for k in provs):
                console.print("[yellow]None is the default, so new virtual TPMs cannot get a key.[/] "
                              "`vmdeploy keyprovider add` sets a new one as the default.")
            if any(k.native for k in provs):
                tpm = any(k.native and k.tpm_required for k in provs)
                console.print("Where a Native Key Provider works: only on hosts in a cluster"
                              + (", and with 'Hosts need a TPM' only on hosts with a physical TPM 2.0:" if tpm else ":"))
                t = Table("Host", "Cluster", "TPM 2.0", "Details")
                hosts = kp.host_tpms(conn)
                for host, cluster, has, desc in hosts:
                    t.add_row(esc(host), esc(cluster) if cluster else "[yellow]none (standalone)[/]",
                              {True: "[green]yes[/]", False: "[yellow]no[/]", None: "?"}[has], esc(desc))
                console.print(t)
                if not any(cluster for _h, cluster, _t, _d in hosts):
                    console.print("[yellow]No host is in a cluster, so no VM can use a Native Key Provider yet.[/] "
                                  + esc(crypto.NEEDS_CLUSTER))
    _run(body)


@keyprovider_app.command("add")
def keyprovider_add(
    name: Annotated[str | None, typer.Option("--name", help="Name of the new Native Key Provider.")] = None,
    tpm_required: Annotated[bool, typer.Option("--tpm-required", help="Use it only on hosts with a physical TPM 2.0 "
                                               "(leave off unless every host has one).")] = False,
    default: Annotated[bool | None, typer.Option("--default/--no-default", help="Make it vCenter's default key "
                                                 "provider (default: yes when there is no default yet).")] = None,
    backup: Annotated[bool, typer.Option("--backup/--no-backup", help="Back it up right away (vCenter only uses it "
                                         "after a backup).")] = True,
    out: OutOpt = None,
    no_password: NoPasswordOpt = False,
    profile: ProfileOpt = None,
    yes: YesOpt = False,
    trust_fingerprint: FingerprintOpt = None,
) -> None:
    """Add a Native Key Provider (free, built into vCenter) for virtual TPMs, make it the default and back it up."""
    from . import keyprovider as kp

    def body():
        conn, p = _connect(profile, yes, trust_fingerprint)
        with conn:
            kp.require_manageable(conn)
            kp.add_flow(conn, p, name=name, tpm_required=tpm_required, make_default=default, backup=backup, out=out,
                        no_password=no_password)
    _run(body)


@keyprovider_app.command("backup")
def keyprovider_backup(
    provider: Annotated[str | None, typer.Option("--provider", help="Native Key Provider to back up (default: "
                                                 "the only one, or asked).")] = None,
    out: OutOpt = None,
    no_password: NoPasswordOpt = False,
    profile: ProfileOpt = None,
    yes: YesOpt = False,
    trust_fingerprint: FingerprintOpt = None,
) -> None:
    """Back up a Native Key Provider (vCenter only uses one after a backup). Works when the vSphere Client's
    'Back up' fails because vCenter is named by its IP address."""
    from . import keyprovider as kp

    def body():
        conn, p = _connect(profile, yes, trust_fingerprint)
        with conn:
            kp.require_manageable(conn)
            natives = kp.native_providers(conn)
            if not natives:
                raise ConfigError("This vCenter has no Native Key Provider.",
                                  hint="Add one with `vmdeploy keyprovider add` (it is backed up as part of that).")
            kp.show_table(natives)
            names = [k.name for k in natives]
            if provider and provider not in names:
                raise ConfigError(f"No Native Key Provider named '{provider}'.", hint=f"Found: {', '.join(names)}.")
            not_backed = [k.name for k in natives if k.backed_up is False]
            name = provider or p.select("Key provider to back up:", [(n, n) for n in names],
                                        default=(not_backed or names)[0], field_name="--provider")
            kp.backup_flow(conn, p, name, out, no_password)
    _run(body)


@keyprovider_app.command("default")
def keyprovider_default(
    provider: Annotated[str | None, typer.Option("--provider", help="Key provider to make the default.")] = None,
    profile: ProfileOpt = None,
    yes: YesOpt = False,
    trust_fingerprint: FingerprintOpt = None,
) -> None:
    """Make a key provider vCenter's default (new virtual TPMs get their keys from it)."""
    from . import keyprovider as kp

    def body():
        conn, p = _connect(profile, yes, trust_fingerprint)
        with conn:
            kp.require_manageable(conn)
            provs = kp.providers(conn)
            if not provs:
                raise ConfigError("This vCenter has no key provider.", hint="Add one with `vmdeploy keyprovider add`.")
            kp.show_table(provs)
            names = [k.name for k in provs]
            if provider and provider not in names:
                raise ConfigError(f"No key provider named '{provider}'.", hint=f"Found: {', '.join(names)}.")
            name = provider or p.select("Key provider to make the default:", [(n, n) for n in names],
                                        field_name="--provider")
            chosen = next(k for k in provs if k.name == name)
            if chosen.native and chosen.backed_up is False:
                warn(f"{name} is not backed up yet: vCenter does not use it until `vmdeploy keyprovider backup`.")
            if not p.confirm(f"Make {name} vCenter's default key provider?", default=True, assume=True):
                raise UserAborted("Nothing was changed.")
            kp.set_default(conn, name)
            console.print(f"[green]{esc(name)} is now the default key provider.[/]")
    _run(body)


@keyprovider_app.command("remove")
def keyprovider_remove(
    provider: Annotated[str | None, typer.Option("--provider", help="Key provider to remove.")] = None,
    profile: ProfileOpt = None,
    yes: YesOpt = False,
    trust_fingerprint: FingerprintOpt = None,
) -> None:
    """Remove a key provider. Refused while any VM still uses it (those VMs could not start again), or while a
    VM's configuration cannot be read (it might use it)."""
    from . import keyprovider as kp

    def body():
        conn, p = _connect(profile, yes, trust_fingerprint)
        with conn:
            kp.require_manageable(conn)
            provs = kp.providers(conn)
            if not provs:
                raise ConfigError("This vCenter has no key provider.")
            kp.show_table(provs)
            names = [k.name for k in provs]
            if provider and provider not in names:
                raise ConfigError(f"No key provider named '{provider}'.", hint=f"Found: {', '.join(names)}.")
            name = provider or p.select("Key provider to remove:", [(n, n) for n in names], field_name="--provider")
            with console.status("Looking for VMs that use it..."):
                users, unchecked = kp.vms_using(conn, name)
            if users:
                raise ConfigError(f"{len(users)} VM(s) use keys from '{name}': {', '.join(users[:10])}"
                                  f"{' ...' if len(users) > 10 else ''}. Nothing was removed.",
                                  hint="Removing it would leave those VMs unable to start. Delete them, or remove "
                                       "their virtual TPM / encryption first.")
            if unchecked:
                raise ConfigError(f"{len(unchecked)} VM(s) could not be checked: {', '.join(unchecked[:10])}"
                                  f"{' ...' if len(unchecked) > 10 else ''}. Nothing was removed.",
                                  hint=f"vCenter cannot read their configuration (e.g. their storage is unavailable), "
                                       f"so they may use keys from '{name}'. Make them accessible again, or remove "
                                       "them from the inventory, then run this again.")
            with p.section("Plan: nothing has been changed yet"):
                console.print(f"  Remove key provider [bold]{esc(name)}[/] (no VM uses it). Its keys are gone from "
                              "vCenter afterwards; a backup file (.p12) can restore it.")
                typed = p.text(f"Type the name ({name}) to confirm:", field_name="--provider",
                               # --yes with --provider: the name was given explicitly; interactively it is typed
                               default=name if (provider and not p.interactive) else None,
                               assume_default=bool(provider))
                if typed != name:
                    raise UserAborted("The name did not match. Nothing was removed.")
            user, pwd = conn.rest_credentials
            with console.status(f"Removing {name}..."), kp.RestSession(conn.decision, user, pwd) as sid:
                kp.delete(conn.decision, sid, name)
            console.print(f"[green]Removed the key provider {esc(name)}.[/]")
            if not any(k.default for k in kp.providers(conn)):
                console.print("[yellow]vCenter has no default key provider now; new virtual TPMs cannot get a key "
                              "until you add one (`vmdeploy keyprovider add`).[/]")
    _run(body)


def _folder_plan_row(name: str, items: int, may_empty: bool) -> str:
    """`access remove`'s plan line (Rich markup, the name escaped) for a folder setup created. A folder is deleted
    only when empty, which deleting the account's VMs (--delete-vms, or that choice when asked) can make it."""
    if items == 0:
        return f"{esc(name)} (created by setup)"
    if may_empty:
        return f"{esc(name)} (created by setup): deleted after its VMs, if they are deleted; otherwise KEPT " \
               f"(it holds {items} item(s) now)"
    return f"{esc(name)} (created by setup) is KEPT: it still holds {items} item(s)"


@access_app.command("remove")
def access_remove(
    profile: ProfileOpt = None, yes: YesOpt = False, trust_fingerprint: FingerprintOpt = None,
    role_name: Annotated[str, typer.Option(help="Name of the role setup created.")] = "vmdeploy-deployer",
    delete_user: Annotated[list[str] | None, typer.Option(
        help="ESXi: also delete this local user when vmdeploy cannot confirm it created it (repeatable).")] = None,
    delete_vms: Annotated[bool, typer.Option("--delete-vms", help="Also delete the VMs in the account's folder "
                                             "(only VMs deployed by vmdeploy). Default: keep them.")] = False,
    delete_iso: Annotated[bool | None, typer.Option(
        "--delete-iso/--keep-iso", help="With deleted VMs: also delete the ISO copies they used if nothing else uses "
                                        "them. Default: ask (keep with --yes).")] = None,
) -> None:
    """Delete everything `access setup` created: permissions, roles, ESXi user, local profile and saved password."""
    from . import access

    def body():
        conn, p = _connect(profile, yes, trust_fingerprint)
        with conn:
            _check_admin(conn)
            found = access.find_existing(conn, role_name)
            principals = {x.lower() for x in found.principals()}

            def is_deploy_profile(pr: Profile) -> bool:
                if pr.name == conn.profile.name or pr.host != conn.profile.host or not pr.username:
                    return False
                try:
                    key = access.normalize_principal(pr.username) if conn.is_vcenter else pr.username
                except ConfigError:
                    return False
                return key.lower() in principals

            store = ProfileStore()
            profiles = [pr for pr in store.list() if is_deploy_profile(pr)]
            kept_others = [f"{name} (for {owner or 'an unknown account'})" for name, owner in found.other_folders]
            if found.empty and not profiles:
                console.print(f"No access created by `vmdeploy access setup` (role '{esc(role_name)}') was found.")
                if kept_others:
                    console.print(f"[dim]Folders vmdeploy created for other accounts or setups (not touched): "
                                  f"{esc(', '.join(kept_others))}. Check the role name (--role-name).[/]")
                return
            # VMs in the account's folder(s): asked about before the account's rights and profile are gone
            # (afterwards only an administrator can delete them).
            deploy_role_id = found.roles.get(role_name)
            folders_seen: dict[str, object] = {}
            for perm in found.permissions:
                ent = perm.entity
                if (conn.is_vcenter and perm.roleId == deploy_role_id and perm.propagate and ent is not None
                        and type(ent).__name__.endswith("Folder")):
                    folders_seen[ent._moId] = ent  # noqa: SLF001
            for f, _name, _items in found.folders:
                folders_seen[f._moId] = f  # noqa: SLF001
            # Names and "deployed by vmdeploy" for every VM, one request per folder (a VM not read counts as not ours:
            # never deleted, its folder kept). A VM is deleted only if the plan said so AND it is still marked right
            # before its deletion (access.delete_planned).
            leftover_vms = access.vms_in_folders(conn, folders_seen.values())
            marked = {r.vm._moId: r.ours for _, recs in leftover_vms for r in recs}  # noqa: SLF001

            def is_ours(vm) -> bool:
                return marked.get(vm._moId, False)  # noqa: SLF001

            with p.section("To be removed"):
                t = Table("What", "Details")  # names are escaped: '[' is allowed in folder and role names
                for perm in found.permissions:
                    t.add_row("Permission", esc(f"{perm.principal} on {access.entity_label(perm.entity)}"))
                for n in found.roles:
                    t.add_row("Role", esc(n))
                for u in found.local_users:
                    t.add_row("Local ESXi user", esc(u))
                for u in found.unverified_users:
                    t.add_row("Local ESXi user", f"{esc(u)} (only if you confirm below)")
                folder_rows = []
                for f, fname, items in found.folders:
                    # --delete-vms, or the question below, may empty it: the plan must not promise it is kept
                    may_empty = (bool(items) and (delete_vms or p.interactive)
                                 and access.emptied_by_deleting_vms(f, is_ours))
                    folder_rows.append((items, may_empty))
                    t.add_row("VM folder", _folder_plan_row(fname, items, may_empty))
                for pr in profiles:
                    t.add_row("Local profile", f"{esc(pr.name)} and its saved password, if any")
                label = access.label_plan(folder_rows, bool(found.other_folders), found.orphan_label)
                if label:
                    t.add_row("Custom attribute", f"'{access.FOLDER_MARKER_FIELD}' ({label})")
                console.print(t)
                if kept_others:
                    console.print(f"[dim]Not touched: folders vmdeploy created for other accounts or setups: "
                                  f"{esc(', '.join(kept_others))}.[/]")
                vm_action = "keep"
                if leftover_vms:
                    vt = Table("VM in the account's folder", "Folder", "Deployed by vmdeploy")
                    for fname, recs in leftover_vms:
                        for r in recs:
                            vt.add_row(esc(r.name), esc(fname), "yes" if r.ours else "no (never deleted here)")
                    console.print(vt)
                    total = sum(len(recs) for _, recs in leftover_vms)
                    if delete_vms:
                        vm_action = "delete"
                    elif p.interactive:
                        vm_action = p.select(
                            f"The account's folder still holds {total} VM(s). What should happen to them?", [
                                ("Keep them (remove only the access; the folder stays)", "keep"),
                                ("Delete them now (power off + delete, only VMs deployed by vmdeploy), then remove "
                                 "everything", "delete"),
                                ("Cancel (nothing is changed)", "cancel")], default="keep", auto_single=False)
                        if vm_action == "cancel":
                            raise UserAborted("Cancelled. Nothing was changed.")
                    else:
                        warn(f"{total} VM(s) in the account's folder are kept. Pass --delete-vms to delete the ones "
                             "vmdeploy deployed.")
                for u in found.unverified_users:
                    # Never delete an account on a guess: the server did not confirm setup created it.
                    if u in (delete_user or []) or p.confirm(
                            f"Also delete local user '{u}'? It has the vmdeploy role, but the host does not confirm "
                            "vmdeploy created it.", default=False, assume=False):
                        found.local_users.append(u)
                    else:
                        warn(f"Local user '{u}' will be kept; only its vmdeploy permission is removed.")
                if not p.confirm("Remove all of this?", default=False, assume=True):
                    raise UserAborted("Cancelled. Nothing was changed.")
            def shown(text: str) -> None:  # as it happens: a failure part-way still shows what was already done
                p.record("Removed", text)

            deleted_isos: list[tuple[str | None, str]] = []
            if vm_action == "delete":  # each only if the plan said yes and it is still marked right before
                _deleted, deleted_isos = access.delete_planned(conn, leftover_vms, warn, on_removed=shown)
                # the folders may be empty now
                found.folders = [(f, n, len(f.childEntity or [])) for f, n, _ in found.folders]
            access.remove(conn, found, on_removed=shown)
            access.record_removed(conn.profile.endpoint, found.principals())
            for u in found.local_users:  # local ESXi users deleted by remove: nothing left to remind about
                access.forget_account(conn.profile.endpoint, u)
            secrets_left = []
            for pr in profiles:
                _deleted, ok = credentials.delete_secrets(pr)
                store.remove(pr.name)
                log.info("Removed: Local profile %s", pr.name, extra=FILE_ONLY)
                shown(f"Local profile {pr.name}")
                if not ok:
                    secrets_left.append(pr)
            for pr in secrets_left:
                _warn_secret_left(pr)
            _offer_iso_cleanup(conn, p, deleted_isos, delete_iso)
            if conn.is_vcenter and found.principals():  # names escaped: '[' is allowed in folder names
                users = esc(", ".join(found.principals()))
                kept = [esc(n) for _f, n, items in found.folders if items]
                console.print(f"[bold]Still to do by hand, if no longer needed:[/] the account itself ({users}) is "
                              "not deleted, because the vSphere API cannot delete vCenter Single Sign-On users. Delete it "
                              "in the vSphere Client (Administration > Single Sign On > Users and Groups)."
                              + (f" Folder(s) {', '.join(kept)} still hold VMs: delete or move them, then run "
                                 "`vmdeploy access remove` again." if kept else "")
                              + ("" if found.folders else " A folder you created yourself for this account is kept; "
                                 "delete it there once it is empty."))
    _run(body)


@app.command()
def doctor(profile: ProfileOpt = None, yes: YesOpt = False, trust_fingerprint: FingerprintOpt = None) -> None:
    """Check the connection, licence, API version and the account's privileges."""
    from . import privileges
    from .inventory import discover

    def body():
        conn, _p = _connect(profile, yes, trust_fingerprint)
        with conn:
            t = Table(show_header=False, box=None, padding=(0, 2))
            t.add_row("Server", conn.product)
            t.add_row("API", f"{conn.about.apiType} {conn.about.apiVersion}")
            t.add_row("Signed in as", conn.user)
            from .trust import shown

            t.add_row("Certificate", f"{conn.decision.describe()} ({shown(conn.decision.cert.subject)})")
            from .crypto import key_provider

            kp = key_provider(conn)
            t.add_row("Key provider", {"yes": "[green]available[/]", "no": "[yellow]none[/]",
                                       "unknown": "unknown"}[kp.status] + f" ({kp.detail}; needed for a virtual TPM)")
            clock_note = _clock_check(conn)
            if clock_note:
                t.add_row("Server clock", clock_note)
            inv = discover(conn)
            for dc in inv.datacenters.values():
                t.add_row(f"Datacenter {dc.name}", f"{len(dc.clusters)} cluster(s), {len(dc.hosts)} host(s), "
                                                   f"{len(dc.datastores)} datastore(s), "
                                                   f"{len(dc.usable_networks())} VM network(s)")
            console.print(t)
            unknown = privileges.unknown_ids(conn)
            if unknown:
                warn(f"Privilege IDs not known to this server (please report): {', '.join(unknown)}")
            root = conn.content.rootFolder
            missing = privileges.check(conn, {g: root for g in ("folder", "resource_pool", "datastore", "network",
                                                                "virtual_machine")})
            if missing is None:
                warn("This server cannot report privileges; skipped.")
            elif missing:
                scope = privileges.deploy_scope(conn, inv)
                if scope is not None:
                    console.print("This account is [bold]restricted[/]: it does not have the deploy privileges "
                                  "everywhere. It can deploy here:")
                    st = Table(show_header=False, box=None, padding=(0, 2))
                    for kind, names in scope.items():
                        st.add_row(f"  {kind}", esc(", ".join(names)) if names else "[red]none[/]")
                    console.print(st)
                    lacking = [k for k, names in scope.items() if not names]
                    if lacking:
                        console.print(f"[yellow]Nothing usable for: {', '.join(lacking)}. Deployments will fail "
                                      "until an administrator grants it (for example with `vmdeploy access setup`).[/]")
                        for kind in lacking:
                            for label, ids in privileges.closest_partial(kind):
                                console.print(f"  [yellow]{kind}: {label} has some, but is missing "
                                              f"{', '.join(ids)}[/]")
                    else:
                        console.print("[green]Everything a deployment needs is available in the places above.[/]")
                if scope is None or _state["verbose"]:
                    console.print("[yellow]Privileges missing at the top of the inventory (they may still be granted "
                                  "on specific folders/clusters):[/]")
                    for g, ids in missing.items():
                        console.print(f"  {g}: {', '.join(ids)}")
                    on_parent = privileges.on_parent_ids(conn)
                    if on_parent:
                        console.print("[dim]Privileges the server checks on the parent object (e.g. the folder holding "
                                      f"a VM): {', '.join(on_parent)}[/]")
            else:
                console.print("[green]All required privileges are granted at the top of the inventory.[/]")
            from .access import find_all_setups
            setups = find_all_setups(conn)
            if setups:
                console.print(f"Deploy access created by `vmdeploy access setup`: role(s) {', '.join(setups)}. "
                              "An administrator can delete it with `vmdeploy access remove`.")
                from .access import missing_from_role
                for role_name in setups:
                    lacking_privs = missing_from_role(conn, role_name)
                    if lacking_privs:
                        warn(f"Role {role_name} on the server is missing: {', '.join(lacking_privs)}.")
            for w in conn.warnings:
                warn(w)
            console.print("[green]Doctor finished.[/]")
    _run(body)


@app.command()
def inventory(profile: ProfileOpt = None, yes: YesOpt = False, trust_fingerprint: FingerprintOpt = None) -> None:
    """Show datacenters, clusters, hosts, datastores and networks."""
    from .inventory import GiB, discover

    def body():
        conn, _ = _connect(profile, yes, trust_fingerprint)
        with conn:
            for dc in discover(conn).datacenters.values():
                console.rule(f"Datacenter {dc.name}")
                th = Table("Host", "Cluster", "State", "Cores", "RAM free/total", "vCPU alloc")
                for h in dc.hosts.values():
                    th.add_row(esc(h.name), esc(h.cluster or "-"), "maintenance" if h.maintenance else h.connection_state,
                               str(h.cpu_cores), f"{h.mem_free_gb:.0f}/{h.mem_bytes / GiB:.0f} GB", str(h.allocated_vcpus))
                console.print(th)
                td = Table("Datastore", "Type", "Free", "Capacity", "Provisioned", "Hosts")
                for d in dc.datastores.values():
                    td.add_row(esc(d.display_name), d.type, f"{d.free / GiB:.0f} GB", f"{d.capacity / GiB:.0f} GB",
                               f"{d.provisioned / max(d.capacity, 1) * 100:.0f}%", str(len(d.hosts)))
                console.print(td)
                tn = Table("Network", "Type")
                for n in dc.usable_networks():
                    tn.add_row(esc(n.label().rsplit("  (", 1)[0]), n.label().rsplit("  (", 1)[-1].rstrip(")"))
                console.print(tn)
    _run(body)


@app.command("list")
def list_vms(profile: ProfileOpt = None, yes: YesOpt = False, trust_fingerprint: FingerprintOpt = None) -> None:
    """List VMs that were deployed by this tool."""
    from . import vmnotes
    from .inventory import vm_properties

    def body():
        conn, _ = _connect(profile, yes, trust_fingerprint)
        with conn:
            # One bulk read for every VM (it downloaded each VM's whole configuration, then 3 requests per VM)
            rows = vm_properties(conn, ["name", "config.annotation", "runtime.powerState", "guest.ipAddress"])
            t = Table("VM", "Power", "IP", "Deployed")
            for _vm, props in sorted(rows, key=lambda row: str(row[1].get("name", ""))):
                notes = props.get("config.annotation")
                if vmnotes.is_marked(notes):
                    t.add_row(esc(str(props.get("name", "?"))), str(props.get("runtime.powerState", "?")),
                              str(props.get("guest.ipAddress") or ""),
                              esc(vmnotes.field(notes, "deployed")))  # anyone may edit Notes: never markup
            console.print(t)
    _run(body)


@app.command()
def destroy(name: str, profile: ProfileOpt = None, yes: YesOpt = False, trust_fingerprint: FingerprintOpt = None,
            datacenter: Annotated[str | None, typer.Option(help="Datacenter that holds the VM.")] = None,
            force: Annotated[bool, typer.Option("--force", help="Allow deleting VMs not created by this tool.")] = False,
            delete_iso: Annotated[bool | None, typer.Option(
                "--delete-iso/--keep-iso", help="Also delete the ISO copy (vmdeploy-iso/) the VM used, if no other VM "
                                                "uses it. Default: ask (keep with --yes).")] = None) -> None:
    """Power off and permanently delete a VM (only VMs this tool deployed, unless --force)."""
    from .deploy import Deployment  # noqa: F401 - shared helpers
    from .inventory import find_vm_with

    def body():
        conn, p = _connect(profile, yes, trust_fingerprint)
        with conn:
            root = None
            if datacenter:
                from .inventory import discover

                dcs = discover(conn, datacenter).datacenters
                if datacenter not in dcs:
                    raise ConfigError(f"No datacenter named '{datacenter}'.")
                root = dcs[datacenter].vm_folder
            # the VM, its Notes and its CD/DVD drives in one read (an unreadable configuration is simply missing)
            found = find_vm_with(conn, name, ["config.annotation", "config.hardware.device"], root=root)
            if found is None:
                raise ConfigError(f"No VM named '{name}'.")
            vm, props = found
            from . import isocopies, vmnotes

            ours = vmnotes.is_marked(props.get("config.annotation"))
            if not ours and not force:
                raise ConfigError(f"'{name}' was not deployed by this tool.", hint="Use --force to delete it anyway.")
            if not p.confirm(f"Permanently delete '{name}' and its disks? This cannot be undone.", default=False,
                             assume=True):
                raise UserAborted("Nothing was deleted.")
            from .access import delete_vm

            attached = [path for _dc, path in isocopies.copies_attached(props.get("config.hardware.device"), None)]
            dc_name = isocopies.datacenter_of(vm) if attached else None
            used_isos = [(dc_name, path) for path in attached]
            delete_vm(vm, name)  # powers it off first; logged there
            console.print(f"[green]Deleted '{esc(name)}'.[/]")
            if conn.managed_by:
                # Seen on vCenter 8.0.3: a VM deleted on a managed host directly stays in vCenter as "(orphaned)".
                console.print(f"[yellow]This host is managed by vCenter Server {esc(conn.managed_by)}, which may "
                              f"still list '{esc(name)}' as (orphaned). Remove it there: right-click > Remove from "
                              "Inventory (its files are already deleted). Deleting through vCenter avoids this.[/]")
            _offer_iso_cleanup(conn, p, used_isos, delete_iso)
    _run(body)


def _offer_iso_cleanup(conn, p: Prompter, copies: list[tuple[str | None, str]], delete_iso: bool | None) -> None:
    """Separately from deleting VMs: offer to delete the vmdeploy ISO copies they used, if nothing else uses them.
    Default is to keep them (they make the next deployment to that datastore faster). `copies`: (datacenter name,
    path) pairs from isocopies.copies_attached (destroy) or access.delete_planned."""
    if not copies:
        return
    from . import isocopies
    from .inventory import discover

    pairs = sorted(set(copies), key=lambda c: (c[1], c[0] or ""))  # the same path may be in two datacenters
    try:
        users = isocopies.iso_users(conn)
    except VmDeployError as e:  # the VM is already deleted: keep the copies rather than guess
        warn(f"{e.message} The ISO cop{'y was' if len(pairs) == 1 else 'ies were'} kept; "
             "`vmdeploy images prune` can delete unused copies later.")
        return
    unused = [(dc, pth) for dc, pth in pairs if not users.get(isocopies.norm(pth))]
    for pth in sorted({pth for _dc, pth in pairs if users.get(isocopies.norm(pth))}):
        console.print(f"[dim]Kept {esc(pth)}: still used by {esc(', '.join(users[isocopies.norm(pth)]))}.[/]")
    if not unused:
        return
    in_several = {pth for pth, n in Counter(pth for _dc, pth in pairs).items() if n > 1}

    def named(dc, pth):  # the same path in two datacenters: say which copy is meant
        return f"{pth} in datacenter {dc}" if dc and pth in in_several else pth

    inv = discover(conn)
    for dc, pth in unused:
        if delete_iso is None:
            remove = p.confirm(f"Also delete the ISO copy {named(dc, pth)}? No other VM uses it; keeping it makes the "
                               "next deployment to this datastore faster.", default=False, assume=False,
                               field_name="--delete-iso")
        else:
            remove = delete_iso
        if remove:
            isocopies.delete(conn, inv, pth, dc)
            p.record("Deleted ISO copy", named(dc, pth))
        else:
            console.print(f"[dim]Kept {esc(named(dc, pth))} (`vmdeploy images prune` lists and deletes unused copies "
                          "later).[/]")


# ------------------------------------------------------------------------------------------------ images
@images_app.command("list")
def images_list() -> None:
    """Show local images, cached downloads and presets."""
    from .images import cache_entries, list_local_images, load_presets
    from .paths import images_dir

    # The folder is printed on its own line: as a table title a long path wraps a few characters per line.
    local = list_local_images()
    console.print(f"[bold]Local images[/] for --local / --pick-local, in: {images_dir()}", highlight=False)
    if local:
        t = Table("File", "Size")
        for f in local:
            t.add_row(esc(f.name), f"{f.stat().st_size / 2**30:.2f} GB")
        console.print(t)
    else:
        console.print("  (none yet: copy .ova, .ovf or .iso files into that folder)")
    t2 = Table("File", "Size", "SHA-256", "Source", title="Download cache")
    for f, meta in cache_entries():
        t2.add_row(esc(f.name), f"{f.stat().st_size / 2**30:.2f} GB", (meta.get("sha256") or "")[:16] + "...",
                   esc(meta.get("url", "")))
    console.print(t2)
    t3 = Table("Preset", "Description", title="Presets (--preset)")
    for n, pr in load_presets().items():
        t3.add_row(n, pr.description)
    console.print(t3)


@images_app.command("pull")
def images_pull(preset: Annotated[str | None, typer.Option(help="Preset to download.")] = None,
                url: Annotated[str | None, typer.Option(help="URL to download.")] = None,
                sha256: Annotated[str | None, typer.Option(help="Expected SHA-256 (for --url).")] = None) -> None:
    """Download and verify an image into the cache without deploying it."""
    from rich.progress import BarColumn, Progress, TextColumn

    from .images import resolve
    from .transfer import check_sha256
    from .ui import SizeColumn, SpeedColumn

    def body():
        if bool(preset) == bool(url):
            raise ConfigError("Give exactly one of --preset or --url.")
        sha = check_sha256(sha256)
        with Progress(TextColumn("{task.description}"), BarColumn(), SizeColumn(), SpeedColumn(),
                      console=console) as prog:
            def factory(desc, total):
                tid = prog.add_task(esc(desc), total=total)
                return lambda n: prog.advance(tid, n)
            img = resolve("preset" if preset else "url", preset or url, sha256=sha, prompter=Prompter(False),
                          progress_factory=factory)
        console.print(f"[green]Ready:[/] {esc(str(img.path))}\n  {esc(img.integrity)}")
    _run(body)


@images_app.command("prune")
def images_prune(profile: ProfileOpt = None, yes: YesOpt = False, trust_fingerprint: FingerprintOpt = None,
                 delete_unused: Annotated[bool, typer.Option(
                     "--delete-unused", help="With --yes: delete every copy no VM uses (without --yes you choose).")]
                 = False) -> None:
    """List the ISO copies vmdeploy left on datastores (vmdeploy-iso/), which VMs use them, and delete unused ones."""
    from . import isocopies
    from .inventory import discover
    from .units import human_size

    def body():
        conn, p = _connect(profile, yes, trust_fingerprint)
        with conn:
            inv = discover(conn)
            skipped: list[str] = []
            with console.status("Looking for vmdeploy-iso/ folders on all datastores..."):
                found = isocopies.copies(inv, skipped)
                users = isocopies.iso_users(conn)
                empty = isocopies.empty_folders(inv)
            if skipped:
                console.print(f"[yellow]Not searched ({len(skipped)} datastore(s) this account may not browse): "
                              f"{esc(', '.join(sorted(skipped)))}.[/]")
            if empty:
                console.print("Empty vmdeploy-iso/ folder(s): "
                              + esc(", ".join(f"[{name}] vmdeploy-iso" for _dc, name, _o in empty)))
                if p.confirm("Delete the empty folder(s)? (nothing is in them)", default=True,
                             assume=delete_unused, field_name="--delete-unused"):
                    for dc, name, obj in empty:
                        if isocopies.delete_empty_folder(conn, dc, name, obj):
                            p.record("Deleted empty folder", f"[{name}] vmdeploy-iso")
            if not found:
                console.print("No ISO copies found in vmdeploy-iso/ folders.")
                return
            t = Table("Where", "ISO copy", "Size", "Used by")
            unused = []
            several = len(inv.datacenters) > 1  # datastore names repeat across datacenters: say which one
            for iso in found:
                who = users.get(isocopies.norm(iso.full), [])
                if not who:
                    unused.append(iso)
                where = iso.label().split(" › ", 1)[0]
                t.add_row(esc(f"{iso.datacenter}: {where}" if several else where), esc(iso.full),
                          human_size(iso.size), esc(", ".join(who)) if who else "[green]no VM[/]")
            console.print(t)
            console.print("[dim]Copies are kept so later deployments to that datastore need no upload or copy. Copies "
                          "in use by a VM cannot be deleted here.[/]")
            if not unused:
                console.print("Every copy is in use; nothing to delete.")
                return
            if not p.interactive:
                picked = list(range(len(unused))) if delete_unused else []
                if not delete_unused:
                    console.print(f"{len(unused)} unused copy(ies). Run again with --delete-unused to delete them.")
            else:
                picked = p.checkbox("Which unused copies should be deleted? (space to tick, Enter to continue)",
                                    [((f"{i.datacenter}: " if several else "")
                                      + f"{i.full}  ({human_size(i.size)})", n) for n, i in enumerate(unused)],
                                    minimum=0)
            if picked and p.confirm(f"Delete {len(picked)} ISO copy(ies)? The original images are not affected.",
                                    default=False, assume=True):
                for n in picked:
                    iso = unused[n]
                    isocopies.delete(conn, inv, iso.full, iso.datacenter or None)
                    p.record("Deleted ISO copy", iso.full)
            elif not picked:
                console.print("Nothing deleted.")
    _run(body)


@images_app.command("clear-cache")
def images_clear() -> None:
    """Delete downloaded images and OVA/OVF copies read from datastores from this computer's cache."""
    from .images import clear_cache

    n, size = clear_cache()
    console.print(f"Removed {n} cached image(s), {size / 2**30:.1f} GB freed.")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
