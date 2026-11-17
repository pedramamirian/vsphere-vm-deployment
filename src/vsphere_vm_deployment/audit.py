"""`vmdeploy access audit`: a read-only report of everything vmdeploy has created in a vCenter/ESXi, and of
leftovers that clean-up (by the tool or by hand) may have missed. Nothing is changed.

Each check returns rows; an empty list means "nothing found". A check that cannot run (missing privilege,
older server) reports that instead of failing the whole audit.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from pyVmomi import vim

from . import inventory, vmnotes
from .access import (
    DEFAULT_ROLE,
    FOLDER_MARKER_FIELD,
    READ_SUFFIX,
    account_exists,
    accounts_named_vmdeploy,
    entity_label,
    load_history,
    same_endpoint,
)
from .connection import Connection
from .tasks import wait_task
from .units import local_date

log = logging.getLogger(__name__)

PREFIX = "vmdeploy"
_DS_PATH = re.compile(r"^\[(?P<ds>[^\]]+)\]\s*/?(?P<path>.*?)/*$")


def ds_folder(path: str) -> str:
    """Normalise a datastore folder path: '[ds]/a/b/', '[ds] a/b' -> '[ds] a/b' (servers differ in format)."""
    m = _DS_PATH.match((path or "").strip())
    return f"[{m['ds']}] {m['path']}" if m else (path or "").strip()


@dataclass
class Section:
    title: str
    columns: tuple[str, ...]
    rows: list[tuple[str, ...]] = field(default_factory=list)
    note: str = ""  # e.g. why a check could not run
    advice: str = ""  # what to do about rows found
    reminder: bool = False  # informational: not a leftover, but worth a look (e.g. deploy accounts)

    @property
    def clean(self) -> bool:
        return not self.rows and not self.note


def _ours(name: str | None) -> bool:
    return bool(name) and name.lower().startswith(PREFIX)


def iso_folder_report(ds_name: str, inside: list[str] | None, attached: set[str]) -> str | None:
    """What `access audit` says about a datastore's vmdeploy-iso folder (`inside`: its entries, None if it could not
    be listed; `attached`: the ISO files on VMs' CD/DVD drives), or None when there is nothing to report. Anything a
    VM uses is in use (kept on purpose), whatever its name. ISOs are recognised as everywhere in vmdeploy
    (isolib.is_iso_name); files the storage keeps for itself (names starting with "." or "@", e.g. NFS lock files
    of an ISO a running VM has open) are left out; anything else is listed on its own, to check by hand."""
    from .isocopies import norm
    from .isolib import ISO_FOLDER, is_iso_name

    if inside is None:
        return "vmdeploy-iso folder (its contents could not be listed)"
    if not inside:
        return "empty vmdeploy-iso folder (`vmdeploy images prune` deletes it)"
    free = [e for e in inside
            if norm(f"[{ds_name}] {ISO_FOLDER}/{e}") not in attached and not e.startswith((".", "@"))]
    unused = [e for e in free if is_iso_name(e)]
    parts = []
    if unused:
        parts.append(f"{len(unused)} of {sum(map(is_iso_name, inside))} ISO copies by vmdeploy, used by no VM "
                     "(`vmdeploy images prune` deletes unused ones)")
    if len(free) > len(unused):
        parts.append(f"{len(free) - len(unused)} other file(s) or folder(s), not ISO copies (check them in the "
                     "vSphere Client)")
    return "; ".join(parts) or None


def _safe(section: Section, fn) -> Section:
    try:
        fn(section)
    except Exception as e:  # noqa: BLE001 - one failing check must not hide the others
        log.debug("audit check %r failed: %s", section.title, e)
        section.note = f"Could not check: {getattr(e, 'msg', None) or e}"
    return section


def run(conn: Connection) -> list[Section]:
    content = conn.content
    am = content.authorizationManager
    roles = {r.roleId: r for r in am.roleList or []}
    our_role_ids = {rid for rid, r in roles.items() if _ours(r.name) or r.name in (DEFAULT_ROLE, DEFAULT_ROLE + READ_SUFFIX)}

    def check_roles(s: Section) -> None:
        for rid in sorted(our_role_ids):
            r = roles[rid]
            s.rows.append((r.name, str(len([p for p in r.privilege or [] if not p.startswith("System.")]))))
        s.advice = "Remove with `vmdeploy access remove` (add --role-name for a custom role name)."

    def check_permissions(s: Section) -> None:
        for p in am.RetrieveAllPermissions() or []:
            role = roles.get(p.roleId)
            orphan = role is None
            if p.roleId in our_role_ids or _ours(p.principal.split("\\")[-1]) or orphan:
                s.rows.append((p.principal, role.name if role else f"(role {p.roleId} no longer exists)",
                               entity_label(p.entity), "yes" if p.propagate else "no"))
        s.advice = "Remove with `vmdeploy access remove`, or in the vSphere Client (the object's Permissions tab)."

    def check_attribute(s: Section) -> None:
        cfm = getattr(content, "customFieldsManager", None)
        field_def = next((f for f in (cfm.field if cfm else []) or [] if f.name == FOLDER_MARKER_FIELD), None)
        if field_def is None:
            return
        carriers = [obj for obj, props in inventory.collect(conn, vim.ManagedEntity, ["customValue"])
                    if any(cv.key == field_def.key for cv in props.get("customValue") or [])]
        s.rows.append((FOLDER_MARKER_FIELD, ", ".join(entity_label(o) for o in carriers) or "nothing (orphaned)"))
        s.advice = "`vmdeploy access remove` deletes it once no folder uses it."

    def check_folders(s: Section) -> None:
        cfm = getattr(content, "customFieldsManager", None)
        key = next((f.key for f in (cfm.field if cfm else []) or [] if f.name == FOLDER_MARKER_FIELD), None)
        for _obj, props in inventory.collect(conn, vim.Folder, ["name", "childEntity", "customValue"]):
            labelled = key is not None and any(cv.key == key for cv in props.get("customValue") or [])
            if labelled or _ours(props.get("name")):
                s.rows.append((props.get("name", "?"), "labelled by setup" if labelled else "name only",
                               str(len(props.get("childEntity") or []))))
        s.advice = "`vmdeploy access remove` deletes labelled folders once empty; others: the vSphere Client."

    def check_vms(s: Section) -> None:
        stale = False
        for _obj, props in inventory.collect(conn, vim.VirtualMachine, ["name", "config.annotation", "runtime.powerState",
                                                               "runtime.connectionState"]):
            marked = vmnotes.is_marked(props.get("config.annotation"))
            if marked or _ours(props.get("name")):
                state = str(props.get("runtime.powerState", "?"))
                cs = str(props.get("runtime.connectionState") or "connected")
                if cs != "connected":  # e.g. deleted on the host directly: vCenter keeps an orphaned entry
                    state, stale = f"{state}, {cs}", True
                s.rows.append((props.get("name", "?"), "deployed by vmdeploy" if marked else "name only", state))
        s.advice = "Delete with `vmdeploy destroy <name>` (or `vmdeploy access remove` for the account's folder)."
        if stale:
            s.advice += (" Orphaned or inaccessible: vCenter lists a VM its host no longer has (for example one "
                         "deleted on the host directly). Remove it in the vSphere Client: right-click > Remove from "
                         "Inventory.")

    def check_datastore_files(s: Section) -> None:
        from . import isocopies

        # strict: if the VM list cannot be read, every VM's folder would look orphaned and every ISO copy unused
        # (the section then reports that it could not be checked instead). One read for both.
        vms = inventory.collect(conn, vim.VirtualMachine, ["config.files.vmPathName", "config.hardware.device"],
                                strict=True)
        registered = {ds_folder((props.get("config.files.vmPathName") or "").rsplit("/", 1)[0]) for _o, props in vms}
        attached = {path for _o, props in vms for path in isocopies.iso_paths(props.get("config.hardware.device"))}
        for _ds, props in inventory.collect(conn, vim.Datastore, ["name", "summary.accessible", "browser"]):
            if not props.get("summary.accessible"):
                continue
            name = props["name"]
            spec = vim.host.DatastoreBrowser.SearchSpec(matchPattern=["*.vmx"])
            task = props["browser"].SearchDatastoreSubFolders_Task(datastorePath=f"[{name}]", searchSpec=spec)
            for res in wait_task(task, what=f"Search {name}") or []:
                folder = ds_folder(res.folderPath)
                if res.file and folder not in registered:
                    s.rows.append((name, folder, ", ".join(f.path for f in res.file)))
            top = props["browser"].SearchDatastore_Task(
                datastorePath=f"[{name}]", searchSpec=vim.host.DatastoreBrowser.SearchSpec(matchPattern=[f"{PREFIX}*"]))
            for f in (wait_task(top, what=f"Search {name}").file or []):
                path = ds_folder(f"[{name}] {f.path}")
                if path not in registered and not any(r[1] == path for r in s.rows):
                    what = "folder"
                    if f.path == "vmdeploy-iso":
                        what = iso_folder_report(name, isocopies.folder_entries(_ds, name), attached)
                        if what is None:
                            continue
                    s.rows.append((name, path, what))
        s.advice = ("VM files that no VM in the inventory uses, e.g. after 'Remove from Inventory' instead of "
                    "'Delete from Disk'. Check them, then delete in the vSphere Client (datastore Files tab). "
                    "Folders of VMs that other tools manage may also appear here.")

    def check_sessions(s: Section) -> None:
        for sess in content.sessionManager.sessionList or []:
            if _ours(sess.userName.split("\\")[-1].split("@")[0]):
                s.rows.append((sess.userName, str(sess.loginTime), str(sess.lastActiveTime)))
        s.advice = "Old sessions expire on their own; an administrator can end them in the vSphere Client."

    def check_accounts(s: Section) -> None:
        endpoint = conn.profile.endpoint if conn.profile else ""
        seen: set[str] = set()
        for e in load_history():
            if not same_endpoint(e["endpoint"], endpoint):
                continue
            exists = account_exists(conn, e["principal"])
            if exists is False:
                continue  # already deleted: nothing to remind about
            seen.add(e["principal"].lower())
            access = f"removed {local_date(e['removed'])}" if e.get("removed") else "still set up"
            s.rows.append((e["principal"], f"access setup {local_date(e['setup'])}, {access}",
                           "yes" if exists else "could not check"))
        for principal in accounts_named_vmdeploy(conn):
            if principal.lower() not in seen:
                s.rows.append((principal, "name starts with 'vmdeploy'", "yes"))
        s.advice = ("Not a leftover: user accounts are yours to manage. If an account was created only for vmdeploy "
                    "and is no longer needed, delete it in the vSphere Client (Administration > Single Sign On > "
                    "Users and Groups); vmdeploy cannot delete vCenter users. Accounts used from other computers "
                    "are only listed if their name starts with 'vmdeploy'.")

    sections = [
        _safe(Section("Roles", ("Role", "Privileges")), check_roles),
        _safe(Section("Permissions", ("Account", "Role", "On", "Applies to objects inside")), check_permissions),
        _safe(Section("Custom attribute", ("Name", "Used by")), check_attribute),
        _safe(Section("VM folders", ("Folder", "Why it is listed", "Items inside")), check_folders),
        _safe(Section("VMs", ("VM", "Why it is listed", "Power")), check_vms),
        _safe(Section("Files on datastores not used by any VM", ("Datastore", "Folder", "Files")),
              check_datastore_files),
        _safe(Section("Open sessions of vmdeploy accounts", ("User", "Signed in", "Last active")), check_sessions),
        _safe(Section("Accounts used with vmdeploy", ("Account", "History", "Still exists"), reminder=True),
              check_accounts),
    ]
    return sections
