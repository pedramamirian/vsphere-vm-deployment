"""`vmdeploy access setup / remove`: a dedicated least-privilege deploy account, prepared by an administrator.

An administrator signs in once. The tool shows exactly what it will create and changes nothing until the
administrator confirms. It then creates:

* a role (default `vmdeploy-deployer`) holding exactly the deploy privileges listed in data/privileges.yaml;
* on vCenter, a companion read-only role (`<role>-read`) granted at the top of the inventory, so the account
  can discover datacenters, hosts, datastores and networks (granting the built-in Read-only role instead
  would make it impossible to tell our permission apart from one an administrator created);
* permissions for the deploy account: the deploy role on the chosen VM folder (propagating, so the account
  can manage the VMs it creates there), on the chosen cluster or standalone host (NOT propagating:
  VMs inherit permissions from their cluster/host and resource pool too, so a propagating grant there would
  hand the account every existing VM on it; vCenter applies a cluster's or host's permissions to its root
  resource pool, which itself cannot hold permissions), and on each chosen datastore and network;
* optionally a new, empty VM folder for the account, labelled with the custom attribute `vmdeploy`
  ("Created by vmdeploy access setup for <user>") so anyone can see where it came from in the vSphere Client,
  and so `remove` can delete it again (only when it is empty);
* on a standalone ESXi host only, the local user itself, with a generated password. vCenter Single Sign-On
  users cannot be created through the public vSphere API, so on vCenter an existing SSO or Active
  Directory user is used.

Everything is identified by the role names, so `remove` deletes exactly what `setup` created and never touches
permissions an administrator set up by hand. A failed setup rolls back what it had already created.
"""

from __future__ import annotations

import logging
import re
import secrets
import string
from collections.abc import Callable
from dataclasses import dataclass, field

from pyVmomi import vim

from .connection import Connection
from .errors import ConfigError, DeploymentError, VmDeployError
from .logsetup import FILE_ONLY
from .privileges import known_privilege_ids, required_privileges
from .tasks import wait_task
from .trust import endpoint_key

log = logging.getLogger(__name__)

DEFAULT_ROLE = "vmdeploy-deployer"
READ_SUFFIX = "-read"
IMAGES_SUFFIX = "-images"
# Image datastores: find ISOs/OVAs and copy them server-side. FileManagement is what CopyDatastoreFile needs on
# the source; it also allows deleting files there, which the plan says.
IMAGE_PRIVILEGES = ["Datastore.Browse", "Datastore.FileManagement"]
# Every other datastore: see (list and read) image files only, so the image picker shows everything in vCenter.
BROWSE_SUFFIX = "-browse"
BROWSE_PRIVILEGES = ["Datastore.Browse"]
DEPLOY_GROUPS = ("folder", "resource_pool", "datastore", "network", "virtual_machine", "compatibility_upgrade",
                 "vtpm")
LOCAL_USER_MARKER = "Created by vmdeploy access setup"
FOLDER_MARKER_FIELD = "vmdeploy"  # custom attribute on folders created by setup
_FOLDER_NAME_BAD = re.compile(r"[/\\%]")
_IMPLICIT = {"System.Anonymous", "System.View", "System.Read"}  # every role has these; the API adds them itself
_ESXI_USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,30}$")
_ROLE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


# ------------------------------------------------------------------------------------------ plan
@dataclass
class Grant:
    entity: object
    label: str  # human-readable, e.g. "VM folder /Servers"
    role: str  # role name
    propagate: bool


@dataclass
class AccessPlan:
    role_name: str
    privileges: list[str]
    principal: str  # vCenter: DOMAIN\user; ESXi: local user name
    grants: list[Grant]
    create_local_user: bool = False
    password: str | None = field(default=None, repr=False)
    new_folder: tuple[object, str] | None = None  # (parent folder, name): created by apply()

    @property
    def read_role_name(self) -> str:
        return self.role_name + READ_SUFFIX

    @property
    def images_role_name(self) -> str:
        return self.role_name + IMAGES_SUFFIX

    @property
    def browse_role_name(self) -> str:
        return self.role_name + BROWSE_SUFFIX


def deploy_privileges(known: set[str] | None) -> list[str]:
    """Every privilege a deployment needs, minus the implicit System.* ones and any ID the server lacks."""
    groups = required_privileges()
    ids = {p for g in DEPLOY_GROUPS for p in groups.get(g, [])} - _IMPLICIT
    if known:
        ids &= known
    return sorted(ids)


def validate_role_name(name: str) -> str:
    if not _ROLE_RE.fullmatch(name):
        raise ConfigError(f"Invalid role name '{name}'.", hint="Use letters, digits, '.', '_' or '-' (max 64).")
    return name


def normalize_principal(user: str) -> str:
    """vCenter permissions name users as DOMAIN\\user. Accept that or user@domain (UPN)."""
    user = user.strip()
    if "\\" in user:
        domain, name = user.split("\\", 1)
    elif "@" in user:
        name, domain = user.rsplit("@", 1)
    else:
        raise ConfigError(f"'{user}' has no domain.",
                          hint="Give the user as user@domain (e.g. svc-deploy@vsphere.local) or DOMAIN\\user.")
    if not domain or not name:
        raise ConfigError(f"'{user}' is not a valid user name.")
    return f"{domain.upper()}\\{name}"


def validate_esxi_user(name: str) -> str:
    if not _ESXI_USER_RE.fullmatch(name):
        raise ConfigError(f"Invalid ESXi user name '{name}'.",
                          hint="Use lower-case letters, digits, '_', '.' or '-', starting with a letter (max 31).")
    if name == "root":
        raise ConfigError("Refusing to use 'root' as the deploy account.")
    return name


def generate_password(length: int = 24) -> str:
    """Meets ESXi's default password policy (all four character classes). No quotes, backslashes or '$',
    so the password is safe to paste into any shell."""
    symbols = "!#%+-=@_~"
    alphabet = string.ascii_letters + string.digits + symbols
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
                and any(c in symbols for c in pw)):
            return pw


def suggest_folder_name(principal: str, taken: set[str]) -> str:
    """'vmdeploy-test-deployer@vsphere.local' -> 'vmdeploy-test-deployer'; 'jdoe@corp' -> 'vmdeploy-jdoe'."""
    user = principal.split("\\")[-1].split("@")[0].strip() or "deployer"
    base = user if user.lower().startswith("vmdeploy") else f"vmdeploy-{user}"
    name, n = base, 2
    while name in taken:
        name, n = f"{base}-{n}", n + 1
    return name


def split_folder_path(value: str) -> tuple[str, str]:
    """'Lab/Apps/vmdeploy-x' or '/Lab/Apps/vmdeploy-x' -> ('/Lab/Apps', 'vmdeploy-x'); 'x' -> ('/', 'x')."""
    parts = [p for p in value.strip().strip("/").split("/") if p]
    if not parts:
        return "/", ""
    return ("/" + "/".join(parts[:-1])) if len(parts) > 1 else "/", parts[-1]


def child_names(folder_paths, parent: str) -> set[str]:
    """Names of the folders directly inside `parent` ('/' = the datacenter's top VM folder)."""
    prefix = "" if parent == "/" else parent
    return {p[len(prefix) + 1:] for p in folder_paths
            if p != "/" and p.startswith(prefix + "/") and "/" not in p[len(prefix) + 1:]}


def folder_name_error(name: str, taken: set[str]) -> str | None:
    if not name.strip():
        return "A folder name is required"
    if len(name) > 80:
        return "Folder names can be at most 80 characters"
    if _FOLDER_NAME_BAD.search(name):
        return "Folder names may not contain / \\ or %"
    if name in taken:
        return f"A folder named '{name}' already exists here"
    return None


def build_vcenter_plan(conn: Connection, *, principal: str, role_name: str, folder: tuple[str, object],
                       compute: tuple[str, object], datastores: list[tuple[str, object]],
                       networks: list[tuple[str, object]], new_folder: tuple[object, str] | None = None,
                       image_datastores: list[tuple[str, object]] | None = None,
                       browse_datastores: list[tuple[str, object]] | None = None) -> AccessPlan:
    """folder/compute/datastores/networks are (label, managed object) pairs chosen by the administrator.
    `compute` is the cluster, or the standalone host's ComputeResource (never its root resource pool: vCenter
    rejects permissions on that sub-entity with "Operation not allowed on sub-entity: Resources").
    With `new_folder` (parent, name) the folder is created by apply(); its grant has no entity until then."""
    role_name = validate_role_name(role_name)
    read_role = role_name + READ_SUFFIX
    grants = [Grant(conn.content.rootFolder, "Top of the inventory (read-only, to discover it)", read_role, True),
              Grant(None, f"New VM folder {folder[0]} (created by vmdeploy)", role_name, True) if new_folder
              else Grant(folder[1], f"VM folder {folder[0]}", role_name, True),
              Grant(compute[1], f"{compute[0]} (placement only)", role_name, False)]
    from .inventory import display  # vCenter's %2f etc. shown as typed

    grants += [Grant(obj, f"Datastore {display(name)}", role_name, False) for name, obj in datastores]
    grants += [Grant(obj, f"Network {display(name)}", role_name, False) for name, obj in networks]
    deploy_ds = {name for name, _ in datastores}  # these already allow browsing and copying
    grants += [Grant(obj, f"Image datastore {display(name)} (find and copy ISO/OVA files)", role_name + IMAGES_SUFFIX,
                     False)
               for name, obj in image_datastores or [] if name not in deploy_ds]
    covered = deploy_ds | {name for name, _ in image_datastores or []}
    grants += [Grant(obj, f"Datastore {display(name)} (see image files)", role_name + BROWSE_SUFFIX, False)
               for name, obj in browse_datastores or [] if name not in covered]
    return AccessPlan(role_name, deploy_privileges(known_privilege_ids(conn)), normalize_principal(principal), grants,
                      new_folder=new_folder)


def build_esxi_plan(conn: Connection, *, username: str, role_name: str) -> AccessPlan:
    """A standalone ESXi host has a single host, so the role is granted on the whole host."""
    role_name = validate_role_name(role_name)
    return AccessPlan(role_name, deploy_privileges(known_privilege_ids(conn)), validate_esxi_user(username),
                      [Grant(conn.content.rootFolder, "This ESXi host (all datastores and networks)", role_name, True)],
                      create_local_user=True, password=generate_password())


# ------------------------------------------------------------------------------------------ checks
def _roles_by_name(am) -> dict[str, object]:
    return {r.name: r for r in am.roleList or []}


def conflicts(conn: Connection, plan: AccessPlan) -> list[str]:
    """Objects on which the account already has a permission that setup did not create. Setting ours there
    would *replace* it (vSphere keeps one permission per account per object), e.g. demote an administrator."""
    am = conn.content.authorizationManager
    ours = {r.roleId for n, r in _roles_by_name(am).items()
            if n in (plan.role_name, plan.read_role_name, plan.images_role_name, plan.browse_role_name)}
    found = []
    for g in plan.grants:
        if g.entity is None:  # a folder setup will create: nobody has permissions on it yet
            continue
        for p in am.RetrieveEntityPermissions(entity=g.entity, inherited=False) or []:
            if p.principal.lower() == plan.principal.lower() and not p.group and p.roleId not in ours:
                role = next((r.name for r in am.roleList if r.roleId == p.roleId), str(p.roleId))
                found.append(f"{g.label}: already has role '{role}'")
    return found


def _role_privileges(plan: AccessPlan, role: str) -> set[str]:
    return {plan.role_name: set(plan.privileges), plan.images_role_name: set(IMAGE_PRIVILEGES),
            plan.browse_role_name: set(BROWSE_PRIVILEGES)}.get(role, set())


def inherited_rights(conn: Connection, plan: AccessPlan) -> list[str] | None:
    """Objects where the account already holds rights setup would not grant, through a group (e.g. vCenter's
    Administrators) or a permission higher up. A permission set on the object itself replaces those there
    (vSphere: an explicit permission on an object overrides propagated ones, and a user's permission overrides
    its groups'), so setup would quietly reduce what the account can do. `conflicts` covers permissions on the
    objects themselves. None: vCenter could not tell (the check is skipped, and the caller says so)."""
    if plan.create_local_user:
        return []  # a brand-new local user has no rights yet
    am = conn.content.authorizationManager
    checks = []  # (entity to ask about, label, privileges our grant gives there)
    for g in plan.grants:
        entity = g.entity
        if entity is None and plan.new_folder:  # a folder setup will create inherits from its parent
            entity = plan.new_folder[0]
        if entity is not None:
            checks.append((entity, g.label, _role_privileges(plan, g.role)))
    if not checks:
        return []
    try:
        results = am.FetchUserPrivilegeOnEntities(entities=[e for e, _l, _p in checks], userName=plan.principal)
    except Exception as e:  # noqa: BLE001 - older servers / simulators: cannot tell
        log.debug("FetchUserPrivilegeOnEntities failed for %s: %s", plan.principal, e)
        return None
    held = {}
    for r in results or []:
        held[getattr(r.entity, "_moId", id(r.entity))] = set(r.privileges or [])
    found = []
    for entity, label, ours in checks:
        extra = sorted(held.get(getattr(entity, "_moId", id(entity)), set()) - ours - _IMPLICIT)
        if extra:
            sample = ", ".join(extra[:3]) + (f" and {len(extra) - 3} more" if len(extra) > 3 else "")
            found.append(f"{label}: already holds {len(extra)} privilege(s) setup would not grant ({sample})")
    return found


def rights_at_top(conn: Connection, principal: str) -> list[str] | None:
    """Privileges the account already holds at the top of the inventory (its own permission there, a group's, or
    vCenter's global ones), beyond what every account has. Asked straight after the user is named: setup puts a
    read-only permission there, which would replace them, so an account with any is refused before the
    placement questions. A rerun of setup passes (its read role holds nothing extra). None: vCenter cannot tell."""
    try:
        res = conn.content.authorizationManager.FetchUserPrivilegeOnEntities(
            entities=[conn.content.rootFolder], userName=principal)
    except Exception as e:  # noqa: BLE001
        log.debug("FetchUserPrivilegeOnEntities failed for %s: %s", principal, e)
        return None
    held = set()
    for r in res or []:
        held |= set(r.privileges or [])
    return sorted(held - _IMPLICIT)


def vms_in_folder(conn: Connection, folder) -> list[str]:
    """Names of the VMs already in a folder (and its subfolders), read in one request: the deploy account gets
    rights over them."""
    from .inventory import vm_properties

    return sorted(str(props.get("name", "?")) for _vm, props in vm_properties(conn, ["name"], root=folder))


def delete_vm(vm, label: str | None = None) -> None:
    """Power off (if needed) and delete a VM and its disks. Every command that deletes a VM (`destroy`, `access
    remove`, `deploy --replace`, the clean-up of a failed import) does it here, so each deletion is in the log."""
    if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
        wait_task(vm.PowerOffVM_Task(), what="Power off")
    wait_task(vm.Destroy_Task(), what="Delete VM")
    log.info("Deleted VM %s (%s)", label or "?", getattr(vm, "_moId", "?"), extra=FILE_ONLY)


def local_user_exists(conn: Connection, username: str) -> bool:
    return bool(_find_local_user(conn, username))


def _find_local_user(conn: Connection, username: str):
    try:
        results = conn.content.userDirectory.RetrieveUserGroups(
            searchStr=username, exactMatch=True, findUsers=True, findGroups=False)
    except vim.fault.NotFound:
        return None
    return next((r for r in results or [] if r.principal == username), None)


# ------------------------------------------------------------------------------------------ apply
def apply(conn: Connection, plan: AccessPlan) -> None:
    """Create everything in the plan. On any failure, undo what this call created, then re-raise."""
    content = conn.content
    am = content.authorizationManager
    undo: list[tuple[str, Callable[[], None]]] = []
    step = "starting"
    try:
        if plan.create_local_user:
            step = f"creating local user {plan.principal}"
            spec = vim.host.LocalAccountManager.AccountSpecification(
                id=plan.principal, password=plan.password, description=LOCAL_USER_MARKER)
            content.accountManager.CreateUser(user=spec)
            log.info("Created local user %s", plan.principal)
            undo.append((f"local user {plan.principal}", lambda: content.accountManager.RemoveUser(userName=plan.principal)))

        if plan.new_folder:
            parent, name = plan.new_folder
            step = f"creating folder {name}"
            new = parent.CreateFolder(name=name)
            log.info("Created VM folder %s", name)
            undo.append((f"folder {name}", lambda f=new: wait_task(f.Destroy_Task(), what="Delete folder")))
            step = f"labelling folder {name}"
            _mark_folder(content, new, plan.principal, plan.role_name)
            for g in plan.grants:
                if g.entity is None:
                    g.entity = new

        role_ids = {}
        existing = _roles_by_name(am)
        for name, privs in ((plan.role_name, plan.privileges), (plan.read_role_name, []),
                            (plan.images_role_name, IMAGE_PRIVILEGES), (plan.browse_role_name, BROWSE_PRIVILEGES)):
            if name not in {g.role for g in plan.grants}:
                continue
            step = f"creating role {name}"
            if name in existing:
                rid = existing[name].roleId
                role_ids[name] = rid
                before = list(existing[name].privilege or [])
                am.UpdateAuthorizationRole(roleId=rid, newName=name, privIds=privs)
                log.info("Updated role %s (%d privileges)", name, len(privs))
                # A re-run: on failure the role goes back to what it was, it is not deleted.
                undo.append((f"role {name} (previous privileges)",
                             lambda rid=rid, name=name, before=before: am.UpdateAuthorizationRole(
                                 roleId=rid, newName=name, privIds=before)))
            else:
                am.AddAuthorizationRole(name=name, privIds=privs)
                # Look the ID up by name rather than trusting the return value (vcsim returns 0 for every role).
                rid = _roles_by_name(am)[name].roleId
                role_ids[name] = rid
                log.info("Created role %s (%d privileges)", name, len(privs))
                undo.append((f"role {name}", lambda rid=rid: am.RemoveAuthorizationRole(roleId=rid, failIfUsed=False)))

        for g in plan.grants:
            step = f"granting {g.role} on {g.label}"
            # A re-run of setup finds the account's earlier permission here (conflicts() allows only setup's own
            # roles): on failure it is put back, not removed, so access that worked keeps working.
            prev = next((x for x in am.RetrieveEntityPermissions(entity=g.entity, inherited=False) or []
                         if x.principal.lower() == plan.principal.lower() and not x.group), None)
            perm = vim.AuthorizationManager.Permission(principal=plan.principal, group=False,
                                                       roleId=role_ids[g.role], propagate=g.propagate)
            am.SetEntityPermissions(entity=g.entity, permission=[perm])
            log.info("Granted role %s to %s on %s (propagate=%s)", g.role, plan.principal, g.label, g.propagate)
            if prev is None:
                undo.append((f"permission on {g.label}",
                             lambda e=g.entity: am.RemoveEntityPermission(entity=e, user=plan.principal,
                                                                          isGroup=False)))
            else:
                restore = vim.AuthorizationManager.Permission(principal=prev.principal, group=False,
                                                              roleId=prev.roleId, propagate=prev.propagate)
                undo.append((f"permission on {g.label} (previous role)",
                             lambda e=g.entity, r=restore: am.SetEntityPermissions(entity=e, permission=[r])))
    except Exception as e:
        log.error("Access setup failed (%s); rolling back %d change(s)", e, len(undo))
        problems = []
        for what, fn in reversed(undo):
            try:
                fn()
            except Exception as ue:  # noqa: BLE001
                problems.append(f"{what}: {ue}")
        msg = getattr(e, "msg", None) or str(e)
        hint = ("Everything created so far was removed again, and anything changed was put back." if not problems else
                "Some changes could not be undone; run `vmdeploy access remove`. " + "; ".join(problems))
        if isinstance(e, vim.fault.UserNotFound):
            msg = f"vCenter does not know the user {plan.principal}."
            hint += " Check the name and domain (vCenter > Administration > Users and Groups)."
        raise VmDeployError(f"Access setup failed while {step}: {msg}", hint=hint) from e


# ------------------------------------------------------------------------------------------ find / remove
@dataclass
class ExistingAccess:
    roles: dict[str, int]  # name -> roleId
    permissions: list[object]  # vim.AuthorizationManager.Permission
    local_users: list[str]  # ESXi users created by setup
    unverified_users: list[str] = field(default_factory=list)  # ESXi users with our role we did not create
    folders: list[tuple[object, str, int]] = field(default_factory=list)  # (folder, name, items inside) setup made
    orphan_label: bool = False  # the `vmdeploy` custom attribute exists but no folder uses it any more
    other_folders: list[tuple[str, str]] = field(default_factory=list)  # (name, account) made for other setups

    @property
    def empty(self) -> bool:
        return not self.roles and not self.folders and not self.orphan_label

    def principals(self) -> list[str]:
        return sorted({p.principal for p in self.permissions})


def find_existing(conn: Connection, role_name: str = DEFAULT_ROLE) -> ExistingAccess:
    am = conn.content.authorizationManager
    roles = {n: r.roleId for n, r in _roles_by_name(am).items()
             if n in (role_name, role_name + READ_SUFFIX, role_name + IMAGES_SUFFIX, role_name + BROWSE_SUFFIX)}
    perms = [p for rid in roles.values() for p in am.RetrieveRolePermissions(roleId=rid) or []]
    users, unverified = [], []
    if not conn.is_vcenter:
        for name in {p.principal for p in perms if not p.group}:
            u = _find_local_user(conn, name)
            if u is not None and (u.fullName or "") == LOCAL_USER_MARKER:
                users.append(name)
            elif u is not None:
                unverified.append(name)  # never delete an account setup cannot prove it created
    principals = {p.principal.lower() for p in perms}
    marked = _marked_folders(conn)
    active = None if principals else _accounts_with_access(conn)

    def ours(owner: str, role: str) -> bool:
        """Is this labelled folder part of this setup? Never one labelled for another role. With permissions of
        this role: a folder made for one of its accounts. Without any (an earlier `access remove` kept the VMs, so
        only the folder is left): a leftover whose account has no access anywhere any more. A folder whose
        account still has access belongs to an active setup and is never touched (nor, with --delete-vms, its
        VMs), e.g. after a mistyped --role-name."""
        if role and role != role_name:
            return False
        if principals:
            return owner.lower() in principals
        return active is not None and bool(owner) and owner.lower() not in active

    folders = [(f, f.name, n) for f, n, owner, role in marked if ours(owner, role)]
    others = [(f.name, owner) for f, _n, owner, role in marked if not ours(owner, role)]
    # e.g. the folder was deleted by hand in the vSphere Client: the attribute definition stays behind
    orphan = conn.is_vcenter and not marked and _marker_key(conn.content) is not None
    return ExistingAccess(roles, perms, sorted(users), sorted(unverified), folders, orphan, others)


def _accounts_with_access(conn: Connection) -> set[str] | None:
    """Accounts (lower case) holding any permission anywhere, with a role that still exists; None if that cannot
    be read (then no leftover folder is claimed)."""
    am = conn.content.authorizationManager
    try:
        live = {r.roleId for r in am.roleList or []}
        return {p.principal.lower() for p in am.RetrieveAllPermissions() or [] if p.roleId in live}
    except Exception as e:  # noqa: BLE001
        log.debug("could not read all permissions: %s", e)
        return None


def _marker_key(content, create: bool = False) -> int | None:
    cfm = getattr(content, "customFieldsManager", None)
    if cfm is None:
        return None
    existing = next((f for f in cfm.field or [] if f.name == FOLDER_MARKER_FIELD), None)
    if existing is not None:
        return existing.key
    if not create:
        return None
    return cfm.AddCustomFieldDef(name=FOLDER_MARKER_FIELD, moType=vim.Folder).key


def _mark_folder(content, folder, principal: str, role_name: str = "") -> None:
    key = _marker_key(content, create=True)
    content.customFieldsManager.SetField(entity=folder, key=key, value=f"{LOCAL_USER_MARKER} for {principal}"
                                         + (f"; role {role_name}" if role_name else ""))


def _marked_folders(conn: Connection) -> list[tuple[object, int, str, str]]:
    """Folders setup created: (folder, number of items inside, account it was created for, role or "" for
    labels written before the role was recorded)."""
    if not conn.is_vcenter:
        return []
    content = conn.content
    key = _marker_key(content)
    if key is None:
        return []
    view = content.viewManager.CreateContainerView(content.rootFolder, [vim.Folder], True)
    try:
        out = []
        for f in view.view:
            value = next((cv.value for cv in getattr(f, "customValue", None) or [] if cv.key == key), None)
            if value and value.startswith(LOCAL_USER_MARKER):
                owner, _, role = (value.split(" for ", 1)[1] if " for " in value else "").partition("; role ")
                out.append((f, len(f.childEntity or []), owner, role))
        return out
    finally:
        view.Destroy()


def missing_from_role(conn: Connection, role_name: str) -> list[str] | None:
    """Deploy privileges the server does NOT hold in the role (vCenter can drop some silently).
    None if the role is not visible to this account."""
    role = _roles_by_name(conn.content.authorizationManager).get(role_name)
    if role is None:
        return None
    held = set(role.privilege or [])
    return [p for p in deploy_privileges(known_privilege_ids(conn)) if p not in held]


def find_all_setups(conn: Connection) -> list[str]:
    """Role names that look like ours (for `doctor`): any role with a companion '-read' role, or the default."""
    try:
        names = set(_roles_by_name(conn.content.authorizationManager))
    except Exception:  # noqa: BLE001
        return []
    return sorted(n for n in names if n == DEFAULT_ROLE or (n + READ_SUFFIX) in names)


# ------------------------------------------------------------------------------------------ history
def _history_path():
    from .paths import config_dir

    return config_dir() / "access_history.json"


def load_history() -> list[dict]:
    """Accounts `access setup` was used with from this computer: endpoint, principal, setup/removed dates.
    Nothing secret: it lets `access audit` remind you about accounts that may no longer be needed."""
    import json

    p = _history_path()
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8")).get("accounts", [])
    except (ValueError, OSError) as e:
        log.debug("access history unreadable: %s", e)
        return []


def _save_history(entries: list[dict]) -> None:
    import json

    p = _history_path()
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps({"accounts": entries}, indent=2), encoding="utf-8")
    tmp.replace(p)


def same_endpoint(a: str, b: str) -> bool:
    """One server, however the letters of its host name were typed (see trust.endpoint_key)."""
    return endpoint_key(a) == endpoint_key(b)


def record_setup(endpoint: str, principal: str, *, created_local_user: bool = False) -> None:
    from datetime import UTC, datetime

    now = datetime.now(UTC).isoformat(timespec="seconds")
    entries = [e for e in load_history()
               if not (same_endpoint(e["endpoint"], endpoint) and e["principal"].lower() == principal.lower())]
    entries.append({"endpoint": endpoint, "principal": principal, "setup": now, "removed": None,
                    "created_by_vmdeploy": created_local_user})
    _save_history(entries)


def record_removed(endpoint: str, principals) -> None:
    from datetime import UTC, datetime

    wanted = {p.lower() for p in principals}
    now = datetime.now(UTC).isoformat(timespec="seconds")
    entries = load_history()
    for e in entries:
        if same_endpoint(e["endpoint"], endpoint) and e["principal"].lower() in wanted:
            e["removed"] = now
    _save_history(entries)


def forget_account(endpoint: str, principal: str) -> None:
    _save_history([e for e in load_history()
                   if not (same_endpoint(e["endpoint"], endpoint) and e["principal"].lower() == principal.lower())])


def account_exists(conn: Connection, principal: str) -> bool | None:
    """Does the user still exist? None if the server cannot tell."""
    domain, _, name = principal.rpartition("\\")
    try:
        ud = conn.content.userDirectory
        domains = [d for d in (ud.domainList or []) if d.lower() == domain.lower()] if domain else [None]
        if domain and not domains:
            domains = [domain]
        for d in domains:
            # Not exactMatch: vCenter's exact match is case-sensitive ("administrator" does not find
            # "Administrator"), while sign-in names are not. The comparison below is exact, ignoring case.
            for r in ud.RetrieveUserGroups(domain=d, searchStr=name or principal, exactMatch=False,
                                           findUsers=True, findGroups=False) or []:
                found = r.principal.split("\\")[-1].split("@")[0]
                if found.lower() == (name or principal).lower():
                    return True
        return False
    except vim.fault.NotFound:
        return False
    except Exception as e:  # noqa: BLE001
        log.debug("user lookup failed for %s: %s", principal, e)
        return None


def user_missing(conn: Connection, principal: str) -> bool:
    """`access setup` on vCenter: True only when the directory says the user does not exist (vmdeploy cannot
    create vCenter users). Unknown counts as present: vCenter itself then reports it when granting access."""
    return account_exists(conn, principal) is False


def accounts_named_vmdeploy(conn: Connection) -> list[str]:
    """Users whose name starts with 'vmdeploy' in the server's user directory (SSO/AD domains, or ESXi)."""
    out: set[str] = set()
    try:
        ud = conn.content.userDirectory
        for d in (ud.domainList or [None]) if conn.is_vcenter else [None]:
            try:
                for r in ud.RetrieveUserGroups(domain=d, searchStr="vmdeploy", exactMatch=False,
                                               findUsers=True, findGroups=False) or []:
                    if r.principal.split("\\")[-1].lower().startswith("vmdeploy"):
                        out.add(f"{d.upper()}\\{r.principal.split(chr(92))[-1]}" if d else r.principal)
            except Exception as e:  # noqa: BLE001 - one directory (e.g. AD) failing must not stop the others
                log.debug("directory search in %s failed: %s", d, e)
    except Exception as e:  # noqa: BLE001
        log.debug("user directory unavailable: %s", e)
    return sorted(out)


def entity_label(entity) -> str:
    if entity is None:
        return "an object the server did not name"
    from .inventory import display

    kind = type(entity).__name__.rsplit(".", 1)[-1]
    try:
        return f"{kind} {display(entity.name)}"
    except Exception:  # noqa: BLE001
        return kind


@dataclass
class FolderVM:
    vm: object  # vim.VirtualMachine
    name: str
    ours: bool  # deployed by vmdeploy (its Notes carry the marker), as read for the plan


def vms_in_folders(conn: Connection, folders) -> list[tuple[str, list[FolderVM]]]:
    """(folder name, its VMs and its subfolders' VMs sorted by name) per folder, with each VM's name and marker
    read in one request per folder (it was a request per VM and property). Each VM is listed once: with a
    permission on a parent of setup's folder, the child's VMs were listed (and their deletion attempted) twice. A
    failed read stops here, before the plan, rather than show every VM as not deployed by vmdeploy."""
    from . import vmnotes
    from .inventory import vm_properties
    from .tasks import fault_message

    out, listed = [], set()
    for folder in folders:
        label = folder._moId  # noqa: SLF001 - known without a request, should reading the name fail too
        try:
            label = folder.name
            rows = vm_properties(conn, ["name", "config.annotation"], root=folder)
        except Exception as e:  # noqa: BLE001
            why = e.message if isinstance(e, VmDeployError) else f"Could not read the VMs: {fault_message(e)}"
            raise DeploymentError(f"{why} (folder {label}). Nothing was changed.",
                                  hint="Run `vmdeploy access remove` again.") from e
        vms = sorted((FolderVM(vm, str(props.get("name", "?")), vmnotes.is_marked(props.get("config.annotation")))
                      for vm, props in rows if vm._moId not in listed), key=lambda r: r.name)  # noqa: SLF001
        listed.update(r.vm._moId for r in vms)  # noqa: SLF001
        if vms:
            out.append((label, vms))
    return out


def delete_planned(conn: Connection, folder_vms: list[tuple[str, list[FolderVM]]], warn,
                   on_removed: Callable[[str], None] | None = None) -> tuple[list[str], list]:
    """Delete the VMs the plan listed as deployed by vmdeploy. Each one is read again right before its deletion,
    in one small request (its Notes and CD/DVD drives, not its whole configuration), and kept if it can no longer
    be read or its Notes no longer carry the marker; `warn` says why. `on_removed` is told of each deletion as it
    happens. Returns (what was deleted, the vmdeploy ISO copies those VMs used, as (datacenter name, path))."""
    from . import isocopies, vmnotes
    from .inventory import vm_properties_of

    done: list[str] = []
    isos: list[tuple[str | None, str]] = []

    def keep(text: str) -> None:
        log.warning("%s", text, extra=FILE_ONLY)
        warn(text)

    for _folder, recs in folder_vms:
        for r in recs:
            if not r.ours:
                keep(f"Kept VM '{r.name}': it was not deployed by vmdeploy.")
                continue
            try:
                props = vm_properties_of(conn, r.vm, ["config.annotation", "config.hardware.device"])
            except DeploymentError as e:
                keep(f"Kept VM '{r.name}': {e.message}")
                continue
            if not vmnotes.is_marked(props.get("config.annotation")):
                keep(f"Kept VM '{r.name}': its Notes no longer mark it as deployed by vmdeploy.")
                continue
            attached = [path for _dc, path in isocopies.copies_attached(props.get("config.hardware.device"), None)]
            dc = isocopies.datacenter_of(r.vm) if attached else None  # its own datacenter, only when needed
            delete_vm(r.vm, r.name)  # logged there
            isos += [(dc, path) for path in attached]
            done.append(f"VM {r.name} (powered off and deleted)")
            if on_removed is not None:
                on_removed(done[-1])
    return done, isos


def emptied_by_deleting_vms(folder, is_ours) -> bool:
    """Would deleting the account's VMs leave `folder` empty? Only VMs vmdeploy deployed (`is_ours`, from the plan's
    read) are deleted, and only VMs: anything else directly inside (another VM, a subfolder, a vApp) keeps the
    folder."""
    children = list(folder.childEntity or [])
    return bool(children) and all(isinstance(c, vim.VirtualMachine) and is_ours(c) for c in children)


def label_plan(folders: list[tuple[int, bool]], other_setups: bool, orphan: bool) -> str | None:
    """How `access remove`'s plan describes the `vmdeploy` custom attribute, or None when it stays. remove() below
    deletes it once no folder carries it (checked on the server after the folders are gone); this is the same rule
    predicted for the plan. `folders`: setup's folders as (items inside, emptied by deleting the account's VMs)."""
    if orphan:
        return "no folder uses it any more"
    if not folders or other_setups or any(items and not may_empty for items, may_empty in folders):
        return None  # a folder that keeps it remains
    if all(items == 0 for items, _ in folders):
        return "the label on the folder(s) above; no other folder uses it"
    return "the label on the folder(s) above: removed too if they are deleted"


def remove(conn: Connection, existing: ExistingAccess, on_removed: Callable[[str], None] | None = None) -> list[str]:
    """Delete the permissions, roles and (ESXi) local users that setup created. Returns what was removed; each
    removal is logged, and passed to `on_removed`, as it happens (a failure part-way still shows what was done).

    Permissions are removed one by one where the server names their object; removing a role with
    failIfUsed=False then deletes any permission still using it, so nothing is left behind either way."""
    content = conn.content
    am = content.authorizationManager
    done: list[str] = []

    def removed(text: str) -> None:
        done.append(text)
        log.info("Removed: %s", text, extra=FILE_ONLY)
        if on_removed is not None:
            on_removed(text)

    unnamed = []  # permissions on an object the server did not name: they go with their role
    for p in existing.permissions:
        if p.entity is None:
            unnamed.append(p)
            continue
        am.RemoveEntityPermission(entity=p.entity, user=p.principal, isGroup=p.group)
        removed(f"Permission for {p.principal} on {entity_label(p.entity)}")
    for name, rid in existing.roles.items():
        am.RemoveAuthorizationRole(roleId=rid, failIfUsed=False)  # also drops permissions still using the role
        removed(f"Role {name}")
    for p in unnamed:
        removed(f"Permission for {p.principal} on {entity_label(None)} (with its role)")
    for user in existing.local_users:
        content.accountManager.RemoveUser(userName=user)
        removed(f"Local user {user}")
    for folder, name, items in existing.folders:
        if items == 0:
            wait_task(folder.Destroy_Task(), what="Delete folder")
            removed(f"VM folder {name} (was empty)")
    if (existing.folders or existing.orphan_label) and not _marked_folders(conn):  # label_plan() predicts this
        key = _marker_key(content)
        if key is not None:  # no folder carries the label any more: remove the custom attribute too
            content.customFieldsManager.RemoveCustomFieldDef(key=key)
            removed(f"Custom attribute '{FOLDER_MARKER_FIELD}'")
    return done
