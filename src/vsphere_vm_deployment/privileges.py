"""Least-privilege checks: does the signed-in account hold the privileges a deployment needs?"""

from __future__ import annotations

import logging
from importlib import resources

import yaml

from .connection import Connection

log = logging.getLogger(__name__)

# Filled by deploy_scope(): objects where some but not all privileges are granted, per kind, with the missing IDs.
_partial: dict[str, list[tuple[str, list[str]]]] = {}


def closest_partial(kind: str, limit: int = 3) -> list[tuple[str, list[str]]]:
    """The objects of this kind that came closest (fewest missing privileges) in the last deploy_scope() call."""
    return sorted(_partial.get(kind, []), key=lambda x: len(x[1]))[:limit]


def required_privileges() -> dict[str, list[str]]:
    text = resources.files("vsphere_vm_deployment.data").joinpath("privileges.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)


def known_privilege_ids(conn: Connection) -> set[str] | None:
    try:
        ids = {p.privId for p in conn.content.authorizationManager.privilegeList or []}
    except Exception as e:  # noqa: BLE001
        log.debug("privilegeList unavailable: %s", e)
        return None
    return ids or None  # an empty list means the server does not expose privileges (e.g. a simulator)


def _on_parent(conn: Connection) -> set[str]:
    """Privileges the server checks on the *parent* of an object (AuthorizationPrivilege.onParent), e.g.
    VirtualMachine.Inventory.Delete: deleting a VM needs it on the folder holding the VM. Asking about such a
    privilege on a folder therefore checks the folder's parent, which is the wrong question."""
    try:
        return {p.privId for p in conn.content.authorizationManager.privilegeList or []
                if getattr(p, "onParent", False)}
    except Exception:  # noqa: BLE001
        return set()


def _child_vm(entity):
    """A VM directly inside a folder, used to check parent-checked privileges on that folder."""
    try:
        return next((c for c in getattr(entity, "childEntity", None) or []
                     if type(c).__name__.endswith("VirtualMachine")), None)
    except Exception:  # noqa: BLE001
        return None


def _lacking(am, session_key, entity, ids: list[str], on_parent: set[str]) -> list[str]:
    """Privileges in `ids` the account does not hold on `entity`. Parent-checked privileges are asked about
    on a VM inside the entity (which checks the entity itself, exactly as a real delete does); if there is
    none they cannot be checked in advance and are not reported."""
    normal = [i for i in ids if i not in on_parent]
    parent = [i for i in ids if i in on_parent]
    lacking: list[str] = []
    if normal:
        result = am.HasPrivilegeOnEntities(entity=[entity], sessionId=session_key, privId=normal)
        lacking += [a.privId for r in result for a in r.privAvailability if not a.isGranted]
    if parent:
        probe = _child_vm(entity)
        if probe is not None:
            result = am.HasPrivilegeOnEntities(entity=[probe], sessionId=session_key, privId=parent)
            lacking += [a.privId for r in result for a in r.privAvailability if not a.isGranted]
    return lacking


def check(conn: Connection, targets: dict[str, object]) -> dict[str, list[str]] | None:
    """`targets` maps a privileges.yaml group (folder, resource_pool, datastore, network, virtual_machine)
    to the inventory object to check it on. Returns {group: [missing privilege ids]}, or None when the
    server cannot answer (e.g. older APIs or a simulator)."""
    groups = required_privileges()
    am = conn.content.authorizationManager
    try:
        session_key = conn.content.sessionManager.currentSession.key
    except Exception:  # noqa: BLE001
        return None
    known = known_privilege_ids(conn)
    if known is None:
        return None
    on_parent = _on_parent(conn)
    missing: dict[str, list[str]] = {}
    for group, entity in targets.items():
        ids = [p for p in groups.get(group, []) if p in known]
        if not ids or entity is None:
            continue
        try:
            lacking = _lacking(am, session_key, entity, ids, on_parent)
        except Exception as e:  # noqa: BLE001
            log.debug("HasPrivilegeOnEntities failed: %s", e)
            return None
        if lacking:
            missing[group] = lacking
    return missing


def deploy_scope(conn: Connection, inv) -> dict[str, list[str]] | None:
    """Where the signed-in account holds *all* privileges a deployment needs, per kind of object, e.g.
    {"VM folders": ["/vmdeploy-test"], "Hosts / clusters": [...], "Datastores": [...], "Networks": [...]}.
    Checked on exactly the objects a deployment uses (the resource pool for placement), so a restricted
    account sees where it can deploy instead of a list of what it lacks at the top. None if not answerable."""
    groups = required_privileges()
    am = conn.content.authorizationManager
    known = known_privilege_ids(conn)
    try:
        session_key = conn.content.sessionManager.currentSession.key
    except Exception:  # noqa: BLE001
        return None
    if known is None:
        return None
    many = len(inv.datacenters) > 1
    candidates: dict[str, tuple[list[str], list[tuple[str, object]]]] = {
        "VM folders": (groups["folder"] + groups["virtual_machine"], []),
        "Hosts / clusters": (groups["resource_pool"], []),
        "Datastores": (groups["datastore"], []),
        "Networks": (groups["network"], []),
    }
    for dc in inv.datacenters.values():
        prefix = f"{dc.name}: " if many else ""
        candidates["VM folders"][1].extend((prefix + path, obj) for path, obj in sorted(dc.folders.items()))
        candidates["Hosts / clusters"][1].extend(
            [(f"{prefix}Cluster {n}", c.resource_pool) for n, c in sorted(dc.clusters.items())]
            + [(f"{prefix}Host {h}", pool) for h, pool in sorted(dc.standalone_pools.items())])
        candidates["Datastores"][1].extend((prefix + n, d.obj) for n, d in sorted(dc.datastores.items()))
        candidates["Networks"][1].extend((prefix + n.name, n.obj) for n in dc.usable_networks())
    scope: dict[str, list[str]] = {}
    _partial.clear()
    on_parent = _on_parent(conn)
    for kind, (ids, objs) in candidates.items():
        ids = sorted({p for p in ids if p in known})
        if not objs or not ids:
            scope[kind] = []
            continue
        normal = [i for i in ids if i not in on_parent]
        parent = [i for i in ids if i in on_parent]
        lacking_by: dict[str, list[str]] = {o._moId: [] for _, o in objs}  # noqa: SLF001
        try:
            if normal:
                result = am.HasPrivilegeOnEntities(entity=[o for _, o in objs], sessionId=session_key, privId=normal)
                for r in result:
                    lacking_by[r.entity._moId] = [a.privId for a in r.privAvailability if not a.isGranted]  # noqa: SLF001
            for _, o in objs if parent else []:
                lacking_by[o._moId] += _lacking(am, session_key, o, parent, on_parent)  # noqa: SLF001
        except Exception as e:  # noqa: BLE001
            log.debug("HasPrivilegeOnEntities failed: %s", e)
            return None
        scope[kind] = [label for label, o in objs if not lacking_by[o._moId]]  # noqa: SLF001
        for label, o in objs:
            lacking = lacking_by[o._moId]  # noqa: SLF001
            if lacking and len(lacking) < len(ids):
                _partial.setdefault(kind, []).append((label, lacking))
    return scope


def on_parent_ids(conn: Connection) -> list[str]:
    """Required privileges the server marks as checked on the *parent* of an object (privilege `onParent`).
    Asking about such a privilege on a folder checks the folder's parent, not the folder."""
    wanted = {p for ids in required_privileges().values() for p in ids}
    try:
        return sorted(p.privId for p in conn.content.authorizationManager.privilegeList or []
                      if p.privId in wanted and getattr(p, "onParent", False))
    except Exception:  # noqa: BLE001
        return []


def unknown_ids(conn: Connection) -> list[str]:
    known = known_privilege_ids(conn)
    if known is None:
        return []
    return [p for ids in required_privileges().values() for p in ids if p not in known]
