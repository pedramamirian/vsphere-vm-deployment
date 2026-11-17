"""`vmdeploy access setup / remove` logic against an in-memory fake of the vSphere authorization API."""

import string
from types import SimpleNamespace as NS

import pytest

from vsphere_vm_deployment import access
from vsphere_vm_deployment.errors import ConfigError, VmDeployError
from vsphere_vm_deployment.privileges import required_privileges


class Entity:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return f"Entity({self.name})"


class FakeAuthManager:
    def __init__(self, known, fail_on_grant=None):
        self.privilegeList = [NS(privId=p) for p in known]
        self._roles = {-1: NS(roleId=-1, name="Admin", privilege=[]), -2: NS(roleId=-2, name="ReadOnly", privilege=[])}
        self._next = 100
        self.perms = {}  # (entity, principal lower) -> NS
        self.fail_on_grant = fail_on_grant
        self.grants = 0

    @property
    def roleList(self):
        return list(self._roles.values())

    def AddAuthorizationRole(self, name, privIds):  # noqa: N802 - vSphere API names
        self._next += 1
        self._roles[self._next] = NS(roleId=self._next, name=name, privilege=list(privIds))
        return self._next

    def UpdateAuthorizationRole(self, roleId, newName, privIds):  # noqa: N802, N803
        self._roles[roleId].privilege = list(privIds)

    def RemoveAuthorizationRole(self, roleId, failIfUsed):  # noqa: N802, N803
        del self._roles[roleId]
        self.perms = {k: v for k, v in self.perms.items() if v.roleId != roleId}

    def SetEntityPermissions(self, entity, permission):  # noqa: N802
        self.grants += 1
        if self.fail_on_grant == self.grants:
            raise RuntimeError("simulated failure")
        for p in permission:
            self.perms[(entity, p.principal.lower())] = NS(entity=entity, principal=p.principal, group=p.group,
                                                          roleId=p.roleId, propagate=p.propagate)

    def RetrieveEntityPermissions(self, entity, inherited):  # noqa: N802
        return [p for (e, _), p in self.perms.items() if e is entity]

    def RetrieveRolePermissions(self, roleId):  # noqa: N802, N803
        return [p for p in self.perms.values() if p.roleId == roleId]

    def RetrieveAllPermissions(self):  # noqa: N802
        return list(self.perms.values())

    def RemoveEntityPermission(self, entity, user, isGroup):  # noqa: N802, N803
        del self.perms[(entity, user.lower())]


class FakeAccounts:
    def __init__(self):
        self.users = {}  # name -> description

    def CreateUser(self, user):  # noqa: N802
        self.users[user.id] = user.description

    def RemoveUser(self, userName):  # noqa: N802, N803
        del self.users[userName]


class FakeDirectory:
    def __init__(self, accounts):
        self.accounts = accounts

    def RetrieveUserGroups(self, searchStr, exactMatch, findUsers, findGroups, **_):  # noqa: N802, N803
        return [NS(principal=n, fullName=d, group=False) for n, d in self.accounts.users.items() if n == searchStr]


ALL_IDS = {p for ids in required_privileges().values() for p in ids}


def make_conn(*, vcenter=True, fail_on_grant=None):
    accounts = FakeAccounts()
    content = NS(authorizationManager=FakeAuthManager(ALL_IDS, fail_on_grant), rootFolder=Entity("root"),
                 accountManager=accounts, userDirectory=FakeDirectory(accounts))
    return NS(content=content, is_vcenter=vcenter)


def vcenter_plan(conn, principal="svc-deploy@vsphere.local"):
    return access.build_vcenter_plan(conn, principal=principal, role_name="vmdeploy-deployer",
                                     folder=("/Lab", Entity("Lab")), compute=("Cluster C1", Entity("C1")),
                                     datastores=[("ds1", Entity("ds1"))], networks=[("VM Network", Entity("net"))])


# ------------------------------------------------------------------------------------------ helpers
@pytest.mark.parametrize(("given", "expected"), [
    ("svc-deploy@vsphere.local", "VSPHERE.LOCAL\\svc-deploy"),
    ("vsphere.example.internal\\svc", "VSPHERE.EXAMPLE.INTERNAL\\svc"),
    (" deployer@corp.example.com ", "CORP.EXAMPLE.COM\\deployer"),
])
def test_normalize_principal(given, expected):
    assert access.normalize_principal(given) == expected


@pytest.mark.parametrize("bad", ["svc-deploy", "@vsphere.local", "svc@"])
def test_normalize_principal_rejects_names_without_domain(bad):
    with pytest.raises(ConfigError):
        access.normalize_principal(bad)


def test_generated_password_meets_esxi_policy_and_is_shell_safe():
    for _ in range(50):
        pw = access.generate_password()
        assert len(pw) == 24
        assert any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
        assert any(c in string.punctuation for c in pw)
        assert not set(pw) & set("'\"`$\\ []")


def test_deploy_role_has_only_deploy_privileges():
    privs = access.deploy_privileges(ALL_IDS)
    assert "VApp.Import" in privs and "Network.Assign" in privs
    assert not {"System.Read", "Authorization.ModifyRoles", "Host.Local.ManageUserGroups"} & set(privs)
    assert "Network.Assign" not in access.deploy_privileges(ALL_IDS - {"Network.Assign"})  # unknown IDs dropped


def test_esxi_user_name_rules():
    assert access.validate_esxi_user("vmdeploy") == "vmdeploy"
    for bad in ("root", "Admin", "1abc", "a b"):
        with pytest.raises(ConfigError):
            access.validate_esxi_user(bad)


# ------------------------------------------------------------------------------------------ setup
def test_vcenter_setup_creates_scoped_permissions():
    conn = make_conn()
    plan = vcenter_plan(conn)
    access.apply(conn, plan)
    am = conn.content.authorizationManager
    names = {r.name: r for r in am.roleList}
    assert set(names) >= {"vmdeploy-deployer", "vmdeploy-deployer-read"}
    assert names["vmdeploy-deployer-read"].privilege == []
    granted = {(p.entity.name, am._roles[p.roleId].name, p.propagate) for p in am.perms.values()}
    assert granted == {("root", "vmdeploy-deployer-read", True), ("Lab", "vmdeploy-deployer", True),
                       ("C1", "vmdeploy-deployer", False), ("ds1", "vmdeploy-deployer", False),
                       ("net", "vmdeploy-deployer", False)}
    assert all(p.principal == "VSPHERE.LOCAL\\svc-deploy" for p in am.perms.values())


def test_esxi_setup_creates_local_user_with_marker():
    conn = make_conn(vcenter=False)
    plan = access.build_esxi_plan(conn, username="vmdeploy", role_name="vmdeploy-deployer")
    access.apply(conn, plan)
    assert conn.content.accountManager.users == {"vmdeploy": access.LOCAL_USER_MARKER}
    assert access.local_user_exists(conn, "vmdeploy")
    [perm] = conn.content.authorizationManager.perms.values()
    assert perm.entity.name == "root" and perm.propagate


def test_failed_setup_rolls_everything_back():
    conn = make_conn(vcenter=False, fail_on_grant=1)
    plan = access.build_esxi_plan(conn, username="vmdeploy", role_name="vmdeploy-deployer")
    with pytest.raises(VmDeployError) as e:
        access.apply(conn, plan)
    assert "removed again" in e.value.hint
    assert "while granting vmdeploy-deployer on This ESXi host" in e.value.message  # says which step failed
    am = conn.content.authorizationManager
    assert conn.content.accountManager.users == {}
    assert "vmdeploy-deployer" not in {r.name for r in am.roleList} and am.perms == {}


def test_a_failed_rerun_puts_the_earlier_access_back_instead_of_removing_it():
    """Re-running setup for a working account and failing part-way removed the account's earlier permissions and
    left changed roles changed (code review). Now they are put back as they were."""
    conn = make_conn(fail_on_grant=3)  # the third grant (the cluster) fails
    am = conn.content.authorizationManager
    am.AddAuthorizationRole(name="vmdeploy-deployer", privIds=["Earlier.Privilege"])
    rid = next(r.roleId for r in am.roleList if r.name == "vmdeploy-deployer")
    plan = vcenter_plan(conn)
    folder = next(g.entity for g in plan.grants if g.label == "VM folder /Lab")
    am.perms[(folder, "vsphere.local\\svc-deploy")] = NS(entity=folder, principal="VSPHERE.LOCAL\\svc-deploy",
                                                         group=False, roleId=rid, propagate=False)
    with pytest.raises(VmDeployError) as e:
        access.apply(conn, plan)
    assert "put back" in e.value.hint
    restored = am.perms[(folder, "vsphere.local\\svc-deploy")]
    assert (restored.roleId, restored.propagate) == (rid, False)  # still there, as it was
    assert am._roles[rid].privilege == ["Earlier.Privilege"]  # the role's earlier privileges
    assert (conn.content.rootFolder, "vsphere.local\\svc-deploy") not in am.perms  # new grants removed
    assert "vmdeploy-deployer-read" not in {r.name for r in am.roleList}  # new role removed


def test_existing_permission_for_the_user_is_reported_not_overwritten():
    conn = make_conn()
    am = conn.content.authorizationManager
    am.perms[(conn.content.rootFolder, "vsphere.local\\svc-deploy")] = NS(
        entity=conn.content.rootFolder, principal="VSPHERE.LOCAL\\svc-deploy", group=False, roleId=-1, propagate=True)
    clash = access.conflicts(conn, vcenter_plan(conn))
    assert clash == ["Top of the inventory (read-only, to discover it): already has role 'Admin'"]


def _rights(conn, by_entity):
    """vCenter's effective privileges of the account per object (groups and inheritance resolved)."""
    calls = []

    def fetch(entities, userName):
        calls.append(userName)
        return [NS(entity=e, privileges=sorted(by_entity.get(e.name, set()))) for e in entities]

    conn.content.authorizationManager.FetchUserPrivilegeOnEntities = fetch
    return calls


def test_an_administrator_through_a_group_is_refused_before_anything_changes():
    """vCenter's Administrators group at the top: a user permission there (and on the folder etc.) would replace
    it, so setup would quietly demote the account. Found from the account's effective privileges."""
    conn = make_conn()
    admin = set(ALL_IDS) | {"Authorization.ModifyPermissions", "Sys.Admin.Example"}
    calls = _rights(conn, {n: admin for n in ("root", "Lab", "C1", "ds1", "net")})
    found = access.inherited_rights(conn, vcenter_plan(conn))
    assert calls == ["VSPHERE.LOCAL\\svc-deploy"]
    assert len(found) == 5 and all("privilege(s) setup would not grant" in f for f in found)
    assert any(f.startswith("Top of the inventory") and "Authorization.ModifyPermissions" in f for f in found)
    assert conn.content.authorizationManager.perms == {}  # a check only


def test_a_dedicated_account_or_a_rerun_of_setup_passes():
    conn = make_conn()
    plan = vcenter_plan(conn)
    _rights(conn, {})  # a new user: nothing beyond System.*
    assert access.inherited_rights(conn, plan) == []
    # Setup ran before for this account: it holds exactly what setup grants, which is not a reason to refuse.
    ours = set(plan.privileges) | {"System.Read", "System.View", "System.Anonymous"}
    _rights(conn, {"Lab": ours, "C1": ours, "ds1": ours, "net": ours, "root": {"System.Read"}})
    assert access.inherited_rights(conn, plan) == []


def test_a_new_folder_is_checked_through_its_parent():
    conn = make_conn()
    plan = vcenter_plan(conn)
    plan.new_folder = (Entity("Parent"), "Deploy")
    folder = next(g for g in plan.grants if getattr(g.entity, "name", None) == "Lab")
    folder.entity = None  # created by apply(): nobody has permissions on it yet, but it inherits from Parent
    _rights(conn, {"Parent": {"VirtualMachine.Interact.Backup.Example"}})
    found = access.inherited_rights(conn, plan)
    assert found and "VirtualMachine.Interact.Backup.Example" in found[0]


def test_rights_at_the_top_are_checked_before_the_placement_questions():
    conn = make_conn()
    calls = _rights(conn, {"root": {"Authorization.ModifyPermissions", "Global.Settings", "System.Read"}})
    assert access.rights_at_top(conn, "VSPHERE.LOCAL\\administrator") == ["Authorization.ModifyPermissions",
                                                                          "Global.Settings"]
    assert calls == ["VSPHERE.LOCAL\\administrator"]
    _rights(conn, {"root": {"System.Read", "System.View", "System.Anonymous"}})  # dedicated, or a setup rerun
    assert access.rights_at_top(conn, "VSPHERE.LOCAL\\svc-deploy") == []
    assert access.rights_at_top(make_conn(), "VSPHERE.LOCAL\\svc-deploy") is None  # cannot tell: later checks


def test_when_vcenter_cannot_tell_the_check_says_so():
    conn = make_conn()  # the fake has no FetchUserPrivilegeOnEntities, like an older server or vcsim
    assert access.inherited_rights(conn, vcenter_plan(conn)) is None


# ------------------------------------------------------------------------------------------ remove
def test_remove_deletes_only_what_setup_created():
    conn = make_conn()
    am = conn.content.authorizationManager
    other = Entity("other-folder")
    am.perms[(other, "vsphere.local\\someone")] = NS(entity=other, principal="VSPHERE.LOCAL\\someone",
                                                     group=False, roleId=-2, propagate=True)
    access.apply(conn, vcenter_plan(conn))

    found = access.find_existing(conn)
    assert len(found.permissions) == 5 and found.principals() == ["VSPHERE.LOCAL\\svc-deploy"]
    done = access.remove(conn, found)

    assert len(done) == 7  # 5 permissions + 2 roles
    assert list(am.perms) == [(other, "vsphere.local\\someone")]  # the administrator's own permission is untouched
    assert {r.name for r in am.roleList} == {"Admin", "ReadOnly"}
    assert access.find_existing(conn).empty


def test_a_role_without_permissions_never_claims_other_setups_folders(monkeypatch):
    """Code review: with no permission of the role (e.g. a mistyped --role-name), every folder vmdeploy ever made
    counted as this role's, and `access remove --delete-vms` deleted them and the VMs inside."""
    conn = make_conn()
    access.apply(conn, vcenter_plan(conn))  # svc-deploy holds vmdeploy-deployer
    mine, theirs, left, other_role = (Entity("svc-deploy-vms"), Entity("bob-vms"), Entity("old-vms"),
                                      Entity("ci-vms"))
    am = conn.content.authorizationManager
    bob_role = am.AddAuthorizationRole(name="team-b", privIds=["System.Read"])
    am.SetEntityPermissions(Entity("x"), [NS(principal="VSPHERE.LOCAL\\bob", group=False, roleId=bob_role,
                                            propagate=True)])
    monkeypatch.setattr(access, "_marked_folders", lambda c: [
        (mine, 0, "VSPHERE.LOCAL\\svc-deploy", "vmdeploy-deployer"),
        (theirs, 3, "VSPHERE.LOCAL\\bob", ""),                   # an older label; bob still has access
        (left, 1, "VSPHERE.LOCAL\\gone", ""),                    # left behind: its account has no access
        (other_role, 2, "VSPHERE.LOCAL\\gone2", "vmdeploy-ci")])  # made for another role
    found = access.find_existing(conn)
    assert [name for _f, name, _n in found.folders] == ["svc-deploy-vms"]
    assert {name for name, _owner in found.other_folders} == {"bob-vms", "old-vms", "ci-vms"}
    typo = access.find_existing(conn, "vmdeploy-deployr")  # no such role: no permissions
    assert [name for _f, name, _n in typo.folders] == ["old-vms"]  # only the leftover nobody can use any more
    assert {name for name, _owner in typo.other_folders} == {"svc-deploy-vms", "bob-vms", "ci-vms"}


def test_setup_records_the_role_on_the_folder_it_creates():
    from vsphere_vm_deployment.access import LOCAL_USER_MARKER, _mark_folder

    written = {}
    content = NS(customFieldsManager=NS(field=[NS(name="vmdeploy", key=9)],
                                        SetField=lambda entity, key, value: written.update(value=value)))
    _mark_folder(content, Entity("f"), "VSPHERE.LOCAL\\svc", "vmdeploy-deployer")
    assert written["value"] == f"{LOCAL_USER_MARKER} for VSPHERE.LOCAL\\svc; role vmdeploy-deployer"


def test_remove_on_esxi_keeps_users_it_did_not_create():
    conn = make_conn(vcenter=False)
    access.apply(conn, access.build_esxi_plan(conn, username="vmdeploy", role_name="vmdeploy-deployer"))
    conn.content.accountManager.users["alice"] = "Alice"
    rid = next(r.roleId for r in conn.content.authorizationManager.roleList if r.name == "vmdeploy-deployer")
    conn.content.authorizationManager.SetEntityPermissions(
        Entity("x"), [NS(principal="alice", group=False, roleId=rid, propagate=False)])

    found = access.find_existing(conn)
    assert found.local_users == ["vmdeploy"] and found.unverified_users == ["alice"]
    access.remove(conn, found)
    assert conn.content.accountManager.users == {"alice": "Alice"}


def test_doctor_detects_setups():
    conn = make_conn()
    assert access.find_all_setups(conn) == []
    access.apply(conn, vcenter_plan(conn))
    assert access.find_all_setups(conn) == ["vmdeploy-deployer"]


# ------------------------------------------------------------------------------------------ folders
@pytest.mark.parametrize(("value", "expected"), [
    ("vmdeploy-ops", ("/", "vmdeploy-ops")),
    ("/vmdeploy-ops", ("/", "vmdeploy-ops")),
    ("Lab/Apps/vmdeploy-ops", ("/Lab/Apps", "vmdeploy-ops")),
    ("/Lab/vmdeploy-ops/", ("/Lab", "vmdeploy-ops")),
])
def test_split_folder_path(value, expected):
    assert access.split_folder_path(value) == expected


def test_child_names_and_suggestions():
    paths = {"/", "/Lab", "/Lab/Apps", "/Lab/vmdeploy-deployer", "/vmdeploy-deployer", "/Other"}
    assert access.child_names(paths, "/") == {"Lab", "vmdeploy-deployer", "Other"}
    assert access.child_names(paths, "/Lab") == {"Apps", "vmdeploy-deployer"}
    assert access.suggest_folder_name("deployer@vsphere.local", set()) == "vmdeploy-deployer"
    assert access.suggest_folder_name("vmdeploy-test-deployer@vsphere.local", set()) == "vmdeploy-test-deployer"
    assert access.suggest_folder_name("deployer@vsphere.local", {"vmdeploy-deployer"}) == "vmdeploy-deployer-2"
    assert access.folder_name_error("a/b", set()) and access.folder_name_error("Lab", {"Lab"})


@pytest.mark.parametrize(("raw", "expected"), [
    ("[LocalDS_0]/DC0_H0_VM0", "[LocalDS_0] DC0_H0_VM0"),           # vcsim
    ("[datastore1] vmdeploy-test-ubuntu01/", "[datastore1] vmdeploy-test-ubuntu01"),  # vCenter
    ("[datastore1] a/b", "[datastore1] a/b"),
    ("[my ds] vm", "[my ds] vm"),
])
def test_datastore_paths_are_normalised(raw, expected):
    from vsphere_vm_deployment.audit import ds_folder

    assert ds_folder(raw) == expected


# ------------------------------------------------------------------------------------------ account reminders
def test_history_records_setup_and_removal(isolated_dirs):
    access.record_setup("vc:443", r"VSPHERE.LOCAL\svc-deploy")
    access.record_setup("vc:443", r"VSPHERE.LOCAL\svc-deploy")  # a second setup replaces the entry
    [e] = access.load_history()
    assert e["principal"] == r"VSPHERE.LOCAL\svc-deploy" and e["removed"] is None
    access.record_removed("vc:443", [r"vsphere.local\SVC-DEPLOY"])
    assert access.load_history()[0]["removed"]
    access.forget_account("vc:443", r"VSPHERE.LOCAL\svc-deploy")
    assert access.load_history() == []
    assert "password" not in (isolated_dirs / "cfg" / "access_history.json").read_text(encoding="utf-8")


def _directory(users):
    def retrieve(domain, searchStr, exactMatch, findUsers, findGroups):  # noqa: N803
        return [NS(principal=u) for u in users
                # like vCenter: the exact match is case-sensitive, the substring search is not
                if (u == searchStr if exactMatch else searchStr.lower() in u.lower())]

    return NS(domainList=["vsphere.local", "corp.example.com"], RetrieveUserGroups=retrieve)


def test_account_lookup_and_vmdeploy_named_accounts():
    conn = NS(is_vcenter=True, content=NS(userDirectory=_directory(["vmdeploy-test-deployer", "alice"])))
    assert access.account_exists(conn, r"VSPHERE.LOCAL\vmdeploy-test-deployer") is True
    assert access.account_exists(conn, r"VSPHERE.LOCAL\gone") is False
    # The SSO administrator is "Administrator"; people type it in lower case (found in real-environment testing).
    conn = NS(is_vcenter=True, content=NS(userDirectory=_directory(["Administrator", "admin-backup"])))
    assert access.account_exists(conn, r"VSPHERE.LOCAL\administrator") is True
    assert access.account_exists(conn, r"VSPHERE.LOCAL\admin") is False  # a substring is not the user
    conn = NS(is_vcenter=True, content=NS(userDirectory=_directory(["vmdeploy-test-deployer", "alice"])))
    assert r"VSPHERE.LOCAL\vmdeploy-test-deployer" in access.accounts_named_vmdeploy(conn)
    assert not any("alice" in a for a in access.accounts_named_vmdeploy(conn))


# ------------------------------------------------------------------------------------------ image datastores
def test_image_datastores_get_their_own_browse_and_copy_role():
    conn = make_conn()
    library, ds1 = Entity("library"), Entity("ds1")
    plan = access.build_vcenter_plan(conn, principal="svc@vsphere.local", role_name="vmdeploy-deployer",
                                     folder=("/Lab", Entity("Lab")), compute=("Host h1", Entity("h1")),
                                     datastores=[("ds1", ds1)], networks=[("net", Entity("net"))],
                                     image_datastores=[("library", library), ("ds1", ds1)])  # ds1 is already a deploy ds
    images = [g for g in plan.grants if g.role == "vmdeploy-deployer-images"]
    assert [g.entity.name for g in images] == ["library"] and not images[0].propagate
    access.apply(conn, plan)
    am = conn.content.authorizationManager
    role = next(r for r in am.roleList if r.name == "vmdeploy-deployer-images")
    assert sorted(role.privilege) == ["Datastore.Browse", "Datastore.FileManagement"]
    found = access.find_existing(conn)
    assert "vmdeploy-deployer-images" in found.roles
    access.remove(conn, found)
    assert not {r.name for r in am.roleList} & {"vmdeploy-deployer", "vmdeploy-deployer-read",
                                                "vmdeploy-deployer-images"}


def test_see_every_datastore_copy_rights_only_where_images_are():
    conn = make_conn()
    ds1, library, other = Entity("ds1"), Entity("library"), Entity("other")
    plan = access.build_vcenter_plan(conn, principal="svc@vsphere.local", role_name="vmdeploy-deployer",
                                     folder=("/Lab", Entity("Lab")), compute=("Host h1", Entity("h1")),
                                     datastores=[("ds1", ds1)], networks=[("net", Entity("net"))],
                                     image_datastores=[("library", library)],
                                     browse_datastores=[("library", library), ("other", other), ("ds1", ds1)])
    by_role = {}
    for g in plan.grants:
        by_role.setdefault(g.role, []).append(g.entity.name if g.entity else None)
    assert by_role["vmdeploy-deployer-images"] == ["library"]
    assert by_role["vmdeploy-deployer-browse"] == ["other"]  # one permission per datastore, the widest one wins
    access.apply(conn, plan)
    role = next(r for r in conn.content.authorizationManager.roleList if r.name == "vmdeploy-deployer-browse")
    assert role.privilege == ["Datastore.Browse"]
    found = access.find_existing(conn)
    assert {"vmdeploy-deployer-browse", "vmdeploy-deployer-images"} <= set(found.roles)
