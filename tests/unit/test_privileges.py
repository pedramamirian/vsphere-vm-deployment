"""`doctor` tells a restricted account where it can deploy; pre-flight checks the right objects."""

from types import SimpleNamespace as NS

from vsphere_vm_deployment.privileges import check, deploy_scope, required_privileges

DELETE = "VirtualMachine.Inventory.Delete"  # vCenter marks it onParent (seen on vCenter 8.0.3)


class Obj:
    def __init__(self, moid, children=()):
        self._moId = moid
        self.childEntity = list(children)


class VirtualMachine(Obj):  # the type name is what the code looks at
    pass


ALL = {p for ids in required_privileges().values() for p in ids}
G = required_privileges()
FOLDER_PRIVS = set(G["folder"] + G["virtual_machine"])


def make(granted: dict[str, set[str]], *, test_folder_children=()):
    """`granted` maps an object's moid to the privilege IDs the server reports as held when asked about it."""

    def has(entity, sessionId, privId):  # noqa: N803 - vSphere API names
        return [NS(entity=e, privAvailability=[NS(privId=p, isGranted=p in granted.get(e._moId, set()))
                                               for p in privId]) for e in entity]

    am = NS(privilegeList=[NS(privId=p, onParent=(p == DELETE)) for p in ALL], HasPrivilegeOnEntities=has)
    conn = NS(content=NS(authorizationManager=am, sessionManager=NS(currentSession=NS(key="k"))))
    dc = NS(name="Datacenter",
            folders={"/": Obj("f-root"), "/vmdeploy-test": Obj("f-test", test_folder_children)},
            clusters={},
            standalone_pools={"192.0.2.10": Obj("p-10"), "192.0.2.11": Obj("p-11")},
            datastores={"datastore1": NS(obj=Obj("ds1")), "datastore2": NS(obj=Obj("ds2"))},
            usable_networks=lambda: [NS(name="VLAN20-Servers", obj=Obj("n1")), NS(name="VM Network", obj=Obj("n2"))])
    return conn, NS(datacenters={"Datacenter": dc})


# What vCenter 8.0.3 answered for the deploy account: everything on the folder except Delete, because asking
# about Delete on the folder checks the folder's *parent*.
LAB = {
    "f-test": FOLDER_PRIVS - {DELETE},
    "p-10": set(G["resource_pool"]),
    "ds1": set(G["datastore"]),
    "n1": set(G["network"]),
    "f-root": {"VirtualMachine.Inventory.Create"},  # partial grants do not count
}


def test_restricted_account_sees_exactly_where_it_can_deploy():
    conn, inv = make(LAB)
    assert deploy_scope(conn, inv) == {
        "VM folders": ["/vmdeploy-test"],  # Delete is not asked about on the (empty) folder itself
        "Hosts / clusters": ["Host 192.0.2.10"],
        "Datastores": ["datastore1"],
        "Networks": ["VLAN20-Servers"],
    }


def test_parent_checked_privilege_is_verified_on_a_vm_in_the_folder():
    vm = VirtualMachine("vm-1")
    conn, inv = make({**LAB, "vm-1": {DELETE}}, test_folder_children=[vm])
    assert deploy_scope(conn, inv)["VM folders"] == ["/vmdeploy-test"]
    conn, inv = make(LAB, test_folder_children=[vm])  # the VM's folder does not grant Delete
    assert deploy_scope(conn, inv)["VM folders"] == []


def test_preflight_does_not_report_delete_on_an_empty_folder():
    conn, inv = make(LAB)
    folder = inv.datacenters["Datacenter"].folders["/vmdeploy-test"]
    assert check(conn, {"folder": folder, "virtual_machine": folder}) == {}


def test_nothing_granted_gives_empty_lists():
    conn, inv = make({})
    assert all(v == [] for v in deploy_scope(conn, inv).values())
