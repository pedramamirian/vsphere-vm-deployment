"""Inventory discovery: everything the deployment needs to know about the environment, read up front.

Only read operations are used here, so discovery is safe to run with any account that can see the
inventory. Values are captured into plain dataclasses (with the managed-object reference kept in `obj`)
so the rest of the tool, and the tests, can work with them easily.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from pyVmomi import vim

from .connection import Connection

log = logging.getLogger(__name__)
UPLINK_NAME_RE = re.compile(r"-DVUplinks-\d+$")


def display(name: str) -> str:
    """vSphere escapes '%', '/' and '\\' in object names as %25, %2f and %5c; show them as the user typed them."""
    import urllib.parse

    return urllib.parse.unquote(name or "")
GiB = 1024**3
MiB = 1024**2


@dataclass
class HostInfo:
    name: str
    obj: object
    moid: str
    cluster: str | None
    connection_state: str
    maintenance: bool
    cpu_cores: int
    cpu_threads: int
    cpu_mhz_total: int
    cpu_usage_mhz: int
    mem_bytes: int
    mem_usage_mb: int
    allocated_vcpus: int
    allocated_mem_mb: int
    datastores: set[str] = field(default_factory=set)
    networks: set[str] = field(default_factory=set)

    @property
    def usable(self) -> bool:
        return self.connection_state == "connected" and not self.maintenance

    @property
    def mem_free_gb(self) -> float:
        return max(0.0, (self.mem_bytes / MiB - self.mem_usage_mb) / 1024)

    @property
    def vcpu_ratio(self) -> float:
        return self.allocated_vcpus / self.cpu_threads if self.cpu_threads else 0.0

    def label(self) -> str:
        state = "" if self.usable else ("  [maintenance]" if self.maintenance else f"  [{self.connection_state}]")
        return (f"{self.name}  ({self.cpu_cores} cores, {self.mem_free_gb:.0f}/{self.mem_bytes / GiB:.0f} GB RAM free, "
                f"{self.allocated_vcpus} vCPU allocated){state}")


@dataclass
class ClusterInfo:
    name: str
    obj: object
    drs: bool
    ha: bool
    hosts: list[str]
    resource_pool: object


@dataclass
class DatastoreInfo:
    name: str
    obj: object
    type: str
    capacity: int
    free: int
    uncommitted: int
    accessible: bool
    maintenance: str
    hosts: set[str] = field(default_factory=set)

    @property
    def provisioned(self) -> int:
        return self.capacity - self.free + self.uncommitted

    @property
    def is_vsan(self) -> bool:
        return self.type.lower() == "vsan"

    @property
    def usable(self) -> bool:
        return self.accessible and self.maintenance in ("normal", "", None)

    @property
    def display_name(self) -> str:
        """The name as typed in vCenter: the API escapes '/' as %2f (and '%' as %25, '\\' as %5c)."""
        return display(self.name)

    def where(self, total_hosts: int) -> str:
        """'192.0.2.10', '192.0.2.10, 192.0.2.11', or 'shared (4 hosts)'."""
        if total_hosts > 1 and len(self.hosts) >= total_hosts:
            return f"shared ({total_hosts} hosts)"
        return ", ".join(sorted(self.hosts)) or "no host"

    def label(self) -> str:
        pct = (1 - self.free / self.capacity) * 100 if self.capacity else 0
        return (f"{self.display_name}  ({self.type}, {self.free / GiB:.0f} GB free of {self.capacity / GiB:.0f} GB, "
                f"{pct:.0f}% used)")

    def host_label(self, total_hosts: int) -> str:
        """Host first, so datastores with similar names on different hosts are easy to tell apart."""
        return f"{self.where(total_hosts)} › {self.label()}"


@dataclass
class NetworkInfo:
    name: str
    obj: object
    kind: str  # standard | dvpg | opaque
    uplink: bool = False
    dvs_uuid: str | None = None
    portgroup_key: str | None = None
    opaque_id: str | None = None
    opaque_type: str | None = None
    hosts: set[str] = field(default_factory=set)
    vc_name: str = ""  # the name vCenter knows; `name` gains a "[switch]" suffix when several networks share it

    def __post_init__(self):
        self.vc_name = self.vc_name or self.name

    def label(self) -> str:
        kinds = {"standard": "standard portgroup", "dvpg": "distributed portgroup", "opaque": "NSX segment"}
        return f"{display(self.name)}  ({kinds.get(self.kind, self.kind)})"


@dataclass
class DatacenterInventory:
    name: str
    obj: object
    vm_folder: object
    hosts: dict[str, HostInfo] = field(default_factory=dict)
    clusters: dict[str, ClusterInfo] = field(default_factory=dict)
    standalone_pools: dict[str, object] = field(default_factory=dict)  # host name -> root resource pool
    datastores: dict[str, DatastoreInfo] = field(default_factory=dict)
    networks: dict[str, NetworkInfo] = field(default_factory=dict)
    folders: dict[str, object] = field(default_factory=dict)  # "/path" -> vim.Folder
    resource_pools: dict[str, object] = field(default_factory=dict)  # "cluster/pool" -> vim.ResourcePool
    vm_names: set[str] = field(default_factory=set)

    def usable_networks(self, host_names: set[str] | None = None) -> list[NetworkInfo]:
        nets = [n for n in self.networks.values() if not n.uplink]
        if host_names:
            nets = [n for n in nets if not n.hosts or n.hosts & host_names]
        return sorted(nets, key=lambda n: n.name.lower())

    def datastores_for(self, host_names: set[str]) -> list[DatastoreInfo]:
        return sorted([d for d in self.datastores.values() if d.hosts & host_names],
                      key=lambda d: -d.free)


@dataclass
class Inventory:
    datacenters: dict[str, DatacenterInventory]
    is_vcenter: bool


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - some properties are unset on disconnected hosts
        return default


def _view(conn: Connection, root, types):
    v = conn.content.viewManager.CreateContainerView(root, types, True)
    try:
        return list(v.view)
    finally:
        v.Destroy()


def collect(conn, vimtype, paths: list[str], *, root=None, strict: bool = False) -> list[tuple[object, dict]]:
    """Read some properties of every object of a type (under `root`, default the whole inventory) in one round
    trip, paged for large inventories: the one way vmdeploy reads many objects (a property read object by object
    is a request each time). A property the server leaves out is missing from the dict. By default a failure
    returns [] (informational checks must never stop a deployment); with `strict` it raises, for callers that
    would otherwise read "no VM uses this" and delete something (ISO copies) or call files orphaned (`access
    audit`). For VMs, vm_properties is the strict form with a readable error."""
    from pyVmomi import vmodl

    content = conn.content
    view = None
    try:  # creating the view can fail too (e.g. an expired session): the same rule applies
        view = content.viewManager.CreateContainerView(root or content.rootFolder, [vimtype], True)
        pc = vmodl.query.PropertyCollector
        spec = pc.FilterSpec(
            objectSet=[pc.ObjectSpec(obj=view, skip=True, selectSet=[
                pc.TraversalSpec(name="view", path="view", skip=False, type=vim.view.ContainerView)])],
            propSet=[pc.PropertySpec(type=vimtype, pathSet=paths)])
        out = []
        result = content.propertyCollector.RetrievePropertiesEx(specSet=[spec], options=pc.RetrieveOptions())
        while result:
            out += [(o.obj, {p.name: p.val for p in o.propSet or []}) for o in result.objects or []]
            if not result.token:
                break
            result = content.propertyCollector.ContinueRetrievePropertiesEx(token=result.token)
        return out
    except Exception as e:  # noqa: BLE001 - a missing privilege or old server: report nothing, never fail
        if strict:
            raise
        log.debug("Could not read %s properties: %s", vimtype, e)
        return []
    finally:
        if view is not None:
            try:
                view.Destroy()
            except Exception as e:  # noqa: BLE001 - never hide the result or the real error behind this
                log.debug("Could not destroy the container view: %s", e)


def _vm_allocation(conn: Connection) -> dict[str, tuple[int, int]]:
    """Host moId -> (vCPUs, memory MB) allocated to its VMs (templates excluded), read for every VM in one paged
    request: reading each VM's full config one call at a time took minutes on large vCenters."""
    alloc: dict[str, tuple[int, int]] = {}
    for _vm, props in collect(conn, vim.VirtualMachine, ["runtime.host", "config.template", "config.hardware.numCPU",
                                                        "config.hardware.memoryMB"]):
        host = props.get("runtime.host")
        if host is None or props.get("config.template"):
            continue
        cpu, mem = alloc.get(host._moId, (0, 0))
        alloc[host._moId] = (cpu + (props.get("config.hardware.numCPU") or 0),
                             mem + (props.get("config.hardware.memoryMB") or 0))
    return alloc


def _host_info(h, cluster_name: str | None, alloc: dict[str, tuple[int, int]] | None = None) -> HostInfo:
    hw = _safe(lambda: h.hardware)
    qs = _safe(lambda: h.summary.quickStats)
    vcpus, mem = (alloc or {}).get(h._moId, (0, 0))
    cores = _safe(lambda: hw.cpuInfo.numCpuCores, 0) or 0
    return HostInfo(
        name=h.name,
        obj=h,
        moid=h._moId,
        cluster=cluster_name,
        connection_state=str(_safe(lambda: h.runtime.connectionState, "unknown")),
        maintenance=bool(_safe(lambda: h.runtime.inMaintenanceMode, False)),
        cpu_cores=cores,
        cpu_threads=_safe(lambda: hw.cpuInfo.numCpuThreads, cores) or cores,
        cpu_mhz_total=int((_safe(lambda: hw.cpuInfo.hz, 0) or 0) / 1e6 * cores),
        cpu_usage_mhz=_safe(lambda: qs.overallCpuUsage, 0) or 0,
        mem_bytes=_safe(lambda: hw.memorySize, 0) or 0,
        mem_usage_mb=_safe(lambda: qs.overallMemoryUsage, 0) or 0,
        allocated_vcpus=vcpus,
        allocated_mem_mb=mem,
        datastores={d.name for d in (_safe(lambda: h.datastore, []) or [])},
        networks={n.name for n in (_safe(lambda: h.network, []) or [])},
    )


def _network_info(n) -> NetworkInfo:
    hosts = {h.name for h in (_safe(lambda: n.host, []) or [])}
    if isinstance(n, vim.dvs.DistributedVirtualPortgroup):
        cfg = n.config
        uplink = bool(_safe(lambda: cfg.uplink, False)) or any(
            t.key == "SYSTEM/DVS.UPLINKPG" for t in (_safe(lambda: n.tag, []) or []))
        return NetworkInfo(name=n.name, obj=n, kind="dvpg", uplink=uplink,
                           dvs_uuid=_safe(lambda: cfg.distributedVirtualSwitch.uuid),
                           portgroup_key=n.key, hosts=hosts)
    if isinstance(n, vim.OpaqueNetwork):
        return NetworkInfo(name=n.name, obj=n, kind="opaque", opaque_id=n.summary.opaqueNetworkId,
                           opaque_type=n.summary.opaqueNetworkType, hosts=hosts)
    return NetworkInfo(name=n.name, obj=n, kind="standard", hosts=hosts)


def _moid(obj) -> str:
    """vCenter's object ID: pyVmomi can return the same object as two Python objects."""
    return getattr(obj, "_moId", None) or str(id(obj))


def _qualify_shared_names(infos: list[NetworkInfo]) -> None:
    """Networks that share a name (a portgroup on several distributed switches, or a standard portgroup and a
    distributed one) are all listed as "name [switch]", so a NIC can never silently land on the wrong one and a
    manifest must say which. vCenter's own name stays in `vc_name`."""
    by_name: dict[str, list[NetworkInfo]] = {}
    for info in infos:
        by_name.setdefault(info.name, []).append(info)
    for group in by_name.values():
        if len({_moid(i.obj) for i in group}) < 2:
            continue
        for info in group:
            where = {"standard": "standard switch", "opaque": "NSX"}.get(info.kind) or _safe(
                lambda o=info.obj: o.config.distributedVirtualSwitch.name, "distributed switch")
            info.name = f"{info.vc_name} [{where}]"
        labels = [i.name for i in group]
        for info in group:  # still ambiguous (e.g. two NSX segments): add the object ID
            if labels.count(info.name) > 1:
                info.name = f"{info.name[:-1]}, {getattr(info.obj, '_moId', '?')}]"


def _walk_folders(folder, prefix: str, out: dict[str, object]) -> None:
    out[prefix or "/"] = folder
    for child in _safe(lambda: folder.childEntity, []) or []:
        if isinstance(child, vim.Folder):
            _walk_folders(child, f"{prefix}/{child.name}", out)


def _walk_pools(pool, prefix: str, out: dict[str, object]) -> None:
    out[prefix] = pool
    for child in _safe(lambda: pool.resourcePool, []) or []:
        if isinstance(child, vim.ResourcePool) and not isinstance(child, vim.VirtualApp):
            _walk_pools(child, f"{prefix}/{child.name}", out)


def discover(conn: Connection, datacenter: str | None = None) -> Inventory:
    content = conn.content
    result: dict[str, DatacenterInventory] = {}
    alloc = _vm_allocation(conn)
    for dc in _view(conn, content.rootFolder, [vim.Datacenter]):
        if datacenter and dc.name != datacenter:
            continue
        inv = DatacenterInventory(name=dc.name, obj=dc, vm_folder=dc.vmFolder)
        for cr in _view(conn, dc.hostFolder, [vim.ComputeResource]):
            if isinstance(cr, vim.ClusterComputeResource):
                cfg = _safe(lambda cr=cr: cr.configurationEx)
                inv.clusters[cr.name] = ClusterInfo(
                    name=cr.name, obj=cr,
                    drs=bool(_safe(lambda cfg=cfg: cfg.drsConfig.enabled, False)),
                    ha=bool(_safe(lambda cfg=cfg: cfg.dasConfig.enabled, False)),
                    hosts=[h.name for h in cr.host], resource_pool=cr.resourcePool)
                for h in cr.host:
                    inv.hosts[h.name] = _host_info(h, cr.name, alloc)
                _walk_pools(cr.resourcePool, cr.name, inv.resource_pools)
            else:
                for h in cr.host:
                    inv.hosts[h.name] = _host_info(h, None, alloc)
                    inv.standalone_pools[h.name] = cr.resourcePool
                _walk_pools(cr.resourcePool, cr.name, inv.resource_pools)
        for ds in dc.datastore:
            s = ds.summary
            inv.datastores[ds.name] = DatastoreInfo(
                name=ds.name, obj=ds, type=s.type or "unknown", capacity=s.capacity or 0, free=s.freeSpace or 0,
                uncommitted=s.uncommitted or 0, accessible=bool(s.accessible),
                maintenance=str(s.maintenanceMode or "normal"),
                hosts={m.key.name for m in (_safe(lambda ds=ds: ds.host, []) or [])})
        # Uplink portgroups carry the physical NICs of a distributed switch and cannot take VM traffic.
        uplink_keys: set[str] = set()
        for dvs in _view(conn, dc.networkFolder, [vim.DistributedVirtualSwitch]):
            for pg in _safe(lambda dvs=dvs: dvs.config.uplinkPortgroup, []) or []:
                uplink_keys.add(pg.key)
        infos = []
        for n in dc.network:
            info = _network_info(n)
            if info.portgroup_key and info.portgroup_key in uplink_keys:
                info.uplink = True
            elif info.kind == "dvpg" and UPLINK_NAME_RE.search(info.name):
                # Fallback for servers that do not report uplinkPortgroup: vCenter names uplink portgroups
                # "<switch>-DVUplinks-<n>" by default.
                info.uplink = True
            infos.append(info)
        seen: set[str] = set()
        unique = []
        for info in infos:  # a datacenter may list the same network object twice
            if _moid(info.obj) not in seen:
                seen.add(_moid(info.obj))
                unique.append(info)
        _qualify_shared_names(unique)
        for info in unique:
            inv.networks[info.name] = info
        _walk_folders(dc.vmFolder, "", inv.folders)
        inv.vm_names = {props.get("name") for _vm, props in vm_properties(conn, ["name"], root=dc.vmFolder)
                        if props.get("name")}
        result[dc.name] = inv
    log.info("Discovered %d datacenter(s)", len(result))
    return Inventory(datacenters=result, is_vcenter=conn.is_vcenter)


def vm_properties(conn: Connection, paths: list[str], root=None) -> list[tuple[object, dict]]:
    """These properties of every VM under `root` (default: the whole inventory), in one bulk read (paged for large
    inventories). Reading `vm.name` or `vm.config` VM by VM sends a request each time (pyVmomi caches nothing), and
    `vm.config` downloads the whole configuration. A property the server leaves out (e.g. an unset configuration)
    is missing from the dict. A failed read raises: callers decide what to show or delete."""
    from .errors import DeploymentError
    from .tasks import fault_message

    try:
        return collect(conn, vim.VirtualMachine, paths, root=root, strict=True)
    except Exception as e:  # noqa: BLE001
        raise DeploymentError(f"Could not read the VMs: {fault_message(e)}") from e


def vm_properties_of(conn: Connection, vm, paths: list[str]) -> dict:
    """These properties of one VM in one small request (`vm.config` would download its whole configuration).
    Missing properties are left out. Raises DeploymentError when the VM cannot be read, e.g. deleted meanwhile."""
    from pyVmomi import vmodl

    from .errors import DeploymentError
    from .tasks import fault_message

    pc = vmodl.query.PropertyCollector
    spec = pc.FilterSpec(objectSet=[pc.ObjectSpec(obj=vm, skip=False)],
                         propSet=[pc.PropertySpec(type=vim.VirtualMachine, pathSet=list(paths))])
    try:
        result = conn.content.propertyCollector.RetrievePropertiesEx(specSet=[spec], options=pc.RetrieveOptions())
    except Exception as e:  # noqa: BLE001
        raise DeploymentError(f"Could not read the VM: {fault_message(e)}") from e
    if not result or not result.objects:
        raise DeploymentError("Could not read the VM: it may have been deleted or moved meanwhile.")
    return {p.name: p.val for p in result.objects[0].propSet or []}


def find_vm_with(conn: Connection, name: str, paths: list[str] = (), root=None) -> tuple[object, dict] | None:
    """(VM, these properties of it) for the VM called `name` under `root` (a datacenter's VM folder; default the
    whole inventory), from one read of every VM's name and these properties. None if there is no such VM. Raises if
    the name is ambiguous, so a destructive action can never hit a same-named VM in another datacenter."""
    from .errors import ConfigError

    matches = [(vm, props) for vm, props in vm_properties(conn, ["name", *paths], root=root)
               if props.get("name") == name]
    if len(matches) > 1:
        raise ConfigError(f"{len(matches)} VMs are named '{name}' (in different datacenters/folders).",
                          hint="Pass --datacenter to choose which one.")
    return matches[0] if matches else None


def find_vm(conn: Connection, name: str, root=None):
    """The VM called `name` under `root` (see find_vm_with), or None."""
    found = find_vm_with(conn, name, root=root)
    return found[0] if found else None
