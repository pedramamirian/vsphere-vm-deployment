"""Batch deployment: one image, the same settings, many targets, built in parallel (`vmdeploy deploy --batch`).

The plan is made once, with the same questions as for one VM plus the batch's own (targets, names, hostnames,
addresses), then checked per VM and reviewed as a whole. Nothing changes in vCenter/ESXi before that review is
confirmed. Each VM is then built by its own builder, over its own session, with no questions: a failure stays with
its VM. See docs/design/batch-deployment.md; the rules that need no vCenter are in batchplan.py.
"""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import fnmatch
import json
import logging
import re
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from pyVmomi import vim
from rich.live import Live
from rich.markup import escape as esc
from rich.table import Table
from rich.text import Text

from . import __version__, compat, isolib, netcheck, vmnotes
from . import ovf as ovflib
from .batchplan import (
    DEPLOYED,
    FAILED,
    HOSTNAME_KEYS,
    NAME_KEYS,
    NOT_STARTED,
    PARTLY_EXIT_CODE,
    PROBLEM,
    SKIPPED,
    SpaceUse,
    Spot,
    address_list,
    check_parallel,
    check_pattern,
    distribute,
    exit_code,
    expand,
    fit_datastores,
    hostname_label,
    pool_addresses,
    range_problem,
    retry_names,
    safe_vm_name,
    short_host,
    tally_by_host,
)
from .connection import clone_session, ensure_session
from .deploy import (
    STEPS,
    Deployment,
    DeployOptions,
    Plan,
    image_name_hint,
    next_free_vm_name,
    suggest_vm_name,
)
from .errors import ConfigError, UserAborted, VmDeployError
from .inventory import ClusterInfo, DatastoreInfo, GiB, HostInfo, collect, vm_properties
from .logsetup import current_log_file, register_secret, safe_url, set_log_label
from .manifest import BatchAddresses, BatchSpec, GuestNetwork, Provisioning
from .ovf import OvfPackage
from .paths import default_log_dir, log_dir, log_dir_problem
from .privileges import check as check_privileges
from .tasks import fault_message
from .ui import DeploymentView, Prompter, console, duration, saved_answers
from .units import human_size

log = logging.getLogger(__name__)

PLAN_STEPS = [s for s in STEPS if s[0] in ("connect", "discover", "image", "inspect", "configure", "preflight", "plan")]
STAGE_STEPS = [("upload_iso", "Place the ISO on a datastore", 5), ("copies", "Copy it to the other datastores", 3)]
REVIEW_FULL_LIST = 40  # more VMs than this: the review lists them per host (problems are always listed in full)
# Threads per build slot: the extra ones are VMs that are built and only wait for their guest's address (each with
# its own vCenter session, polled every few seconds).
WAITING_PER_BUILD = 4


@dataclass
class BatchOptions:
    """Command-line settings that override the manifest's `batch:` section."""
    parallel: int | None = None
    parallel_uploads: int | None = None
    per_host: int | None = None
    stop_on_failure: bool = False
    keep_failed: bool = False
    retry_file: Path | None = None
    manifest_path: str | None = None


@dataclass
class Target:
    """Where some of the batch's VMs go: a host, or a DRS cluster (host None), with its resource pool and
    datastore."""
    label: str
    host: HostInfo | None
    cluster: ClusterInfo | None
    pool: object
    pool_path: str
    entry: int | None = None  # its batch.targets[] entry (for messages); None when picked interactively
    datastore: DatastoreInfo | None = None
    datastore_spec: str | None = None
    count: int | None = None
    ovf: dict[str, str] = field(default_factory=dict)
    problem: str | None = None  # e.g. the host is in maintenance mode: its VMs are skipped
    compat_key: str | None = None

    @property
    def drs(self) -> bool:
        return self.host is None

    def hosts(self, dc) -> set[str]:
        if self.host:
            return {self.host.name}
        return {n for n in self.cluster.hosts if n in dc.hosts and dc.hosts[n].usable}

    @property
    def key(self) -> str:
        """Where the per-host limit applies: the host, or the whole DRS cluster."""
        return self.host.name if self.host else f"cluster {self.cluster.name}"

    @property
    def where(self) -> str:
        return self.host.name if self.host else f"{self.cluster.name} (DRS)"


@dataclass(eq=False)  # each VM is itself (used as a key, e.g. by the space check)
class Slot:
    """One VM of the batch, from planning to its result."""
    n: int
    i: int
    target: Target
    name: str = ""
    pattern_name: str = ""  # the name before a clash was resolved (what --retry-failed matches)
    hostname: str | None = None
    address: str | None = None
    address_problem: str | None = None  # a range with no free address left for it: a check failure at the review
    plan: Plan | None = None
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    clash: bool = False
    replace_vm: object = None
    status: str = "ready"  # ready, then deployed | problem | failed | skipped | not-started
    step: str | None = None
    error: str | None = None
    hint: str | None = None
    kept: bool = False
    created: bool = False  # a VM was created before it failed (and was then deleted, unless kept)
    cleanup_failed: bool = False  # deleting that half-built VM failed: it is still there (destroy --batch lists it)
    result: dict | None = None
    row: RowView | None = None


# ================================================================================================ the plan
class BatchDeployment(Deployment):
    def __init__(self, opts: DeployOptions, bopts: BatchOptions):
        super().__init__(opts, steps=PLAN_STEPS)
        self.view.title = f"vsphere-vm-deployment {__version__}: batch"
        self.b: BatchSpec = opts.manifest.batch or BatchSpec()
        self.batch_spec = self.b
        self.bo = bopts
        self.keep_failed = bopts.keep_failed or self.b.keep_failed
        self.stop_on_failure = bopts.stop_on_failure or self.b.on_failure == "stop"
        self.n_vms = bopts.parallel or self.b.parallel.vms
        self.n_uploads = bopts.parallel_uploads or self.b.parallel.uploads
        self.n_per_host = bopts.per_host or self.b.parallel.per_host
        self.name_conflict = "replace" if opts.replace else self.b.name_conflict
        self.retry: set[str] | None = None
        self.retry_doc: dict | None = None
        self.retry_of: str | None = None
        if bopts.retry_file:
            try:
                doc = json.loads(Path(bopts.retry_file).read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                raise ConfigError(f"Could not read {bopts.retry_file}: {e}") from None
            self.retry = retry_names(doc)
            if not self.retry:
                raise ConfigError(f"{bopts.retry_file} lists no failed, skipped or not-started VMs: nothing to retry.")
            self.retry_doc, self.retry_of = doc, str(Path(bopts.retry_file).resolve())
            answers = doc.get("answers")
            if isinstance(answers, dict) and answers:
                # each question is answered as in the first run while that answer still fits; "Change my answers"
                # at the review asks them all again
                self.p.replay = answers
                console.print(Text(f"Retrying {len(self.retry)} VM(s) of {Path(bopts.retry_file).name} with the "
                                   "same answers as that run (Change my answers at the review to change any).",
                                   style="dim"), soft_wrap=True)
            elif not opts.manifest.batch:
                console.print(Text(f"{Path(bopts.retry_file).name} has no saved answers (written by an older "
                                   "version): answer the questions the same way as that run.", style="yellow"),
                              soft_wrap=True)
        self.targets: list[Target] = []
        self.slots: list[Slot] = []
        self.batch_warnings: list[str] = []
        self.compats: dict[str, compat.Compat] = {}
        self.hostname_pattern: str | None = "{name}"
        self.addresses: BatchAddresses | None = None
        self._ip_uses: list | None = None  # addresses in use, read once per pass when a range is handed out
        self.stop_new = threading.Event()
        self.cancel = threading.Event()
        # The signed-in session is shared: one builder at a time asks it for a clone ticket.
        self.clone_lock = threading.Lock()
        self.started = datetime.now()
        self.build_t0: float | None = None  # when the confirmed batch started changing things (ISO staging, builds)

    # ------------------------------------------------------------------------------------- entry point
    def run(self) -> dict:
        try:
            with self.view:
                try:
                    inv = self._prepare()
                    self._plan_and_review(inv)
                except (VmDeployError, KeyboardInterrupt) as e:
                    self.view.fail_running(getattr(e, "message", "cancelled") if not isinstance(e, KeyboardInterrupt)
                                           else "cancelled")
                    raise
                except Exception:
                    self.view.fail_running("unexpected error (see log)")
                    raise
            ready = [s for s in self.slots if s.status == "ready"]
            # the review may have been open longer than vCenter's idle timeout: an interactive run asks for the
            # password again (whoever is at the keyboard must know it); a --yes run signs in again by itself
            if ready and ensure_session(self.conn, self.p) and not self.p.interactive:
                console.print(Text(f"The session had expired while the review was open: signed in again as "
                                   f"{self.conn.user}.", style="dim"))
            self.build_t0 = time.monotonic()
            if ready and self.image.is_iso:
                self._stage_isos(ready)
            self._execute()
            return self._finish()
        finally:
            if self.pkg:
                self.pkg.close()
            if self.conn:
                self.conn.close()

    def _check_retry_image(self) -> None:
        """A retry deploys the image the first run deployed: a preset such as ubuntu-lts may have a newer build by
        now, and a file may have been replaced. Interactive: said in the review. --yes: refused."""
        first = (self.retry_doc or {}).get("image_sha256")
        now = getattr(self.image, "sha256", None)
        if not first or not now or first.lower() == now.lower():
            return
        what = (f"The image is not the one the first run deployed ({self.retry_doc.get('image') or '?'}, SHA-256 "
                f"{first[:12]}…; now {self.image.display}, {now[:12]}…): the retried VMs would differ from the others")
        if not self.p.interactive:
            raise ConfigError(what + ".", hint=f"Use the same image (e.g. --sha256 {first} with the same source), or "
                                               "deploy without --retry-failed.")
        self.batch_warnings.append(what + ".")

    def _plan_and_review(self, inv) -> None:
        v = self.view
        while True:
            v.start("configure")
            self.plan = self._configure(inv)
            self._check_retry_image()
            v.done("configure", f"{len(self.slots)} VM(s) on {len(self.targets)} target(s)")
            v.start("preflight")
            self._preflight()
            blocked = sum(1 for s in self.slots if s.blockers)
            warned = bool(self.batch_warnings) or any(s.warnings for s in self.slots)
            if blocked:
                v.done("preflight", f"{blocked} of {len(self.slots)} VM(s) cannot be deployed", status="warn")
            else:
                v.done("preflight", "all checks passed" if not warned else "passed, with warnings",
                       status="warn" if warned else "done")
            v.start("plan")
            if self._review_plan():
                break
            v.reset("configure", "preflight", "plan")
            self.p.start_revision()
        v.done("plan", "confirmed")

    # ------------------------------------------------------------------------------------- questions
    def _configure(self, inv) -> Plan:
        p = self.p
        self.batch_warnings, self.compats = [], {}  # "Change my answers" starts again from here
        dcs = list(inv.datacenters.values())
        with p.section("Placement"):
            dc, by_iso = self._choose_datacenter(dcs)
            plan = Plan(dc=dc)
            p.record("Datacenter", dc.name + (" (where the chosen ISO is)" if by_iso else ""))
            plan.folder_path, plan.folder = self._ask_folder(dc)
            self.targets = self._ask_targets(dc)
            mode, count = self._ask_distribution()
        first = self.targets[0]  # questions that need one compute resource (e.g. guest OS list) ask it here
        plan.host, plan.cluster, plan.pool, plan.pool_path = first.host, first.cluster, first.pool, first.pool_path
        plan.batch_hosts = set().union(*(t.hosts(dc) for t in self.targets))

        if self.image.is_iso:
            with p.section("Guest operating system"):
                self._ask_guest_os(plan)
        with p.section("Sizing"):
            self._ask_sizing(plan)
        spots = [Spot(t.key, self._free_mb(t, dc), t.count) for t in self.targets]
        self.assignment = distribute(spots, mode, count, plan.memory_mb or 0)
        p.record("VMs", f"{len(self.assignment)} on {len(self.targets)} target(s)"
                        + (" (spread by free memory)" if mode == "total" else ""))
        with p.section("VM names"):
            pattern = self._ask_names()
        with p.section("Storage"):
            self._ask_target_datastores(dc)
            plan.datastore = first.datastore
            if all(t.datastore.is_vsan for t in self.targets):
                plan.provisioning = Provisioning.THIN
                p.record("Disks", "thin (vSAN: the datastore's default storage policy is applied)")
            else:
                plan.provisioning = self._ask_provisioning()
                p.record("Disks", f"{plan.provisioning.value} provisioning")
            plan.extra_disks = [(size, prov or plan.provisioning) for size, prov in plan.extra_disks]
        with p.section("Networking"):
            self._ask_networks(plan)
        if self.image.is_iso:
            with p.section("Virtual hardware"):
                self._ask_iso_hardware(plan)
        else:
            with p.section("Virtual hardware"):
                self._ask_compat(plan)
                plan.nested_hv = self._ask_nested(plan)
            self._ask_guest(plan)
            self._ask_ovf_options(plan)
        self._finish_configure(plan)
        with p.section("Per-VM settings"):
            self._ask_per_vm(plan)
        self.slots = self._make_slots(plan, pattern)
        return plan

    def _ask_targets(self, dc) -> list[Target]:
        """The manifest's batch.targets, or a checklist of hosts and clusters."""
        targets = self._manifest_targets(dc) if self.b.targets else self._pick_targets(dc)
        seen: dict[str, int] = {}
        for k, t in enumerate(targets):
            if t.key in seen:
                raise ConfigError(f"{t.where} is chosen twice in the batch's targets.",
                                  hint="Name each host or DRS cluster once (use count for more VMs on it).")
            seen[t.key] = k
        if not targets:
            raise ConfigError("The batch has no targets.", hint="Choose at least one host or cluster.")
        usable = [t for t in targets if not t.problem]
        self.p.record("Targets", ", ".join(t.where + (f" [{t.problem}]" if t.problem else "") for t in targets)
                      if len(targets) <= 8 else f"{len(usable)} usable of {len(targets)} chosen")
        return targets

    def _host_target(self, dc, h: HostInfo, entry: int | None, spec=None) -> Target:
        if h.cluster:
            c = dc.clusters[h.cluster]
            root, root_name = c.resource_pool, c.name
        else:
            c = None
            root = dc.standalone_pools.get(h.name)
            root_name = next((k for k, v in dc.resource_pools.items() if "/" not in k and root is not None
                              and v._moId == root._moId), h.name)
        t = Target(label=h.name, host=h, cluster=c, pool=root, pool_path=root_name, entry=entry)
        self._apply_spec(dc, t, spec)
        if not h.usable:
            t.problem = f"host {h.name} is " + ("in maintenance mode" if h.maintenance else h.connection_state)
        return t

    def _cluster_target(self, dc, c: ClusterInfo, entry: int | None, spec=None) -> Target:
        t = Target(label=f"{c.name} (DRS)", host=None, cluster=c, pool=c.resource_pool, pool_path=c.name, entry=entry)
        self._apply_spec(dc, t, spec)
        if not t.hosts(dc):
            t.problem = f"cluster {c.name} has no usable host"
        return t

    def _apply_spec(self, dc, t: Target, spec) -> None:
        """A manifest entry's own datastore, count, OVF properties and resource pool (or the shared pool)."""
        selects = bool(spec and (spec.host or spec.cluster or spec.folder or spec.hosts_matching))
        pool_only = bool(spec and spec.resource_pool and not selects)  # _pool_target sets that pool itself
        want_pool = None if pool_only else ((spec.resource_pool if spec else None) or self.m.placement.resource_pool)
        if want_pool:
            key = want_pool if want_pool in dc.resource_pools and want_pool.split("/")[0] == t.pool_path \
                else f"{t.pool_path}/{want_pool.strip('/')}"
            if key not in dc.resource_pools:
                raise ConfigError(f"Resource pool '{want_pool}' not found for {t.where}.",
                                  hint="Pools: " + ", ".join(k for k in dc.resource_pools
                                                             if k.split("/")[0] == t.pool_path))
            t.pool, t.pool_path = dc.resource_pools[key], key
        if spec:
            t.datastore_spec, t.count = spec.datastore, spec.count
            t.ovf = dict(spec.ovf.properties) if spec.ovf else {}

    def _manifest_targets(self, dc) -> list[Target]:
        out: list[Target] = []
        for k, spec in enumerate(self.b.targets):
            f = f"batch.targets[{k}]"
            if spec.host:
                h = dc.hosts.get(spec.host)
                if not h:
                    raise ConfigError(f"{f}: host '{spec.host}' not found.", hint=f"Hosts: {', '.join(sorted(dc.hosts))}")
                out.append(self._host_target(dc, h, k, spec))
            elif spec.cluster:
                c = dc.clusters.get(spec.cluster)
                if not c:
                    raise ConfigError(f"{f}: cluster '{spec.cluster}' not found.",
                                      hint=f"Clusters: {', '.join(sorted(dc.clusters)) or '(none)'}")
                if spec.drs:
                    if not c.drs:
                        raise ConfigError(f"{f}: DRS is off on cluster {c.name}, so it cannot place the VMs.",
                                          hint="Remove `drs: true` to deploy to each of its hosts.")
                    out.append(self._cluster_target(dc, c, k, spec))
                else:
                    out += [self._host_target(dc, dc.hosts[n], k, spec) for n in sorted(c.hosts) if n in dc.hosts]
            elif spec.folder or spec.hosts_matching:
                if spec.folder:
                    want = "/" + spec.folder.strip("/")
                    hosts = [h for h in dc.hosts.values()
                             if (_host_folder(h) + "/").startswith(want.rstrip("/") + "/")]
                    what = f"host folder '{spec.folder}'"
                else:
                    hosts = [h for h in dc.hosts.values()
                             if fnmatch.fnmatchcase(h.name.lower(), spec.hosts_matching.lower())]
                    what = f"the pattern '{spec.hosts_matching}'"
                if not hosts:
                    raise ConfigError(f"{f}: no host matches {what}.", hint=f"Hosts: {', '.join(sorted(dc.hosts))}")
                out += [self._host_target(dc, h, k, spec) for h in sorted(hosts, key=lambda h: h.name)]
            else:  # a resource pool on its own: where the account cannot see hosts (hosted VMware clouds)
                out.append(self._pool_target(dc, spec, k, f))
        return out

    def _pool_target(self, dc, spec, k: int, f: str) -> Target:
        want = spec.resource_pool.strip("/")
        keys = [key for key in dc.resource_pools if key == want or key.endswith("/" + want)]
        if len(keys) != 1:
            raise ConfigError(f"{f}: resource pool '{spec.resource_pool}' " + ("is ambiguous" if keys else "not found")
                              + ".", hint="Pools: " + ", ".join(sorted(dc.resource_pools)))
        owner = keys[0].split("/")[0]
        if owner in dc.clusters:
            c = dc.clusters[owner]
            if not c.drs:
                raise ConfigError(f"{f}: cluster {c.name} has DRS off, so it cannot place VMs in that pool.",
                                  hint="Name the hosts instead (host or hosts_matching), with resource_pool.")
            t = self._cluster_target(dc, c, k, spec)
        else:
            h = next((dc.hosts[n] for n, pool in dc.standalone_pools.items()
                      if pool is not None and dc.resource_pools.get(owner) is not None
                      and pool._moId == dc.resource_pools[owner]._moId), None)
            if h is None:
                raise ConfigError(f"{f}: could not tell which host or cluster owns '{spec.resource_pool}'.")
            t = self._host_target(dc, h, k, spec)
        t.pool, t.pool_path = dc.resource_pools[keys[0]], keys[0]
        return t

    def _pick_targets(self, dc) -> list[Target]:
        p = self.p
        hosts = sorted(dc.hosts.values(), key=lambda h: h.name)  # a long list asks for a name pattern first (ui)
        choices: list[tuple] = []
        for c in sorted(dc.clusters.values(), key=lambda c: c.name):
            usable = [n for n in c.hosts if n in dc.hosts and dc.hosts[n].usable]
            if c.drs:
                choices.append((f"Cluster {c.name}: let DRS place the VMs ({len(usable)} usable host(s))",
                                ("drs", c.name), None if usable else "no usable host"))
            choices.append((f"Cluster {c.name}: every usable host ({len(usable)})", ("cluster", c.name),
                            None if usable else "no usable host"))
        for h in hosts:
            why = None if h.usable else ("maintenance mode" if h.maintenance else h.connection_state)
            choices.append((h.label() + (f"  [cluster {h.cluster}]" if h.cluster else ""), ("host", h.name), why))
        picked = p.checkbox("Deploy to:", choices, field_name="batch.targets")
        out: list[Target] = []
        for kind, name in picked:
            if kind == "drs":
                out.append(self._cluster_target(dc, dc.clusters[name], None))
            elif kind == "cluster":
                out += [self._host_target(dc, dc.hosts[n], None) for n in sorted(dc.clusters[name].hosts)
                        if n in dc.hosts and dc.hosts[n].usable]
            else:
                out.append(self._host_target(dc, dc.hosts[name], None))
        unique: dict[str, Target] = {}
        for t in out:  # a host ticked on its own and through its cluster is used once
            unique.setdefault(t.key, t)
        return list(unique.values())

    def _ask_distribution(self) -> tuple[str, int | None]:
        p, b = self.p, self.b
        several = len(self.targets) > 1 or any(t.drs for t in self.targets)
        if "distribution" in b.model_fields_set or not several:
            mode = b.distribution
        else:
            each = "each host or DRS cluster" if any(t.drs for t in self.targets) else "each host"
            mode = p.select("How many VMs?", [
                (f"The same number on {each}", "per_host"),
                ("A total number, with more on hosts that have more free memory", "total")],
                default="per_host", field_name="batch.distribution", assume_default=True)
        count = b.count
        if count is None and mode == "per_host" and not all(t.count for t in self.targets):
            count = p.integer("VMs on each:", default=1, field_name="batch.count", maximum=1000) \
                if p.would_ask("batch.count") else 1
        elif count is None and mode == "total":
            count = p.integer("How many VMs in total?", default=len(self.targets), field_name="batch.count",
                              maximum=1000)
        return mode, count

    @staticmethod
    def _free_mb(t: Target, dc) -> float:
        """Memory still free where the target's VMs run (all of a DRS cluster's usable hosts together)."""
        return sum(dc.hosts[n].mem_free_gb * 1024 for n in t.hosts(dc) if n in dc.hosts)

    def _ask_names(self) -> str | None:
        b, p = self.b, self.p
        if b.names:
            if len(b.names) != len(self.assignment):
                raise ConfigError(f"batch.names has {len(b.names)} name(s) for {len(self.assignment)} VMs.",
                                  hint="Give one name per VM, or use a pattern in batch.name.")
            p.record("VM names", ", ".join(b.names[:4]) + (", ..." if len(b.names) > 4 else ""))
            return None
        base = name_base(self.pkg, self.image)
        suggested = f"{base}-{{n:02}}"

        def valid(s: str):
            try:
                check_pattern(s, "VM name pattern")
            except ConfigError as e:
                return e.message
            dup = _first_repeat(self._names_for(s))
            if dup:
                return (f"'{dup}' would be the name of several VMs (names must be unique in the VM folder): add "
                        "{n}, or {host} with {i}")
            return True

        if b.name is None and p.interactive:
            console.print(Text("  Names come from a pattern. The suggestion gives:"))
            console.print(Text(f"    {_name_span(self._names_for(suggested))}", style="cyan"))
            if len(self.targets) > 1:
                console.print(Text("  To number the VMs on each host separately, include the host: ")
                              + Text(f"{base}-{{host}}-{{i:02}}", style="cyan"))
            console.print(Text("  {n} = 1, 2, 3…   {n:02} = 01, 02, 03…   {host} = the host's name   "
                               "{i} = the VM's number on its host", style="dim"))
        pattern = b.name or p.text("VM name pattern:", default=suggested, field_name="batch.name", validate=valid)
        names = self._names_for(pattern)
        if "{datastore}" in pattern:  # not chosen yet: shown in the review
            p.record("VM names", f"{pattern}  ({len(names)} VMs; {{datastore}} is filled in once the datastores "
                                 "are chosen)")
        else:
            p.record("VM names", _name_span(names, ends_only=True)
                     + (f"  ({len(names)} VMs)" if len(names) > 1 else ""))
        return pattern

    def _names_for(self, pattern: str) -> list[str]:
        """Every VM's name from a pattern, in batch order (before name clashes are resolved)."""
        return [safe_vm_name(expand(pattern, self._values(k), NAME_KEYS)) for k in range(len(self.assignment))]

    def _values(self, k: int) -> dict[str, object]:
        """Placeholder values of the k-th VM (before its datastore is known: {datastore} is filled in later)."""
        ti, i = self.assignment[k]
        t = self.targets[ti]
        host = short_host(t.host.name) if t.host else t.cluster.name
        return {"n": self.b.start + k, "i": i, "host": host,
                "datastore": t.datastore.display_name if t.datastore else "datastore"}

    def _ask_target_datastores(self, dc) -> None:
        p = self.p
        choose_each = None
        for t in self.targets:
            hosts = t.hosts(dc) or ({t.host.name} if t.host else set())
            candidates = sorted((d for d in dc.datastores.values() if d.usable and hosts and hosts <= d.hosts),
                                key=lambda d: -d.free)
            f = f"batch.targets[{t.entry}].datastore" if t.entry is not None else "batch.targets[].datastore"
            if t.datastore_spec and t.datastore_spec != "auto":
                ds = dc.datastores.get(t.datastore_spec)
                if not ds:
                    raise ConfigError(f"{f}: datastore '{t.datastore_spec}' not found.",
                                      hint=f"Datastores: {', '.join(sorted(dc.datastores))}")
                t.datastore = ds
                if not hosts <= ds.hosts and not t.problem:
                    t.problem = f"datastore {ds.display_name} is not mounted on {t.where}"
                elif not ds.usable and not t.problem:
                    t.problem = f"datastore {ds.display_name} is not accessible (or in maintenance mode)"
                continue
            if not candidates:
                t.datastore = next(iter(dc.datastores.values()), None)
                t.problem = t.problem or f"no usable datastore is mounted on {t.where}"
                continue
            if t.datastore_spec == "auto" or len(candidates) == 1:
                t.datastore = candidates[0]
                continue
            if t.problem:  # its VMs are skipped anyway: no question for it
                t.datastore = candidates[0]
                continue
            # Each answer is kept under its own key (answer_key): one manifest field can answer several of these
            # questions (every host of a cluster entry), and a retry must give each host its own datastore again.
            if choose_each is None:
                several = sum(1 for x in self.targets if not x.datastore_spec) > 1
                choose_each = "each" if not several else p.select(
                    "Datastores:", [("The one with the most free space on each host", "auto"),
                                    ("Choose for each host", "each")],
                    default="auto", field_name=f, answer_key="batch.datastore_choice")
            if choose_each == "auto":
                t.datastore = candidates[0]
            else:
                t.datastore = p.select(f"Datastore on {t.where}:", [(d.label(), d) for d in candidates],
                                       default=candidates[0], field_name=f, answer_key=f"batch.datastore[{t.key}]")
        shown = [f"{t.where}: {t.datastore.display_name}" for t in self.targets if t.datastore]
        p.record("Datastores", ", ".join(shown) if len(shown) <= 6 else f"{len(shown)} chosen (see the review)")

    def _ask_compat(self, plan: Plan) -> None:
        """VM compatibility for every target: one version that all their hosts support (a version some hosts
        cannot run fails only those VMs, at the checks)."""
        image_version = self.pkg.info.hardware_version if self.pkg else None
        for t in self.targets:
            cr = t.cluster.obj if t.cluster else t.host.obj.parent
            t.compat_key = getattr(cr, "_moId", str(id(cr)))
            if t.compat_key not in self.compats:
                self.compats[t.compat_key] = compat.discover(cr, plan.dc.obj, host=t.host.obj if t.host else None,
                                                             image=image_version)
        found = list(self.compats.values())
        common = compat.Compat(image=image_version)
        lists = [set(c.supported) for c in found if c.supported]
        if lists:
            common.supported = sorted(set.intersection(*lists), key=compat.number)
        defaults = [c.host_default for c in found if c.host_default and (not lists or c.host_default in
                                                                         common.supported)]
        common.host_default = min(defaults, key=compat.number) if defaults else None
        policy = next((c for c in found if c.policy), None)
        if policy:
            common.policy, common.policy_source = policy.policy, policy.policy_source
        given = self.m.hardware.hardware_version
        if given:
            key = common.resolve(given)
        else:
            options = common.options()
            prefer_upgrade = self.image.is_iso or self.image.source_kind == "preset"
            default = common.recommended(prefer_upgrade=prefer_upgrade)
            if not options:
                key = image_version
            elif len(options) == 1:
                key = options[0][1]
            else:
                key = self.p.select("VM compatibility (virtual hardware version), for every target host:", options,
                                    default=default, field_name="hardware.hardware_version", assume_default=True,
                                    auto_single=False)
        plan.hardware_version = key
        plan.compat_upgrade = bool(image_version and key and compat.number(key) > compat.number(image_version))
        plan.warnings.extend(common.warnings(key))
        self.p.record("VM compatibility", compat.describe(key)
                      + (f"  (upgraded from the image's version {compat.number(image_version)})"
                         if plan.compat_upgrade else ""))

    def _ask_per_vm(self, plan: Plan) -> None:
        """Hostnames and addresses: per VM, the same for all, or left to the image."""
        p, b = self.p, self.b
        props = list(plan.ovf_properties.values()) + [v for t in self.targets for v in t.ovf.values()]
        uses_address = any("{address}" in str(v) for v in props)
        if plan.guest:
            if b.hostname:
                choice = b.hostname
            else:
                choice = p.select("Hostnames:", [("The same as each VM's name", "{name}"),
                                                 ("A pattern (e.g. web{n:02})", "__pattern__"),
                                                 ("Leave it to the image (vmdeploy does not set one)", "skip")],
                                  default="{name}", field_name="batch.hostname", assume_default=True,
                                  answer_key="batch.hostname_choice")  # the pattern below is batch.hostname
                if choice == "__pattern__":
                    def valid(s: str):
                        try:
                            check_pattern(s, "hostname pattern", hostname=True)
                        except ConfigError as e:
                            return e.message
                        return True
                    choice = p.text("Hostname pattern ({name}, {n}, {n:02}, {host}, {i}):", default="{name}",
                                    field_name="batch.hostname", validate=valid)
            self.hostname_pattern = None if choice == "skip" else choice
            p.record("Hostnames", "left to the image" if choice == "skip" else choice)
        else:
            self.hostname_pattern = None
            if b.hostname and b.hostname != "skip":
                raise ConfigError("batch.hostname is set, but no guest settings are applied to these VMs.",
                                  hint="Hostnames are set through cloud-init (guest settings on a cloud-init image), "
                                       "or use {hostname} in an OVF property. Remove batch.hostname otherwise.")
        if plan.guest or uses_address:
            from .cloudinit import sets_dhcp_identifier

            by_mac = sets_dhcp_identifier(plan.guest)
            dhcp = "DHCP, identified by MAC address" if by_mac else "DHCP"
            if b.addresses:
                self.addresses = b.addresses
            elif p.would_ask("batch.addresses.mode"):
                mode = p.select("Guest IP addresses:", [
                    ("DHCP (the guest identifies itself by its MAC address, so reservations by MAC work)" if by_mac
                     else "DHCP (nothing is written: the image's default)", "dhcp"),
                    ("Static, from a range or a list", "static")], default="dhcp", field_name="batch.addresses.mode")
                self.addresses = BatchAddresses(mode="dhcp") if mode == "dhcp" else self._ask_static_addresses()
            else:
                self.addresses = BatchAddresses(mode="dhcp")
            a = self.addresses
            p.record("Addresses", dhcp if a.mode == "dhcp" else f"static: {a.range or ', '.join(a.addresses)}"
                     + (f", gateway {a.gateway}" if a.gateway else ""))
        elif b.addresses and b.addresses.mode == "static":
            raise ConfigError("batch.addresses is set, but nothing applies addresses to these VMs.",
                              hint="Addresses go in through cloud-init (guest settings on a cloud-init image) or an "
                                   "OVF property that uses {address}. An ISO install sets its address in the "
                                   "installer.")
        else:
            self.addresses = None

    def _ask_static_addresses(self) -> BatchAddresses:
        """A range or list, the prefix, gateway and DNS servers, each checked as it is typed (a typo is asked
        again, instead of ending the run once every other question is answered), then all of them together with
        the prefix (network or broadcast addresses, the gateway in every address's subnet)."""
        p = self.p
        from .netcheck import dns_error, gateway_error, suggested_gateway

        count = len(self.assignment)  # every VM of the batch has its address, also those a retry leaves out
        while True:
            text = p.text("Addresses: a range to take free ones from (192.0.2.50-192.0.2.69), or a list, one per VM "
                          "(192.0.2.50, 192.0.2.61):", field_name="batch.addresses.range",
                          validate=lambda s: addresses_problem(s, count) or True).strip()
            rng, listed = split_addresses(text)
            first = (listed[0] if listed else (rng or "").replace(" ", "").split("-")[0]).split("/")[0]
            prefix = p.integer("Prefix length (e.g. 24):", default=24, maximum=32,
                               field_name="batch.addresses.prefix")
            subnet = f"{first}/{prefix}"
            gw = p.text("Default gateway:", default=suggested_gateway(subnet), field_name="batch.addresses.gateway",
                        validate=lambda s, net=subnet: not s.strip() or gateway_error(s.strip(), net) or True).strip()
            dns = p.text("DNS servers (comma separated):", default=gw, field_name="batch.addresses.dns",
                         validate=lambda s: dns_error(_words(s)) or True)
            a = BatchAddresses(mode="static", range=rng, list=listed, prefix=prefix, gateway=gw or None,
                               dns=_words(dns))
            try:
                if a.range:
                    if problem := range_problem(a.range, count, prefix=a.prefix, gateway=a.gateway, dns=a.dns,
                                                what="The range"):
                        raise ConfigError(problem)
                else:
                    address_list("static", range_text=None, listed=a.addresses, prefix=a.prefix, gateway=a.gateway,
                                 count=count, what="The list")
                return a
            except ConfigError as e:
                if not p.interactive:
                    raise
                console.print(Text(f"  ! {e.message} Answer the addresses again.", style="yellow"), soft_wrap=True)
                for k in ("batch.addresses.range", "batch.addresses.prefix", "batch.addresses.gateway",
                          "batch.addresses.dns"):
                    p.replay.pop(k, None)  # a retry's saved answers are what did not fit: not offered again

    # ------------------------------------------------------------------------------------- the VMs
    def _make_slots(self, plan: Plan, pattern: str | None) -> list[Slot]:
        b, dc = self.b, plan.dc
        slots: list[Slot] = []
        for k, (ti, i) in enumerate(self.assignment):
            t = self.targets[ti]
            values = self._values(k)
            name = b.names[k] if b.names else safe_vm_name(expand(pattern, values, NAME_KEYS))
            slots.append(Slot(n=self.b.start + k, i=i, target=t, name=name, pattern_name=name))
        names = [s.name for s in slots]
        dups = sorted({n for n in names if names.count(n) > 1})
        if dups:
            raise ConfigError(f"The name pattern gives the same name to several VMs: {', '.join(dups[:5])}.",
                              hint="Put {n} in batch.name (e.g. web-{n:02}), or {host} and {i}.")
        self._ip_uses = None
        a = self.addresses if self.addresses and self.addresses.mode == "static" else None
        if a and a.range:  # a pool: handed out below, once the VMs to build are known
            if a.prefix is None:
                raise ConfigError("batch.addresses.prefix is needed with a range (e.g. 24).")
            if problem := range_problem(a.range, len(slots), prefix=a.prefix, gateway=a.gateway, dns=a.dns):
                raise ConfigError(problem, hint="Give a longer range, or fewer VMs.")
        elif a:  # a list: one address per VM of the whole batch, in VM order (a retry's VMs keep theirs)
            for s, addr in zip(slots, address_list("static", range_text=None, listed=a.addresses, prefix=a.prefix,
                                                   gateway=a.gateway, count=len(slots)), strict=True):
                s.address = addr
        if self.retry is not None:
            missing = sorted(self.retry - {s.name for s in slots})
            slots = [s for s in slots if s.name in self.retry]
            if missing:
                self.batch_warnings.append(f"Not in this batch any more (check the manifest is the same): "
                                           f"{', '.join(missing)}.")
            if not slots:
                raise ConfigError("None of the VMs to retry are in this batch.",
                                  hint="Use the same manifest as the batch that wrote the results file.")
        taken = set(dc.vm_names)
        for s in slots:
            if s.name in taken:
                if self.name_conflict == "next-free":
                    s.name = next_free_vm_name(s.name, taken | {x.name for x in slots if x is not s})
                else:
                    s.clash = True
            taken.add(s.name)
        if a and a.range:
            self._give_pool_addresses(slots, plan)
        for s in slots:
            values = {**self._values(slots_index(self.assignment, s, self.b.start)), "name": s.name}
            if self.hostname_pattern:
                s.hostname = hostname_label(expand(self.hostname_pattern, values, HOSTNAME_KEYS)) or None
            s.plan = self._slot_plan(plan, s)
        return slots

    def _give_pool_addresses(self, slots: list[Slot], plan: Plan) -> None:
        """A range is a pool: each VM to build gets the next address that is free, as vCenter sees it (a running
        VM's reported address or a host's), so an address in use does not cost a VM. A retry's VMs keep the address
        they were planned with, and a VM that replaces another keeps that one's. The skipped addresses are said at
        the review; a VM left without one fails its check. Powered-off VMs, VMs without VMware Tools and other
        devices are not seen, except a retry's earlier runs' VMs: their addresses are in the results files."""
        a = self.addresses
        self._ip_uses = netcheck.ip_uses(self.conn)  # read once: the checks use it too
        earlier = held_addresses(self.retry_doc)  # a retry: what the batch's earlier runs gave, seen or not
        in_use: dict[str, str] = {}
        for u in self._ip_uses:
            in_use.setdefault(u.ip, u.owner)
        for ip, vm in earlier:
            in_use.setdefault(ip, f"VM '{vm}', from an earlier run of this batch")
        planned = {(r.get("pattern_name") or r.get("name")): r.get("address")
                   for r in (self.retry_doc or {}).get("vms") or [] if isinstance(r, dict)}
        replacing = self.name_conflict == "replace"

        def own(s: Slot) -> set[str]:
            if not (replacing and s.clash):
                return set()
            return ({u.ip for u in self._ip_uses if u.owner == f"VM '{s.name}'"}
                    | {ip for ip, vm in earlier if vm == s.name})

        vms = [(s, own(s), planned.get(s.pattern_name)) for s in slots]
        given, skipped = pool_addresses(a.range, a.prefix, vms=vms, in_use=in_use,
                                        reserved={x for x in (a.gateway, *a.dns) if x})
        for s in slots:
            s.address = given.get(s)
            if s.address is None:
                s.address_problem = f"no free address left for it in {a.range} (see the addresses skipped above)"
        if skipped:
            shown = ", ".join(skipped[:5]) + (f" and {len(skipped) - 5} more" if len(skipped) > 5 else "")
            plan.notes.append(f"Addresses from {a.range}: skipped {shown}.")

    def _slot_plan(self, shared: Plan, s: Slot) -> Plan:
        t = s.target
        pl = dataclasses.replace(
            shared, name=s.name, host=t.host, cluster=t.cluster, pool=t.pool, pool_path=t.pool_path,
            datastore=t.datastore, batch_hosts=None, warnings=[], blockers=[], notes=list(shared.notes),
            networks=list(shared.networks), extra_disks=list(shared.extra_disks),
            iso_rejected=set(shared.iso_rejected), replace_vm=None)
        if t.datastore and t.datastore.is_vsan:
            pl.provisioning = Provisioning.THIN
        values = {**self._values(slots_index(self.assignment, s, self.b.start)), "name": s.name,
                  "hostname": s.hostname or s.name, "address": (s.address or "").split("/")[0]}
        props = {**shared.ovf_properties, **t.ovf}
        pl.ovf_properties = {k: expand(v, values) for k, v in props.items()}
        register_passwords(pl.ovf_properties, self.pkg.info.properties if self.pkg else [])
        if shared.guest:
            g = shared.guest.model_copy(deep=True)
            g.hostname = s.hostname
            a = self.addresses
            g.network = GuestNetwork(mode="static", address=s.address, gateway=a.gateway, dns=a.dns,
                                     search=a.search) if s.address and a else None
            pl.guest = g
        return pl

    # ------------------------------------------------------------------------------------- checks
    def _preflight(self) -> None:
        plan, conn = self.plan, self.conn
        dc = plan.dc
        self.batch_warnings += list(plan.warnings)
        errors, warns = check_parallel(self.n_vms, self.n_uploads, self.n_per_host,
                                       hosts=len({t.key for t in self.targets}), is_vcenter=conn.is_vcenter)
        if errors:
            raise ConfigError(" ".join(errors), hint="Change batch.parallel in the manifest, or --per-host.")
        self.batch_warnings += warns
        if plan.extra_disks and self.pkg:
            kinds = self.pkg.info.storage_controllers(plan.deployment_option)
            if kinds and not kinds & {"scsi", "nvme"}:
                raise ConfigError(f"The image's VM has only {', '.join(sorted(k.upper() for k in kinds))} disk "
                                  "controller(s); extra disks need a SCSI or NVMe controller.",
                                  hint="Remove resources.extra_disks (add the disks after deployment instead).")
        existing = self._existing_vms(dc) if any(s.clash for s in self.slots) else {}
        vlans = self._portgroup_vlans()
        uses = self._ip_uses if self._ip_uses is not None else \
            netcheck.ip_uses(conn) if any(s.address for s in self.slots) else []
        props = {pr.key: pr for pr in self.pkg.info.properties} if self.pkg else {}
        checked_rights: dict[tuple, dict | None] = {}
        for s in self.slots:
            s.blockers, s.warnings = [], []
            t = s.target
            if t.problem:
                s.blockers.append(t.problem)
                continue
            if s.address_problem:
                s.blockers.append(s.address_problem)
                continue
            self._check_name(s, existing)
            self._check_networks(s, dc, vlans)
            self._check_slot_compat(s)
            s.blockers += ovf_value_problems(s.plan.ovf_properties, props)
            if s.address and s.plan.networks:
                net0 = s.plan.networks[0][1]
                blockers, warnings = netcheck.find_conflicts(uses, s.address, getattr(net0, "vc_name", "") or net0.name,
                                                             ignore_vm=s.name if s.replace_vm is not None else None)
                s.blockers += blockers
                s.warnings += warnings
            if s.plan.vtpm:
                self._with_slot(s, self._check_vtpm)
            key = (id(t.pool), id(t.datastore), id(s.plan.networks[0][1]) if s.plan.networks else None)
            if key not in checked_rights:
                checked_rights[key] = check_privileges(conn, {
                    "folder": plan.folder, "resource_pool": t.pool, "datastore": t.datastore.obj,
                    "network": s.plan.networks[0][1].obj if s.plan.networks else None, "virtual_machine": plan.folder,
                    **({"compatibility_upgrade": plan.folder} if plan.compat_upgrade else {}),
                    **({"vtpm": plan.folder} if plan.vtpm else {})})
            for group, ids in (checked_rights[key] or {}).items():
                s.warnings.append(f"missing privileges on {group.replace('_', ' ')}: {', '.join(ids)}")
        self._check_hostnames()
        self._check_space()
        self._check_host_load(dc)
        if self.image.is_iso:
            self._check_iso()

    def _with_slot(self, s: Slot, check) -> None:
        """Run a single-VM check on this VM's plan, quietly (its notes would flood the screen), keeping what it
        finds on the VM."""
        shared, view = self.plan, self.view
        self.plan, self.view = s.plan, DeploymentView("check", PLAN_STEPS, enabled=False)
        self.view._log_plain = lambda text: None  # noqa: SLF001 - silent
        try:
            check()
        finally:
            self.plan, self.view = shared, view
        s.blockers += s.plan.blockers
        s.warnings += s.plan.warnings
        s.plan.blockers, s.plan.warnings = [], []

    def _existing_vms(self, dc) -> dict[str, dict]:
        """Name -> where the existing VM is (folder, host) and whether this tool deployed it."""
        folders = {getattr(obj, "_moId", None): path for path, obj in dc.folders.items()}
        hosts = {h.moid: h.name for h in dc.hosts.values()}
        out: dict[str, dict] = {}
        for vm, props in vm_properties(self.conn, ["name", "parent", "runtime.host", "config.annotation"],
                                       root=dc.vm_folder):
            name = props.get("name")
            if not name:
                continue
            host = props.get("runtime.host")
            parent = props.get("parent")
            out[name] = {"vm": vm, "folder": folders.get(getattr(parent, "_moId", None), "?"),
                         "host": hosts.get(getattr(host, "_moId", None), "?"),
                         "marked": vmnotes.is_marked(props.get("config.annotation"))}
        return out

    def _check_name(self, s: Slot, existing: dict[str, dict]) -> None:
        if not s.clash:
            return
        where = existing.get(s.name, {})
        at = f"folder {where.get('folder', '?')}, host {where.get('host', '?')}"
        if self.name_conflict == "replace":
            if where.get("marked"):
                s.replace_vm = where.get("vm")
                s.plan.replace_vm = s.replace_vm
                s.warnings.append(f"the existing VM '{s.name}' ({at}) will be DELETED and re-created")
            else:
                s.blockers.append(f"a VM named '{s.name}' already exists ({at}) and was not deployed by vmdeploy, so "
                                  "it is never replaced")
        else:
            s.blockers.append(f"a VM named '{s.name}' already exists ({at})")

    def _portgroup_vlans(self) -> dict[str, dict[str, int]]:
        """Host name -> {standard port group name: VLAN ID}, for the batch's hosts, in one read."""
        names = set().union(*(t.hosts(self.plan.dc) for t in self.targets))
        out: dict[str, dict[str, int]] = {}
        for _obj, props in collect(self.conn, vim.HostSystem, ["name", "config.network.portgroup"]):
            if props.get("name") in names:
                out[props["name"]] = {pg.spec.name: pg.spec.vlanId for pg in props.get("config.network.portgroup") or []
                                      if getattr(pg, "spec", None)}
        return out

    def _check_networks(self, s: Slot, dc, vlans: dict[str, dict[str, int]]) -> None:
        t = s.target
        hosts = t.hosts(dc)
        for _ovf, net, _adapter in s.plan.networks:
            if net.hosts and not hosts & net.hosts:
                s.blockers.append(f"network {net.vc_name} is not available on {t.where}")
                continue
            if net.hosts and not hosts <= net.hosts:
                s.warnings.append(f"network {net.vc_name} is only on some hosts of {t.where}; DRS uses only those")
            if net.kind != "standard" or not t.host:
                continue
            here = vlans.get(t.host.name, {}).get(net.vc_name)
            others: dict[int, list[str]] = {}
            for other in self.targets:
                if other.host and other.host.name != t.host.name:
                    v = vlans.get(other.host.name, {}).get(net.vc_name)
                    if v is not None and v != here:
                        others.setdefault(v, []).append(other.host.name)
            if here is not None and others:
                elsewhere = "; ".join(f"VLAN {v} on {', '.join(sorted(hs))}" for v, hs in sorted(others.items()))
                s.warnings.append(f"port group {net.vc_name} is VLAN {here} on {t.host.name}, but {elsewhere}")

    def _check_slot_compat(self, s: Slot) -> None:
        key = s.plan.hardware_version
        c = self.compats.get(s.target.compat_key or "")
        if key and c and c.supported and key not in c.supported:
            s.blockers.append(f"VM compatibility {compat.describe(key)} is not supported on {s.target.where} "
                              f"(newest there: {compat.describe(c.newest)})")

    def _check_hostnames(self) -> None:
        seen: dict[str, list[str]] = {}
        for s in self.slots:
            if s.hostname and not s.blockers:
                seen.setdefault(s.hostname.lower(), []).append(s.name)
        for hostname, names in seen.items():
            if len(names) > 1:
                self.batch_warnings.append(f"Hostname {hostname} is used by {len(names)} VMs ({', '.join(names[:5])}"
                                           f"{', ...' if len(names) > 5 else ''}); put {{n}} in batch.hostname to make "
                                           "them different.")

    def _check_space(self) -> None:
        uses = []
        for s in self.slots:
            if s.blockers or not s.target.datastore:
                continue
            initial, full = self._space_needed(s.plan)
            uses.append(SpaceUse(s, s.target.datastore.display_name, initial, full))
        free = {t.datastore.display_name: t.datastore.free for t in self.targets if t.datastore}
        refused, warnings = fit_datastores(uses, free, human_size)
        for s, why in refused.items():
            s.blockers.append(why)
        self.batch_warnings += [w[0].upper() + w[1:] + "." for w in warnings.values()]

    def _check_host_load(self, dc) -> None:
        mem: dict[str, int] = {}
        cpu: dict[str, int] = {}
        for s in self.slots:
            if s.blockers or not s.target.host:
                continue
            h = s.target.host.name
            mem[h] = mem.get(h, 0) + (s.plan.memory_mb or 0)
            cpu[h] = cpu.get(h, 0) + (s.plan.cpu or 0)
        for name, add_mb in mem.items():
            h = dc.hosts[name]
            if h.mem_bytes and (h.allocated_mem_mb + add_mb) / 1024 > h.mem_bytes / GiB:
                self.batch_warnings.append(f"{name} would have {(h.allocated_mem_mb + add_mb) / 1024:.0f} GB of VM "
                                           f"memory allocated on {h.mem_bytes / GiB:.0f} GB physical RAM.")
            if h.cpu_threads and (h.allocated_vcpus + cpu[name]) / h.cpu_threads > 4:
                self.batch_warnings.append(f"{name} would have {h.allocated_vcpus + cpu[name]} vCPU on "
                                           f"{h.cpu_threads} logical CPUs "
                                           f"({(h.allocated_vcpus + cpu[name]) / h.cpu_threads:.1f}:1 overcommit).")

    def _check_iso(self) -> None:
        """The ISO checks of one VM, for the first VM that can be deployed: where the ISO comes from and whether it
        is already on a datastore. The others get a copy of the same file when the ISO is placed (_stage_isos)."""
        rep = next((s for s in self.slots if not s.blockers), None)
        if rep is None:
            return
        shared = self.plan
        self.plan = rep.plan
        try:
            if self.image.source_kind == "datastore_iso":
                self._check_iso_on_datastore()
            elif self.image.path:
                self._find_same_iso_on_datastores()
        finally:
            self.plan = shared
        if rep.plan.blockers:  # the ISO cannot be used at all: no VM can be built
            for s in self.slots:
                s.blockers += [b for b in rep.plan.blockers if b not in s.blockers]
        self.batch_warnings += rep.plan.warnings
        rep.plan.blockers, rep.plan.warnings = [], []
        self.iso_rep = rep

    # ------------------------------------------------------------------------------------- review
    def _review_plan(self) -> bool:
        plan, p = self.plan, self.p
        ok = [s for s in self.slots if not s.blockers]
        blocked = [s for s in self.slots if s.blockers]
        head = Table(show_header=False, box=None, padding=(0, 2))
        head.add_row("[bold]Image", esc(f"{self.image.display}  [{self.image.format.upper()}]"))
        head.add_row("[bold]Each VM", esc(
            f"{plan.cpu} vCPU, {plan.memory_mb / 1024:g} GB RAM, {plan.disk_gb} GB disk ({plan.provisioning.value})"
            + "".join(f", +{size} GB" for size, _ in plan.extra_disks)
            + f"; {compat.describe(plan.hardware_version)}"))
        head.add_row("[bold]Networks", esc(", ".join(n.name for _, n, _ in plan.networks)))
        head.add_row("[bold]Folder", esc(plan.folder_path))
        if plan.guest:
            from .cloudinit import sets_dhcp_identifier

            g = plan.guest
            login = " + ".join(x for x, on in (("SSH key", g.ssh_authorized_keys), ("password", g.password_hash)) if on)
            static = self.addresses and self.addresses.mode == "static"
            head.add_row("[bold]First boot", esc(
                f"cloud-init: user {g.username}" + (f" ({login})" if login else "")
                + f"; hostnames {self.hostname_pattern or 'left to the image'}"
                + ("; static addresses" if static else
                   "; DHCP (identified by MAC address)" if sets_dhcp_identifier(g) else "; DHCP")))
        if plan.ovf_properties:
            head.add_row("[bold]Properties", f"{len(plan.ovf_properties)} OVF propert(ies) set")
        head.add_row("[bold]After", ", ".join(x for x in (
            "power on" if plan.power_on else "leave powered off", "wait for IP" if plan.wait_for_ip else "",
            "baseline snapshot" if plan.snapshot else "") if x))
        head.add_row("[bold]Parallel", f"{self.n_vms} VMs at a time, {self.n_uploads} upload(s), {self.n_per_host} "
                                       "per host")
        failing = "; on failure: stop starting new VMs" if self.stop_on_failure else ""
        head.add_row("[bold]Failures", ("a VM that fails half-way is kept for troubleshooting" if self.keep_failed
                                        else "a VM that fails half-way is deleted; the others carry on") + failing)
        with p.section("Review the batch (nothing has been changed yet)"):
            console.print(head)
            console.print(self._slot_table())
            for n in plan.notes:
                console.print(f"[dim]  i {esc(n)}")
            for w in self.batch_warnings:
                console.print(f"[yellow]  ! {esc(w)}")
            for text, names in _grouped((s.warnings, s.name) for s in self.slots if not s.blockers):
                console.print(f"[yellow]  ! {esc(names)}: {esc(text)}")
            for s in blocked:
                console.print(f"[bold red]  ✖ {esc(s.name)} ({esc(s.target.where)}): {esc('; '.join(s.blockers))}")
            if blocked:
                console.print(f"[red]{len(blocked)} of {len(self.slots)} VM(s) fail their checks and would be "
                              "skipped.[/]")
            replacing = [s for s in ok if s.replace_vm is not None]
            if not p.interactive:
                if blocked and self.b.on_check_failure == "cancel":
                    raise ConfigError(f"Cannot deploy: {len(blocked)} VM(s) fail their checks "
                                      "(batch.on_check_failure: cancel).",
                                      hint="Fix the problems above, or set on_check_failure: skip. Nothing was "
                                           "changed.")
                if not ok:
                    raise ConfigError("None of the batch's VMs can be deployed.",
                                      hint="Fix the problems above, then run again. Nothing was changed.")
                self._skip(blocked)
                return True
            options = []
            if ok:
                options.append((f"Deploy the {len(ok)} VM(s)" + (f" (skip the {len(blocked)} that fail their checks)"
                                                                 if blocked else ""), "deploy"))
            options += [("Change my answers (your answers are pre-selected; the image is not downloaded again)",
                         "change"),
                        ("Cancel (nothing is changed)", "cancel")]
            choice = p.select("What next?", options, default="deploy" if ok else "change", auto_single=False)
            if choice == "cancel":
                raise UserAborted("Batch cancelled at the review step; nothing was changed.")
            if choice != "deploy":
                return False
            if replacing and not p.confirm(f"Delete and re-create the {len(replacing)} existing VM(s) "
                                           f"({', '.join(s.name for s in replacing[:5])}"
                                           f"{', ...' if len(replacing) > 5 else ''})?", default=False):
                self._decline_replacements(replacing)
                blocked = [s for s in self.slots if s.blockers]
            self._skip(blocked)
            if not any(s.status == "ready" for s in self.slots):
                raise UserAborted("Nothing left to deploy; nothing was changed.")
            return True

    def _decline_replacements(self, replacing: list[Slot]) -> None:
        """The existing VMs are kept, so these VMs are skipped. If the ISO was checked for one of them, it is checked
        again for a VM that is built: whether the ISO is used where it is, copied or uploaded depends on the VM's
        host, and staging needs that VM's plan to say which (still before anything is changed)."""
        for s in replacing:
            s.blockers.append("replacing the existing VM was declined")
        if self.image.is_iso and any(s is getattr(self, "iso_rep", None) for s in replacing):
            self._check_iso()

    def _skip(self, slots) -> None:
        for s in slots:
            s.status, s.step, s.error = SKIPPED, "checks", "; ".join(s.blockers)

    def _slot_table(self) -> Table:
        many = len(self.slots) > REVIEW_FULL_LIST
        t = Table(box=None, padding=(0, 2), header_style="bold")
        if many:  # one line per host; the problems are listed in full below the table
            for col in ("Host", "VMs", "Datastore", "Names", "Check"):
                t.add_column(col)
            groups: dict[str, list[Slot]] = {}
            for s in self.slots:
                groups.setdefault(s.target.where, []).append(s)
            for where, ss in groups.items():
                bad = sum(1 for s in ss if s.blockers)
                t.add_row(esc(where), str(len(ss)), esc(ss[0].target.datastore.display_name
                                                        if ss[0].target.datastore else "-"),
                          esc(f"{ss[0].name} .. {ss[-1].name}" if len(ss) > 1 else ss[0].name),
                          Text(f"✖ {bad} fail" if bad else "ok", style="red" if bad else "green"))
            return t
        for col in ("#", "VM", "Host", "Datastore", "Address", "Check"):
            t.add_column(col)
        for s in self.slots:
            check = Text("✖ fails", style="red") if s.blockers else (Text("! warning", style="yellow") if s.warnings
                                                                     else Text("ok", style="green"))
            t.add_row(str(s.n), esc(s.name), esc(s.target.where),
                      esc(s.target.datastore.display_name if s.target.datastore else "-"),
                      esc(s.address or ("DHCP" if self.addresses and self.addresses.mode == "dhcp" else "-")), check)
        return t

    # ------------------------------------------------------------------------------------- the ISO, once
    def _stage_isos(self, ready: list[Slot]) -> None:
        """Place the ISO once (as for one VM: used where it is, copied host to host, or uploaded once), then give
        every other VM a copy its host can reach: vCenter copies it host to host, so the ISO leaves this computer
        at most once."""
        rep = getattr(self, "iso_rep", None) or ready[0]
        if rep not in ready:
            rep = ready[0]
        view = DeploymentView(f"vsphere-vm-deployment {__version__}: placing the ISO", STAGE_STEPS)
        shared_view, shared_plan = self.view, self.plan
        self.view, self.plan, self.p.view = view, rep.plan, view
        dc = rep.plan.dc
        try:
            with view:
                try:
                    self._stage_iso()
                except VmDeployError as e:
                    for s in ready:
                        s.status, s.step, s.error, s.hint = FAILED, "Place the ISO", e.message, e.hint
                    return
                path = rep.plan.iso_datastore_path
                src_ds = dc.datastores.get(isolib.split(path)[0])
                copies: dict[str, str | VmDeployError] = {}
                pending = [s for s in ready if s is not rep and not (src_ds and s.target.hosts(dc) <= src_ds.hosts)]
                if not pending:
                    view.skip("copies", "every host can use it where it is")
                for s in ready:
                    if s is rep or s not in pending:
                        s.plan.iso_datastore_path = path
                for s in pending:
                    ds = s.target.datastore
                    if ds.name not in copies:
                        view.start("copies", f"{path} -> {ds.display_name} (server-side)")
                        try:
                            copies[ds.name], how = isolib.ensure_copied(
                                self.conn, dc.obj, path, ds.obj, isolib.copy_target(ds.name, path),
                                on_progress=lambda f: view.update("copies", fraction=f),
                                reuse_if=lambda full, src=path: self._same_iso(src, full))
                            view.note("copies", f"{copies[ds.name]} ({how})", style="dim")
                        except VmDeployError as e:
                            copies[ds.name] = e
                    got = copies[ds.name]
                    if isinstance(got, VmDeployError):
                        s.status, s.step, s.error, s.hint = FAILED, "Copy the ISO", got.message, got.hint
                    else:
                        s.plan.iso_datastore_path = got
                if pending:
                    bad = sum(1 for v in copies.values() if isinstance(v, VmDeployError))
                    view.done("copies", f"{len(copies) - bad} copy/copies ready" + (f", {bad} failed" if bad else ""),
                              status="warn" if bad else "done")
        finally:
            self.view, self.plan, self.p.view = shared_view, shared_plan, shared_view
        for s in ready:  # the builders find the ISO in place: nothing to upload or copy
            s.plan.iso_copy_from, s.plan.iso_copy_via_pc, s.plan.iso_found_on_datastore = None, False, False

    def _same_iso(self, source: str, full: str) -> bool:
        if self.image.sha256:
            return self._copy_is_genuine(full, "copies")
        return bool(self._same_remote(source, full))

    # ------------------------------------------------------------------------------------- building
    def _execute(self) -> None:
        ready = [s for s in self.slots if s.status == "ready"]
        if not ready:
            return
        dc = self.plan.dc
        host_limits = {}
        for s in ready:
            t = s.target
            # A DRS cluster gets the per-host limit for each of its usable hosts (DRS spreads the VMs over them).
            hosts = max(1, len(t.hosts(dc))) if t.drs else 1
            host_limits.setdefault(t.key, threading.Semaphore(self.n_per_host * hosts))
        uploads = threading.Semaphore(self.n_uploads)
        # --parallel limits the VMs being *built*. A VM waiting for its guest's address is not built any more, so it
        # gives its slot back (VmBuilder._wait_for_ip) and needs only a thread: more threads than build slots, so
        # the next VMs start while earlier ones wait for their address (up to several minutes each).
        builds = threading.Semaphore(self.n_vms)
        workers = min(len(ready), self.n_vms * WAITING_PER_BUILD)
        board = BatchView(self.slots, f"vsphere-vm-deployment {__version__}: building {len(ready)} VM(s)")
        for s in self.slots:
            s.row = RowView(s, self.cancel, plain=not board.enabled)
        with board, ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vmdeploy") as pool:
            pending = {pool.submit(self._build_one, s, host_limits[s.target.key], builds, uploads)
                       for s in build_order(ready)}
            while pending:
                try:
                    _done, pending = wait(pending, timeout=0.25, return_when=FIRST_COMPLETED)
                    if self.stop_on_failure and not self.stop_new.is_set() and \
                            any(s.status in (FAILED, PROBLEM) for s in ready):
                        self.stop_new.set()
                        log.warning("A VM failed and on_failure is stop: no new VMs are started")
                except KeyboardInterrupt:
                    self._interrupted(board)

    def _interrupted(self, board: BatchView) -> None:
        """Ctrl+C: stop starting new VMs; then let the running ones finish, or stop and clean them up. A second
        Ctrl+C stops and cleans up at once."""
        if self.stop_new.is_set():
            self.cancel.set()
            log.warning("Second Ctrl+C: stopping the running builds and cleaning up")
            return
        self.stop_new.set()
        log.warning("Ctrl+C: no new VMs are started")
        running = any(s.row and s.row.state == "running" for s in self.slots)
        choice = "stop"
        if running and self.p.interactive:
            try:
                with board.paused():
                    choice = self.p.select("Ctrl+C: no new VMs will be started. The VMs being built now:", [
                        ("Let them finish", "finish"), ("Stop them and clean up", "stop")], default="finish",
                        auto_single=False)
            except (UserAborted, KeyboardInterrupt):
                choice = "stop"
        if choice == "stop":
            self.cancel.set()

    def _build_one(self, s: Slot, host_limit: threading.Semaphore, builds: threading.Semaphore,
                   uploads: threading.Semaphore) -> None:
        """Take the host's slot, then a build slot (in that order, so a VM whose host is busy holds no build slot),
        build the VM, and give both back as soon as it only waits for its address."""
        row = s.row
        held: list[threading.Semaphore] = []

        def release() -> None:
            while held:
                held.pop().release()

        def take(limit: threading.Semaphore, reason: str) -> bool:
            row.set_waiting(reason)
            while not limit.acquire(timeout=0.5):
                if self.stop_new.is_set():
                    return False
            held.append(limit)
            return True

        try:
            ok = take(host_limit, f"waiting for its host (at most {self.n_per_host} at a time per host)") and \
                take(builds, f"waiting (at most {self.n_vms} VMs built at a time)")
            if not ok or self.stop_new.is_set():
                s.status, s.error = NOT_STARTED, "not started (the batch was stopped)"
                row.finish(NOT_STARTED)
                return
            VmBuilder(self, s, release, uploads).build()
            if self.stop_on_failure and s.status in (FAILED, PROBLEM) and not self.stop_new.is_set():
                # Set here, before this worker can take the next VM (the main loop would notice it too late).
                self.stop_new.set()
                log.warning("%s failed and on_failure is stop: no new VMs are started", s.name)
        finally:
            release()

    # ------------------------------------------------------------------------------------- results
    def _finish(self) -> dict:
        rows = [self._row(s) for s in self.slots]
        code = exit_code([r["status"] for r in rows])
        finished = datetime.now()
        build_s = round(time.monotonic() - self.build_t0, 1) if self.build_t0 is not None else None
        doc = {
            "batch": True, "version": __version__, "started": self.started.isoformat(timespec="seconds"),
            "finished": finished.isoformat(timespec="seconds"), "build_seconds": build_s,
            # which vCenter the VMs' ids (moid) belong to: `destroy --batch` finds VMs by id only on the same one
            "vcenter_uuid": _instance_uuid(self.conn),
            "manifest": self.bo.manifest_path,
            "image": self.image.display, "image_sha256": self.image.sha256, "datacenter": self.plan.dc.name,
            "totals": {k: sum(1 for r in rows if r["status"] == k) for k in (DEPLOYED, PROBLEM, FAILED, SKIPPED,
                                                                             NOT_STARTED)},
            "exit_code": code, "warnings": self.batch_warnings, "vms": rows,
            # what was answered (never a password), so --retry-failed can ask nothing again
            "answers": saved_answers(self.p.answers),
            # the run this one retried: `destroy --batch` on this file deletes that run's VMs too
            "retry_of": self.retry_of,
            # how it was started, so `deploy --retry-failed FILE` needs nothing else
            "profile": self.o.profile.name, "source": self._source(),
            "options": {"parallel": self.bo.parallel, "parallel_uploads": self.bo.parallel_uploads,
                        "per_host": self.bo.per_host, "stop_on_failure": self.bo.stop_on_failure,
                        "keep_failed": self.bo.keep_failed},
        }
        path = save_results(doc, f"batch-{self.started:%Y%m%d-%H%M%S}")
        if path:
            doc["results_file"] = str(path)
        print_summary(doc, build_s, path, self.bo.manifest_path)
        return doc

    def _source(self) -> dict | None:
        """The image as given on the command line (a local file by its full path, so a retry from another folder
        finds it). None when it was chosen in the questions: the saved answers cover that."""
        kind, value = self.o.image_kind, self.o.image_value
        if not kind:
            return None
        if kind == "local" and getattr(self.image, "path", None):
            value = str(Path(self.image.path).resolve())
        if kind == "url" and value and safe_url(value) != value:
            # a password or token in the URL (user:password@, a pre-signed query) is never saved, as in the logs:
            # a retry asks for --url again, and the saved SHA-256 checks it is the same image
            return {"kind": kind, "value": safe_url(value), "sha256": self.o.sha256, "redacted": True}
        return {"kind": kind, "value": value, "sha256": self.o.sha256}

    def _row(self, s: Slot) -> dict:
        r = s.result or {}
        # pattern_name: what --retry-failed matches (name_conflict: next-free may have made web-01 web-01-2)
        return {"n": s.n, "name": s.name, "pattern_name": s.pattern_name, "host": s.target.where,
                "datastore": s.target.datastore.display_name if s.target.datastore else None,
                "address": s.address, "hostname": s.hostname,
                "status": s.status if s.status != "ready" else NOT_STARTED, "step": s.step, "error": s.error,
                "hint": s.hint, "kept": s.kept, "created": s.created, "cleanup_failed": s.cleanup_failed,
                "moid": r.get("moid"), "ip": r.get("ip"),
                "console_url": r.get("console_url"), "warnings": s.warnings + list(r.get("warnings") or []),
                "timings_s": r.get("timings_s")}


HIDDEN = "********"


def register_passwords(values: dict[str, str], props) -> None:
    """A VM's values of the image's password properties, as filled in for it, are never logged: a password set for
    one target, or through a pattern, is not the manifest value registered when the questions were asked."""
    for pr in props:
        if pr.password and values.get(pr.key):
            register_secret(str(values[pr.key]))


def ovf_value_problems(values: dict[str, str], props: dict) -> list[str]:
    """Why the image refuses each of a VM's OVF property values (a check failure for that VM). A password's value
    is never shown: the message reaches the screen, the results file and --json."""
    out = []
    for key, value in values.items():
        pr = props.get(key)
        if pr is not None and (why := ovflib.check_value(pr, value)):
            out.append(f"OVF property {key} = '{HIDDEN if pr.password else value}': {why}")
    return out


def _name_span(names: list[str], ends_only: bool = False) -> str:
    """'a, b, … z' (or 'a … z' with ends_only) for a preview of many names; all of them when there are few."""
    if len(names) <= 3:
        return ", ".join(names)
    return f"{names[0]} … {names[-1]}" if ends_only else f"{names[0]}, {names[1]}, … {names[-1]}"


def name_base(pkg, image) -> str:
    """The start of the suggested name pattern: the image's product name, or its file name without the extension
    (image_name_hint drops it, so nothing more is cut: 'rhel-9.4-x86_64-dvd', not 'rhel-9')."""
    return safe_vm_name(suggest_vm_name(image_name_hint(pkg, image), set()) or "vm")[:60]


def _words(text: str) -> list[str]:
    return [x for x in text.replace(",", " ").split() if x]


def split_addresses(text: str) -> tuple[str | None, list[str]]:
    """Typed addresses as (range, list): a range has a '-'; a list is separated by commas or spaces."""
    text = text.strip()
    return (text, []) if "-" in text else (None, _words(text))


def addresses_problem(text: str, count: int) -> str | None:
    """Why a typed range or list cannot give the batch's `count` VMs an address each, or None. A range is a pool
    (the addresses in use are skipped when the VMs get theirs); a list gives one address per VM, in order. The prefix
    is not known yet: a list entry without one is checked as a single address (all are checked again with it)."""
    if not text.strip():
        return "Type a range (192.0.2.50-192.0.2.69) or a list (192.0.2.50, 192.0.2.61)."
    rng, listed = split_addresses(text)
    if rng:
        return range_problem(rng, count, what="The range")
    try:
        address_list("static", range_text=None, listed=listed, prefix=32, gateway=None, count=count, what="The list")
    except ConfigError as e:
        return e.message
    return None


def _first_repeat(names: list[str]) -> str | None:
    seen: set[str] = set()
    for n in names:
        if n in seen:
            return n
        seen.add(n)
    return None


def build_order(ready: list[Slot]) -> list[Slot]:
    """The order the VMs are handed to the workers: round-robin over their targets (each target's first VM, then
    each one's second, ...; targets in batch order). A worker waits for its VM's host, so a queue that started with
    one host's VMs kept every worker on that host and the other hosts idle (simulated: 4 hosts x 50 VMs at
    --parallel 8 took 2.4 times as long, 3.4 VMs built at a time instead of 8)."""
    index: dict[int, int] = {}
    for s in ready:
        index.setdefault(id(s.target), len(index))
    return sorted(ready, key=lambda s: (s.i, index[id(s.target)]))


def slots_index(assignment, s: Slot, start: int) -> int:
    return s.n - start


def _grouped(items) -> list[tuple[str, str]]:
    """The same warning on many VMs is listed once, with the VMs' names."""
    by_text: dict[str, list[str]] = {}
    for texts, name in items:
        for text in texts:
            by_text.setdefault(text, []).append(name)
    return [(text, ", ".join(names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else ""))
            for text, names in by_text.items()]


def _host_folder(h: HostInfo) -> str:
    """'/Lab/Hosts' for a host inside host folders (the datacenter's own 'host' folder is the root)."""
    parts: list[str] = []
    obj = getattr(h.obj, "parent", None)
    while obj is not None and not isinstance(obj, vim.Datacenter):
        if isinstance(obj, vim.Folder):
            parts.append(obj.name)
        obj = getattr(obj, "parent", None)
    parts = parts[:-1]  # the datacenter's root host folder ("host")
    return "/" + "/".join(reversed(parts))


# ================================================================================================ one VM
class VmBuilder(Deployment):
    """Builds one VM of a confirmed batch: the single-VM steps, over its own session, without questions."""

    # Ctrl+C in a batch does not just stop the wait (BatchDeployment._interrupted asks what to do), so the
    # single-VM hint is left out.
    IP_WAIT_HINT = ""

    def __init__(self, parent: BatchDeployment, slot: Slot, release_slots, uploads: threading.Semaphore):
        super().__init__(parent.o)
        self.parent, self.slot = parent, slot
        self.view = slot.row
        self.p = Prompter(False, self.view)
        self.trust = copy.copy(parent.trust)  # shares the certificates already trusted in this run
        self.trust.prompter = self.p
        self.inv, self.image, self.appliance = parent.inv, parent.image, parent.appliance
        self.image_dc = parent.image_dc
        self.plan = slot.plan
        self.keep_partial = parent.keep_failed
        self.batch_spec = parent.b
        self._release_slots = release_slots
        self._uploads = uploads

    def _say(self, markup: str) -> None:
        text = Text.from_markup(markup).plain
        log.info("%s", text)
        self.view.note_line(text)

    def _status(self, text: str):
        text = _CTRL_C_SKIP.sub("", Text.from_markup(text).plain)
        log.info("%s", text)
        self.view.note_line(text)
        return contextlib.nullcontext()

    def _wait_for_ip(self, vm, timeout: int):
        # Waiting for the guest is neither work on the host nor a build: let the next VMs start.
        self._release_slots()
        return super()._wait_for_ip(vm, timeout)

    def build(self) -> None:
        s, row = self.slot, self.view
        set_log_label(s.name)
        row.set_running()
        try:
            self.pkg = OvfPackage(self.parent.pkg.path) if self.parent.pkg else None  # its own file handle
            with self.parent.clone_lock:
                ensure_session(self.parent.conn)  # a long batch can leave the main session idle too
                self.conn = clone_session(self.parent.conn)
            if self.plan.replace_vm is not None:
                row.start("create", "deleting the existing VM first (replace)")
                self._destroy(self.plan.replace_vm, f"existing VM '{s.name}' (replace)")
            if self.image.is_iso:
                self._deploy_iso()
            else:
                row.set_waiting("waiting for an upload slot")
                while not self._uploads.acquire(timeout=0.5):
                    row.check_cancel()
                row.set_running()
                try:
                    self._deploy_ova()
                finally:
                    self._uploads.release()
            self._power_and_finish()
            s.result, s.status = self.summary, DEPLOYED
            row.finish(DEPLOYED, self.summary.get("ip") or "")
        except BaseException as e:  # noqa: BLE001 - a failure stays with this VM
            row.cleaning = True
            s.step = row.running_title() or s.step or ("" if self.conn else "open its own session")
            # a vSphere fault's text, not pyVmomi's dump of the whole fault object
            s.error = getattr(e, "message", None) or fault_message(e) or type(e).__name__
            s.created = bool(self.created or self.vm is not None)
            s.hint = getattr(e, "hint", None)
            if not isinstance(e, VmDeployError | KeyboardInterrupt):
                log.exception("Unexpected error while building %s", s.name)
            row.fail_running(s.error)
            if self.vm_ready:
                s.status, s.kept = PROBLEM, True
                s.result = self.summary or None
            else:
                s.status = FAILED
            try:
                self._cleanup_after_failure(e)
            except BaseException as ce:  # noqa: BLE001 - never hide the build failure
                log.warning("clean-up of %s failed: %s", s.name, ce)
            s.created = s.created or self.aborted_vm is not None  # an aborted import's VM, removed by vCenter
            s.cleanup_failed = self.cleanup_failed  # it says so on the row, but the summary must not say "deleted"
            if s.status == FAILED and self.keep_partial and self.created and self.vm is not None:
                s.kept = True
            row.finish(s.status, s.error)
        finally:
            if self.pkg:
                self.pkg.close()
            if self.conn:
                self.conn.close()
            set_log_label(None)


# ================================================================================================ the screen
class RowView(DeploymentView):
    """One VM's steps, shown as one row of the batch table (or as plain lines without a terminal). The builder
    calls it like the single-VM view; it also stops the build when the batch is cancelled (Ctrl+C)."""

    def __init__(self, slot: Slot, cancel: threading.Event, plain: bool):
        super().__init__(slot.name, STEPS, enabled=False)
        self.slot, self.cancel, self.plain = slot, cancel, plain
        self.cleaning = False
        self.state = "queued"  # queued | waiting | running | done states (deployed, failed, ...)
        self.wait_reason = ""
        self.moved, self.total, self.t0, self.t_end = 0, None, None, None
        self.last = ""
        self._speed_mark = (0.0, 0)
        self.speed = 0.0

    def check_cancel(self) -> None:
        if self.cancel.is_set() and not self.cleaning:
            raise UserAborted("Stopped (Ctrl+C).")

    def set_waiting(self, reason: str) -> None:
        self.state, self.wait_reason = "waiting", reason

    def set_running(self) -> None:
        self.state = "running"
        self.t0 = self.t0 or time.monotonic()

    def finish(self, status: str, detail: str = "") -> None:
        self.state, self.t_end = status, time.monotonic()
        self.last = detail or self.last
        if self.plain:
            console.print(f"{self.slot.name}: {status}" + (f" ({detail})" if detail else ""), markup=False)

    def running_title(self) -> str | None:
        return next((s.title for s in self.steps.values() if s.status == "running"), None)

    def start(self, key: str, detail: str = "") -> None:
        self.check_cancel()
        super().start(key, detail)

    def update(self, key: str, detail: str | None = None, fraction: float | None = None) -> None:
        self.check_cancel()
        super().update(key, detail, fraction)

    def note_line(self, text: str) -> None:
        self.last = text
        if self.plain:
            console.print(f"{self.slot.name}: {text}", markup=False)

    def note(self, key: str, text: str, style: str = "yellow") -> None:
        super().note(key, text, style)
        self.last = text

    def _log_plain(self, text: str) -> None:
        if self.plain:
            console.print(f"{self.slot.name}: {text.strip()}", markup=False)

    def begin_transfer(self, key: str, description: str, total: int | None):
        self.check_cancel()
        self._transfer_step = key  # done(key) ends the transfer, so the next step shows no stale percentage
        self.moved, self.total = 0, total
        self._speed_mark = (time.monotonic(), 0)
        last_log = [0.0]

        def advance(nbytes: int) -> None:
            self.check_cancel()
            self.moved += nbytes
            if total:
                self.steps[key].fraction = min(1.0, self.moved / total)
            now = time.monotonic()
            t0, m0 = self._speed_mark
            if now - t0 >= 2:
                self.speed = (self.moved - m0) / (now - t0)
                self._speed_mark = (now, self.moved)
            if self.plain and now - last_log[0] > 10:
                last_log[0] = now
                pct = f"{self.moved * 100 / total:.0f}%" if total else human_size(self.moved)
                console.print(f"{self.slot.name}: {description}: {pct}", markup=False)

        return advance

    def end_transfer(self) -> None:
        self.total, self._transfer_step = None, None

    @contextlib.contextmanager
    def paused(self, header: str | None = None):
        yield


_CTRL_C_SKIP = re.compile(r"\s*\(Ctrl\+C to skip[^)]*\)")

_STATE_STYLE = {DEPLOYED: ("✔", "green"), PROBLEM: ("!", "yellow"), FAILED: ("✖", "bold red"),
                SKIPPED: ("–", "dim"), NOT_STARTED: ("–", "dim")}


class BatchView:
    """The live table: one row per VM, the running ones first when they do not all fit on the screen."""

    def __init__(self, slots: list[Slot], title: str):
        self.slots, self.title = slots, title
        self.enabled = console.is_terminal
        self._live: Live | None = None
        self.t0 = time.monotonic()

    def _new_live(self) -> Live:
        return Live(get_renderable=self._render, console=console, refresh_per_second=4, transient=True,
                    redirect_stderr=False, redirect_stdout=False)

    def __enter__(self) -> BatchView:
        if self.enabled:
            self._live = self._new_live()
            self._live.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._live:
            self._live.stop()
            self._live = None
        if self.enabled:
            console.print(self._render(final=True))

    @contextlib.contextmanager
    def paused(self):
        live = self._live
        if live:
            live.stop()
        try:
            yield
        finally:
            if live and self._live is live:
                self._live = self._new_live()  # not live.start(): see DeploymentView.paused
                self._live.start()

    def _render(self, final: bool = False):
        rows = [s for s in self.slots if s.row is not None and s.status != SKIPPED]
        counts: dict[str, int] = {}
        for s in self.slots:
            state = s.status if s.status != "ready" else (s.row.state if s.row else "queued")
            if s.row and s.row.cleaning and s.row.state == "running":
                state = "cleaning up"
            counts[state] = counts.get(state, 0) + 1
        room = max(5, console.height - 8) if not final else len(rows)
        if len(rows) > room:
            active = [s for s in rows if s.row.state in ("running", "waiting")]
            done = [s for s in rows if s.row.state not in ("running", "waiting", "queued")]
            rows = (active + done[-max(0, room - len(active)):])[:room]
        t = Table(box=None, padding=(0, 1), expand=True, show_header=False)
        t.add_column(width=2)
        t.add_column(no_wrap=True)
        t.add_column(no_wrap=True, style="dim")
        t.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        t.add_column(justify="right", no_wrap=True, style="dim")
        for s in rows:
            r = s.row
            if r.state in _STATE_STYLE:
                icon, style = _STATE_STYLE[r.state]
                text = Text(f"{r.state}" + (f": {r.last}" if r.last else ""), style=style)
                took = duration((r.t_end or time.monotonic()) - r.t0) if r.t0 else ""
            elif r.state == "running" and r.cleaning:
                icon = "⠿"
                text = Text("cleaning up", style="bold yellow")
                if r.last:
                    text.append(f"  {r.last}", style="dim")
                took = duration(time.monotonic() - r.t0) if r.t0 else ""
            elif r.state == "running":
                icon = "⠿"
                title = r.running_title() or "starting"
                step = next((x for x in r.steps.values() if x.status == "running"), None)
                detail = step.detail if step else ""
                text = Text(title, style="bold")
                if r.total:
                    pct = r.moved * 100 / r.total
                    text.append(f"  {pct:3.0f}%  {human_size(r.speed)}/s" if r.speed else f"  {pct:3.0f}%",
                                style="cyan")
                elif detail:
                    text.append(f"  {detail}", style="dim")
                took = duration(time.monotonic() - r.t0) if r.t0 else ""
            else:
                icon, text, took = "…", Text(r.wait_reason or "queued", style="dim"), ""
            t.add_row(icon, s.name, s.target.where, text, took)
        summary = ", ".join(f"{n} {k}" for k, n in counts.items())
        from rich.console import Group
        from rich.panel import Panel

        return Panel(Group(t, Text(summary + f"   {duration(time.monotonic() - self.t0)}", style="dim")),
                     title=f"[bold]{esc(self.title)}", title_align="left", border_style="cyan")


# ================================================================================================ summary
def save_results(doc: dict, stem: str) -> Path | None:
    """Write a batch's results file, without which it cannot be retried or deleted as a whole: in the log folder,
    or the standard one when that cannot be written now (a share gone offline during a long batch, also one named
    by VMDEPLOY_LOG_DIR). Never over another file: a batch started in the same second (another run, or another
    computer sharing the folder) gets <stem>-2.json. None when no folder can be written."""
    folders: list[Path] = []
    try:
        folders.append(log_dir())
    except OSError as e:
        log.warning("the log folder cannot be used now (%s): the results file goes to the standard folder", e)
    folders.append(default_log_dir())
    text = json.dumps(doc, indent=2)
    for folder in dict.fromkeys(folders):
        try:
            folder.mkdir(parents=True, exist_ok=True)
            for k in range(1, 100):
                path = folder / (f"{stem}.json" if k == 1 else f"{stem}-{k}.json")
                try:
                    with open(path, "x", encoding="utf-8") as f:
                        f.write(text)
                    return path
                except FileExistsError:
                    continue
        except OSError as e:
            log.warning("could not write the results file in %s: %s", folder, e)
    return None


def results_arg(path: Path) -> str:
    """A results file as a command names it: its name alone when it is in the log folder (looked up there), else
    its path, quoted when it has spaces (a folder such as "OneDrive - Company" would split the command). Also its
    path when the chosen folder could not be used and the file went to the standard one: once that folder (a share)
    is back, a name alone is looked up there."""
    try:
        folder = log_dir()
        if log_dir_problem() is None and Path(folder).resolve() == path.parent.resolve():
            return path.name
    except OSError:  # the log folder cannot be reached: the full path
        pass
    text = str(path)
    return f'"{text}"' if any(c.isspace() for c in text) else text


def print_summary(doc: dict, seconds: float | None, path: Path | None, manifest_path: str | None) -> None:
    """`seconds`: from the confirmed review to the end (the time spent answering questions is not counted)."""
    rows = doc["vms"]
    totals = doc["totals"]
    parts = [f"{totals[DEPLOYED] + totals[PROBLEM]} deployed"]
    parts += [f"{totals[k]} {label}" for k, label in ((FAILED, "failed"), (SKIPPED, "skipped"),
                                                      (NOT_STARTED, "not started")) if totals[k]]
    style = "bold green" if doc["exit_code"] == 0 else "bold yellow" if doc["exit_code"] == 4 else "bold red"
    took = f" in {duration(seconds)}" if seconds is not None else ""
    console.print(Text(f"\nBatch finished{took}: " + ", ".join(parts), style=style))

    hosts = tally_by_host(rows)
    t = Table(box=None, padding=(0, 2), header_style="bold")
    for col in ("Host", "Deployed", "Failed", "Skipped", "Not started"):
        t.add_column(col, justify="left" if col == "Host" else "right")
    for host, tally in hosts.items():
        bad = tally.failed or tally.skipped or tally.not_started
        t.add_row(Text(host, style="yellow" if bad else ""), str(tally.deployed), str(tally.failed or ""),
                  str(tally.skipped or ""), str(tally.not_started or ""))
    console.print(t)

    problems = [r for r in rows if r["status"] != DEPLOYED]
    if problems:
        console.print(Text("\nNot deployed, or deployed with a problem (where to look):", style="bold"))
        p = Table(box=None, padding=(0, 2), header_style="bold")
        for col in ("VM", "Host", "Result", "Step", "Why"):
            p.add_column(col, overflow="fold")
        for r in problems:
            result = {FAILED: "failed", SKIPPED: "skipped", NOT_STARTED: "not started", PROBLEM: "deployed, problem"}
            what = result.get(r["status"], r["status"])
            if r.get("kept"):
                what += " (VM kept)"
            elif r.get("cleanup_failed"):
                what += " (the partial VM could NOT be deleted: it is still there)"
            elif r["status"] == FAILED and r.get("created", True):
                what += " (partial VM deleted)"
            why = (r.get("error") or "") + (f"  hint: {r['hint']}" if r.get("hint") else "")
            p.add_row(esc(r["name"]), esc(r["host"] or "?"), what, esc(r.get("step") or ""), esc(why))
        console.print(p)
    deployed = [r for r in rows if r["status"] in (DEPLOYED, PROBLEM)]
    if deployed and len(deployed) <= 30:
        console.print(Text("\nDeployed:", style="bold"))
        d = Table(box=None, padding=(0, 2), header_style="bold")
        for col in ("VM", "Host", "IP address"):
            d.add_column(col, overflow="fold")
        for r in deployed:
            d.add_row(esc(r["name"]), esc(r["host"] or "?"), esc(r.get("ip") or "-"))
        console.print(d)
        links = [r for r in deployed if r.get("console_url")]
        if links:
            # One line each, never broken by Rich (soft_wrap): a link folded inside a table cell cannot be clicked
            # or copied in one piece.
            console.print(Text("\nConsole links:", style="bold"))
            for r in links:
                console.print(Text(f"  {r['name']}  ", style="dim") + Text(r["console_url"]), soft_wrap=True)
    elif deployed:
        console.print(f"\n{len(deployed)} VMs deployed (each one's address and console link are in the results file).")
    for w in doc.get("warnings") or []:
        console.print(f"[yellow]! {esc(w)}[/]")
    if path:
        # Commands on one line each (soft_wrap: Rich broke one inside a folder name), with the file's name alone when
        # it is in the log folder (where a name is looked up): short, and nothing to quote.
        console.print(Text("\nResults saved: ") + Text(str(path)), soft_wrap=True)
        arg = results_arg(path)
        if deployed or any(r.get("kept") or r.get("cleanup_failed") for r in rows):
            also = " (and the run it retried)" if doc.get("retry_of") else ""
            console.print(f"[dim]To delete this batch's VMs{also} later: vmdeploy destroy --batch {esc(arg)}[/]",
                          soft_wrap=True)
        if problems and any(r["status"] in (FAILED, SKIPPED, NOT_STARTED) for r in problems):
            # everything else (manifest, image, profile, answers) is in the results file
            console.print(f"Retry the ones that were not deployed: [bold]vmdeploy deploy --retry-failed "
                          f"{esc(arg)}[/]  (or --retry-failed latest)", soft_wrap=True)
    elif doc.get("vms"):
        console.print("[yellow]! The results file could not be saved (the log says why): delete or retry this "
                      "batch's VMs one by one.[/]")
    lf = current_log_file()
    if lf:
        console.print(f"[dim]Log: {lf}[/]")


# ================================================================================================ destroy --batch
_URN = re.compile(r"urn:vmomi:VirtualMachine:[^:/]+:([0-9a-fA-F-]{36})")
_DESTROY_PROPS = ["name", "config.annotation", "config.hardware.device", "runtime.powerState"]


def _instance_uuid(conn) -> str | None:
    """vCenter's instance UUID (None on ESXi, whose VM ids are only unique on that host)."""
    try:
        return conn.content.about.instanceUuid or None
    except Exception:  # noqa: BLE001 - only used to match ids; without it VMs are matched by name
        return None


@dataclass
class DoomedVM:
    """One VM of a batch's results, as found now."""
    name: str  # as the results file has it
    host: str | None
    datacenter: str
    vm: object = None
    current_name: str | None = None  # its name now (a VM found by id may have been renamed since)
    power: str = ""
    isos: list[str] = field(default_factory=list)  # vmdeploy ISO copies it uses
    why: str | None = None  # not deleted: why
    gone: bool = False  # not there any more: nothing to do


def with_retried_runs(files: list[Path]) -> list[Path]:
    """The results files, each preceded by the runs it retried (`retry_of`, followed back to the first run), so
    one `destroy --batch` on a retry's file deletes the first run's VMs too. Each file once; a retried run's file
    that is gone (or on another computer's path) is looked for by name in the log folder, else said and skipped."""
    from .logfiles import results_file

    out: list[Path] = []
    seen: set[str] = set()

    def add(f: Path) -> None:
        key = str(f.resolve()).lower()
        if key in seen:
            return
        seen.add(key)
        try:
            prev = json.loads(f.read_text(encoding="utf-8")).get("retry_of")
        except (OSError, ValueError, AttributeError):
            prev = None  # load_batch_vms reports an unreadable file
        if isinstance(prev, str) and prev:
            first = Path(prev) if Path(prev).exists() else results_file(Path(Path(prev).name))
            if first.exists():
                console.print(Text("Also the run it retried: ", style="dim") + Text(str(first)), soft_wrap=True)
                add(first)
            else:
                console.print(Text(f"! {f.name} retried {Path(prev).name}, which is not in the log folder any more: "
                                   "only the VMs of the files given are listed.", style="yellow"), soft_wrap=True)
        out.append(f)

    for f in files:
        add(Path(f))
    return out


def holds_vm(r: dict) -> bool:
    """Whether a results row's VM is there (unless deleted since): deployed, deployed with a problem, a failed VM
    that was kept, or one whose deletion failed."""
    return r.get("status") in (DEPLOYED, PROBLEM) or bool(r.get("kept")) or bool(r.get("cleanup_failed"))


def held_addresses(doc: dict | None) -> list[tuple[str, str]]:
    """(address, VM name) for each VM a results file's batch left with an address, in that file and the runs it
    retried (`retry_of`, followed back to the first run, quietly: one that cannot be found or read ends the chain).
    vCenter does not see the address of a VM that is powered off (power_on: false) or has no VMware Tools, so
    without this a retry could give it to another VM."""
    from .logfiles import results_file

    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    while isinstance(doc, dict):
        for r in doc.get("vms") or []:
            if isinstance(r, dict) and r.get("address") and r.get("name") and holds_vm(r):
                out.append((str(r["address"]).split("/")[0].strip(), str(r["name"])))
        prev = doc.get("retry_of")
        if not isinstance(prev, str) or not prev:
            break
        try:
            f = Path(prev) if Path(prev).exists() else results_file(Path(Path(prev).name))
            key = str(f.resolve()).lower()
            if key in seen or not f.is_file():
                break
            seen.add(key)
            doc = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError, ConfigError):
            break
    return out


def load_batch_vms(files: list[Path]) -> tuple[list[tuple[dict, str | None]], set[str]]:
    """(results row, the vCenter UUID its id belongs to) for every VM the results files say exists (deployed,
    deployed with a problem, a failed VM that was kept, or one whose deletion failed), and the datacenters. A VM in
    several files (a retry) counts once, from the last file that lists it."""
    rows: dict[tuple[str, str], tuple[dict, str | None]] = {}
    dcs: set[str] = set()
    for f in files:
        try:
            doc = json.loads(Path(f).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise ConfigError(f"Could not read {f}: {e}") from None
        if not isinstance(doc, dict) or not doc.get("batch") or not isinstance(doc.get("vms"), list):
            raise ConfigError(f"{f} is not a batch results file.",
                              hint="Use the batch-<date>-<time>.json file a batch printed at the end.")
        dc = str(doc.get("datacenter") or "")
        dcs.add(dc)
        for r in doc["vms"]:
            if holds_vm(r):
                urn = _URN.search(r.get("console_url") or "")  # files written before vcenter_uuid was recorded
                rows[(dc, r["name"])] = ({**r, "datacenter": dc},
                                         doc.get("vcenter_uuid") or (urn.group(1) if urn else None))
    return list(rows.values()), dcs


def find_batch_vms(conn, rows: list[tuple[dict, str | None]], dcs: set[str]) -> list[DoomedVM]:
    """Find each VM in one read per datacenter: by its id when the results file comes from this vCenter (a VM
    renamed since is still found; ids are not reused), otherwise by its name. Only VMs whose Notes carry the
    vmdeploy marker may be deleted."""
    from .inventory import discover
    from .isocopies import copies_attached

    here = _instance_uuid(conn)
    inv = discover(conn)
    found: dict[str, tuple[dict[str, tuple], dict[str, list]]] = {}  # datacenter: (VMs by id, VMs by name)
    for dc in dcs:
        if dc not in inv.datacenters:
            raise ConfigError(f"No datacenter named '{dc}' on this server.",
                              hint="Connect to the vCenter or host the batch deployed to (--profile).")
        by_id: dict[str, tuple] = {}
        by_name: dict[str, list] = {}
        for vm, props in vm_properties(conn, _DESTROY_PROPS, root=inv.datacenters[dc].vm_folder):
            by_id[vm._moId] = (vm, props)
            by_name.setdefault(str(props.get("name", "")), []).append((vm, props))
        found[dc] = (by_id, by_name)
    out: list[DoomedVM] = []
    for r, uuid in rows:
        d = DoomedVM(name=r["name"], host=r.get("host"), datacenter=r["datacenter"])
        by_id, by_name = found[d.datacenter]
        if here and uuid == here and r.get("moid"):
            hit = by_id.get(r["moid"])
        else:
            named = by_name.get(d.name, [])
            if len(named) > 1:
                d.why = f"{len(named)} VMs are named '{d.name}': delete it with `vmdeploy destroy` and --datacenter"
                out.append(d)
                continue
            hit = named[0] if named else None
        if hit is None:
            d.gone = True
            d.why = "not found (already deleted" + ("" if here and uuid == here else ", or renamed") + ")"
        else:
            d.vm, props = hit
            d.current_name = str(props.get("name", d.name))
            d.power = {"poweredOn": "on", "poweredOff": "off", "suspended": "suspended"}.get(
                str(props.get("runtime.powerState", "")), "")
            d.isos = [path for _dc, path in copies_attached(props.get("config.hardware.device"), None)]
            if not vmnotes.is_marked(props.get("config.annotation")):
                d.why = "not deployed by vmdeploy (its Notes have no vmdeploy marker)"
        out.append(d)
    return out


def destroy_batch(conn, p: Prompter, files: list[Path]) -> tuple[int, list[tuple[str, str]]]:
    """`vmdeploy destroy --batch FILE...`: one list, one confirmation, then each VM in turn (a failure does not stop
    the others). Returns (exit code, the ISO copies the deleted VMs used, as (datacenter, path))."""
    from .access import delete_vm

    rows, dcs = load_batch_vms(with_retried_runs(files))
    if not rows:
        console.print("The results file lists no deployed VMs: nothing to delete.")
        return 0, []
    vms = find_batch_vms(conn, rows, dcs)
    doomed = [d for d in vms if d.vm is not None and not d.why]
    t = Table(box=None, padding=(0, 2), header_style="bold")
    for col in ("VM", "Host", "Power", "Action"):
        t.add_column(col, overflow="fold")
    for d in vms:
        renamed = d.current_name and d.current_name != d.name
        label = Text(d.current_name or d.name) + (Text(f" (was {d.name})", style="dim") if renamed else Text(""))
        note = Text(d.why or "delete", style="dim" if d.gone else "yellow" if d.why else "red")
        t.add_row(label, esc(d.host or "?"), d.power, note)
    console.print(t)
    if not doomed:
        console.print("Nothing to delete.")
        return (4 if any(d.why and not d.gone for d in vms) else 0), []
    if not p.confirm(f"Permanently delete these {len(doomed)} VM(s) and their disks? This cannot be undone.",
                     default=False, assume=True):
        raise UserAborted("Nothing was deleted.")
    failed: list[DoomedVM] = []
    isos: list[tuple[str, str]] = []
    for k, d in enumerate(doomed):
        name = d.current_name or d.name
        try:
            delete_vm(d.vm, name)
        except KeyboardInterrupt:
            left = doomed[k:]
            for x in left:
                x.why = "stopped (Ctrl+C) before it was deleted" if x is not d else \
                    "stopped (Ctrl+C) while it was being deleted: check it in vCenter"
            console.print(f"[yellow]Stopped (Ctrl+C): {len(left)} VM(s) not deleted or not finished.[/]")
            log.warning("destroy --batch stopped with Ctrl+C; not deleted: %s",
                        ", ".join(x.current_name or x.name for x in left))
            failed += left
            break
        except Exception as e:  # noqa: BLE001 - one VM's failure does not stop the others
            d.why = getattr(e, "message", None) or str(e) or type(e).__name__
            failed.append(d)
            console.print(f"[red]✖ {esc(name)}: {esc(d.why)}[/]")
            continue
        console.print(f"[green]Deleted '{esc(name)}'.[/]")
        isos += [(d.datacenter, path) for path in d.isos]
    deleted = len(doomed) - len(failed)
    refused = [d for d in vms if d.why and not d.gone and d not in failed]
    style = "green" if not failed and not refused else "yellow" if deleted else "red"
    console.print(f"[{style}]Deleted {deleted} of {len(doomed)} VM(s).[/]")
    if deleted and conn.managed_by:
        # Seen on vCenter 8.0.3: a VM deleted on a managed host directly stays in vCenter as "(orphaned)".
        console.print(f"[yellow]This host is managed by vCenter Server {esc(conn.managed_by)}, which may still list "
                      "the deleted VMs as (orphaned). Remove them there: right-click > Remove from Inventory (their "
                      "files are already deleted). Deleting through vCenter avoids this.[/]")
    for d in failed + refused:
        console.print(f"[yellow]  Not deleted: {esc(d.current_name or d.name)} ({esc(d.why or 'stopped')})[/]")
    if not failed and not refused:
        return 0, isos
    return (PARTLY_EXIT_CODE if deleted else 1), isos


def needs_batch(manifest, flags: dict[str, object]) -> bool:
    """Is this a batch run? (a `batch:` section, --batch, or any batch-only flag)"""
    return manifest.batch is not None or any(flags.values())
