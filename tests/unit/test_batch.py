"""Batch deployment rules that need no vCenter (batchplan.py) and the `batch:` manifest section."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vsphere_vm_deployment import batchplan as bp
from vsphere_vm_deployment.errors import ConfigError
from vsphere_vm_deployment.manifest import Manifest


# ------------------------------------------------------------------------------------------------ patterns
def test_patterns_fill_in_numbers_hosts_and_padding():
    values = {"n": 3, "i": 1, "host": "esx-a", "datastore": "local-a1"}
    assert bp.expand("web-{n:02}", values) == "web-03"
    assert bp.expand("app-{host}-{i}", values) == "app-esx-a-1"
    assert bp.expand("{datastore}/{n:003}", values) == "local-a1/003"


def test_patterns_leave_other_braces_alone():
    """OVF property values may hold JSON: only the batch's own placeholders are filled in."""
    values = {"address": "192.0.2.50", "name": "web-01"}
    assert bp.expand('{"ip": "{address}", "x": {y}}', values) == '{"ip": "192.0.2.50", "x": {y}}'
    assert bp.has_placeholder("ip={address}") and not bp.has_placeholder("{y}") and not bp.has_placeholder(None)


@pytest.mark.parametrize("pattern, message", [
    ("web-{nn}", "unknown placeholder"),
    ("web-{host:02}", "only {n} and {i} can be padded"),
    ("web-{n", "unmatched brace"),
    ("web-{name}", "unknown placeholder"),  # a VM name cannot contain itself
])
def test_bad_name_patterns_are_refused(pattern, message):
    with pytest.raises(ConfigError) as e:
        bp.check_pattern(pattern, "batch.name")
    assert message in e.value.message


def test_hostname_patterns_may_use_the_vm_name():
    bp.check_pattern("{name}", "batch.hostname", hostname=True)
    assert bp.hostname_label("Web_01.example") == "Web-01-example"
    assert bp.hostname_label("-x" * 40) == "x-" * 30 + "x"  # cut to 63, then no leading or trailing "-"


def test_short_host_names():
    assert bp.short_host("esx-a.example.test") == "esx-a"
    assert bp.short_host("192.0.2.10") == "192-0-2-10"  # an address is kept whole
    assert bp.safe_vm_name("a/b\\c%d") == "a-b-c-d"


# ------------------------------------------------------------------------------------------------ addresses
def test_address_ranges_and_lists():
    assert bp.address_list("dhcp", range_text=None, listed=[], prefix=None, gateway=None, count=3) == []
    got = bp.address_list("static", range_text="192.0.2.50-52", listed=[], prefix=24, gateway="192.0.2.1", count=3)
    assert got == ["192.0.2.50/24", "192.0.2.51/24", "192.0.2.52/24"]
    got = bp.address_list("static", range_text="192.0.2.250-198.51.100.1", listed=[], prefix=8, gateway=None,
                          count=1)
    assert got == ["192.0.2.250/8"]  # only as many as there are VMs
    got = bp.address_list("static", range_text=None, listed=["192.0.2.9/24", "192.0.2.7"], prefix=24, gateway=None,
                          count=2)
    assert got == ["192.0.2.9/24", "192.0.2.7/24"]


@pytest.mark.parametrize("kwargs, message", [
    ({"range_text": "192.0.2.50-52", "prefix": 24, "count": 4}, "3 address(es) for 4 VMs"),
    ({"range_text": "192.0.2.50", "prefix": 24, "count": 1}, "is not a range"),
    ({"range_text": "192.0.2.52-50", "prefix": 24, "count": 1}, "ends before it starts"),
    ({"range_text": "192.0.2.50-52", "prefix": None, "count": 1}, "prefix is needed"),
    ({"listed": ["192.0.2.7"], "prefix": None, "count": 1}, "has no prefix length"),
    ({"listed": ["192.0.2.7/24", "192.0.2.7/24"], "prefix": None, "count": 2}, "more than once"),
    ({"range_text": "192.0.2.50-52", "prefix": 24, "count": 1, "gateway": "198.51.100.1"}, "gateway"),
])
def test_bad_addresses_are_refused_with_the_field(kwargs, message):
    args = {"range_text": None, "listed": [], "prefix": None, "gateway": None, **kwargs}
    with pytest.raises(ConfigError) as e:
        bp.address_list("static", **args)
    assert message in e.value.message and "batch.addresses" in e.value.message + (e.value.hint or "")


# ------------------------------------------------------------------------------------------------ distribution
def test_per_host_uses_each_targets_own_count():
    spots = [bp.Spot("a", 1000), bp.Spot("b", 1000, count=2), bp.Spot("c", 1000)]
    assert bp.distribute(spots, "per_host", None, 512) == [(0, 1), (1, 1), (1, 2), (2, 1)]
    assert bp.distribute(spots, "per_host", 3, 512) == [(0, 1), (0, 2), (0, 3), (1, 1), (1, 2), (2, 1), (2, 2), (2, 3)]


def test_total_spreads_by_free_memory():
    spots = [bp.Spot("small", 4096), bp.Spot("big", 16384)]
    placed = bp.distribute(spots, "total", 5, 4096)
    assert sum(1 for k, _ in placed if k == 1) == 4 and sum(1 for k, _ in placed if k == 0) == 1
    assert placed == sorted(placed)  # batch order: target by target


def test_total_needs_a_count_and_no_per_target_counts():
    with pytest.raises(ConfigError, match="batch.count is needed"):
        bp.distribute([bp.Spot("a", 1)], "total", None, 1)
    with pytest.raises(ConfigError, match="only works with distribution: per_host"):
        bp.distribute([bp.Spot("a", 1, count=2)], "total", 2, 1)
    with pytest.raises(ConfigError, match="no targets"):
        bp.distribute([], "per_host", 1, 1)


# ------------------------------------------------------------------------------------------------ space
def test_space_is_added_up_per_datastore_and_a_vm_that_does_not_fit_takes_none():
    gib = 2**30
    uses = [bp.SpaceUse("vm1", "ds1", 40 * gib, 40 * gib), bp.SpaceUse("vm2", "ds1", 40 * gib, 40 * gib),
            bp.SpaceUse("vm3", "ds1", 10 * gib, 10 * gib), bp.SpaceUse("vm4", "ds2", 5 * gib, 500 * gib)]
    refused, warnings = bp.fit_datastores(uses, {"ds1": 60 * gib, "ds2": 100 * gib}, lambda b: f"{b // gib} GB")
    assert set(refused) == {"vm2"}  # vm3 still fits after vm2 was refused
    assert "60 GB free" in refused["vm2"] and "before this one take 40 GB" in refused["vm2"]
    assert set(warnings) == {"ds2"} and "500 GB" in warnings["ds2"]


# ------------------------------------------------------------------------------------------------ limits
def test_parallel_limits():
    errors, warnings = bp.check_parallel(4, 2, 2, hosts=4, is_vcenter=True)
    assert errors == [] and warnings == []
    errors, _ = bp.check_parallel(4, 2, 9, hosts=4, is_vcenter=True)
    assert errors and "at most 8" in errors[0]
    errors, warnings = bp.check_parallel(4, 2, 9, hosts=1, is_vcenter=False)  # ESXi has no queue: warn only
    assert errors == [] and any("more than 2" in w for w in warnings)
    _, warnings = bp.check_parallel(30, 5, 2, hosts=3, is_vcenter=True)
    assert any("uploads" in w for w in warnings) and any("only wait" in w for w in warnings)


# ------------------------------------------------------------------------------------------------ results
def test_exit_codes():
    assert bp.exit_code(["deployed", "deployed"]) == 0
    assert bp.exit_code(["deployed", "failed"]) == bp.PARTLY_EXIT_CODE == 4
    assert bp.exit_code(["problem"]) == 4  # deployed, but a later step failed
    assert bp.exit_code(["failed", "skipped", "not-started"]) == 1
    assert bp.exit_code([]) == 1


def test_summary_per_host_lists_every_vm_that_did_not_deploy():
    rows = [{"name": "w1", "host": "a", "status": "deployed"},
            {"name": "w2", "host": "a", "status": "failed", "error": "upload failed"},
            {"name": "w3", "host": "b", "status": "skipped", "error": "a VM named 'w3' already exists"},
            {"name": "w4", "host": "b", "status": "not-started"},
            {"name": "w5", "host": "c", "status": "problem", "error": "the snapshot failed"}]
    t = bp.tally_by_host(rows)
    assert (t["a"].deployed, t["a"].failed) == (1, 1) and t["a"].problems == ["w2: upload failed"]
    assert (t["b"].skipped, t["b"].not_started) == (1, 1)
    assert t["b"].problems == ["w3: skipped, a VM named 'w3' already exists", "w4: not started"]
    assert t["c"].deployed == 1 and "deployed, but the snapshot failed" in t["c"].problems[0]


def test_retry_takes_failed_skipped_and_not_started():
    doc = {"vms": [{"name": "a", "status": "deployed"}, {"name": "b", "status": "failed"},
                   {"name": "c", "status": "skipped"}, {"name": "d", "status": "not-started"},
                   {"name": "e", "status": "problem"}]}
    assert bp.retry_names(doc) == {"b", "c", "d"}
    with pytest.raises(ConfigError, match="not a vmdeploy batch results file"):
        bp.retry_names({"vm": "x"})


# ------------------------------------------------------------------------------------------------ manifest
def _manifest(batch: dict, **rest) -> Manifest:
    return Manifest.model_validate({"batch": batch, **rest})


def test_batch_manifest_is_validated():
    m = _manifest({"name": "web-{n:02}", "targets": [{"host": "esx-a", "datastore": "auto", "count": 2},
                                                     {"cluster": "c1", "drs": True},
                                                     {"resource_pool": "Compute-ResourcePool"}],
                   "addresses": {"mode": "static", "list": ["192.0.2.5/24"]}})
    assert m.batch.targets[0].count == 2 and m.batch.addresses.addresses == ["192.0.2.5/24"]
    assert m.batch.parallel.vms == 4 and m.batch.on_check_failure == "skip"


@pytest.mark.parametrize("batch, rest, message", [
    ({"targets": [{"host": "a", "cluster": "b"}]}, {}, "one of host, cluster"),
    ({"targets": [{"datastore": "x"}]}, {}, "each entry needs"),
    ({"targets": [{"host": "a", "drs": True}]}, {}, "drs: true needs a cluster"),
    ({"name": "x-{n}", "names": ["a"]}, {}, "either `name`"),
    ({"names": ["a", "a"]}, {}, "different from each other"),
    ({"name": "x-{bad}"}, {}, "unknown placeholder"),
    ({"hostname": "{n"}, {}, "unmatched brace"),
    ({"name_conflict": "overwrite"}, {}, "name_conflict must be one of"),
    ({"addresses": {"mode": "static"}}, {}, "needs either `range` or `list`"),
    ({"addresses": {"mode": "dhcp", "gateway": "192.0.2.1"}}, {}, "only used with mode: static"),
    ({"parallel": {"vms": 0}}, {}, "greater than or equal to 1"),
    ({}, {"vm": {"name": "x"}}, "remove vm.name"),
    ({}, {"placement": {"host": "a"}}, "placement.host"),
    ({}, {"guest": {"hostname": "a"}}, "guest.hostname"),
])
def test_bad_batch_manifests_are_refused(batch, rest, message):
    with pytest.raises(ValidationError) as e:
        _manifest(batch, **rest)
    assert message in str(e.value)


def test_cloud_init_without_a_hostname_keeps_the_images():
    """A batch can leave hostnames to the image: no hostname is written anywhere."""
    from vsphere_vm_deployment import cloudinit as ci
    from vsphere_vm_deployment.manifest import GuestSpec

    g = GuestSpec(username="u", ssh_authorized_keys=["ssh-ed25519 AAAA k"])
    assert "hostname" not in ci.render_user_data(g, None, network_in_userdata=False)
    assert "local-hostname" not in ci.render_metadata(None, g)
    assert ci.ovf_property_values({"hostname", "user-data", "instance-id"}, "#cloud-config\n", None).keys() == \
        {"user-data", "instance-id"}
    assert "hostname: web-01" in ci.render_user_data(g, "web-01", network_in_userdata=False)


def test_dhcp_identifier_is_the_mac_address_by_default():
    """A fresh Ubuntu VM asked its DHCP server twice under two identities (seen on a real vCenter: every VM of a
    batch changed address during its first boot), and DHCP reservations by MAC never match its default DUID."""
    import base64

    import yaml

    from vsphere_vm_deployment import cloudinit as ci
    from vsphere_vm_deployment.manifest import GuestNetwork, GuestSpec

    g = GuestSpec(username="u", ssh_authorized_keys=["ssh-ed25519 AAAA k"])
    eth = yaml.safe_load(ci.render_metadata("web-01", g, mac="00:50:56:AA:BB:CC"))["network"]["ethernets"]["primary"]
    assert eth == {"match": {"macaddress": "00:50:56:aa:bb:cc"}, "dhcp4": True, "dhcp-identifier": "mac"}
    prop = yaml.safe_load(base64.b64decode(ci.ovf_network_config(g, "00:50:56:AA:BB:CC")))
    assert prop["network"]["ethernets"]["primary"]["dhcp-identifier"] == "mac"

    image = GuestSpec(username="u", dhcp_identifier="image")
    assert "network" not in yaml.safe_load(ci.render_metadata("web-01", image))  # the image's default stays
    assert ci.ovf_network_config(image, "00:50:56:aa:bb:cc") is None and not ci.sets_dhcp_identifier(image)

    static = GuestSpec(username="u", network=GuestNetwork(mode="static", address="192.0.2.50/24"))
    eth = yaml.safe_load(ci.render_metadata("web-01", static))["network"]["ethernets"]["primary"]
    assert "dhcp-identifier" not in eth and eth["addresses"] == ["192.0.2.50/24"]
    assert ci.ovf_network_config(static, None) is None  # static addresses keep their user-data route

    with pytest.raises(ValidationError, match="dhcp_identifier"):
        GuestSpec(dhcp_identifier="duid")


def test_destroy_batch_reads_results_files(tmp_path):
    """Every VM a batch (and its retries) left: deployed, deployed with a problem, or a failed VM that was kept.
    The last file wins for a VM in several; the vCenter comes from the file, or from the console link of an older
    file."""
    import json

    from vsphere_vm_deployment import batch as b

    uuid = "65f92227-c279-414e-83ad-18abdbc8e3a4"
    first = tmp_path / "first.json"
    first.write_text(json.dumps({"batch": True, "datacenter": "DC", "vms": [
        {"name": "a", "status": "deployed", "moid": "vm-1",
         "console_url": f"https://vc/ui/app/vm;nav=v/urn:vmomi:VirtualMachine:vm-1:{uuid}/summary"},
        {"name": "b", "status": "failed", "kept": False},
        {"name": "c", "status": "failed", "kept": True, "moid": "vm-3"},
        {"name": "d", "status": "skipped"}]}))
    retry = tmp_path / "retry.json"
    retry.write_text(json.dumps({"batch": True, "datacenter": "DC", "vcenter_uuid": "other",
                                 "vms": [{"name": "b", "status": "deployed", "moid": "vm-9"}]}))
    rows, dcs = b.load_batch_vms([first, retry])
    assert dcs == {"DC"}
    assert {r["name"]: u for r, u in rows} == {"a": uuid, "c": None, "b": "other"}

    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    with pytest.raises(ConfigError, match="not a batch results file"):
        b.load_batch_vms([bad])


def test_no_address_note_fits_the_image(monkeypatch):
    """Seen on a real vCenter: an Ubuntu VM on a network without DHCP was told "Many appliances do not report their
    address". A cloud-init image runs VMware Tools: the note must point at DHCP instead, with or without guest
    settings (and must not fail when there are none)."""
    from types import SimpleNamespace as NS

    from vsphere_vm_deployment import deploy as d

    for pkg, guest, expect in ((NS(info=NS(has_cloud_init_properties=True)), None, "no DHCP server"),
                               (NS(info=NS(has_cloud_init_properties=False)), None, "Many appliances")):
        notes = []
        view = NS(steps={"ip": NS(status="pending"), "snapshot": NS(status="pending")},
                  start=lambda *a, **k: None, done=lambda *a, **k: None, skip=lambda *a, **k: None,
                  note=lambda key, text, style=None: notes.append(text), timings=lambda: {})
        plan = NS(power_on=False, wait_for_ip=True, guest=guest, snapshot=False)
        fake = NS(plan=plan, view=view, vm=NS(), pkg=pkg, vm_ready=False, m=NS(post_deploy=NS(wait_timeout_s=1)),
                  _wait_for_ip=lambda vm, t: None)
        with pytest.raises(AttributeError):  # stops at the summary, after the notes (the fake has no more)
            d.Deployment._power_and_finish(fake)
        assert any(expect in n for n in notes), notes


def test_name_preview_helpers():
    from vsphere_vm_deployment import batch as b

    names = [f"web-{k:02}" for k in range(1, 7)]
    assert b._name_span(names) == "web-01, web-02, … web-06"
    assert b._name_span(names, ends_only=True) == "web-01 … web-06"
    assert b._name_span(names[:2], ends_only=True) == "web-01, web-02"
    assert b._first_repeat(["a-01", "a-02", "b-01", "a-01"]) == "a-01"
    assert b._first_repeat(names) is None


def test_a_vm_waiting_for_its_address_frees_its_build_slot(monkeypatch):
    """Seen on a real vCenter: four VMs only waiting for their guests' addresses kept the next VMs queued for over
    a minute. With one build slot and one slot per host, three VMs must still all reach that wait together."""
    import threading
    from types import SimpleNamespace as NS

    from vsphere_vm_deployment import batch as b

    lock, started, all_in = threading.Lock(), [], threading.Event()

    class FakeBuilder:
        def __init__(self, parent, slot, release_slots, uploads):
            self.slot, self.release_slots = slot, release_slots

        def build(self):
            with lock:
                started.append(self.slot.name)
                if len(started) == 3:
                    all_in.set()
            self.release_slots()  # what VmBuilder._wait_for_ip does
            self.slot.status = b.DEPLOYED if all_in.wait(5) else b.FAILED

    monkeypatch.setattr(b, "VmBuilder", FakeBuilder)
    target = b.Target(label="esx-a", host=NS(name="esx-a.example.test"), cluster=None, pool=None, pool_path="/")
    dep = object.__new__(b.BatchDeployment)
    dep.slots = [b.Slot(n=k, i=k, target=target, name=f"vm-{k}") for k in (1, 2, 3)]
    dep.plan = NS(dc=NS(hosts={}))
    dep.n_vms = dep.n_per_host = dep.n_uploads = 1
    dep.stop_new, dep.cancel = threading.Event(), threading.Event()
    dep.stop_on_failure = False
    dep._execute()
    assert [s.status for s in dep.slots] == [b.DEPLOYED] * 3


def test_live_view_restarted_after_a_pause_does_not_erase_what_was_printed(monkeypatch):
    """Seen on a real terminal: the batch review lost all but its first lines when the step panel came back."""
    import io

    from rich.console import Console

    from vsphere_vm_deployment import ui

    buf = io.StringIO()
    term = Console(file=buf, force_terminal=True, force_interactive=True, width=100, height=40)
    monkeypatch.setattr(ui, "console", term)
    view = ui.DeploymentView("test", [("a", "First step", 1.0), ("b", "Second step", 1.0)])
    with view:
        view._live.refresh()
        with view.paused("Review"):
            for k in range(10):
                term.print(f"review line {k}")
            printed = len(buf.getvalue())
        view._live.refresh()
        after = buf.getvalue()[printed:]
    assert "First step" in after
    assert "\x1b[1A" not in after[:after.index("First step")], "the panel moved up over the printed lines"


def test_a_row_cleaning_up_says_so_and_what_it_waits_for():
    """Seen on a real vCenter: after "Stop them and clean up", the rows said "starting" for a minute while the
    hosts released the disks, and the footer already counted them as failed; the folder note offered a Ctrl+C
    skip that a batch does not have."""
    import io
    import threading
    from types import SimpleNamespace as NS

    from rich.console import Console

    from vsphere_vm_deployment import batch as b

    target = b.Target(label="esx-a", host=NS(name="esx-a.example.test"), cluster=None, pool=None, pool_path="/")
    slot = b.Slot(n=1, i=1, target=target, name="vm-1")
    slot.row = b.RowView(slot, threading.Event(), plain=False)
    slot.row.set_running()
    slot.row.cleaning, slot.status = True, b.FAILED
    builder = object.__new__(b.VmBuilder)
    builder.view = slot.row
    builder._status(r"Deleting the folder \[ds1] vm-1: the host may take a few minutes to release the disk "
                    "(Ctrl+C to skip and delete it yourself later)...")
    view = b.BatchView([slot], "building 1 VM(s)")
    view.t0 = 0.0
    buf = io.StringIO()
    Console(file=buf, width=200).print(view._render())
    out = buf.getvalue()
    assert "cleaning up" in out and "Deleting the folder [ds1] vm-1" in out and "release the disk" in out
    assert "Ctrl+C" not in out and "starting" not in out and "failed" not in out


# ------------------------------------------------------------------------------------------------ review fixes
def test_a_retry_matches_vms_by_the_name_their_pattern_gave():
    """name_conflict: next-free renamed web-01 to web-01-2; a retry matches its VMs before clashes are resolved,
    so the results file keeps the pattern's name (files from before it was kept: their name)."""
    from types import SimpleNamespace as NS

    from vsphere_vm_deployment import batch as b

    s = b.Slot(n=1, i=1, target=NS(where="esx-a", datastore=None), name="web-01-2", pattern_name="web-01",
               status=b.FAILED)
    row = b.BatchDeployment._row(NS(), s)
    assert row["name"] == "web-01-2" and row["pattern_name"] == "web-01"
    doc = {"vms": [row, {"name": "web-02", "pattern_name": "web-02", "status": "deployed"},
                   {"name": "web-03", "status": "not-started"}]}
    assert bp.retry_names(doc) == {"web-01", "web-03"}


def test_vms_are_handed_to_the_workers_round_robin_over_the_hosts():
    """Workers wait for their VM's host: a queue in host order kept every worker on the first host."""
    from types import SimpleNamespace as NS

    from vsphere_vm_deployment import batch as b

    ta, tb, tc = NS(name="a"), NS(name="b"), NS(name="c")
    slots = [b.Slot(n=k, i=i, target=t) for k, (t, i) in enumerate(
        [(ta, 1), (ta, 2), (ta, 3), (tb, 1), (tb, 2), (tc, 1)])]
    assert [(s.target.name, s.i) for s in b.build_order(slots)] == \
        [("a", 1), ("b", 1), ("c", 1), ("a", 2), ("b", 2), ("a", 3)]


def test_the_results_file_survives_a_lost_log_folder_and_a_batch_started_the_same_second(tmp_path, monkeypatch):
    """VMDEPLOY_LOG_DIR on a share that went offline made log_dir() raise before the fallback; and two batches
    started in the same second wrote one file."""
    import json

    from vsphere_vm_deployment import batch as b

    def offline():
        raise FileNotFoundError(2, "The network path was not found")

    monkeypatch.setattr(b, "log_dir", offline)
    monkeypatch.setattr(b, "default_log_dir", lambda: tmp_path / "standard")
    first = b.save_results({"run": 1}, "batch-20261122-101500")
    second = b.save_results({"run": 2}, "batch-20261122-101500")
    assert first == tmp_path / "standard" / "batch-20261122-101500.json"
    assert second == tmp_path / "standard" / "batch-20261122-101500-2.json"
    assert json.loads(first.read_text())["run"] == 1 and json.loads(second.read_text())["run"] == 2


def test_a_partial_vm_that_could_not_be_deleted_is_said_and_listed_for_destroy(tmp_path, capsys, monkeypatch):
    """The clean-up swallows its own failure: the summary said "partial VM deleted" and destroy --batch skipped it."""
    import json
    from types import SimpleNamespace as NS

    from vsphere_vm_deployment import batch as b
    from vsphere_vm_deployment import deploy as d

    said = []

    def destroy(vm, what):
        raise RuntimeError("the VM is busy")

    fake = NS(aborted_vm=None, created=True, vm=object(), conn=object(), vm_ready=False, keep_partial=False,
              p=NS(interactive=False), plan=NS(name="web-01"), _destroy=destroy, _say=said.append,
              cleanup_failed=False)
    d.Deployment._cleanup_after_failure(fake, RuntimeError("upload failed"))
    assert fake.cleanup_failed is True and "Could not remove 'web-01'" in said[-1]

    monkeypatch.setenv("COLUMNS", "250")
    rows = [{"n": 1, "name": "web-01", "host": "esx-a", "status": b.FAILED, "step": "Upload disks",
             "error": "reset", "created": True, "cleanup_failed": True}]
    doc = {"vms": rows, "exit_code": 1, "datacenter": "DC", "batch": True,
           "totals": {"deployed": 0, "problem": 0, "failed": 1, "skipped": 0, "not-started": 0}}
    f = tmp_path / "batch.json"
    f.write_text(json.dumps(doc))
    b.print_summary(doc, 1.0, f, None)
    out = capsys.readouterr().err
    assert "could NOT be deleted" in out and "partial VM deleted" not in out and "destroy --batch" in out
    assert [r["name"] for r, _uuid in b.load_batch_vms([f])[0]] == ["web-01"]


def test_static_addresses_are_checked_as_they_are_typed():
    """Enter at "Addresses:" ended the run, and a typo failed only after every other question."""
    from vsphere_vm_deployment.batch import addresses_problem, split_addresses

    assert "Type a range" in addresses_problem("  ", 3)
    assert addresses_problem("192.0.2.50-52", 3) is None and addresses_problem("192.0.2.50 - 192.0.2.52", 3) is None
    assert "has 2 address(es) a VM can have, for 3 VMs" in addresses_problem("192.0.2.50-51", 3)
    assert "The list has 1 address(es) for 4 VMs" in addresses_problem("192.0.2.50", 4)  # not "batch.addresses"
    assert addresses_problem("192.0.2.300-310", 2)
    assert addresses_problem("192.0.2.50, 192.0.2.61 192.0.2.70/24", 3) is None
    assert split_addresses(" 192.0.2.50, 192.0.2.61 ") == (None, ["192.0.2.50", "192.0.2.61"])


def test_the_iso_is_checked_again_when_the_vm_it_was_checked_for_is_skipped():
    """Declining to replace the VM the ISO checks ran for left staging with a plan that never had them."""
    from types import SimpleNamespace as NS

    from vsphere_vm_deployment import batch as b

    a, c = b.Slot(n=1, i=1, target=NS()), b.Slot(n=2, i=2, target=NS())
    checked = []
    fake = NS(image=NS(is_iso=True), iso_rep=a, _check_iso=lambda: checked.append(True))
    b.BatchDeployment._decline_replacements(fake, [c])
    assert c.blockers == ["replacing the existing VM was declined"] and checked == []
    b.BatchDeployment._decline_replacements(fake, [a])
    assert checked == [True]


def test_a_url_with_a_password_or_token_is_not_saved():
    """The results file (and --json) kept --url as typed, though logs and the screen hide these."""
    from types import SimpleNamespace as NS

    from vsphere_vm_deployment import batch as b

    def source(url):
        return b.BatchDeployment._source(NS(o=NS(image_kind="url", image_value=url, sha256=None),
                                            image=NS(path=None)))

    secret = source("https://svc:S3cret@files.example.test/web.ova?sig=T0ken")
    assert secret["redacted"] is True and "S3cret" not in secret["value"] and "T0ken" not in secret["value"]
    plain = source("https://files.example.test/web.ova")
    assert plain["value"] == "https://files.example.test/web.ova" and "redacted" not in plain


def test_a_range_is_a_pool_that_skips_addresses_in_use():
    """Found in real testing: a range of 5 for 4 VMs whose first address was in use skipped that VM, and the fifth
    address was never used. A range is a pool now (a list keeps one address per VM, in order)."""
    in_use = {"192.0.2.240": "VM 'dc01'", "192.0.2.243": "ESXi host 'esx-a' (vmk0)"}
    given, skipped = bp.pool_addresses("192.0.2.240-192.0.2.246", 24, vms=[(k, set(), None) for k in "abcd"],
                                       in_use=in_use, reserved={"192.0.2.245"})
    assert given == {"a": "192.0.2.241/24", "b": "192.0.2.242/24", "c": "192.0.2.244/24", "d": "192.0.2.246/24"}
    assert skipped == ["192.0.2.240 (used by VM 'dc01')", "192.0.2.243 (used by ESXi host 'esx-a' (vmk0))",
                       "192.0.2.245 (the gateway or a DNS server)"]
    given, _ = bp.pool_addresses("192.0.2.240-242", 24, vms=[(k, set(), None) for k in "abc"], in_use=in_use,
                                 reserved=set())
    assert given == {"a": "192.0.2.241/24", "b": "192.0.2.242/24", "c": None}  # run out: a check failure
    # a retry's VM keeps its planned address, a VM that replaces another keeps that one's
    given, _ = bp.pool_addresses("192.0.2.240-246", 24, vms=[("a", set(), None), ("b", set(), "192.0.2.244/24"),
                                                             ("c", {"192.0.2.240"}, None)], in_use=in_use, reserved=set())
    assert given == {"a": "192.0.2.241/24", "b": "192.0.2.244/24", "c": "192.0.2.240/24"}
    given, skipped = bp.pool_addresses("192.0.2.0-2", 24, vms=[("a", set(), None), ("b", set(), None)], in_use={},
                                       reserved=set())
    assert given == {"a": "192.0.2.1/24", "b": "192.0.2.2/24"} and skipped == ["192.0.2.0 (the subnet's network address)"]


def test_a_range_is_checked_as_a_pool():
    assert bp.range_problem("192.0.2.240-244", 4) is None
    assert "has 3 address(es) a VM can have, for 4 VMs" in bp.range_problem("192.0.2.0-3", 4, prefix=24)
    assert "not in one subnet" in bp.range_problem("192.0.2.250-198.51.100.5", 2, prefix=24)
    assert "is not in the VM's subnet" in bp.range_problem("192.0.2.240-244", 4, prefix=24, gateway="198.51.100.1")
    assert bp.range_problem("192.0.2.1-5", 4, prefix=24, gateway="192.0.2.1") is None  # the gateway is only skipped
    assert "is not a range" in bp.range_problem("192.0.2.240", 1)


def test_a_batch_hands_a_range_out_as_a_pool(monkeypatch):
    from types import SimpleNamespace as NS

    from vsphere_vm_deployment import batch as b
    from vsphere_vm_deployment.manifest import BatchAddresses
    from vsphere_vm_deployment.netcheck import IpUse

    uses = [IpUse("192.0.2.240", 24, "VM 'dc01'", "net-a", "esx-a"), IpUse("192.0.2.242", 24, "VM 'web-03'", "net-a",
                                                                          "esx-a")]
    monkeypatch.setattr(b.netcheck, "ip_uses", lambda conn: uses)
    slots = [b.Slot(n=k, i=k, target=NS(), name=f"web-0{k}", pattern_name=f"web-0{k}") for k in (1, 2, 3)]
    slots[2].clash = True  # web-03 exists and is replaced: it keeps its address
    plan = NS(notes=[])
    fake = NS(addresses=BatchAddresses(mode="static", range="192.0.2.240-192.0.2.245", prefix=24, gateway="192.0.2.1"),
              conn=None, name_conflict="replace", _ip_uses=None,
              retry_doc={"vms": [{"name": "web-02", "pattern_name": "web-02", "address": "192.0.2.244/24"}]})
    b.BatchDeployment._give_pool_addresses(fake, slots, plan)
    assert [s.address for s in slots] == ["192.0.2.241/24", "192.0.2.244/24", "192.0.2.242/24"]
    assert plan.notes == ["Addresses from 192.0.2.240-192.0.2.245: skipped 192.0.2.240 (used by VM 'dc01')."]
    assert fake._ip_uses is uses  # read once: the checks use it too


def test_a_retry_never_gives_an_address_the_earlier_runs_vms_hold(tmp_path, monkeypatch):
    """Found in review: vCenter does not see a powered-off VM's address (power_on: false), so a retried VM without
    its planned address took the address of a VM the first run deployed. The results files say which VMs hold one,
    back to the first run; a VM that replaces one of them still keeps its address."""
    import json
    from types import SimpleNamespace as NS

    from vsphere_vm_deployment import batch as b
    from vsphere_vm_deployment.manifest import BatchAddresses
    from vsphere_vm_deployment.netcheck import IpUse

    first = tmp_path / "batch-1.json"  # run 1: web-03 deployed; web-05 failed and its partial VM was deleted
    first.write_text(json.dumps({"vms": [
        {"name": "web-03", "status": "deployed", "address": "192.0.2.242/24"},
        {"name": "web-05", "status": "failed", "address": "192.0.2.245/24"}]}), encoding="utf-8")
    retry_doc = {"retry_of": str(first), "vms": [  # run 2, retried now
        {"name": "web-01", "pattern_name": "web-01", "status": "deployed", "address": "192.0.2.241/24"},
        {"name": "web-02", "pattern_name": "web-02", "status": "skipped", "address": None},
        {"name": "web-04", "pattern_name": "web-04", "status": "failed", "kept": True, "address": "192.0.2.243/24"}]}
    monkeypatch.setattr(b.netcheck, "ip_uses", lambda conn: [IpUse("192.0.2.240", 24, "VM 'dc01'", "net-a", "esx-a")])
    slots = [b.Slot(n=k, i=k, target=NS(), name=f"web-0{k}", pattern_name=f"web-0{k}") for k in (2, 4)]
    slots[1].clash = True  # the kept web-04 is there, and replaced: it keeps its address
    plan = NS(notes=[])
    fake = NS(addresses=BatchAddresses(mode="static", range="192.0.2.240-192.0.2.246", prefix=24),
              conn=None, name_conflict="replace", _ip_uses=None, retry_doc=retry_doc)
    b.BatchDeployment._give_pool_addresses(fake, slots, plan)
    assert [s.address for s in slots] == ["192.0.2.244/24", "192.0.2.243/24"]
    assert plan.notes == ["Addresses from 192.0.2.240-192.0.2.246: skipped 192.0.2.240 (used by VM 'dc01'), "
                          "192.0.2.241 (used by VM 'web-01', from an earlier run of this batch), "
                          "192.0.2.242 (used by VM 'web-03', from an earlier run of this batch)."]
    # web-04 not replaced (name_conflict: next-free renamed it): the kept VM's address is not given again
    slots = [b.Slot(n=4, i=4, target=NS(), name="web-04-2", pattern_name="web-04")]
    fake.name_conflict = "next-free"
    b.BatchDeployment._give_pool_addresses(fake, slots, NS(notes=[]))
    assert slots[0].address == "192.0.2.244/24"
    # a retried run's file that is gone ends the chain quietly
    assert b.held_addresses({"retry_of": str(tmp_path / "gone.json"), "vms": []}) == []


def test_a_password_is_never_shown_in_a_check_failure_and_never_logged(monkeypatch):
    """Found in the security review: a password set for one target (or through a pattern) was shown in its VM's
    check failure, which also goes into the results file and --json, and it was not registered as a secret (only
    the manifest's shared values were)."""
    from vsphere_vm_deployment import batch as b
    from vsphere_vm_deployment import logsetup
    from vsphere_vm_deployment.ovf import OvfProperty

    def prop(key, password=False):
        return OvfProperty(key=key, type="string", default="", label=key, description="", user_configurable=True,
                           password=password, qualifiers="MinLen(12)")

    monkeypatch.setattr(logsetup, "_runtime_secrets", set())
    props = {"admin_password": prop("admin_password", password=True), "site": prop("site")}
    values = {"admin_password": "web-01-Pa55", "site": "east-01", "other": "x"}  # both too short; "other" unknown
    assert b.ovf_value_problems(values, props) == [
        "OVF property admin_password = '********': Must be at least 12 characters.",
        "OVF property site = 'east-01': Must be at least 12 characters."]
    b.register_passwords(values, props.values())
    assert logsetup.redact("filled in: web-01-Pa55, site east-01") == "filled in: ***, site east-01"


def test_the_summary_names_the_results_file_so_its_commands_can_be_pasted(tmp_path, monkeypatch):
    """Found in real testing: the printed commands held the full path, unquoted though it had spaces, and Rich broke
    the line inside a folder name."""
    from vsphere_vm_deployment import batch as b

    logs = tmp_path / "OneDrive - Company" / "logs"
    logs.mkdir(parents=True)
    monkeypatch.setattr(b, "log_dir", lambda: logs)
    monkeypatch.setattr(b, "log_dir_problem", lambda: None)
    assert b.results_arg(logs / "batch-20261122-203324.json") == "batch-20261122-203324.json"
    elsewhere = tmp_path / "Old Logs" / "batch-1.json"
    assert b.results_arg(elsewhere) == f'"{elsewhere}"'
    # Found in review: the chosen folder (a share) was offline, so the file went to the standard folder, which
    # log_dir() gave this time too. A name alone would be looked up on the share once it is back: the path, then.
    monkeypatch.setattr(b, "log_dir_problem", lambda: "The log folder is not available")
    assert b.results_arg(logs / "batch-20261122-203324.json") == f'"{logs / "batch-20261122-203324.json"}"'
