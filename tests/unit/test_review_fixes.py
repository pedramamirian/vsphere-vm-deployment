"""Regression tests for the issues found by the pre-release code review: one test (or two) per finding."""

import base64
import gzip
import hashlib
import http.server
import threading
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
import yaml

import vsphere_vm_deployment
from vsphere_vm_deployment.errors import ConfigError, DeploymentError
from vsphere_vm_deployment.manifest import GuestSpec, NetworkSpec


def _no_progress(*_a):
    return lambda n: None


# ------------------------------------------------------------------------------------------ image cache
def test_clear_cache_never_touches_other_files_in_a_custom_cache_folder(tmp_path, monkeypatch):
    """VMDEPLOY_CACHE_DIR may name a folder that also holds the user's own files (the README suggests a bigger
    drive); `images clear-cache` used to delete the whole folder."""
    from vsphere_vm_deployment import images

    monkeypatch.setenv("VMDEPLOY_CACHE_DIR", str(tmp_path))
    photo = tmp_path / "photos" / "a.jpg"
    photo.parent.mkdir()
    photo.write_bytes(b"x")
    own_iso = tmp_path / "my-own.iso"
    own_iso.write_bytes(b"y" * 10)
    cached = tmp_path / "urls" / "abc" / "img.ova"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"z" * 5)
    assert [p for p, _ in images.cache_entries()] == [cached]  # the user's own ISO is not vmdeploy's
    assert images.clear_cache() == (1, 5)
    assert not cached.exists() and photo.exists() and own_iso.exists()


def test_a_cached_download_matches_a_checksum_written_with_colons(tmp_path, monkeypatch):
    from vsphere_vm_deployment import images

    dest = tmp_path / "img.iso"
    dest.write_bytes(b"abc")
    sha = hashlib.sha256(b"abc").hexdigest()
    with_colons = ":".join(sha[i:i + 2] for i in range(0, 64, 2)).upper()
    monkeypatch.setattr(images, "download", lambda *a, **k: pytest.fail("downloaded again"))
    assert images._cached_or_download("https://example.com/img.iso", dest, with_colons, _no_progress,
                                      _no_progress) == (sha, "cached copy re-verified")


# ------------------------------------------------------------------------------------------ transfers
class _ShortBody(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", "1000")
        self.end_headers()
        self.wfile.write(b"x" * 400)  # then the connection closes, 600 bytes short

    def log_message(self, *a):
        pass


def test_a_download_cut_short_is_not_accepted_as_complete(tmp_path, monkeypatch):
    """http.client returns b'' instead of raising when a connection drops early; the truncated file used to be
    cached as the image."""
    from vsphere_vm_deployment.errors import ImageError
    from vsphere_vm_deployment.transfer import download

    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(var, raising=False)
    srv = http.server.HTTPServer(("127.0.0.1", 0), _ShortBody)
    t = threading.Thread(target=srv.handle_request, daemon=True)
    t.start()
    dest = tmp_path / "img.iso"
    try:
        with pytest.raises(ImageError, match="Download failed"):
            download(f"http://127.0.0.1:{srv.server_port}/img.iso", dest, expected_sha256=None,
                     progress_factory=_no_progress)
    finally:
        t.join(5)
        srv.server_close()
    assert not dest.exists() and not (tmp_path / "img.iso.part").exists()


# ------------------------------------------------------------------------------------------ ISO copies
def test_an_iso_copy_is_never_trusted_by_name_and_size_and_never_overwritten(monkeypatch):
    """Security review: a deploy account could plant a different file under an official ISO's name and size.
    Copies go to an unused name unless the caller confirmed an existing copy's content."""
    from vsphere_vm_deployment import isolib

    existing = {"ubuntu.iso": 2_000, "ubuntu-2.iso": 2_000, "ubuntu-old.iso": 2_000, "other.iso": 2_000}
    monkeypatch.setattr(isolib, "list_folder", lambda ds_obj, ds, folder: dict(existing))
    target = "[local2] vmdeploy-iso/ubuntu.iso"
    assert isolib.unused_target(None, target) == "[local2] vmdeploy-iso/ubuntu-3.iso"
    assert isolib.unused_target(None, "[local2] vmdeploy-iso/new.iso") == "[local2] vmdeploy-iso/new.iso"
    # Candidates: the name and its -N variants of the same size only, the plain name first.
    assert isolib.copies_in(None, target, 2_000) == [target, "[local2] vmdeploy-iso/ubuntu-2.iso"]
    assert isolib.copies_in(None, target, 1_999) == [] and isolib.copies_in(None, target, None) == []

    copies, checked = [], []
    fm = NS(MakeDirectory=lambda **k: None, CopyDatastoreFile_Task=lambda **k: copies.append(k) or "task")
    monkeypatch.setattr(isolib, "wait_task", lambda task, **k: None)
    monkeypatch.setattr(isolib, "_size", lambda conn, dc, full: 2_000)
    conn = NS(content=NS(fileManager=fm))
    # Same name and size but not confirmed: copied to a new name; the existing files are untouched.
    dest, how = isolib.ensure_copied(conn, None, "[nfs] iso/ubuntu.iso", None, target,
                                     reuse_if=lambda full: checked.append(full) and False)
    assert dest == "[local2] vmdeploy-iso/ubuntu-3.iso" and how == "copied by vCenter, host to host"
    assert copies[-1]["destinationName"] == dest and copies[-1]["force"] is False
    assert checked == [target, "[local2] vmdeploy-iso/ubuntu-2.iso"]
    # Confirmed by the caller: reused, nothing copied.
    copies.clear()
    assert isolib.ensure_copied(conn, None, "[nfs] iso/ubuntu.iso", None, target, reuse_if=lambda full: True) == \
        (target, "copied earlier; checked; reused")
    assert copies == []


def test_a_folder_that_cannot_be_listed_is_never_taken_for_free(monkeypatch):
    """A failed search used to read as "no file there", so a copy or upload could overwrite an existing ISO."""
    from pyVmomi import vim

    from vsphere_vm_deployment import isolib

    def fails_with(fault):
        def wait(task, **k):
            e = DeploymentError("datastore search failed: ...")
            e.fault = fault
            raise e
        return wait

    ds = NS(browser=NS(SearchDatastore_Task=lambda **k: "task"))
    monkeypatch.setattr(isolib, "wait_task", fails_with(vim.fault.FileNotFound()))
    assert isolib.list_folder(ds, "ds1", "vmdeploy-iso") == {}  # no folder yet: nothing there
    monkeypatch.setattr(isolib, "wait_task", fails_with(vim.fault.NoPermission()))
    with pytest.raises(DeploymentError, match="Could not list"):
        isolib.unused_target(ds, "[ds1] vmdeploy-iso/a.iso")


def test_a_name_taken_during_the_copy_is_left_alone_and_another_name_tried(monkeypatch):
    from pyVmomi import vim

    from vsphere_vm_deployment import isolib

    names = {"a.iso": 5}
    monkeypatch.setattr(isolib, "list_folder", lambda ds_obj, ds, folder: dict(names))
    monkeypatch.setattr(isolib, "_size", lambda conn, dc, full: 5)
    deleted = []
    fm = NS(MakeDirectory=lambda **k: None, CopyDatastoreFile_Task=lambda **k: k["destinationName"],
            DeleteDatastoreFile_Task=lambda **k: deleted.append(k) or "task")

    def wait(task, **k):
        if task == "[ds1] vmdeploy-iso/a-2.iso":  # another deployment wrote a-2.iso just after the listing
            names["a-2.iso"] = 5
            e = DeploymentError("Copy ISO failed: file exists")
            e.fault = vim.fault.FileAlreadyExists()
            raise e

    monkeypatch.setattr(isolib, "wait_task", wait)
    assert isolib.ensure_copied(NS(content=NS(fileManager=fm)), None, "[nfs] a.iso", None,
                                "[ds1] vmdeploy-iso/a.iso") == ("[ds1] vmdeploy-iso/a-3.iso",
                                                                "copied by vCenter, host to host")
    assert deleted == []


def _reuse_fake(reuse=None, genuine=True, sha="ab" * 32, rejected=(), copy=None):
    plan = NS(dc=NS(obj=None), datastore=NS(name="ds1", obj=None), host_names={"h1"},
              iso_datastore_path=None, iso_rejected=set(rejected))
    notes = []
    return NS(plan=plan, notes=notes, view=NS(done=lambda *a, **k: None, update=lambda *a, **k: None,
                                              note=lambda step, text, **k: notes.append(text)),
              image=NS(path=Path("win.iso"), sha256=sha), m=NS(image=NS(reuse_datastore_copy=reuse)),
              conn=NS(is_vcenter=True), _copy_is_genuine=genuine if callable(genuine) else lambda full: genuine)


def test_an_earlier_upload_is_used_only_after_its_full_checksum_matches(monkeypatch):
    """It was attached after the review on name and size alone, ignoring a No and reuse_datastore_copy: false."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib

    cand = NS(path="vmdeploy-iso/win.iso", size=10, hosts={"h1"}, datastore="ds1", full="[ds1] vmdeploy-iso/win.iso")
    monkeypatch.setattr(isolib, "find_isos", lambda dc: [cand])
    fake = _reuse_fake()
    assert d.Deployment._reuse_uploaded_iso(fake, 10) and fake.plan.iso_datastore_path == cand.full
    fake = _reuse_fake(genuine=False)  # same name and size, different content
    assert not d.Deployment._reuse_uploaded_iso(fake, 10) and fake.plan.iso_datastore_path is None
    for fake in (_reuse_fake(reuse=False), _reuse_fake(sha=None),
                 _reuse_fake(rejected={cand.full})):  # said No to, or rejected by sampling: not read again
        assert not d.Deployment._reuse_uploaded_iso(fake, 10)


def test_every_earlier_copy_of_the_iso_is_considered_and_a_failed_copy_means_an_upload(monkeypatch):
    """Copies are named name-2.iso, name-3.iso, ... so those are earlier uploads too; a server-side copy that
    fails (e.g. the source is locked) falls back to the upload instead of failing the deployment."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib

    def iso(name, hosts=frozenset({"h1"}), ds="ds1"):
        return NS(path=f"vmdeploy-iso/{name}", size=10, hosts=set(hosts), datastore=ds,
                  full=f"[{ds}] vmdeploy-iso/{name}")

    planted, good = iso("win.iso"), iso("win-2.iso")
    monkeypatch.setattr(isolib, "find_isos", lambda dc: [planted, good, iso("win-old.iso"), iso("other.iso")])
    checked = []
    fake = _reuse_fake(genuine=lambda full: checked.append(full) or full == good.full)
    assert d.Deployment._reuse_uploaded_iso(fake, 10) and fake.plan.iso_datastore_path == good.full
    assert checked == [planted.full, good.full]  # never win-old.iso or other.iso

    elsewhere = iso("win.iso", hosts={"h9"}, ds="nfs9")  # on a datastore the VM's host cannot see: copied

    def locked(*a, **k):
        raise DeploymentError("Copy ISO failed: the file is locked")

    monkeypatch.setattr(isolib, "find_isos", lambda dc: [elsewhere])
    monkeypatch.setattr(isolib, "ensure_copied", locked)
    fake = _reuse_fake()
    assert not d.Deployment._reuse_uploaded_iso(fake, 10) and fake.plan.iso_datastore_path is None
    assert any("uploading instead" in n for n in fake.notes)


def test_a_copy_is_genuine_only_when_its_whole_content_has_the_images_checksum():
    from vsphere_vm_deployment import deploy as d

    notes = []
    view = NS(steps={"upload_iso": NS(status="pending")}, start=lambda *a: None, update=lambda *a: None,
              note=lambda step, text, **k: notes.append(text))
    good = "ab" * 32
    for got, expected in ((good, True), ("cd" * 32, False), (None, False)):
        fake = NS(image=NS(sha256=good.upper()), view=view, _datastore_sha256=lambda full, step, got=got: got)
        assert d.Deployment._copy_is_genuine(fake, "[ds1] vmdeploy-iso/win.iso") is expected
    assert any("different content" in n for n in notes) and any("could not be read" in n for n in notes)
    assert d.Deployment._copy_is_genuine(NS(image=NS(sha256=None), view=view), "[ds1] x.iso") is False
    # A file that failed once is not read in full again during the same deployment.
    reads = []
    fake = NS(image=NS(sha256=good), view=view, plan=NS(iso_rejected=set()),
              _datastore_sha256=lambda full, step: reads.append(full) or "cd" * 32)
    assert not d.Deployment._copy_is_genuine(fake, "[ds1] x.iso") and not d.Deployment._copy_is_genuine(
        fake, "[ds1] x.iso")
    assert reads == ["[ds1] x.iso"]


def test_a_copy_on_the_vms_datastore_is_checked_in_full_or_sampled_against_its_source():
    """A known SHA-256 (local or downloaded ISO, or --sha256) always means a full check. A datastore ISO without
    --sha256 has no checksum: its earlier copy on the VM's own datastore is compared with the source by samples."""
    from vsphere_vm_deployment import deploy as d

    view = NS(note=lambda *a, **k: None)
    full = NS(image=NS(sha256="ab" * 32), _copy_is_genuine=lambda f, step: f == "[ds1] vmdeploy-iso/a.iso")
    assert d.Deployment._copy_matches(full, "[ds1] vmdeploy-iso/a.iso")
    assert not d.Deployment._copy_matches(full, "[ds1] vmdeploy-iso/a-2.iso")
    for same, expected in ((True, True), (False, False), (None, False)):
        plan = NS(iso_copy_from="[local9] iso/a.iso", iso_rejected=set())
        fake = NS(image=NS(sha256=None), plan=plan, view=view, _same_remote=lambda a, b, same=same: same)
        assert d.Deployment._copy_matches(fake, "[ds1] vmdeploy-iso/a.iso") is expected
        assert (plan.iso_rejected == set()) is expected
    no_source = NS(image=NS(sha256=None), plan=NS(iso_copy_from=None, iso_rejected=set()), view=view)
    assert not d.Deployment._copy_matches(no_source, "[ds1] vmdeploy-iso/a.iso")


# ------------------------------------------------------------------------------------------ datacenters
def _dcs(*specs):
    return {name: NS(name=name, obj=name, datastores=dict.fromkeys(ds)) for name, ds in specs}


def test_datastore_files_are_read_in_the_vms_datacenter_and_ambiguous_names_stop():
    """Security review: datastore names are unique only within a datacenter. The first datacenter with that name
    was read (and checksummed) while vCenter gave the VM the file in its own datacenter."""
    from vsphere_vm_deployment import deploy as d

    dcs = _dcs(("Site-A", ["vsanDatastore", "a-only"]), ("Site-B", ["vsanDatastore"]))
    fake = NS(inv=NS(datacenters=dcs), plan=None)
    assert d.Deployment._datacenter_of(fake, "a-only").name == "Site-A"
    with pytest.raises(ConfigError, match="several datacenters") as e:
        d.Deployment._datacenter_of(fake, "vsanDatastore")
    assert "placement" in e.value.hint
    with pytest.raises(ConfigError, match="not found"):
        d.Deployment._datacenter_of(fake, "nope")
    fake.plan = NS(dc=dcs["Site-B"])  # once the VM's datacenter is chosen, only that one
    assert d.Deployment._datacenter_of(fake, "vsanDatastore").name == "Site-B"
    with pytest.raises(ConfigError, match="not in datacenter Site-B"):
        d.Deployment._datacenter_of(fake, "a-only")


def test_an_iso_copy_is_deleted_in_its_own_datacenter(monkeypatch, caplog):
    import logging

    from vsphere_vm_deployment import isocopies

    caplog.set_level(logging.INFO, logger="vsphere_vm_deployment.isocopies")

    dcs = _dcs(("Site-A", ["vsanDatastore"]), ("Site-B", ["vsanDatastore"]))
    deleted = []
    fm = NS(DeleteDatastoreFile_Task=lambda name, datacenter: deleted.append((datacenter, name)) or "task")
    monkeypatch.setattr(isocopies, "wait_task", lambda task, **k: None)
    monkeypatch.setattr(isocopies, "delete_empty_folder", lambda *a: False)
    conn, inv = NS(content=NS(fileManager=fm)), NS(datacenters=dcs)
    isocopies.delete(conn, inv, "[vsanDatastore] vmdeploy-iso/a.iso", "Site-B")
    assert deleted == [("Site-B", "[vsanDatastore] vmdeploy-iso/a.iso")]
    assert [r.getMessage() for r in caplog.records] == [  # smoke test: deletions were not in the log file
        "Deleted the ISO copy [vsanDatastore] vmdeploy-iso/a.iso (datacenter Site-B)"]
    with pytest.raises(DeploymentError, match="ambiguous"):
        isocopies.delete(conn, inv, "[vsanDatastore] vmdeploy-iso/a.iso")
    with pytest.raises(DeploymentError, match="not found in datacenter Site-C"):
        isocopies.delete(conn, inv, "[vsanDatastore] vmdeploy-iso/a.iso", "Site-C")
    assert len(deleted) == 1


def test_a_vms_datacenter_is_found_through_its_parents(monkeypatch):
    from vsphere_vm_deployment import isocopies

    class FakeDatacenter:
        name = "Site-B"

    monkeypatch.setattr(isocopies, "vim", NS(Datacenter=FakeDatacenter))
    assert isocopies.datacenter_of(NS(parent=NS(parent=FakeDatacenter()))) == "Site-B"  # VM -> folder -> DC
    assert isocopies.datacenter_of(NS(parent=None, parentVApp=NS(parent=NS(parent=FakeDatacenter())))) == "Site-B"
    assert isocopies.datacenter_of(NS(parent=None)) is None


def test_a_datastore_file_read_earlier_is_reused_only_while_it_is_the_same_file(tmp_path, monkeypatch):
    """The cache of datastore files was reused on size alone, so a file replaced on the datastore by another of the
    same size was deployed stale. Now: the SHA-256 when one is known, otherwise size and last-modified time."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib, transfer
    from vsphere_vm_deployment.errors import ChecksumMismatch

    content = b"ISO" * 100
    want = hashlib.sha256(content).hexdigest()
    cached = tmp_path / "a.iso"
    cached.write_bytes(b"x" * len(content))  # same size, different content
    served = {"body": content, "modified": "2026-01-01T00:00:00+00:00"}
    monkeypatch.setattr(isolib, "_stat", lambda conn, dc, full: (len(served["body"]), served["modified"]))
    monkeypatch.setattr(d, "check_local_space", lambda *a: None)
    reads = []
    monkeypatch.setattr(transfer, "read_stream",
                        lambda decision, url, sink, **k: reads.append(url) or sink(served["body"]))
    notes = []
    fake = NS(conn=None, view=NS(note=lambda step, text, **k: notes.append(text)),
              _datacenter_of=lambda name: NS(obj=None), _datastore_http=lambda full: (None, "/folder/a.iso", {}))

    def read(**k):
        return d.Deployment._read_datastore_file(fake, "[ds1] iso/a.iso", None, dest=cached, **k)

    # With a known SHA-256: the stale copy is read again; the matching one is used.
    assert read(expected_sha=want.upper()).read_bytes() == content and len(reads) == 1
    assert any("out of date" in n for n in notes)
    read(expected_sha=want)
    assert len(reads) == 1 and any("SHA-256 checked" in n for n in notes)
    # Without one: used while the datastore file's size and last-modified time are unchanged.
    read()
    assert len(reads) == 1 and any("unchanged since" in n for n in notes)
    served["modified"] = "2026-02-01T00:00:00+00:00"  # replaced on the datastore by a file of the same size
    read()
    assert len(reads) == 2
    # A fresh read that does not have the expected SHA-256 is never kept.
    served["body"] = b"z" * len(content)
    cached.write_bytes(b"y" * len(content))
    with pytest.raises(ChecksumMismatch, match="does not match"):
        read(expected_sha=want)
    assert not (tmp_path / "a.iso.part").exists()


def test_with_yes_a_copy_whose_content_cannot_be_compared_is_skipped_not_declined(tmp_path, monkeypatch):
    """--yes without reuse_datastore_copy: a copy whose sampled content could not be compared is not used, but
    that is not a "No": the next copy is still considered (it used to stop the search and force an upload)."""
    import contextlib

    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import isolib

    local = tmp_path / "win.iso"
    local.write_bytes(b"w" * 64)

    def cand(ds):
        return NS(path="iso/win.iso", size=64, hosts={"h1"}, datastore=ds, full=f"[{ds}] iso/win.iso",
                  label=lambda: f"h1 › [{ds}] iso/win.iso")

    first, second = cand("nfs1"), cand("nfs2")
    monkeypatch.setattr(isolib, "find_isos", lambda dc: [first, second])
    plan = NS(dc=None, datastore=NS(name="ds1"), host_names={"h1"}, iso_rejected=set(),
              iso_datastore_path=None, iso_copy_from=None, iso_found_on_datastore=False)
    p = NS(interactive=False, section=lambda title: contextlib.nullcontext(), record=lambda *a: None,
           confirm=lambda q, default, assume, field_name: assume)
    fake = NS(plan=plan, image=NS(path=local), view=NS(note=lambda *a, **k: None), p=p,
              m=NS(image=NS(reuse_datastore_copy=None)),
              _same_content=lambda path, c: None if c is first else True)
    d.Deployment._find_same_iso_on_datastores(fake)
    assert plan.iso_datastore_path == second.full and plan.iso_found_on_datastore


# ------------------------------------------------------------------------------------------ networks
def _networks_fake(ovf_nets, specs):
    nets = [NS(name=n, label=lambda n=n: n) for n in ("pg-mgmt", "pg-data", "pg-other")]
    dc = NS(usable_networks=lambda hosts: nets, networks={n.name: n for n in nets})
    asked = []
    p = NS(select=lambda q, choices, **k: (asked.append(q), choices[0][1])[1], record=lambda *a: None)
    fake = NS(p=p, pkg=NS(info=NS(networks=ovf_nets)) if ovf_nets is not None else None,
              m=NS(networks=[NetworkSpec(**s) for s in specs]))
    return fake, NS(dc=dc, host_names={"h1"}, networks=[]), asked


def test_named_and_positional_network_entries_are_each_used_once():
    """[{ovf_network: Mgmt, portgroup: pg-mgmt}, {portgroup: pg-data}] put both NICs on pg-mgmt."""
    from vsphere_vm_deployment import deploy as d

    fake, plan, asked = _networks_fake(["VM Network", "Mgmt"], [{"ovf_network": "Mgmt", "portgroup": "pg-mgmt"},
                                                               {"portgroup": "pg-data"}])
    d.Deployment._ask_networks(fake, plan)
    assert [(o, n.name) for o, n, _ in plan.networks] == [("VM Network", "pg-data"), ("Mgmt", "pg-mgmt")]
    assert asked == []


def test_network_entries_that_fit_nowhere_are_errors_not_dropped():
    from vsphere_vm_deployment import deploy as d

    fake, plan, _ = _networks_fake(["VM Network"], [{"portgroup": "pg-mgmt"}, {"portgroup": "pg-data"}])
    with pytest.raises(ConfigError, match="2 entries but the image has 1 network"):
        d.Deployment._ask_networks(fake, plan)
    fake, plan, _ = _networks_fake(["VM Network"], [{"ovf_network": "Typo", "portgroup": "pg-mgmt"}])
    with pytest.raises(ConfigError, match="'Typo' is not a network of this image"):
        d.Deployment._ask_networks(fake, plan)
    fake, plan, _ = _networks_fake(None, [{"portgroup": "pg-mgmt"}, {"portgroup": "pg-data"}])  # ISO: one NIC each
    d.Deployment._ask_networks(fake, plan)
    assert [n.name for _, n, _ in plan.networks] == ["pg-mgmt", "pg-data"]


def test_an_unknown_network_adapter_is_refused_when_the_manifest_is_read():
    from pydantic import ValidationError

    assert NetworkSpec(adapter="VMXNET3").adapter == "vmxnet3"
    with pytest.raises(ValidationError, match="vmxnet3, e1000e or e1000"):
        NetworkSpec(adapter="vmxnet")


def test_every_network_that_shares_a_name_is_qualified_and_keeps_vcenters_name():
    """A third same-named portgroup kept the bare name; a renamed standard portgroup sent an invented name."""
    from pyVmomi import vim

    from vsphere_vm_deployment.inventory import NetworkInfo, _qualify_shared_names
    from vsphere_vm_deployment.vmspec import nic_backing

    def dvpg(moid, switch):
        return NetworkInfo(name="Prod", obj=NS(_moId=moid, config=NS(distributedVirtualSwitch=NS(name=switch))),
                           kind="dvpg")

    std = NetworkInfo(name="Prod", obj=vim.Network("network-9"), kind="standard")
    solo = NetworkInfo(name="Solo", obj=vim.Network("network-1"), kind="standard")
    infos = [dvpg("dvportgroup-1", "dvs1"), dvpg("dvportgroup-2", "dvs2"), dvpg("dvportgroup-3", "dvs3"), std, solo]
    _qualify_shared_names(infos)
    assert [i.name for i in infos] == ["Prod [dvs1]", "Prod [dvs2]", "Prod [dvs3]", "Prod [standard switch]", "Solo"]
    assert {i.vc_name for i in infos} == {"Prod", "Solo"}
    assert nic_backing(std).deviceName == "Prod"  # what vCenter knows, never the label


# ------------------------------------------------------------------------------------------ sizing, paths, URLs
def test_accepting_the_images_own_disk_size_does_not_grow_the_disk():
    """vCenter's 48.6 GB system disk is offered as 49 GB; accepting that grew the disk."""
    from vsphere_vm_deployment.deploy import Deployment

    assert Deployment._disk_growth(NS(disk_gb=49, image_disk_gb=49)) is None
    assert Deployment._disk_growth(NS(disk_gb=60, image_disk_gb=49)) == 60
    assert Deployment._disk_growth(NS(disk_gb=40, image_disk_gb=None)) == 40  # ISO installs: the chosen size


def test_a_mistyped_datastore_name_is_a_clear_error(tmp_path):
    """It used to end as 'Unexpected error: . This is probably a bug.' (StopIteration)."""
    from vsphere_vm_deployment import deploy as d

    fake = NS(inv=NS(datacenters={"DC": NS(datastores={"datastore1": 1}, obj=None)}), plan=None,
              _datastore_cache=lambda full: tmp_path)
    fake._datacenter_of = lambda name: d.Deployment._datacenter_of(fake, name)
    with pytest.raises(ConfigError, match="'datastre1' was not found"):
        d.Deployment._read_datastore_file(fake, "[datastre1] lab/app.ova", None)


def test_the_image_step_never_shows_a_urls_password_or_token(monkeypatch):
    from vsphere_vm_deployment import deploy as d

    class Stop(Exception):
        pass

    started = []
    view = NS(start=lambda key, detail=None: started.append(detail), steps={"image": NS(weight=1)})
    fake = NS(view=view, o=NS(sha256=None), m=NS(image=NS(sha256=None)), p=None,
              _choose_image_source=lambda: ("url", "https://user:s3cret@example.com/x.iso?X-Amz-Signature=tok3n"))
    monkeypatch.setattr(d, "resolve", lambda *a, **k: (_ for _ in ()).throw(Stop()))
    with pytest.raises(Stop):
        d.Deployment._acquire_image(fake)
    assert "s3cret" not in started[0] and "tok3n" not in started[0] and "example.com/x.iso" in started[0]


# ------------------------------------------------------------------------------------------ live panel
def test_nested_sections_keep_the_live_panel_stopped_until_the_outer_one_ends(monkeypatch):
    """A section inside another restarted the panel while the outer one was still asking questions."""
    from vsphere_vm_deployment import ui

    v = ui.DeploymentView("t", [("a", "A", 1.0)], enabled=False)
    events = []
    v._live = NS(stop=lambda: events.append("stop"), start=lambda: events.append("start"))
    with v.paused("outer"):
        with v.paused("inner"):
            pass
        assert events == ["stop"]
    assert events == ["stop", "start"]

    # A question asked outside any section pauses the panel by itself.
    events.clear()

    class Answer:
        def unsafe_ask(self):
            events.append("asked")
            return True

    monkeypatch.setattr(ui.questionary, "confirm", lambda *a, **k: Answer())
    p = ui.Prompter(interactive=False, view=v)
    p.interactive = True  # pytest has no terminal, so the constructor would switch interactive mode off
    assert p.confirm("Continue?") is True
    assert events == ["stop", "asked", "start"]


# ------------------------------------------------------------------------------------------ ISO users
def test_iso_copies_are_never_judged_unused_when_the_vms_cannot_be_read():
    """A transient error made every copy look unused, and `images prune --yes --delete-unused` deleted them."""
    from vsphere_vm_deployment import isocopies

    def boom(**k):
        raise RuntimeError("session expired")

    content = NS(rootFolder=None, viewManager=NS(CreateContainerView=lambda *a: NS(Destroy=lambda: None)),
                 propertyCollector=NS(RetrievePropertiesEx=boom))
    with pytest.raises(DeploymentError, match="nothing was deleted"):
        isocopies.iso_users(NS(content=content))


def test_destroy_keeps_the_iso_copy_when_its_users_cannot_be_read(monkeypatch):
    from vsphere_vm_deployment import cli, isocopies

    warned = []
    monkeypatch.setattr(isocopies, "iso_users", lambda conn: (_ for _ in ()).throw(
        DeploymentError("Could not read which VMs use the ISO copies; nothing was deleted.")))
    monkeypatch.setattr(cli, "warn", warned.append)
    cli._offer_iso_cleanup(None, None, [(None, "[ds] vmdeploy-iso/a.iso")], None)
    assert warned and "was kept" in warned[0]


# ------------------------------------------------------------------------------------------ cloud-init
GUEST = GuestSpec(hostname="web01", username="alex",
                  network={"mode": "static", "address": "192.0.2.50/24", "gateway": "192.0.2.1"})


def test_a_static_address_can_be_bound_to_one_adapter_by_mac():
    """`match: name: en*` gave every adapter the static address and a default route."""
    from vsphere_vm_deployment import cloudinit as ci

    md = yaml.safe_load(ci.render_metadata("web01", GUEST, mac="00:50:56:AA:BB:CC"))
    assert md["network"]["ethernets"]["primary"]["match"] == {"macaddress": "00:50:56:aa:bb:cc"}
    assert yaml.safe_load(ci.render_metadata("web01", GUEST))["network"]["ethernets"]["primary"]["match"] == \
        {"name": "en*"}  # one NIC: unchanged
    assert "macaddress: 00:50:56:aa:bb:cc" in ci.render_user_data(GUEST, "web01", network_in_userdata=True,
                                                                  mac="00:50:56:AA:BB:CC")


def test_nic1_is_the_adapter_on_the_first_chosen_network():
    from pyVmomi import vim

    from vsphere_vm_deployment import deploy as d

    first, other = vim.Network("network-1"), vim.Network("network-2")

    def card(key, net, mac):
        c = vim.vm.device.VirtualVmxnet3(key=key, macAddress=mac)
        c.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo(network=net, deviceName="x")
        return c

    vm = NS(config=NS(hardware=NS(device=[card(4001, first, "00:50:56:00:00:02"),
                                          card(4000, other, "00:50:56:00:00:01")])))
    plan = NS(networks=[("VM Network", NS(kind="standard", obj=first), "vmxnet3")])
    assert d.Deployment._nic1_mac(NS(vm=vm), plan) == "00:50:56:00:00:02"


def test_the_static_address_is_rewritten_for_nic1_before_the_first_boot(monkeypatch):
    from vsphere_vm_deployment import deploy as d

    specs = []
    monkeypatch.setattr(d, "wait_task", lambda task, **k: None)
    vm = NS(ReconfigVM_Task=lambda spec: specs.append(spec))
    fake = NS(vm=vm, view=NS(note=lambda *a, **k: None), _nic1_mac=lambda plan: "00:50:56:00:00:02")
    plan = NS(guest=GUEST, guest_route="guestinfo", warnings=[], networks=[])
    d.Deployment._bind_static_address_to_nic1(fake, plan, "#cloud-config\n", NS(properties=[]))
    extra = {o.key: o.value for o in specs[0].extraConfig}
    md = yaml.safe_load(gzip.decompress(base64.b64decode(extra["guestinfo.metadata"])))
    assert md["network"]["ethernets"]["primary"]["match"] == {"macaddress": "00:50:56:00:00:02"}


# ------------------------------------------------------------------------------------------ trust prompt
def _render(markup_text: str) -> str:
    """What a terminal shows for a markup string, as plain text (styles applied, tags consumed)."""
    from io import StringIO

    from rich.console import Console

    buf = StringIO()
    Console(file=buf, force_terminal=False, width=400, emoji=False, highlight=False).print(markup_text, markup=True)
    return buf.getvalue()


def test_a_certificate_cannot_add_lines_or_hide_the_real_fingerprint_at_the_trust_prompt():
    """Security review: a Subject Alternative Name like `x"]<newline>SHA-256 fingerprint: <real server's>[conceal
    black]` printed as markup added a fake fingerprint line and hid the real one."""
    from datetime import UTC, datetime, timedelta

    from vsphere_vm_deployment.trust import CertInfo, cert_details

    real = "aa" * 32  # the presented (attacker's) certificate
    claimed = CertInfo.pretty("bb" * 32)  # the genuine server's fingerprint, copied into the certificate
    san = f'vc.example.internal"]\nSHA-256 fingerprint: {claimed}[conceal black]\x1b[8m‮'
    now = datetime.now(UTC)
    cert = CertInfo(der=b"x", subject="vc", issuer="vc", not_before=now - timedelta(days=1),
                    not_after=now + timedelta(days=1), sans=[san], sha256=real, sha1="00" * 20,
                    subject_dn="CN=vc[bold red]", issuer_dn="CN=vc")
    out = _render(cert_details(cert, "self-signed\n[/]"))
    lines = out.rstrip("\n").split("\n")
    assert len(lines) == 7  # Subject, Issuer, Names/IPs, Valid from, Expires, SHA-256, Validation result
    fingerprint_lines = [ln for ln in lines if ln.startswith("SHA-256 fingerprint:")]
    assert fingerprint_lines == [f"SHA-256 fingerprint: {CertInfo.pretty(real)}"]  # only the real one, as a line
    assert "[conceal black]" in out and "CN=vc[bold red]" in out  # shown as text, not applied
    assert "\\x0a" in out and "\\x1b" in out and "\\u202e" in out and "\x1b" not in out


def test_fingerprints_are_never_turned_into_emoji():
    """Rich's emoji codes turned ':AB:' and ':CD:' in a fingerprint into emoji (about 1 in 9 fingerprints)."""
    from io import StringIO

    from vsphere_vm_deployment import ui
    from vsphere_vm_deployment.trust import CertInfo

    fp = CertInfo.pretty("ab" * 2 + "cd" * 30)  # AB:AB:CD:CD:...
    assert ":AB:" in fp and not ui.console._emoji  # the shared console has emoji codes switched off
    buf = StringIO()
    console = ui.console.__class__(file=buf, force_terminal=False, width=400, emoji=ui.console._emoji)
    console.print(f"Previously trusted SHA-256 fingerprint: {fp}")
    assert fp in buf.getvalue()


# ------------------------------------------------------------------------------------------ TLS
def test_the_api_version_request_uses_the_verified_connection(monkeypatch):
    """It used an unverified TLS context; CONTRIBUTING.md: never disable TLS validation."""
    from vsphere_vm_deployment import connection as c

    seen = {}

    def find(proto, host, port, path, versions, ctx, *rest):
        seen["ctx"] = ctx
        return "vim.version.v8_0_3_0"

    monkeypatch.setattr(c.pyvim_connect, "__FindSupportedVersion", find, raising=False)
    ctx = object()
    assert c._supported_version("vc.example.internal", 443, ctx) == "vim.version.v8_0_3_0" and seen["ctx"] is ctx


def test_no_code_ever_creates_an_unverified_tls_context():
    package = Path(vsphere_vm_deployment.__file__).parent
    assert not [p.name for p in package.rglob("*.py") if "_create_unverified_context" in p.read_text(encoding="utf-8")]


# ------------------------------------------------------------------------------------------ profiles
def test_replacing_a_profile_with_another_server_deletes_its_saved_password(monkeypatch):
    """Re-using a profile name for another server must not send the old server's saved password to the new one
    (security review). The secret is bound to its server, so the new profile never reads it; the old profile's
    entry is deleted too, to tidy the keychain."""
    from vsphere_vm_deployment import cli, credentials
    from vsphere_vm_deployment.profiles import ProfileStore
    from vsphere_vm_deployment.ui import Prompter

    deleted = []
    monkeypatch.setattr(credentials, "delete_secret",
                        lambda profile, kind="password": deleted.append((profile.name, profile.host, kind)) or True)
    monkeypatch.setattr(credentials, "keychain_available", lambda: True)
    store = ProfileStore()
    p = Prompter(interactive=False)
    cli._profile_wizard(p, store, host="vc1.example.internal", name="lab", username="admin@vsphere.local",
                        remember=True)
    cli._profile_wizard(p, store, host="vc1.example.internal", name="lab", username="admin@vsphere.local",
                        remember=True)  # same server and account: the saved password still belongs to it
    assert deleted == []
    cli._profile_wizard(p, store, host="vc2.example.internal", name="lab", username="admin@vsphere.local",
                        remember=True)
    assert ("lab", "vc1.example.internal", "password") in deleted  # the old server's entry
    assert store.get("lab").host == "vc2.example.internal"


def test_a_storage_policy_is_refused_until_it_is_supported():
    """placement.storage_policy was accepted and silently ignored (audit): refused with an explanation instead."""
    from pydantic import ValidationError

    from vsphere_vm_deployment.manifest import Placement

    assert Placement(datastore="ds1").storage_policy is None
    with pytest.raises(ValidationError, match="storage policy is not supported yet"):
        Placement(storage_policy="gold")
