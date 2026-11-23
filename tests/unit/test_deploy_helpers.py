"""Small deploy helpers found during real-environment testing."""

import pytest

from vsphere_vm_deployment.deploy import explain_import_warning, suggest_vm_name


def test_default_vm_name_drops_cloudimg_and_build_date():
    assert suggest_vm_name("ubuntu-resolute-26.04-cloudimg-20261016") == "ubuntu-resolute-26.04"
    assert suggest_vm_name("ubuntu-noble-24.04-cloudimg-20240423.1") == "ubuntu-noble-24.04"


def test_default_vm_name_is_unique():
    taken = {"ubuntu-resolute-26.04", "ubuntu-resolute-26.04-2"}
    assert suggest_vm_name("ubuntu-resolute-26.04-cloudimg-20261016", taken) == "ubuntu-resolute-26.04-3"


def test_a_taken_vm_name_gets_the_first_free_dash_number():
    """The 'Choose another VM name' default was name-2 even when that was taken too. Numbers are never counted up
    (decided in the fourth review: 'rhel9' or 'win11_x64' are versions as often as 'web01' is a counter)."""
    from vsphere_vm_deployment.deploy import next_free_vm_name

    assert next_free_vm_name("web01", {"web01"}) == "web01-2"
    assert next_free_vm_name("web01", {"web01", "web01-2"}) == "web01-3"
    for version in ("rhel9", "win11_x64", "ubuntu-24.04"):
        assert next_free_vm_name(version, {version}) == f"{version}-2"
    assert next_free_vm_name("free01", {"other"}) == "free01"
    long = "a" * 80
    assert next_free_vm_name(long, {long}) == "a" * 78 + "-2"
    assert next_free_vm_name(long, {long} | {"a" * 78 + f"-{n}" for n in range(2, 10)}) == "a" * 77 + "-10"


def test_default_vm_name_fallbacks():
    assert suggest_vm_name(None) == "new-vm"
    assert suggest_vm_name("Vendor Appliance") == "Vendor Appliance"
    assert "/" not in suggest_vm_name("a/b")


def test_unknown_ovf_config_key_is_explained():
    msg = "Line 115: Unable to parse 'enableMPTSupport' for attribute 'key' on element 'Config'."
    text = explain_import_warning(msg)
    assert "enableMPTSupport" in text and "harmless" in text
    assert explain_import_warning("Something else") == "vCenter: Something else"


def test_wait_times_read_as_minutes_and_seconds():
    from vsphere_vm_deployment.deploy import min_sec

    assert min_sec(49) == "0 min 49 sec"
    assert min_sec(153) == "2 min 33 sec"
    assert min_sec(200) == "3 min 20 sec"
    assert min_sec(300) == "5 min"
    assert min_sec(0) == "0 min 0 sec"


# ------------------------------------------------------------------ IP address must settle (seen on vCenter 8.0.3)
class _Clock:
    def __init__(self):
        self.t = 0.0

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.t += s


def _fake_vm(clock, timeline):
    """timeline: list of (from_second, ip or None)."""
    from types import SimpleNamespace as NS

    class Guest:
        @property
        def ipAddress(self):  # noqa: N802 - vSphere API name
            current = None
            for start, ip in timeline:
                if clock.t >= start:
                    current = ip
            return current

        net = []
        toolsRunningStatus = "guestToolsRunning"

    return NS(guest=Guest())


def _poll(monkeypatch, timeline, timeout=300):
    from types import SimpleNamespace as NS

    from vsphere_vm_deployment import deploy as d

    clock = _Clock()
    monkeypatch.setattr(d.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(d.time, "sleep", clock.sleep)
    fake_self = NS(view=NS(update=lambda *a, **k: None), IP_SETTLE_S=d.Deployment.IP_SETTLE_S,
                   IP_WAIT_HINT=d.Deployment.IP_WAIT_HINT, _current_ipv4=d.Deployment._current_ipv4)
    return d.Deployment._poll_ip(fake_self, _fake_vm(clock, timeline), timeout), clock.t


def test_ip_that_changes_after_first_boot_is_not_reported_early(monkeypatch):
    # first DHCP lease .213 at 20 s, second lease .214 at 35 s (cloud-init restarted networking)
    ip, waited = _poll(monkeypatch, [(20, "198.51.100.213"), (35, "198.51.100.214")])
    assert ip == "198.51.100.214" and waited >= 35 + 30


def test_stable_ip_is_reported_after_the_settle_time(monkeypatch):
    ip, waited = _poll(monkeypatch, [(10, "192.0.2.50")])
    assert ip == "192.0.2.50" and 40 <= waited < 50


def test_link_local_and_no_address_time_out(monkeypatch):
    ip, waited = _poll(monkeypatch, [(5, "169.254.3.4")], timeout=60)
    assert ip is None and waited >= 60


def test_answers_are_offered_again_on_a_second_pass():
    from vsphere_vm_deployment.ui import Prompter

    p = Prompter(interactive=False)
    p._keep("guest.network.mode", "static")
    p._keep("", "not remembered")
    p.start_revision()
    assert p._prev("guest.network.mode", "dhcp") == "static"
    assert p._prev("vm.name", "default") == "default" and p.answers == {}


def test_wait_text_drops_minutes_for_short_limits():
    from vsphere_vm_deployment.deploy import wait_text

    assert wait_text(12, 30) == "12 sec of 30 sec"
    assert wait_text(153, 300) == "2 min 33 sec of 5 min"


def test_local_space_is_checked_before_a_large_read(tmp_path, monkeypatch):
    import shutil
    from collections import namedtuple

    import pytest

    from vsphere_vm_deployment.deploy import check_local_space
    from vsphere_vm_deployment.errors import PreflightError

    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(shutil, "disk_usage", lambda p: usage(100 * 2**30, 95 * 2**30, 5 * 2**30))
    check_local_space(tmp_path, 3 * 2**30, "read x.ova")  # 3 GB + 1 GB spare fits in 5 GB
    with pytest.raises(PreflightError) as e:
        check_local_space(tmp_path, 12 * 2**30, "read [datastore1 (1)] big.ova")
    assert "needs 12.0 GB" in e.value.message and "only 5.0 GB is free" in e.value.message
    assert "VMDEPLOY_CACHE_DIR" in e.value.hint and "clear-cache" in e.value.hint


def test_every_fault_class_named_in_the_code_exists():
    """A misspelled fault class only fails when that error actually happens (found in the lab: a cancelled import
    crashed on vim.fault.ManagedObjectNotFound, which is vmodl.fault.ManagedObjectNotFound)."""
    import pathlib
    import re

    from pyVmomi import vim, vmodl

    src = pathlib.Path(__file__).resolve().parents[2] / "src"
    missing = []
    for f in src.rglob("*.py"):
        for m in re.finditer(r"\b(vim|vmodl)\.fault\.([A-Za-z]+)", f.read_text(encoding="utf-8")):
            if not hasattr(vim.fault if m.group(1) == "vim" else vmodl.fault, m.group(2)):
                missing.append(f"{f.name}: {m.group(0)}")
    assert not missing


def test_a_deleted_vm_counts_as_gone():
    from pyVmomi import vmodl

    from vsphere_vm_deployment.deploy import _vm_gone

    class Deleted:
        @property
        def name(self):
            raise vmodl.fault.ManagedObjectNotFound(msg="already deleted")

    class Present:
        name = "x"

    assert _vm_gone(Deleted()) is True and _vm_gone(Present()) is False


def test_import_spec_carries_the_chosen_size():
    """A vCenter-managed ESXi host refuses resizing over a direct connection, so the size goes into the import."""
    from pyVmomi import vim

    from vsphere_vm_deployment.vmspec import size_import_spec

    spec = vim.VirtualMachineImportSpec(configSpec=vim.vm.ConfigSpec(
        numCPUs=2, numCoresPerSocket=1, memoryMB=16384,
        memoryAllocation=vim.ResourceAllocationInfo(reservation=16384)))
    changes = size_import_spec(spec, cpu=4, cores_per_socket=4, memory_mb=8192)
    cs = spec.configSpec
    assert (cs.numCPUs, cs.numCoresPerSocket, cs.memoryMB, cs.memoryAllocation.reservation) == (4, 4, 8192, 8192)
    assert "memory 16384 MB -> 8192 MB" in changes
    assert size_import_spec(spec, cpu=4, cores_per_socket=4, memory_mb=8192) == []
    assert size_import_spec(vim.VirtualAppImportSpec(), cpu=4, cores_per_socket=None, memory_mb=None) == []


def test_config_spec_split_into_parts():
    from pyVmomi import vim

    from vsphere_vm_deployment.vmspec import split_config_spec

    disk = vim.vm.device.VirtualDisk(key=2000, capacityInKB=1)
    spec = vim.vm.ConfigSpec(numCPUs=2, memoryMB=4096, annotation="x",
                             extraConfig=[vim.option.OptionValue(key="guestinfo.userdata", value="y")],
                             deviceChange=[vim.vm.device.VirtualDeviceSpec(operation="edit", device=disk)])
    parts = dict(split_config_spec(spec))
    assert list(parts) == ["CPU", "memory", "VM notes", "cloud-init data (guestinfo)", "disk size"]
    assert parts["CPU"].numCPUs == 2 and parts["CPU"].memoryMB is None
    assert parts["disk size"].deviceChange[0].device is disk


def test_managed_host_refusing_disk_growth_falls_back_to_the_disk_file(monkeypatch):
    """Direct connection to a vCenter-managed ESXi host: the combined reconfigure and the disk-size part are
    refused; the other parts are applied and the disk is grown through VirtualDiskManager instead."""
    from types import SimpleNamespace

    import pytest
    from pyVmomi import vim

    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment.errors import DeploymentError

    refused = DeploymentError("Reconfigure VM failed: Access to resource settings on the host is restricted to the "
                              "server that is managing it: '198.51.100.5'.")
    applied, extended = [], []

    def wait_task(task, what="", **_):
        if task == "refuse":
            raise refused
        if what.startswith("Extend"):
            extended.append(task)
        else:
            applied.append(what)

    monkeypatch.setattr(d, "wait_task", wait_task)
    disk = vim.vm.device.VirtualDisk(key=2000, capacityInKB=40 * 1024 * 1024,
                                     backing=vim.vm.device.VirtualDisk.FlatVer2BackingInfo(fileName="[ds] vm/vm.vmdk"))
    spec = vim.vm.ConfigSpec(annotation="notes", deviceChange=[
        vim.vm.device.VirtualDeviceSpec(operation="edit", device=disk)])

    def reconfig(spec):
        return "refuse" if spec.deviceChange else "ok"

    notes = []
    vdm = SimpleNamespace(ExtendVirtualDisk_Task=lambda **kw: kw)
    fake = SimpleNamespace(vm=SimpleNamespace(ReconfigVM_Task=reconfig),
                           conn=SimpleNamespace(content=SimpleNamespace(virtualDiskManager=vdm)),
                           plan=SimpleNamespace(provisioning=d.Provisioning.THIN, dc=SimpleNamespace(obj="dc")),
                           view=SimpleNamespace(note=lambda *a, **k: notes.append(a)))
    fake._extend_disk_file = lambda disk: d.Deployment._extend_disk_file(fake, disk)
    d.Deployment._reconfigure_in_parts(fake, spec, refused)
    assert applied == ["Reconfigure VM (VM notes)"]
    assert extended == [{"name": "[ds] vm/vm.vmdk", "datacenter": "dc", "newCapacityKb": 40 * 1024 * 1024,
                         "eagerZero": False}]

    # When the disk file cannot be extended either, the error names the refused part.
    vdm.ExtendVirtualDisk_Task = lambda **kw: "refuse"
    with pytest.raises(DeploymentError, match="Refused: disk size"):
        d.Deployment._reconfigure_in_parts(fake, spec, refused)


def test_import_spec_creates_disk_1_at_the_chosen_size():
    """Hosts managed by vCenter, reached directly, refuse growing a disk afterwards: it is created at size."""
    from pyVmomi import vim

    from vsphere_vm_deployment.vmspec import KB_PER_GB, size_import_spec

    d1 = vim.vm.device.VirtualDisk(key=1, capacityInKB=10 * KB_PER_GB)
    d2 = vim.vm.device.VirtualDisk(key=2, capacityInKB=5 * KB_PER_GB)
    spec = vim.VirtualMachineImportSpec(configSpec=vim.vm.ConfigSpec(numCPUs=2, memoryMB=1024, deviceChange=[
        vim.vm.device.VirtualDeviceSpec(operation="add", device=d) for d in (d1, d2)]))
    assert size_import_spec(spec, cpu=None, cores_per_socket=None, memory_mb=None, disk_gb=40) == \
        ["disk 1 created at 40 GB"]
    assert (d1.capacityInKB, d2.capacityInKB) == (40 * KB_PER_GB, 5 * KB_PER_GB)
    assert size_import_spec(spec, cpu=None, cores_per_socket=None, memory_mb=None, disk_gb=20) == []  # never shrinks


def test_appliance_settings_questions_by_type(monkeypatch):
    """Interactive: on/off settings are yes/no questions, ValueMaps a list, passwords hidden; descriptions in
    full above the question; blank answers shown as "(empty)"; what reaches vCenter uses its spelling."""
    from types import SimpleNamespace as NS

    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment.manifest import OvfSpec
    from vsphere_vm_deployment.ovf import OvfProperty

    def prop(key, type_="string", default="", password=False, qualifiers="", desc=""):
        return OvfProperty(key=key, type=type_, default=default, label=key, description=desc,
                           user_configurable=True, password=password, qualifiers=qualifiers)

    props = [prop("hostname", desc="Hostname of\n     this router"), prop("scp", "boolean", "false"),
             prop("vlan"), prop("secret", password=True), prop("size", qualifiers='ValueMap{"s","l"}', default="l"),
             prop("Flag to skip prechecks.", "boolean", "false")]  # vCenter's label ends with a full stop
    printed, asked, recorded = [], [], []
    answers = {"hostname:": "r1", "scp?": True, "vlan:": "", "secret (Enter to leave empty):": "", "size:": "s",
               "Flag to skip prechecks?": False}

    def ask(kind):
        def f(q, *a, **k):
            asked.append((kind, q))
            return answers[q]
        return f

    monkeypatch.setattr(d.console, "print", lambda *a, **k: printed.append(a[0]))
    p = NS(interactive=True, would_ask=lambda f: True, section=lambda h: __import__("contextlib").nullcontext(),
           text=ask("text"),
           confirm=ask("confirm"), select=ask("select"), record=lambda label, val: recorded.append((label, val)))
    fake = NS(pkg=NS(info=NS(properties=props, has_cloud_init_properties=False)), m=NS(ovf=OvfSpec()), p=p)
    plan = NS()
    d.Deployment._ask_ovf_options(fake, plan)
    assert [k for k, _ in asked] == ["text", "confirm", "text", "text", "select", "confirm"]
    assert "[dim]Hostname of this router[/]" in printed
    assert recorded == [("hostname", "r1"), ("scp", "yes"), ("vlan", "(empty)"), ("secret", "(empty)"),
                        ("size", "s"), ("Flag to skip prechecks", "no")]
    assert plan.ovf_properties == {"hostname": "r1", "scp": "True", "vlan": "", "secret": "", "size": "s",
                                  "Flag to skip prechecks.": "False"}


def test_a_password_the_image_refuses_is_not_shown_back(monkeypatch):
    """Found in the security review: the hint for a manifest value the image refuses repeated the value, a
    password's too."""
    from types import SimpleNamespace as NS

    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment import logsetup
    from vsphere_vm_deployment.errors import ConfigError
    from vsphere_vm_deployment.manifest import OvfSpec
    from vsphere_vm_deployment.ovf import OvfProperty

    monkeypatch.setattr(logsetup, "_runtime_secrets", set())  # this test's values stay out of the others' logs
    for key, password, hint in (("admin_password", True, None), ("site", False, "Given: 'east-01'.")):
        pr = OvfProperty(key=key, type="string", default="", label=key, description="", user_configurable=True,
                         password=password, qualifiers="MinLen(12)")
        fake = NS(pkg=NS(info=NS(properties=[pr], has_cloud_init_properties=False)),
                  m=NS(ovf=OvfSpec(properties={key: "east-01"})), p=NS(), batch_spec=None)
        with pytest.raises(ConfigError) as e:
            d.Deployment._ask_ovf_options(fake, NS())
        assert e.value.hint == hint and "east-01" not in e.value.message


def _eula_fake(monkeypatch, tmp_path, answers):
    from types import SimpleNamespace as NS

    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment.manifest import OvfSpec

    monkeypatch.setenv("VMDEPLOY_LOG_DIR", str(tmp_path))
    out, questions, recorded = [], [], []
    monkeypatch.setattr(d.console, "print", lambda *a, **k: out.append(str(a[0]) if a else ""))
    monkeypatch.setattr(d.console, "rule", lambda *a, **k: out.append(f"RULE {a[0] if a else ''}"))
    it = iter(answers)

    def ask(q, *a, **k):
        questions.append((q, a[0] if a else None, k.get("default")))
        return next(it)

    p = NS(interactive=True, section=lambda h: __import__("contextlib").nullcontext(), select=ask, confirm=ask,
           record=lambda label, val: recorded.append((label, val)))
    fake = NS(p=p, m=NS(ovf=OvfSpec()), pkg=NS(info=NS(product="VMware vCenter Server Appliance", name="vcsa")))
    fake._save_eula = lambda i, t: d.Deployment._save_eula(fake, i, t)
    return (lambda eulas: d.Deployment._accept_eulas(fake, eulas)), out, questions, recorded


def test_a_long_licence_is_previewed_saved_and_shown_in_full_on_request(monkeypatch, tmp_path):
    """vCenter's OVA: a ~94,000-character licence scrolled the question off screen."""
    long_text = "Foundation Agreement\n" + "\n".join(f"{n}. Clause text." for n in range(1, 1500))
    run, out, questions, recorded = _eula_fake(monkeypatch, tmp_path, ["show:1", "accept"])
    run([long_text, "Short licence two."])
    saved = tmp_path / "licences" / "VMware-vCenter-Server-Appliance-licence-1.txt"
    assert saved.read_text(encoding="utf-8") == long_text
    assert "RULE Licence 1 of 2: Foundation Agreement" in out and "RULE Licence 2 of 2: Short licence two." in out
    assert sum(1 for line in out if line == long_text) == 1  # in full only when asked for
    assert any("1,500 lines" in line and str(saved) in line for line in out)
    q, choices, default = questions[0]
    assert default == "decline" and [v for _, v in choices] == ["accept", "show:1", "decline"]
    # Found in testing: "Show licence 1" made an endless loop, and licence 2 had scrolled away when accepting.
    _, choices, default = questions[1]
    assert default == "decline" and [v for _, v in choices] == ["accept", "decline"]  # shown once: not offered again
    after_full = out[out.index(long_text):]
    assert "Short licence two." in after_full  # the short licence again, right above the question
    assert any("Accepting accepts all 2 licence(s)" in line and "2: Short licence two. (in full above)" in line
               and "1: Foundation Agreement (shown in full)" in line for line in after_full)
    assert recorded == [("Licence", "2 agreement(s) accepted")]


def test_declining_or_a_short_licence(monkeypatch, tmp_path):
    from vsphere_vm_deployment.errors import UserAborted

    run, *_ = _eula_fake(monkeypatch, tmp_path, ["decline"])
    with pytest.raises(UserAborted, match="declined; nothing was deployed"):
        run(["x\n" * 200])
    run, out, questions, _ = _eula_fake(monkeypatch, tmp_path, [False])
    with pytest.raises(UserAborted):
        run(["You agree to things."])
    assert "You agree to things." in out and questions[0][2] is False  # short: shown in full, yes/no, default No


def test_licence_titles_and_previews_from_vcenters_ova(tmp_path):
    from vsphere_vm_deployment.deploy import EULA_PREVIEW_CHARS, eula_preview, eula_title

    assert eula_title("Foundation Agreement\n1. INTRODUCTION") == "Foundation Agreement"
    second = ("Copyright © 1998-2024 VMware, Inc. All rights reserved. This product is protected by copyright and "
              "intellectual property laws in the United States")
    assert eula_title(second) == "Copyright © 1998-2024 VMware, Inc."  # the first sentence, not "This product i"
    assert eula_title("word " * 30).endswith("…") and "  " not in eula_title("word " * 30)
    paragraphs = "\n".join(f"{n}. " + "Clause text, quite long. " * 15 for n in range(1, 262))  # ~375 chars a line
    preview = eula_preview(paragraphs)
    assert preview.startswith("1. ") and len(preview) <= EULA_PREVIEW_CHARS and preview.count("\n") < 5
