import base64
from types import SimpleNamespace

import pytest

from vsphere_vm_deployment.auth import decode_saml
from vsphere_vm_deployment.connection import is_free_hypervisor_license
from vsphere_vm_deployment.errors import AuthError, ConfigError, MissingInput
from vsphere_vm_deployment.inventory import UPLINK_NAME_RE
from vsphere_vm_deployment.logsetup import redact, register_secret
from vsphere_vm_deployment.profiles import AuthMethod, OAuthSettings, Profile, ProfileStore
from vsphere_vm_deployment.ui import DeploymentView, Prompter


# ---------------------------------------------------------------- redaction
def test_redaction_patterns():
    assert "hunter2" not in redact("login password=hunter2 ok")
    assert "abc.def" not in redact("Authorization: Bearer abc.def")
    assert "XYZ" not in redact("Cookie: vmware_soap_session=XYZ; Path=/")
    assert "secret-token" not in redact('{"access_token": "secret-token"}')
    register_secret("MyS3cretValue")
    assert "MyS3cretValue" not in redact("the value MyS3cretValue appeared")


# ---------------------------------------------------------------- licence detection
@pytest.mark.parametrize("name,key,free", [
    ("vSphere 8 Hypervisor", "esxBasic", True),
    ("Evaluation Mode", "eval", False),
    ("vSphere 8 Enterprise Plus", "esx.enterprisePlus.cpuPackage", False),
])
def test_free_license_detection(name, key, free):
    assert is_free_hypervisor_license([SimpleNamespace(name=name, editionKey=key)]) is free


# ---------------------------------------------------------------- SAML decoding
def test_decode_saml():
    xml = "<saml2:Assertion>x</saml2:Assertion>"
    assert decode_saml(base64.b64encode(xml.encode()).decode()) == xml
    assert decode_saml(xml) == xml
    with pytest.raises(AuthError):
        decode_saml("!!!not-base64!!!")


# ---------------------------------------------------------------- profiles
def test_profile_store_roundtrip(isolated_dirs):
    store = ProfileStore()
    store.save(Profile(name="lab", host="vcsa.lab", username="admin@vsphere.local"))
    store.save(Profile(name="sso", host="vc.corp", auth=AuthMethod.OAUTH_PASSWORD,
                       oauth=OAuthSettings(token_url="https://adfs/adfs/oauth2/token", client_id="abc")))
    assert store.default_name() == "lab"
    assert store.get("sso").oauth.client_id == "abc"
    store.set_default("sso")
    store.remove("sso")
    assert store.default_name() == "lab"
    with pytest.raises(ConfigError):
        store.get("sso")
    text = (isolated_dirs / "cfg" / "profiles.yaml").read_text()
    import re

    assert not re.search(r"^\s*(password|client_secret|pwd):", text, re.M)


def test_profile_name_validation():
    with pytest.raises(ValueError):
        Profile(name="bad name", host="x")


# ---------------------------------------------------------------- UI
def test_weighted_overall_progress():
    v = DeploymentView("t", [("a", "A", 1), ("b", "B", 9)], enabled=False)
    v.done("a")
    assert v.overall_fraction() == pytest.approx(0.1)
    v.start("b")
    v.update("b", fraction=0.5)
    assert v.overall_fraction() == pytest.approx(0.55)


def test_non_interactive_prompts():
    p = Prompter(interactive=False)
    assert p.text("q", default="d", assume_default=True) == "d"
    assert p.confirm("q", assume=True) is True
    assert p.select("q", [("A", "a"), ("B", "b")], default="b", assume_default=True) == "b"
    with pytest.raises(MissingInput) as e:
        p.text("VM name:", field_name="vm.name")
    assert "vm.name" in e.value.hint
    with pytest.raises(MissingInput):
        p.confirm("Deploy?")


def test_select_rejects_none_values():
    p = Prompter(interactive=False)
    p.interactive = True
    with pytest.raises(ValueError):
        p.select("q", [("A", None), ("B", "b")])


def test_select_shows_a_long_description_for_the_highlighted_choice_only(monkeypatch):
    """vCenter's sizes have long descriptions that ran off the screen when part of every line."""
    from vsphere_vm_deployment import ui

    seen = {}

    class Answer:
        def ask(self):
            return "tiny"

    def fake_select(question, choices, default=None, **k):
        seen["choices"], seen["default"] = choices, default
        return Answer()

    monkeypatch.setattr(ui.questionary, "select", fake_select)
    monkeypatch.setattr(ui.Prompter, "_ask", lambda self, q: q.ask())
    p = Prompter(interactive=False)
    p.interactive = True
    assert p.select("Size:", [("Tiny: 2 vCPU", "tiny", "Requires 579 GB of disk space."), ("Small", "small")],
                    default="tiny") == "tiny"
    tiny, small = seen["choices"]
    assert tiny.title == "Tiny: 2 vCPU" and small.title == "Small" and seen["default"] is tiny
    if ui._CHOICE_DESCRIPTIONS:
        assert tiny.description == "Requires 579 GB of disk space." and small.description is None


def test_uplink_name_fallback():
    assert UPLINK_NAME_RE.search("DSwitch-DVUplinks-35")
    assert not UPLINK_NAME_RE.search("VLAN20-Servers")


def test_safe_url_and_traceback_redaction(tmp_path):
    import logging

    from vsphere_vm_deployment.logsetup import RedactingFormatter, safe_url

    assert safe_url("https://bucket.s3.amazonaws.com/x.ova?X-Amz-Signature=abc&sig=def") == \
        "https://bucket.s3.amazonaws.com/x.ova?***"
    assert "pw" not in safe_url("https://user:pw@host/x.iso")
    assert redact("see https://user:pw@host/x.iso now").count("pw") == 0
    try:
        raise RuntimeError("password=hunter2 rejected")
    except RuntimeError:
        import sys

        rec = logging.LogRecord("t", logging.ERROR, __file__, 1, "boom", (), sys.exc_info())
    assert "hunter2" not in RedactingFormatter("%(message)s").format(rec)


def test_https_required_for_idp():
    from vsphere_vm_deployment.auth import idp_token

    with pytest.raises(AuthError, match="https"):
        idp_token("http://idp.example.com/token", "c", grant="client_credentials", client_secret="s")


@pytest.mark.parametrize(("name", "ok"), [
    ("vCenter-main", True),
    ("lab_esxi.01", True),
    ("", False),
    ("two words", False),
    ("vCenter-mainvmdeploy -v doctor -p vCenter-main\n", False),  # a pasted command (seen in testing)
    ("a/b", False),
    (r"a\b", False),
    ("host:443", False),
    ("x" * 65, False),
])
def test_profile_name_rules(name, ok):
    from vsphere_vm_deployment.profiles import profile_name_error

    assert (profile_name_error(name) is None) is ok


def test_vsphere_escaped_names_are_shown_as_typed():
    from vsphere_vm_deployment.inventory import DatastoreInfo, display

    assert display("SSD 2 (2tb) (Apps%2fDB)") == "SSD 2 (2tb) (Apps/DB)"
    ds = DatastoreInfo(name="SSD 2 (2tb) (Apps%2fDB)", obj=None, type="VMFS", capacity=2 * 1024**4,
                       free=1024**4, uncommitted=0, accessible=True, maintenance="normal", hosts={"192.0.2.11"})
    assert ds.host_label(4).startswith("192.0.2.11 › SSD 2 (2tb) (Apps/DB)  (VMFS")
    ds.hosts = {"a", "b", "c", "d"}
    assert ds.host_label(4).startswith("shared (4 hosts) › ")


def test_datastore_paths_survive_rich_tables():
    # Rich reads "[datastore1 (3)]" as a style tag and drops it unless escaped (seen in `access audit`).
    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table

    t = Table("Folder")
    t.add_row(escape("[datastore1 (3)] vmdeploy-iso"))
    c = Console(width=80, record=True)
    c.print(t)
    assert "[datastore1 (3)] vmdeploy-iso" in c.export_text()


def test_step_times_leave_out_the_users_answers(monkeypatch):
    from vsphere_vm_deployment import ui

    clock = [100.0]
    monkeypatch.setattr(ui.time, "monotonic", lambda: clock[0])
    v = ui.DeploymentView("t", [("connect", "Connect", 1), ("plan", "Review", 1)], enabled=False, untimed=("plan",))
    v.start("connect")
    clock[0] += 2  # working
    with v.waiting():  # the password prompt: 40 s of the user's time
        clock[0] += 40
    clock[0] += 1.5  # working again
    v.done("connect")
    v.start("plan")
    with v.waiting():
        clock[0] += 300
    v.done("plan")
    assert v.timings() == {"connect": 3.5}  # the review is the user's time: not shown at all
    assert [ui.duration(x) for x in (0.4, 12, 185, 3720)] == ["<1s", "12s", "3m 05s", "1h 02m"]


def test_a_step_with_two_phases_counts_both(monkeypatch, caplog):
    """Real-environment smoke test: the full SHA-256 check of an ISO copy, then vCenter's copy of it, are one step.
    Starting the copy restarted the step's clock: it showed 36 s for about 80 s of work, and the total left the
    check out. The steps' outcomes are written to the log file (not to the console a second time with -v)."""
    import logging

    from vsphere_vm_deployment import ui

    clock = [100.0]
    monkeypatch.setattr(ui.time, "monotonic", lambda: clock[0])
    caplog.set_level(logging.INFO, logger="vsphere_vm_deployment.ui")
    v = ui.DeploymentView("t", [("upload_iso", "Upload ISO to datastore", 1)], enabled=False)
    v.start("upload_iso", "checking the copy")
    clock[0] += 43
    v.start("upload_iso", "copying it")
    clock[0] += 36
    v.done("upload_iso", "[ds1] vmdeploy-iso/x.iso (copied by vCenter, host to host)")
    assert v.timings() == {"upload_iso": 79.0}
    [record] = [r for r in caplog.records if r.name == "vsphere_vm_deployment.ui"]
    assert record.getMessage() == ("[done] Upload ISO to datastore: [ds1] vmdeploy-iso/x.iso (copied by vCenter, "
                                   "host to host) (1m 19s)") and getattr(record, "file_only", False)
    v.start("upload_iso", "again")  # a step that finished starts afresh
    clock[0] += 5
    v.done("upload_iso")
    assert v.timings() == {"upload_iso": 5.0}
    for style, level in (("red", logging.ERROR), ("bold red", logging.ERROR), ("yellow", logging.WARNING),
                         ("dim", logging.INFO), ("", logging.INFO)):
        v.note("upload_iso", f"a {style or 'plain'} note", style=style)
        assert caplog.records[-1].levelno == level  # a blocker or a warning keeps its weight in the log
