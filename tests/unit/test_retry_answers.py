"""--retry-failed reuses the first run's answers while they still fit, never a licence, password or the review; a
retry with a different image is pointed out. Also the naming bugs found with an ISO batch."""

from types import SimpleNamespace as NS

import pytest

from vsphere_vm_deployment import ui
from vsphere_vm_deployment.errors import ConfigError


@pytest.fixture
def prompter(monkeypatch):
    asked = []

    def question(kind):
        def make(q, *a, **k):
            asked.append(q)
            return NS(unsafe_ask=lambda: {"text": "typed", "select": k.get("choices", [NS(value=None)])[0].value,
                                          "checkbox": []}[kind])
        return make

    for kind in ("text", "select", "checkbox"):
        monkeypatch.setattr(ui.questionary, kind, question(kind))
    monkeypatch.setattr(ui.questionary, "password", question("text"))
    p = ui.Prompter(interactive=False)
    p.interactive = True  # pytest has no terminal
    p.asked = asked
    return p


def test_answers_that_still_fit_are_not_asked(prompter):
    prompter.replay = {"vm.name": "web-{n}", "post_deploy.snapshot": False, "batch.targets": [["host", "esx-b"]],
                       "placement.datastore": {"name": "ds2"}, "batch.count": "2"}
    assert prompter.text("VM name pattern:", field_name="vm.name") == "web-{n}"
    assert prompter.confirm("Snapshot?", field_name="post_deploy.snapshot") is False
    hosts = [("esx-a  (2 cores)", ("host", "esx-a")), ("esx-b  (2 cores)", ("host", "esx-b"))]
    assert prompter.checkbox("Deploy to:", hosts, field_name="batch.targets") == [("host", "esx-b")]
    ds = [NS(name="ds1"), NS(name="ds2")]
    assert prompter.select("Datastore:", [("ds1", ds[0]), ("ds2", ds[1])], field_name="placement.datastore") is ds[1]
    assert prompter.integer("VMs on each:", field_name="batch.count") == 2
    assert prompter.asked == []
    assert ui.saved_answers(prompter.answers)["placement.datastore"] == {"name": "ds2"}


def test_an_answer_that_no_longer_fits_is_asked(prompter):
    prompter.replay = {"batch.targets": [["host", "esx-gone"]], "vm.name": "bad/name", "image": "nope"}
    hosts = [("esx-a", ("host", "esx-a")), ("esx-b", ("host", "esx-b"))]
    prompter.checkbox("Deploy to:", hosts, field_name="batch.targets")
    prompter.text("VM name:", field_name="vm.name", validate=lambda s: "/" not in s or "no /")
    prompter.select("Where is the VM image?", [("local", "local"), ("url", "url")], field_name="image")
    assert prompter.asked == ["Deploy to:", "VM name:", "Where is the VM image?"]


def test_a_licence_a_password_and_the_review_are_never_reused(prompter):
    prompter.replay = {"ovf.accept_eula": True, "secret": "x"}
    prompter.answers = {"ovf.accept_eula": True, "_iso_copy_offered": "x", "--delete-iso": True, "vm.name": "a"}
    assert ui.saved_answers(prompter.answers) == {"vm.name": "a"}
    prompter.confirm("Accept the licence?", field_name="ovf.accept_eula")
    prompter.text("Password:", field_name="secret", secret=True)
    prompter.select("What next?", [("Deploy", "deploy"), ("Cancel", "cancel")])
    assert prompter.asked == ["Accept the licence? (yes/no, suggested: no)", "Password:", "What next?"]


def test_a_url_holding_a_password_or_token_is_never_saved():
    """Found in the re-review: --url was redacted, but a URL typed at "Where is the VM image?" was saved as typed
    (and shown "as in the first run" by a retry). Text that only looks like one is kept."""
    saved = ui.saved_answers({
        "image": "url", "image.url": "https://svc:S3cret@files.example.test/web.ova",
        "ovf.properties.feed": "https://files.example.test/feed.json?sig=T0ken",
        "batch.hosts": ["https://files.example.test/a?sig=T0ken"],
        "guest.ssh_authorized_keys": "ssh-ed25519 AAAAC3NzaC1 admin@workstation",
        "ovf.properties.contact": "admin@example.test", "ovf.properties.mirror": "https://files.example.test/web.ova"})
    assert not {"image.url", "ovf.properties.feed", "batch.hosts"} & saved.keys()
    assert saved["image"] == "url" and saved["guest.ssh_authorized_keys"].endswith("admin@workstation")
    assert saved["ovf.properties.contact"] == "admin@example.test"
    assert saved["ovf.properties.mirror"] == "https://files.example.test/web.ova"


def test_static_addresses_that_do_not_fit_together_are_asked_again(monkeypatch, capsys):
    """Each answer is checked as it is typed, then all of them with the prefix: a gateway outside the second
    address's subnet asks the addresses again instead of ending the run (it used to end it, answers lost)."""
    from vsphere_vm_deployment.batch import BatchDeployment

    typed = iter(["192.0.2.50, 198.51.100.7", "24", "192.0.2.1", "",
                  "192.0.2.50-51", "24", "192.0.2.1", "192.0.2.53"])
    asked = []
    monkeypatch.setattr(ui.questionary, "text", lambda q, **k: asked.append(q) or NS(unsafe_ask=lambda: next(typed)))
    p = ui.Prompter(interactive=False)
    p.interactive = True  # pytest has no terminal
    a = BatchDeployment._ask_static_addresses(NS(p=p, assignment=[(0, 1), (0, 2)]))
    assert a.range == "192.0.2.50-51" and a.gateway == "192.0.2.1" and a.dns == ["192.0.2.53"]
    assert len(asked) == 8 and "Answer the addresses again" in capsys.readouterr().err


def test_the_hostname_choice_and_its_pattern_are_kept_apart(monkeypatch):
    """Both were kept under batch.hostname, so a retry asked "Hostnames:" again whenever a pattern was chosen."""
    from vsphere_vm_deployment.batch import BatchDeployment
    from vsphere_vm_deployment.manifest import BatchSpec, GuestSpec

    def per_vm(prompter):
        fake = NS(p=prompter, b=BatchSpec(), targets=[NS(ovf={})], hostname_pattern=None, addresses=None)
        BatchDeployment._ask_per_vm(fake, NS(ovf_properties={}, guest=GuestSpec(username="ops")))
        return fake.hostname_pattern

    picks = iter(["__pattern__", "dhcp"])
    monkeypatch.setattr(ui.questionary, "select", lambda q, **k: NS(unsafe_ask=lambda: next(picks)))
    monkeypatch.setattr(ui.questionary, "text", lambda q, **k: NS(unsafe_ask=lambda: "web{n:02}"))
    p = ui.Prompter(interactive=False)
    p.interactive = True
    assert per_vm(p) == "web{n:02}"
    saved = ui.saved_answers(p.answers)
    assert saved["batch.hostname_choice"] == "__pattern__" and saved["batch.hostname"] == "web{n:02}"

    for kind in ("select", "text"):
        monkeypatch.setattr(ui.questionary, kind, lambda q, **k: pytest.fail(f"asked again: {q}"))
    retry = ui.Prompter(interactive=False)  # --yes: the saved answers only
    retry.replay = saved
    assert per_vm(retry) == "web{n:02}"


def test_change_my_answers_asks_everything_again(prompter):
    prompter.replay = {"vm.name": "web"}
    assert prompter.text("VM name:", field_name="vm.name") == "web"
    prompter.start_revision()
    assert prompter.text("VM name:", field_name="vm.name") == "typed" and prompter.asked == ["VM name:"]


def test_yes_runs_use_the_saved_answers_where_they_would_take_a_default():
    p = ui.Prompter(interactive=False)
    assert not p.would_ask("batch.count")
    p.replay = {"batch.count": "3"}
    assert p.would_ask("batch.count") and p.integer("VMs on each:", field_name="batch.count") == 3


def test_a_retry_with_another_image_is_pointed_out():
    from vsphere_vm_deployment.batch import BatchDeployment

    def check(interactive, now):
        b = NS(retry_doc={"image": "Ubuntu build 1", "image_sha256": "a" * 64}, image=NS(sha256=now, display="x"),
               p=NS(interactive=interactive), batch_warnings=[])
        BatchDeployment._check_retry_image(b)
        return b.batch_warnings

    assert check(True, "a" * 64) == [] and check(True, None) == []
    assert "not the one the first run deployed" in check(True, "b" * 64)[0]
    with pytest.raises(ConfigError, match="not the one the first run deployed"):
        check(False, "b" * 64)


def test_iso_copies_and_name_suggestions_use_the_file_name():
    """Found in real testing: an ISO in a datastore's top folder was copied as 'vmdeploy-iso/[ds] x.iso', and a
    local ISO's name suggestion was its whole path ('C:-Users-...')."""
    from vsphere_vm_deployment.deploy import image_name_hint, suggest_vm_name
    from vsphere_vm_deployment.isolib import copy_target

    assert copy_target("ssd-01", "[datastore1 (1)] ubuntu.iso") == "[ssd-01] vmdeploy-iso/ubuntu.iso"
    assert copy_target("ssd-01", "[ds] isos/linux/ubuntu.iso") == "[ssd-01] vmdeploy-iso/ubuntu.iso"
    assert copy_target("ssd-01", "ubuntu.iso") == "[ssd-01] vmdeploy-iso/ubuntu.iso"
    local = NS(datastore_path=None, path=r"C:\Users\someone\images\ubuntu-24.04.4-live-server-amd64.iso", display="")
    assert suggest_vm_name(image_name_hint(None, local)) == "ubuntu-24.04.4-live-server-amd64"
    on_ds = NS(datastore_path="[ds] isos/win11.iso", path=None, display="")
    assert image_name_hint(None, on_ds) == "win11"
    assert image_name_hint(NS(info=NS(name="Ubuntu Server")), local) == "Ubuntu Server"
    # a batch's pattern starts the same way: the extension is already gone, so nothing more is cut at a dot
    from vsphere_vm_deployment.batch import name_base

    assert name_base(None, local) == "ubuntu-24.04.4-live-server-amd64"
    assert name_base(None, NS(datastore_path=None, path="/isos/rhel-9.4-x86_64-dvd.iso", display="")) == \
        "rhel-9.4-x86_64-dvd"


def test_a_retry_takes_how_the_first_run_was_started_from_its_results_file(tmp_path, capsys):
    """`vmdeploy deploy --retry-failed latest` is the whole command: the manifest, image source, profile and batch
    options come from the results file (a moved manifest is said, and the saved answers cover it)."""
    import json

    from vsphere_vm_deployment.cli import _retry_settings

    man = tmp_path / "batch.yaml"
    man.write_text("batch: {}\n")
    f = tmp_path / "batch-20261121-192930.json"
    f.write_text(json.dumps({"batch": True, "vms": [], "manifest": str(man), "profile": "lab",
                             "source": {"kind": "preset", "value": "ubuntu-lts", "sha256": None},
                             "options": {"parallel": 2}}))
    got = _retry_settings(f)
    assert got["manifest"] == man and got["profile"] == "lab" and got["options"]["parallel"] == 2
    assert got["source"]["value"] == "ubuntu-lts"
    assert "As that run: manifest" in capsys.readouterr().err
    man.unlink()
    got = _retry_settings(f)
    assert "manifest" not in got and got["manifest_gone"] == str(man)  # said, or refused with --yes, by deploy
    assert _retry_settings(tmp_path / "missing.json") == {}


def test_a_retry_refuses_what_its_results_file_cannot_give(tmp_path):
    """Found in review. A manifest that is gone: what it set was never an answer to save, so --yes refuses (it
    said "its saved answers are used instead"). A URL with a password or token is never saved: give --url again."""
    import json

    from typer.testing import CliRunner

    from vsphere_vm_deployment.cli import app

    f = tmp_path / "batch-20261122-101500.json"
    f.write_text(json.dumps({"batch": True, "vms": [{"name": "a", "status": "failed"}],
                             "manifest": str(tmp_path / "moved.yaml")}))
    r = CliRunner().invoke(app, ["deploy", "--retry-failed", str(f), "--yes"])
    assert r.exit_code == 2 and "is not there any more" in r.output and "Give it with -f" in r.output
    f.write_text(json.dumps({"batch": True, "vms": [{"name": "a", "status": "failed"}],
                             "source": {"kind": "url", "value": "https://***@files.example.test/web.ova",
                                        "sha256": None, "redacted": True}}))
    r = CliRunner().invoke(app, ["deploy", "--retry-failed", str(f), "--yes"])
    assert r.exit_code == 2 and "held a password or token" in r.output and "--url" in r.output
    r = CliRunner().invoke(app, ["deploy", "--retry-failed", str(f)])  # interactive: the image is asked again
    assert "choose the image again" in r.output and "Give it again with --url" not in r.output


def test_each_hosts_datastore_is_kept_and_reused_for_that_host(monkeypatch):
    """Found in review: every 'Datastore on <host>' answer was kept under one field name, so a retry gave every
    host the last host's datastore and said it was "as in the first run"."""
    from vsphere_vm_deployment.batch import BatchDeployment, Target

    def store(name, free):
        return NS(name=name, display_name=name, usable=True, hosts={"esx-a", "esx-b"}, free=free, is_vsan=False,
                  label=lambda: name)

    stores = {"ds-1": store("ds-1", 200), "ds-2": store("ds-2", 100)}
    dc = NS(datastores=stores, hosts={})

    def targets():
        return [Target(label=h, host=NS(name=h, usable=True), cluster=None, pool=None, pool_path="")
                for h in ("esx-a", "esx-b")]

    picks = iter(["each", stores["ds-1"], stores["ds-2"]])
    monkeypatch.setattr(ui.questionary, "select", lambda q, **k: NS(unsafe_ask=lambda: next(picks)))
    p = ui.Prompter(interactive=False)
    p.interactive = True  # pytest has no terminal
    first = NS(p=p, targets=targets())
    BatchDeployment._ask_target_datastores(first, dc)
    assert [t.datastore.name for t in first.targets] == ["ds-1", "ds-2"]
    saved = ui.saved_answers(p.answers)
    assert saved == {"batch.datastore_choice": "each", "batch.datastore[esx-a]": {"name": "ds-1"},
                     "batch.datastore[esx-b]": {"name": "ds-2"}}

    monkeypatch.setattr(ui.questionary, "select", lambda q, **k: pytest.fail(f"asked again: {q}"))
    retry = NS(p=ui.Prompter(interactive=False), targets=targets())  # --yes: the saved answers only
    retry.p.replay = saved
    BatchDeployment._ask_target_datastores(retry, dc)
    assert [t.datastore.name for t in retry.targets] == ["ds-1", "ds-2"]
