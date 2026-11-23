"""The log folder can be chosen (`vmdeploy logs --folder`), results files are found with `latest` or their name,
and an unreachable folder never stops a run or loses a results file."""

import json
import logging

import pytest
from typer.testing import CliRunner

from vsphere_vm_deployment import logsetup, paths
from vsphere_vm_deployment.cli import _results_files, app
from vsphere_vm_deployment.errors import ConfigError
from vsphere_vm_deployment.logfiles import batch_files, read_batch, results_file


@pytest.fixture
def no_override(isolated_dirs, monkeypatch):
    """No VMDEPLOY_LOG_DIR, and a standard folder inside the test's own folder."""
    monkeypatch.delenv("VMDEPLOY_LOG_DIR")
    default = isolated_dirs / "standard-logs"
    monkeypatch.setattr(paths, "default_log_dir", lambda: default)
    monkeypatch.setenv("COLUMNS", "250")
    return default


def _logs(*args):
    return CliRunner().invoke(app, ["logs", *args])


def _batch(folder, stamp, deployed=2, total=2, dc="DC1"):
    vms = [{"name": f"vm-{i}", "status": "deployed" if i < deployed else "failed"} for i in range(total)]
    f = folder / f"batch-{stamp}.json"
    f.write_text(json.dumps({"batch": True, "started": f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]}T"
                                                      f"{stamp[9:11]}:{stamp[11:13]}:{stamp[13:]}",
                             "datacenter": dc, "image": "ubuntu.ova", "vms": vms,
                             "totals": {"deployed": deployed, "failed": total - deployed}}), encoding="utf-8")
    return f


def test_the_chosen_folder_is_kept_and_default_goes_back(no_override, isolated_dirs):
    chosen = isolated_dirs / "synced" / "vmdeploy-logs"
    r = _logs("--folder", str(chosen))
    assert r.exit_code == 0, r.output
    assert chosen.is_dir() and not list(chosen.glob(".vmdeploy-write-test*"))
    assert paths.log_dir() == chosen and paths.log_dir_source() == "setting"
    assert "set it once on each computer" in r.output

    r = _logs("--folder", "default")
    assert r.exit_code == 0, r.output
    assert paths.log_dir() == no_override and paths.log_dir_source() == "default"


def test_the_write_check_never_opens_a_file_already_in_the_folder(no_override, isolated_dirs):
    """Found in the security review: the check wrote to .vmdeploy-write-test and deleted it, so a file of that name
    already in a shared folder was emptied and removed. It now creates a file of its own, and says to keep the
    folder to yourself (a results file in it decides what a retry deploys and what destroy --batch deletes)."""
    chosen = isolated_dirs / "shared" / "logs"
    chosen.mkdir(parents=True)
    (chosen / ".vmdeploy-write-test").write_text("keep me", encoding="utf-8")
    r = _logs("--folder", str(chosen))
    assert r.exit_code == 0, r.output
    assert [f.name for f in chosen.iterdir()] == [".vmdeploy-write-test"]  # its own check file is gone
    assert (chosen / ".vmdeploy-write-test").read_text(encoding="utf-8") == "keep me"
    assert "only you can write to" in r.output


def test_the_write_check_never_writes_through_a_link(no_override, isolated_dirs):
    """The same with a link of that name: the file it points to was emptied."""
    chosen = isolated_dirs / "shared" / "logs"
    chosen.mkdir(parents=True)
    precious = isolated_dirs / "precious.txt"
    precious.write_text("precious", encoding="utf-8")
    try:
        (chosen / ".vmdeploy-write-test").symlink_to(precious)
    except OSError:
        pytest.skip("this system does not let the test create a symbolic link")
    assert _logs("--folder", str(chosen)).exit_code == 0
    assert precious.read_text(encoding="utf-8") == "precious"


def test_an_unreachable_folder_falls_back_and_says_so(no_override, isolated_dirs):
    missing = isolated_dirs / "offline-share" / "logs"
    paths.write_settings({"log_folder": str(missing)})
    assert paths.log_dir() == no_override
    assert "not available" in paths.log_dir_problem() and str(missing) in paths.log_dir_problem()
    assert not missing.parent.exists()  # a missing drive or share is never created locally
    r = CliRunner().invoke(app, ["logs"])
    assert "not available" in r.output


def test_a_deleted_chosen_folder_is_created_again(no_override, isolated_dirs):
    chosen = isolated_dirs / "share" / "logs"
    chosen.parent.mkdir()
    paths.write_settings({"log_folder": str(chosen)})
    assert paths.log_dir() == chosen and chosen.is_dir()
    assert paths.log_dir_problem() is None


def test_environment_variable_comes_first(isolated_dirs, monkeypatch):
    paths.write_settings({"log_folder": str(isolated_dirs / "chosen")})
    assert paths.log_dir() == isolated_dirs / "logs" and paths.log_dir_source() == "env"
    r = _logs("--folder", str(isolated_dirs / "chosen"))
    assert "VMDEPLOY_LOG_DIR is set" in r.output


def test_a_folder_inside_a_git_repository_is_warned_about(no_override, isolated_dirs):
    repo = isolated_dirs / "project"
    (repo / ".git").mkdir(parents=True)
    r = _logs("--folder", str(repo / "logs"))
    assert r.exit_code == 0
    assert "inside a Git repository" in r.output and ".gitignore" in r.output


def test_an_unwritable_folder_is_refused(no_override, isolated_dirs):
    blocker = isolated_dirs / "a-file"
    blocker.write_text("x")
    r = _logs("--folder", str(blocker / "logs"))
    assert r.exit_code == 2 and "Cannot use" in r.output
    assert paths.log_dir_source() == "default"


def test_logging_falls_back_when_the_folder_cannot_be_written(no_override, isolated_dirs, monkeypatch):
    chosen = isolated_dirs / "read-only"
    chosen.mkdir()
    paths.write_settings({"log_folder": str(chosen)})
    real = logging.FileHandler
    calls = []

    def handler(path, *a, **k):
        calls.append(path)
        if len(calls) == 1:
            raise PermissionError(13, "Access is denied")
        return real(path, *a, **k)

    monkeypatch.setattr(logging, "FileHandler", handler)
    log_file = logsetup.setup_logging(0)
    try:
        assert log_file.parent == no_override
        assert "Cannot write to the log folder" in paths.log_dir_problem()
    finally:
        for h in logging.getLogger().handlers:
            h.close()
        logging.getLogger().handlers.clear()


def test_latest_and_bare_names_find_results_files(no_override, isolated_dirs, monkeypatch):
    with pytest.raises(ConfigError, match="no batch results files"):
        results_file(paths.Path("latest"))
    folder = paths.log_dir()
    older = _batch(folder, "20261120-090000")
    newer = _batch(folder, "20261121-082532")
    assert batch_files() == [newer, older]
    assert results_file(paths.Path("latest")) == newer
    assert results_file(paths.Path("LATEST")) == newer
    assert results_file(paths.Path(older.name)) == older  # the name `vmdeploy logs` shows
    monkeypatch.chdir(isolated_dirs)
    elsewhere = isolated_dirs / "copy.json"
    elsewhere.write_text("{}")
    assert results_file(paths.Path("copy.json")) == paths.Path("copy.json")  # the current folder first
    assert results_file(paths.Path("nope.json")) == paths.Path("nope.json")  # left for the reader's error


def test_latest_is_resolved_before_signing_in(no_override, monkeypatch):
    from vsphere_vm_deployment import cli

    monkeypatch.setattr(cli, "_connect", lambda *a, **k: pytest.fail("must not sign in"))
    r = CliRunner().invoke(app, ["destroy", "--batch", "latest", "--yes"])
    assert r.exit_code == 2 and "no batch results files" in r.output


def test_latest_says_which_file_it_picked(no_override, capsys):
    f = _batch(paths.log_dir(), "20261121-082532")
    assert _results_files([paths.Path("latest")]) == [f]
    assert "Newest results file" in capsys.readouterr().err  # the console writes to stderr
    assert _results_files([f]) == [f]
    assert "Newest results file" not in capsys.readouterr().err


def test_logs_lists_batches_newest_first(no_override):
    folder = paths.log_dir()
    _batch(folder, "20261120-090000", deployed=1, total=3)
    _batch(folder, "20261121-082532")
    (folder / "batch-20261119-070000.json").write_text("not json", encoding="utf-8")
    (folder / "vmdeploy-20261121-082530.log").write_text("x" * 3000, encoding="utf-8")
    r = _logs()
    assert r.exit_code == 0, r.output
    out = r.output
    assert "the standard folder" in out
    assert out.index("batch-20261121-082532.json") < out.index("batch-20261120-090000.json")
    assert "1 of 3" in out and "2 of 2" in out and "cannot be read" in out
    assert "vmdeploy-20261121-082530.log" in out and "3 KB" in out
    assert "--retry-failed latest" in out and "vmdeploy logs --folder PATH" in out
    assert read_batch(folder / "batch-20261119-070000.json").readable is False


def test_a_missing_results_file_is_refused_before_signing_in(no_override, monkeypatch):
    """A mistyped file name was only reported after the sign-in (and its password prompt)."""
    from vsphere_vm_deployment import cli

    monkeypatch.setattr(cli, "_connect", lambda *a, **k: pytest.fail("must not sign in"))
    r = CliRunner().invoke(app, ["destroy", "--batch", "batch-2026112-101500.json", "--yes"])
    assert r.exit_code == 2 and "No results file batch-2026112-101500.json" in r.output


def test_the_listing_shows_an_images_file_name_not_its_path(no_override):
    """Found in real testing: an ISO batch's full local path made the table too wide to read."""
    f = _batch(paths.log_dir(), "20261122-101500")
    doc = json.loads(f.read_text(encoding="utf-8"))
    doc["image"] = r"C:\Users\someone\Lab Images\ubuntu-24.04.4-live-server-amd64.iso"
    f.write_text(json.dumps(doc), encoding="utf-8")
    out = _logs().output
    assert "ubuntu-24.04.4-live-server-amd64.iso" in out and "Lab Images" not in out
