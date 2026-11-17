"""A failed command leaves its error in the log file, not only on screen (found in real-environment testing:
a log attached to a bug report only showed the command line)."""

from typer.testing import CliRunner

from vsphere_vm_deployment.cli import app


def _log_text(isolated_dirs) -> str:
    logs = sorted((isolated_dirs / "logs").glob("vmdeploy-*.log"))
    return logs[-1].read_text(encoding="utf-8")


def test_error_is_written_to_the_log_file(isolated_dirs):
    r = CliRunner().invoke(app, ["doctor", "--yes", "-p", "no-such-profile"])
    assert r.exit_code != 0
    assert "No profile named 'no-such-profile'" in _log_text(isolated_dirs)


def test_error_is_not_shown_twice_with_verbose(isolated_dirs):
    r = CliRunner().invoke(app, ["-v", "doctor", "--yes", "-p", "no-such-profile"])
    assert r.output.count("No profile named") == 1
