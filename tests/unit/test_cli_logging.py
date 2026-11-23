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


def test_the_profile_option_works_before_the_command_too(isolated_dirs):
    """Found in real testing: `vmdeploy -p NAME doctor` failed with "No such option: -p" while -v must go there."""
    for args in (["-p", "no-such-profile", "doctor", "--yes"], ["doctor", "--yes", "-p", "no-such-profile"]):
        r = CliRunner().invoke(app, args)
        assert "No such option" not in r.output and "No profile named 'no-such-profile'" in r.output
