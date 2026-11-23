"""An expired vCenter/ESXi session (idle past the server's timeout, e.g. with the review left open) is renewed
before anything changes, or refused with a clear message; failures read as one line, not a fault dump."""

from types import SimpleNamespace

import pytest
from pyVmomi import vim

from vsphere_vm_deployment.batch import FAILED, SKIPPED, print_summary
from vsphere_vm_deployment.connection import ensure_session
from vsphere_vm_deployment.errors import AuthError


class FakeSessionManager:
    def __init__(self, alive: bool, password: str = "right"):
        self.alive, self.password, self.logins = alive, password, []

    @property
    def currentSession(self):  # noqa: N802 - the vSphere property name
        if not self.alive:
            raise vim.fault.NotAuthenticated(msg="The session is not authenticated.")
        return object()

    def Login(self, userName, password):  # noqa: N802, N803
        self.logins.append(userName)
        if password != self.password:
            raise vim.fault.InvalidLogin()
        self.alive = True


def _conn(sm, credentials=("svc@vsphere.local", "right")):
    return SimpleNamespace(content=SimpleNamespace(sessionManager=sm), rest_credentials=credentials,
                           profile=SimpleNamespace(endpoint="192.0.2.10:443"))


def test_a_live_session_is_left_alone():
    sm = FakeSessionManager(alive=True)
    assert ensure_session(_conn(sm)) is False and sm.logins == []


def test_an_expired_session_is_renewed_with_the_password_in_memory():
    sm = FakeSessionManager(alive=False)
    assert ensure_session(_conn(sm)) is True and sm.logins == ["svc@vsphere.local"]


def test_a_federated_sign_in_cannot_be_renewed_and_says_so():
    with pytest.raises(AuthError, match="federated sign-in cannot be renewed"):
        ensure_session(_conn(FakeSessionManager(alive=False), credentials=None))


def test_a_changed_password_is_reported():
    sm = FakeSessionManager(alive=False, password="changed")
    with pytest.raises(AuthError, match="signing in again as svc@vsphere.local failed"):
        ensure_session(_conn(sm))


def test_partial_vm_deleted_only_when_one_was_created(capsys, monkeypatch):
    monkeypatch.setenv("COLUMNS", "250")
    rows = [{"n": 1, "name": "a", "host": "h1", "status": FAILED, "step": "open its own session",
             "error": "The session is not authenticated.", "created": False},
            {"n": 2, "name": "b", "host": "h2", "status": FAILED, "step": "Upload disks", "error": "reset",
             "created": True},
            {"n": 3, "name": "c", "host": "h3", "status": SKIPPED, "step": "checks", "error": "in use"}]
    doc = {"vms": rows, "exit_code": 1,
           "totals": {"deployed": 0, "problem": 0, "failed": 2, "skipped": 1, "not-started": 0}}
    print_summary(doc, 1.0, None, None)
    out = capsys.readouterr().err
    assert out.count("partial VM deleted") == 1
    assert "dynamicType" not in out


class FakePrompter:
    """Answers password prompts from a list; Ctrl+C when the list runs out."""

    def __init__(self, answers, interactive=True):
        import contextlib

        self.answers, self.interactive, self.asked, self.recorded = list(answers), interactive, [], []
        self.section = lambda header: contextlib.nullcontext()

    def password(self, question, field_name=""):
        self.asked.append(question)
        if not self.answers:
            raise KeyboardInterrupt
        return self.answers.pop(0)

    def record(self, label, value):
        self.recorded.append((label, value))


def test_interactive_runs_ask_for_the_password_again_never_reuse_it():
    """Someone at a terminal left open must not be able to deploy: the password kept from the start is not used."""
    sm = FakeSessionManager(alive=False, password="typed-again")
    conn = _conn(sm, credentials=("svc@vsphere.local", "kept-from-start"))
    p = FakePrompter(["typed-again"])
    assert ensure_session(conn, p) is True
    assert p.asked == ["Password for svc@vsphere.local:"] and sm.logins == ["svc@vsphere.local"]
    assert conn.rest_credentials == ("svc@vsphere.local", "typed-again")


def test_a_wrong_password_can_be_retried_then_stops():
    sm = FakeSessionManager(alive=False, password="right")
    assert ensure_session(_conn(sm), FakePrompter(["wrong", "right"])) is True and len(sm.logins) == 2
    sm = FakeSessionManager(alive=False, password="right")
    with pytest.raises(AuthError, match="Nothing was changed"):
        ensure_session(_conn(sm), FakePrompter(["a", "b", "c"]))


def test_ctrl_c_at_the_password_prompt_signs_in_to_nothing():
    sm = FakeSessionManager(alive=False)
    with pytest.raises(KeyboardInterrupt):
        ensure_session(_conn(sm), FakePrompter([]))
    assert sm.logins == []


def test_yes_runs_sign_in_again_by_themselves():
    sm = FakeSessionManager(alive=False)
    p = FakePrompter([], interactive=False)
    assert ensure_session(_conn(sm), p) is True and p.asked == []
