"""Waiting on vCenter/ESXi tasks while reporting their percentage to the step view."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from types import SimpleNamespace

from pyVmomi import vim, vmodl

from .connection import license_fault_to_error
from .errors import DeploymentError

log = logging.getLogger(__name__)
_FIELDS = ("info.state", "info.progress", "info.error", "info.result")


def _task_info(task):
    """task.info, or only the fields we need when the full TaskInfo cannot be read (some servers, e.g. vcsim,
    report a non-inventory object such as the FileManager as the task's entity, which pyVmomi rejects)."""
    try:
        return task.info
    except TypeError as e:
        log.debug("Reading the whole TaskInfo failed (%s); reading state/progress/error/result only", e)
    pc = vim.ServiceInstance("ServiceInstance", task._stub).RetrieveContent().propertyCollector  # noqa: SLF001
    spec = vmodl.query.PropertyCollector.FilterSpec(
        objectSet=[vmodl.query.PropertyCollector.ObjectSpec(obj=task)],
        propSet=[vmodl.query.PropertyCollector.PropertySpec(type=vim.Task, pathSet=list(_FIELDS))])
    props = {}
    for obj in pc.RetrieveContents([spec]) or []:
        props.update({p.name: p.val for p in obj.propSet or []})
    return SimpleNamespace(state=props.get("info.state"), progress=props.get("info.progress"),
                           error=props.get("info.error"), result=props.get("info.result"))


def fault_message(err) -> str:
    """A fault's text. vCenter sometimes leaves `msg` as a placeholder ("RuntimeFault.summary") and puts the real
    explanation in faultMessage (e.g. "Key provider X is not compatible with the host Y. Reason: ...")."""
    msg = getattr(err, "msg", None) or ""
    details = [m.message for m in getattr(err, "faultMessage", None) or [] if getattr(m, "message", None)]
    if details and (not msg or msg.endswith(".summary")):
        return " ".join(details)
    return msg or (" ".join(details) if details else str(err))


def wait_task(task, *, on_progress: Callable[[float], None] | None = None, poll: float = 0.5,
              timeout: float | None = None, what: str = "task"):
    """Block until `task` finishes. Returns task.info.result. Raises DeploymentError on failure."""
    start = time.monotonic()
    while True:
        info = _task_info(task)
        if info.state == vim.TaskInfo.State.success:
            if on_progress:
                on_progress(1.0)
            return info.result
        if info.state == vim.TaskInfo.State.error:
            err = info.error
            mapped = license_fault_to_error(err)
            if mapped is not err:
                raise mapped
            msg = fault_message(err)
            log.debug("%s failed with %s: %r", what, type(err).__name__, err)  # full fault, for troubleshooting
            failure = DeploymentError(f"{what} failed: {msg}")
            failure.fault = err  # the vSphere fault itself, for callers that must tell faults apart by type
            raise failure
        if on_progress and info.progress is not None:
            on_progress(info.progress / 100)
        if timeout and time.monotonic() - start > timeout:
            raise DeploymentError(f"{what} did not finish within {int(timeout)} s.")
        time.sleep(poll)
