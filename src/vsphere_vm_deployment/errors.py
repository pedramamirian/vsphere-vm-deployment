"""Exceptions that carry a user-facing explanation and, where possible, a hint on how to fix it."""

from __future__ import annotations


class VmDeployError(Exception):
    """Base error. `hint` is shown to the user under the message."""

    exit_code = 1

    def __init__(self, message: str, hint: str | None = None):
        super().__init__(message)
        self.message = message
        self.hint = hint


class UserAborted(VmDeployError):
    """The user declined a prompt (certificate, EULA, plan confirmation) or pressed Ctrl-C."""

    exit_code = 130


class MissingInput(VmDeployError):
    """A value is required but we are running non-interactively (--yes) and the manifest lacks it."""

    exit_code = 2


class ConfigError(VmDeployError):
    exit_code = 2


class TrustError(VmDeployError):
    """A TLS certificate could not be validated and was not trusted by the user."""


class AuthError(VmDeployError):
    pass


class LicenseRestricted(VmDeployError):
    """The target host runs the free vSphere Hypervisor license; the vSphere API is read-only."""

    exit_code = 3


class ImageError(VmDeployError):
    pass


class ChecksumMismatch(ImageError):
    pass


class PreflightError(VmDeployError):
    pass


class DeploymentError(VmDeployError):
    pass
