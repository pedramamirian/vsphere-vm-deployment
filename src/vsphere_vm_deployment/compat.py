"""VM compatibility (virtual hardware version): what the image asks for, what the host or cluster can run,
and what the administrator set as the "Default VM Compatibility" policy.

Why it matters: a VM can only run on, and be migrated to, hosts that support its version; newer versions
bring newer virtual hardware and security features (e.g. vTPM, newer Secure Boot support). Environments with
strict versioning set a default on the cluster or datacenter, and that default is what the tool proposes.
A VM is never set *below* the version its image needs (the image may depend on newer virtual hardware).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from .errors import ConfigError

log = logging.getLogger(__name__)

# Minimum ESXi release for each VM version (Broadcom KB 315655, "ESXi/ESX hosts and compatible VM versions").
ESXI_FOR_VERSION = {
    4: "ESX 3.x", 7: "ESXi 4.x", 8: "ESXi 5.0", 9: "ESXi 5.1", 10: "ESXi 5.5", 11: "ESXi 6.0", 13: "ESXi 6.5",
    14: "ESXi 6.7", 15: "ESXi 6.7 U2", 17: "ESXi 7.0", 18: "ESXi 7.0 U1", 19: "ESXi 7.0 U2", 20: "ESXi 8.0",
    21: "ESXi 8.0 U2", 22: "ESXi 9.0",
}
_VMX = re.compile(r"^vmx-(\d+)$")
KEYWORDS = ("keep", "default", "newest")


def number(key: str | None) -> int:
    m = _VMX.match(key or "")
    return int(m.group(1)) if m else 0


def describe(key: str | None) -> str:
    n = number(key)
    if not n:
        return "host default"
    esxi = ESXI_FOR_VERSION.get(n)
    return f"{esxi} and later (VM version {n})" if esxi else f"VM version {n}"


def highest(keys) -> str | None:
    keys = [k for k in keys if number(k)]
    return max(keys, key=number) if keys else None


@dataclass
class Compat:
    image: str | None  # what the OVA/OVF asks for (None for ISO installs)
    supported: list[str] = field(default_factory=list)  # versions the target can create, e.g. ["vmx-10", ...]
    host_default: str | None = None
    policy: str | None = None  # administrator's "Default VM Compatibility" on the cluster or datacenter
    policy_source: str = ""  # e.g. "cluster Lab-Cluster"

    @property
    def newest(self) -> str | None:
        return highest(self.supported)

    @property
    def default(self) -> str | None:
        """The administrator's policy if set, else the host's default."""
        return self.policy or self.host_default

    def allowed(self, key: str) -> bool:
        if self.supported and key not in self.supported:
            return False
        return number(key) >= number(self.image)  # never below what the image needs

    def options(self) -> list[tuple[str, str]]:
        """(label, version) choices, without duplicates or downgrades below the image's version."""
        out: list[tuple[str, str]] = []
        seen: set[str] = set()

        def add(label: str, key: str | None) -> None:
            if key and key not in seen and self.allowed(key):
                seen.add(key)
                out.append((label, key))

        add(f"Keep the image's: {describe(self.image)}", self.image)
        if self.policy:
            add(f"{describe(self.policy)}: the {self.policy_source} default set by your administrator", self.policy)
        add(f"{describe(self.host_default)}: the host's default", self.host_default)
        add(f"{describe(self.newest)}: the newest this host supports", self.newest)
        return out

    def recommended(self, *, prefer_upgrade: bool) -> str | None:
        """Policy first (strict environments); otherwise upgrade general-purpose images and keep vendor
        appliances at the version their vendor tested."""
        choices = [k for _, k in self.options()]
        if self.policy and self.policy in choices:
            return self.policy
        if not prefer_upgrade and self.image in choices:
            return self.image
        for key in (self.host_default, self.newest, self.image):
            if key in choices:
                return key
        return choices[0] if choices else None

    def resolve(self, value: str) -> str | None:
        """A manifest value (keep | default | newest | vmx-NN) to a concrete version."""
        v = value.strip().lower()
        if v == "keep":
            key = self.image or self.default
        elif v == "default":
            key = self.default
        elif v == "newest":
            key = self.newest
        elif _VMX.match(v):
            key = v
        else:
            raise ConfigError(f"hardware.hardware_version '{value}' is not valid.",
                              hint="Use keep, default, newest or a version such as vmx-21.")
        if key and not self.allowed(key):
            if number(key) < number(self.image):
                raise ConfigError(f"{describe(key)} is older than the image needs ({describe(self.image)}).",
                                  hint="A VM cannot be set below the version its image was built for.")
            raise ConfigError(f"{describe(key)} is not supported by the chosen host or cluster.",
                              hint=f"Supported: {', '.join(sorted(self.supported, key=number))}")
        return key

    def warnings(self, key: str | None) -> list[str]:
        out = []
        if self.policy and key and number(key) != number(self.policy):
            out.append(f"VM compatibility {describe(key)} differs from the {self.policy_source} default "
                       f"({describe(self.policy)}); it may not migrate to every host your administrator expects.")
        if self.image and self.supported and number(self.image) > number(self.newest):
            out.append(f"The image needs {describe(self.image)}, newer than this host supports "
                       f"({describe(self.newest)}).")
        return out


def discover(compute_resource, datacenter, *, host=None, image: str | None = None) -> Compat:
    """Read what the chosen cluster/host supports and any administrator policy. Read-only."""
    c = Compat(image=image)
    try:
        descs = compute_resource.environmentBrowser.QueryConfigOptionDescriptor() or []
        c.supported = sorted((d.key for d in descs if getattr(d, "createSupported", True) and number(d.key)),
                             key=number)
        c.host_default = next((d.key for d in descs if getattr(d, "defaultConfigOption", False)), None)
    except Exception as e:  # noqa: BLE001
        log.debug("QueryConfigOptionDescriptor failed: %s", e)
    for obj, kind, attr in ((compute_resource, "cluster", "configurationEx"), (datacenter, "datacenter", "configuration")):
        try:
            key = getattr(getattr(obj, attr), "defaultHardwareVersionKey", None)
        except Exception:  # noqa: BLE001
            key = None
        if number(key):
            is_cluster = type(obj).__name__.endswith("ClusterComputeResource")
            if kind == "datacenter" or is_cluster:
                c.policy, c.policy_source = key, f"{kind if kind == 'datacenter' else 'cluster'} {obj.name}"
                break
    return c
