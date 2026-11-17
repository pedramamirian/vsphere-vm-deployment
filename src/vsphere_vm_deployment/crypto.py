"""Can this VM get a virtual TPM? A vTPM needs a key provider in vCenter (the free Native Key Provider is
enough). Read-only.

Asking vCenter for its default key provider needs `Cryptographer.ManageKeyServers`, which a restricted deploy
account does not have; the host's encryption state (readable by anyone) is used as a fallback.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)

HOW_TO_ADD = ("Add one as an administrator with `vmdeploy keyprovider add` (adds a free Native Key Provider, makes "
              "it the default and backs it up), or in the vSphere Client: select the vCenter > Configure > Security "
              "> Key Providers > Add > Add Native Key Provider, then 'Back up' it (vCenter only uses it after a "
              "backup; if 'Back up' fails, `vmdeploy keyprovider backup`).")

# Broadcom documents both limits below; vmdeploy explains them and never works around them (README "Virtual TPM:
# where it works"). It does not create clusters or move hosts: that is the administrator's decision.
CLUSTER_RULE = ("vCenter only gives a Native Key Provider's keys to hosts in a vSphere cluster (Broadcom KB "
                "369538).")
CLUSTER_FIX = ("A single-host cluster with DRS and HA off is enough. Creating a cluster and moving a host into it "
               "is an administrator's decision; vmdeploy does not change your clusters. See docs/windows.md.")
NEEDS_CLUSTER = f"{CLUSTER_RULE} {CLUSTER_FIX}"
NO_VTPM_WITHOUT_VCENTER = ("Broadcom does not support a virtual TPM on an ESXi host without vCenter (KB 414781), "
                           "so vmdeploy does not offer one here. Deploy through vCenter, to a host in a cluster "
                           "(docs/windows.md).")


def no_vtpm_on_esxi(conn) -> str:
    """Why a host reached directly cannot give a VM a virtual TPM, and what to do instead."""
    vc = getattr(conn, "managed_by", None)
    if vc:
        return (f"This host is managed by vCenter {vc}, but you are connected to the host directly, and only vCenter "
                "can give a VM a virtual TPM. Use a profile for the vCenter instead (the host must be in a cluster "
                "there; docs/windows.md).")
    return NO_VTPM_WITHOUT_VCENTER


@dataclass
class KeyProvider:
    status: str  # "yes" | "no" | "unknown"
    detail: str
    provider: str | None = None  # the default key provider's name, when known
    tpm_required: bool = False  # "Use key provider only with TPM protected ESXi hosts"
    native: bool = False  # a Native Key Provider: only hosts in a cluster can use it

    @property
    def available(self) -> bool:
        return self.status == "yes"


def host_tpm(host) -> tuple[bool | None, str]:
    """(has a TPM 2.0, description) of an ESXi host. None: could not be read."""
    try:
        cap = host.capability
        if cap is None:
            return None, "unknown"
        version = str(getattr(cap, "tpmVersion", None) or "")
        if not getattr(cap, "tpmSupported", False) or not version.startswith("2"):
            return False, f"no TPM 2.0{f' (TPM {version})' if version else ''}"
        att = getattr(getattr(host.summary, "tpmAttestation", None), "status", None)
        return True, f"TPM {version}" + (f", attestation {att}" if att else "")
    except Exception as e:  # noqa: BLE001
        log.debug("TPM state of a host unavailable: %s", e)
        return None, "unknown"


def key_provider(conn, host=None) -> KeyProvider:
    if not conn.is_vcenter:
        return KeyProvider("no", "an ESXi host reached directly has no key provider (a virtual TPM needs vCenter)")
    cm = getattr(conn.content, "cryptoManager", None)
    if cm is not None and hasattr(cm, "GetDefaultKmsCluster"):
        try:
            default = cm.GetDefaultKmsCluster(entity=None, defaultsToParent=True)
            if default is not None:
                info = next((c for c in cm.ListKmsClusters() or [] if c.clusterId.id == default.id), None)
                if (info is not None and str(getattr(info, "managementType", "")) == "nativeProvider"
                        and getattr(info, "hasBackup", None) is False):
                    return KeyProvider("no", f"Native Key Provider '{default.id}' is not backed up yet, and vCenter "
                                             "only uses it after a backup: back it up in the vSphere Client, or "
                                             "run `vmdeploy keyprovider backup`")
                return KeyProvider("yes", f"default key provider '{default.id}'", default.id,
                                   bool(getattr(info, "tpmRequired", False)) if info is not None else False,
                                   info is not None and str(getattr(info, "managementType", "")) == "nativeProvider")
            providers = cm.ListKmsClusters() or []
            if providers:
                names = ", ".join(p.clusterId.id for p in providers)
                return KeyProvider("no", f"key provider(s) {names} exist, but none is set as the default")
            return KeyProvider("no", "no key provider is configured in vCenter")
        except Exception as e:  # noqa: BLE001 - typically NoPermission for a restricted account
            log.debug("key provider query failed: %s", e)
    state = None
    try:
        state = host.runtime.cryptoState if host is not None else None
    except Exception as e:  # noqa: BLE001
        log.debug("host crypto state unavailable: %s", e)
    if state == "safe":
        return KeyProvider("yes", "the host is ready for encryption (it has a key from a key provider)")
    return KeyProvider("unknown", "could not confirm a key provider (an administrator can: `vmdeploy doctor`)")
