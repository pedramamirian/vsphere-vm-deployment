"""Test-only shim for the vcsim simulator.

vcsim (govmomi's vCenter simulator) returns an empty string for several enum properties that real
vCenter/ESXi always populate (e.g. VirtualMachine.runtime.faultToleranceState). pyVmomi 9 rejects the
empty value, so reading `vm.runtime` against vcsim raises AttributeError. During tests only, this shim
lets pyVmomi's SOAP deserializer map an empty enum value to the enum's first defined value.
Production code never imports this module.
"""

from __future__ import annotations

import builtins

from pyVmomi import SoapAdapter, VmomiSupport

_real_getattr = builtins.getattr


def _lenient_getattr(obj, name, *default):
    try:
        return _real_getattr(obj, name, *default)
    except AttributeError:
        if name == "" and isinstance(obj, type) and issubclass(obj, VmomiSupport.Enum):
            values = _real_getattr(obj, "values", None) or []
            if values:
                return _real_getattr(obj, values[0])
        raise


def install() -> None:
    # SoapAdapter looks up `getattr` in its module globals before builtins, so this only affects
    # pyVmomi's deserializer.
    SoapAdapter.getattr = _lenient_getattr
