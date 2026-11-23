"""Static IP checks: is what the user typed a sensible address, gateway and DNS list, and is the address
already in use by a VM or ESXi host that vCenter/ESXi can see?

Everything here is read-only. Conflicts are found from what VMware Tools reports for running VMs and from the
ESXi hosts' VMkernel addresses; physical devices and VMs without VMware Tools are invisible to it, which the
messages say.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

_DOTTED = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# ------------------------------------------------------------------------------------------ input checks
def _parse_ipv4(text: str, what: str) -> tuple[ipaddress.IPv4Address | None, str | None]:
    t = text.strip()
    if not _DOTTED.match(t):
        return None, f"{what} '{t}' is not an IPv4 address: use four numbers from 0 to 255 separated by dots, " \
                     "e.g. 192.0.2.10"
    parts = t.split(".")
    for part in parts:
        if int(part) > 255:
            return None, f"{what} '{t}': each number must be 0-255 ('{part}' is too big)"
    if any(len(part) > 1 and part.startswith("0") for part in parts):
        fixed = ".".join(str(int(x)) for x in parts)
        return None, f"{what} '{t}': numbers must not have leading zeros (did you mean {fixed}?)"
    return ipaddress.IPv4Address(t), None


def _special(ip: ipaddress.IPv4Address) -> str | None:
    for test, kind in ((ip.is_unspecified, "an unspecified (0.0.0.0)"), (ip.is_loopback, "a loopback"),
                       (ip.is_multicast, "a multicast"), (ip.is_link_local, "a link-local (169.254.x.x)"),
                       (ip.is_reserved, "a reserved")):
        if test:
            return kind
    return None


def address_error(text: str) -> str | None:
    """Problem with an 'address/prefix' entry, or None."""
    t = (text or "").strip()
    if "/" not in t:
        return f"Add the subnet prefix after a slash, e.g. {t or '192.0.2.10'}/24 (/24 = mask 255.255.255.0)"
    ip_text, _, prefix_text = t.partition("/")
    ip, err = _parse_ipv4(ip_text, "Address")
    if err:
        return err
    if _DOTTED.match(prefix_text.strip()):
        try:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{prefix_text.strip()}").prefixlen
            return f"Write the mask as a prefix: {ip}/{prefix} (instead of /{prefix_text.strip()})"
        except ValueError:
            return f"'{prefix_text}' is not a valid subnet mask"
    if not prefix_text.strip().isdigit() or not 1 <= int(prefix_text) <= 32:
        return "The prefix after the slash must be a number from 1 to 32 (e.g. /24 = mask 255.255.255.0)"
    kind = _special(ip)
    if kind:
        return f"{ip} is {kind} address and cannot be used for a VM"
    net = ipaddress.IPv4Interface(f"{ip}/{int(prefix_text)}").network
    if net.prefixlen <= 30:
        first, last = net.network_address + 1, net.broadcast_address - 1
        if ip == net.network_address:
            return f"{ip} is the network address of {net}; use an address from {first} to {last}"
        if ip == net.broadcast_address:
            return f"{ip} is the broadcast address of {net}; use an address from {first} to {last}"
    return None


def suggested_gateway(address: str) -> str | None:
    """The first usable address of the VM's subnet, the most common gateway (e.g. .1 in a /24)."""
    if address_error(address):
        return None
    iface = ipaddress.IPv4Interface(address.strip())
    if iface.network.prefixlen >= 31:
        return None
    first = iface.network.network_address + 1
    return str(first if first != iface.ip else first + 1)


def gateway_error(text: str, address: str) -> str | None:
    gw, err = _parse_ipv4(text, "Gateway")
    if err:
        return err
    if address_error(address):
        return None  # the address itself is reported first
    iface = ipaddress.IPv4Interface(address.strip())
    net = iface.network
    if gw not in net:
        hint = suggested_gateway(address)
        return (f"Gateway {gw} is not in the VM's subnet {net} (from {address.strip()}). It has to be inside it"
                + (f", e.g. {hint}." if hint else "."))
    if gw == iface.ip:
        return "The gateway cannot be the VM's own address"
    if net.prefixlen <= 30 and gw in (net.network_address, net.broadcast_address):
        return f"{gw} is the {'network' if gw == net.network_address else 'broadcast'} address of {net}"
    return None


def dns_error(servers: list[str]) -> str | None:
    for s in servers:
        ip, err = _parse_ipv4(s, "DNS server")
        if err:
            return err
        kind = _special(ip)
        if kind and not ip.is_loopback:
            return f"DNS server {ip} is {kind} address"
    return None


def describe(address: str) -> str:
    iface = ipaddress.IPv4Interface(address.strip())
    net = iface.network
    return f"{iface.ip} in {net} (mask {net.netmask})"


# ------------------------------------------------------------------------------------------ conflicts
@dataclass
class IpUse:
    ip: str
    prefix: int | None  # None if not reported
    owner: str  # "VM 'name'" or "ESXi host 'name' (vmk0)"
    network: str | None  # portgroup name, None if unknown
    host: str  # ESXi host the VM runs on / the host itself


def ip_uses(conn) -> list[IpUse]:
    """IPv4 addresses reported by running VMs (VMware Tools) and by ESXi hosts' VMkernel adapters."""
    from pyVmomi import vim

    from .inventory import collect, display

    hosts = {}
    uses: list[IpUse] = []
    for obj, props in collect(conn, vim.HostSystem, ["name", "config.network.vnic"]):
        name = props.get("name", "?")
        hosts[obj._moId] = name  # noqa: SLF001
        for vnic in props.get("config.network.vnic") or []:
            ip = getattr(getattr(vnic.spec, "ip", None), "ipAddress", None)
            if ip and ":" not in ip:
                mask = getattr(vnic.spec.ip, "subnetMask", None)
                prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen if mask else None
                uses.append(IpUse(ip, prefix, f"ESXi host '{name}' ({vnic.device})", vnic.portgroup or None, name))
    for _obj, props in collect(conn, vim.VirtualMachine, ["name", "guest.net", "runtime.host", "runtime.powerState"]):
        if props.get("runtime.powerState") != "poweredOn":
            continue
        host_ref = props.get("runtime.host")
        host = hosts.get(getattr(host_ref, "_moId", None), "?")
        for nic in props.get("guest.net") or []:
            configs = getattr(getattr(nic, "ipConfig", None), "ipAddress", None) or []
            seen = set()
            for c in configs:
                if c.ipAddress and ":" not in c.ipAddress:
                    seen.add(c.ipAddress)
                    uses.append(IpUse(c.ipAddress, c.prefixLength, f"VM '{display(props.get('name'))}'", nic.network, host))
            for ip in nic.ipAddress or []:
                if ":" not in ip and ip not in seen:
                    uses.append(IpUse(ip, None, f"VM '{display(props.get('name'))}'", nic.network, host))
    return uses


def find_conflicts(uses: list[IpUse], address: str, network: str, *, ignore_vm: str | None = None) \
        -> tuple[list[str], list[str]]:
    """(blockers, warnings) for putting `address` (CIDR) on portgroup `network`."""
    iface = ipaddress.IPv4Interface(address.strip())
    ip = str(iface.ip)
    blockers: list[str] = []
    warnings: list[str] = []
    subnets_here: set[ipaddress.IPv4Network] = set()
    for u in uses:
        if ignore_vm and u.owner == f"VM '{ignore_vm}'":
            continue
        if u.network == network and u.prefix and u.owner.startswith("VM"):
            subnets_here.add(ipaddress.IPv4Interface(f"{u.ip}/{u.prefix}").network)
        if u.ip != ip:
            continue
        where = f"on network {u.network}" if u.network else "on an unknown network"
        if u.network == network and u.owner.startswith("VM"):
            blockers.append(f"{ip} is already used by {u.owner} {where} (host {u.host}).")
        else:
            warnings.append(f"{ip} is also used by {u.owner} {where} (host {u.host}). That is a conflict if that "
                            f"network and {network} are the same subnet/VLAN.")
    if subnets_here and iface.network not in subnets_here and not any(iface.ip in n for n in subnets_here):
        shown = ", ".join(str(n) for n in sorted(subnets_here, key=lambda n: (int(n.network_address), n.prefixlen)))
        warnings.append(f"Other VMs on {network} use {shown}, but {address.strip()} is in {iface.network}. Check that "
                        "you picked the right network and address.")
    return blockers, warnings
