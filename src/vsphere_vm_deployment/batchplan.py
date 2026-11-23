"""Batch deployment, the parts that need no vCenter: name and hostname patterns, address lists, spreading VMs over
targets, adding up datastore space, the parallel limits, and the result of a batch.

Kept apart from batch.py (which talks to vCenter and draws the screen) so every rule here is unit-tested directly.
See docs/design/batch-deployment.md.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from .errors import ConfigError

# {n} the VM's number in the batch, {i} its number on its host, {host} the host's short name, {datastore} the
# datastore, {name} the VM's name (hostnames and OVF properties), {address} and {hostname} (OVF properties).
# {n:02} pads a number to two digits.
_TOKEN = re.compile(r"\{([a-z]+)(?::(0?\d{1,2}))?\}")
NAME_KEYS = frozenset({"n", "i", "host", "datastore"})
HOSTNAME_KEYS = NAME_KEYS | {"name"}
OVF_KEYS = HOSTNAME_KEYS | {"address", "hostname"}
NUMBER_KEYS = frozenset({"n", "i"})

# VM results. "problem": the VM was fully built, then a later step (e.g. the snapshot) failed; the VM is kept.
DEPLOYED, PROBLEM, FAILED, SKIPPED, NOT_STARTED = "deployed", "problem", "failed", "skipped", "not-started"
RETRYABLE = frozenset({FAILED, SKIPPED, NOT_STARTED})
PARTLY_EXIT_CODE = 4  # some VMs deployed, some not (docs/design/batch-deployment.md, section 9)


def has_placeholder(value: str | None) -> bool:
    return bool(value) and any(m.group(1) in OVF_KEYS for m in _TOKEN.finditer(value))


def check_pattern(pattern: str, field_name: str, *, hostname: bool = False) -> None:
    """A name or hostname pattern: only known placeholders, padding only on numbers, no stray braces."""
    allowed = HOSTNAME_KEYS if hostname else NAME_KEYS
    for m in _TOKEN.finditer(pattern):
        key, pad = m.group(1), m.group(2)
        if key not in allowed:
            raise ConfigError(f"{field_name}: unknown placeholder {{{key}}} in '{pattern}'.",
                              hint="Use " + ", ".join(f"{{{k}}}" for k in sorted(allowed)) + ".")
        if pad and key not in NUMBER_KEYS:
            raise ConfigError(f"{field_name}: only {{n}} and {{i}} can be padded (e.g. {{n:02}}), not {{{key}}}.")
    if "{" in _TOKEN.sub("", pattern) or "}" in _TOKEN.sub("", pattern):
        raise ConfigError(f"{field_name}: unmatched brace in '{pattern}'.",
                          hint="Placeholders look like {n}, {n:02} or {host}.")


def expand(pattern: str, values: dict[str, object], keys: frozenset[str] = OVF_KEYS) -> str:
    """Fill in the known placeholders; any other text (including other braces, e.g. JSON in an OVF property) is left
    exactly as it is."""
    def one(m: re.Match) -> str:
        key, pad = m.group(1), m.group(2)
        if key not in keys or key not in values:
            return m.group(0)
        value = values[key]
        if pad and key in NUMBER_KEYS:
            return str(value).zfill(int(pad))
        return str(value)

    return _TOKEN.sub(one, pattern)


def short_host(name: str) -> str:
    """'esx-a.example.test' -> 'esx-a'; an address such as 192.0.2.10 -> '192-0-2-10' (dots would read as a
    domain, and an address cut at its first dot means nothing)."""
    try:
        ipaddress.ip_address(name)
        return name.replace(".", "-").replace(":", "-")
    except ValueError:
        return name.split(".", 1)[0]


def safe_vm_name(text: str) -> str:
    return re.sub(r"[/\\%]", "-", text)[:80]


def hostname_label(text: str) -> str:
    """A single DNS label: other characters become '-', at most 63 characters, no leading or trailing '-'."""
    return re.sub(r"[^A-Za-z0-9-]", "-", text)[:63].strip("-")


# ------------------------------------------------------------------------------------------------ addresses
def parse_range(range_text: str, what: str = "batch.addresses.range") -> tuple[ipaddress.IPv4Address,
                                                                              ipaddress.IPv4Address]:
    """A range's first and last address: '192.0.2.50-192.0.2.69', or '192.0.2.50-69' (spaces are ignored)."""
    first_text, sep, last_text = range_text.replace(" ", "").partition("-")
    if not sep:
        raise ConfigError(f"{what} '{range_text}' is not a range.",
                          hint="Write it as 192.0.2.50-192.0.2.69 (or 192.0.2.50-69).")
    try:
        first = ipaddress.IPv4Address(first_text)
        last = ipaddress.IPv4Address(last_text) if "." in last_text else \
            ipaddress.IPv4Address(".".join(first_text.split(".")[:3] + [last_text]))
    except ValueError as e:
        raise ConfigError(f"{what} '{range_text}': {e}") from None
    if int(last) < int(first):
        raise ConfigError(f"{what} '{range_text}' ends before it starts.")
    return first, last


def address_list(mode: str, *, range_text: str | None, listed: Sequence[str], prefix: int | None,
                 gateway: str | None, count: int, what: str = "batch.addresses") -> list[str]:
    """One CIDR address per VM, in VM order (an empty list for DHCP). The range or list must hold enough addresses
    for every VM; extra ones are unused. Raises ConfigError with the field to fix (`what` names it in messages).
    A batch hands a range out as a pool instead (pool_addresses): this is for lists."""
    from .netcheck import address_error, gateway_error

    if mode != "static":
        return []
    out: list[str] = []
    if range_text:
        first, last = parse_range(range_text)
        if prefix is None:
            raise ConfigError("batch.addresses.prefix is needed with a range (e.g. 24).")
        size = int(last) - int(first) + 1
        if size < count:
            raise ConfigError(f"batch.addresses has {size} address(es) for {count} VMs.",
                              hint="Give a longer range or list, or fewer VMs.")
        # Only as many as there are VMs: a range typed as 192.0.2.1-198.51.100.1 holds millions.
        out = [f"{ipaddress.IPv4Address(x)}/{prefix}" for x in range(int(first), int(first) + count)]
    else:
        for entry in listed:
            entry = entry.strip()
            if "/" not in entry:
                if prefix is None:
                    raise ConfigError(f"batch.addresses.list: '{entry}' has no prefix length.",
                                      hint="Write it as 192.0.2.50/24, or set batch.addresses.prefix.")
                entry = f"{entry}/{prefix}"
            out.append(entry)
    for a in out:
        if problem := address_error(a):
            raise ConfigError(f"{what}: {a}: {problem}")
    plain = [a.split("/")[0] for a in out]
    if len(set(plain)) != len(plain):
        dup = sorted({a for a in plain if plain.count(a) > 1})
        raise ConfigError(f"{what}: {', '.join(dup)} given more than once.")
    if len(out) < count:
        raise ConfigError(f"{what} has {len(out)} address(es) for {count} VMs.",
                          hint="Give a longer range or list, or fewer VMs.")
    if gateway:
        for a in out[:count]:
            if problem := gateway_error(gateway, a):
                raise ConfigError(f"batch.addresses.gateway: {problem} (for {a})")
    return out[:count]


# A range is a pool: each VM gets the next address that is free, so one already in use does not cost a VM (a list
# keeps its order instead, one address per VM: its addresses are often planned per VM, e.g. in DNS).
def _never_given(ip: ipaddress.IPv4Address, net: ipaddress.IPv4Network | None, reserved: set[str]) -> str | None:
    """Why an address of a range is never given to a VM, or None: the subnet's network or broadcast address, the
    gateway or a DNS server."""
    if net is not None and net.prefixlen <= 30 and ip in (net.network_address, net.broadcast_address):
        return f"the subnet's {'network' if ip == net.network_address else 'broadcast'} address"
    if str(ip) in reserved:
        return "the gateway or a DNS server"
    return None


def range_problem(range_text: str, count: int, *, prefix: int | None = None, gateway: str | None = None,
                  dns: Sequence[str] = (), what: str = "batch.addresses.range") -> str | None:
    """Why a range cannot be the pool for `count` VMs, or None. The addresses in use are only known when the VMs
    get theirs (they are skipped then), so this checks the range itself: it parses, holds `count` addresses a VM can
    have, and, once the prefix is known, lies in one subnet, with the gateway in it."""
    from .netcheck import address_error, gateway_error

    try:
        first, last = parse_range(range_text, what)
    except ConfigError as e:
        return e.message
    if problem := address_error(f"{first}/32") or address_error(f"{last}/32"):
        return f"{what} '{range_text}': {problem}"
    net = None
    if prefix is not None:
        net = ipaddress.IPv4Interface(f"{first}/{prefix}").network
        if last not in net:
            return f"{what} '{range_text}' is not in one subnet: with /{prefix}, {first} is in {net} but {last} is not."
        # checked against a host address of the subnet that is not the gateway itself (often its first one, .1)
        hosts = [net.network_address + 1, net.network_address + 2] if net.prefixlen <= 30 else [first, last]
        host = next((h for h in hosts if str(h) != (gateway or "").strip()), hosts[0])
        if gateway and (problem := gateway_error(gateway, f"{host}/{prefix}")):
            return f"batch.addresses.gateway: {problem}"
    reserved = {x for x in (gateway, *dns) if x}
    usable = 0
    for x in range(int(first), int(last) + 1):  # stops at `count`: a range may be a whole /16
        if _never_given(ipaddress.IPv4Address(x), net, reserved) is None:
            usable += 1
            if usable >= count:
                return None
    return f"{what} '{range_text}' has {usable} address(es) a VM can have, for {count} VMs."


def pool_addresses(range_text: str, prefix: int, *, vms: Sequence[tuple[object, set[str], str | None]],
                   in_use: dict[str, str], reserved: set[str]) -> tuple[dict[object, str | None], list[str]]:
    """Give each VM a free address of the range, in VM order. An address in use is skipped, unless it is one the VM
    this one replaces has (it is deleted first: `own`), and so are the subnet's network and broadcast addresses, the
    gateway and the DNS servers (`reserved`). A VM keeps the address it was planned with (`prefer`: a retry's, from
    the results file) while that is still free.

    `vms`: (key, own addresses, preferred address) in VM order; `in_use`: {address: what uses it}. Returns ({key:
    'address/prefix', or None when the range has run out}, ["address (why it was skipped)", ...])."""
    first, last = parse_range(range_text)
    net = ipaddress.IPv4Interface(f"{first}/{prefix}").network
    lo, hi = int(first), int(last)
    taken: set[int] = set()
    out: dict[object, int | None] = {}

    def why_not(x: int, own: set[str]) -> str | None:
        ip = ipaddress.IPv4Address(x)
        if x in taken:
            return "given to another VM of this batch"
        if why := _never_given(ip, net, reserved):
            return why
        return f"used by {in_use[str(ip)]}" if str(ip) in in_use and str(ip) not in own else None

    def number(text: str | None) -> int | None:
        try:
            return int(ipaddress.IPv4Address((text or "").split("/")[0]))
        except ValueError:
            return None

    for key, own, prefer in vms:  # 1. a retry's VMs keep their planned addresses
        x = number(prefer)
        if x is not None and lo <= x <= hi and why_not(x, own) is None:
            out[key] = x
            taken.add(x)
    for key, own, _prefer in vms:  # 2. a VM that replaces another keeps that one's address
        if key not in out:
            x = next((x for x in sorted(filter(None, map(number, own))) if lo <= x <= hi and why_not(x, own) is None),
                     None)
            if x is not None:
                out[key] = x
                taken.add(x)
    skipped: dict[int, str] = {}
    cursor = lo
    for key, own, _prefer in vms:  # 3. the others: the next free address
        if key in out:
            continue
        while cursor <= hi and (why := why_not(cursor, own)) is not None:
            if cursor not in taken:
                skipped.setdefault(cursor, why)
            cursor += 1
        out[key] = cursor if cursor <= hi else None
        if cursor <= hi:
            taken.add(cursor)
            cursor += 1
    return ({k: f"{ipaddress.IPv4Address(x)}/{prefix}" if x is not None else None for k, x in out.items()},
            [f"{ipaddress.IPv4Address(x)} ({why})" for x, why in sorted(skipped.items())])


# ------------------------------------------------------------------------------------------------ distribution
@dataclass
class Spot:
    """Where VMs can go, for spreading them: one host, or a DRS cluster / resource pool (`free_mb` adds up its
    hosts). `count` is the target's own count (per_host only)."""
    key: str
    free_mb: float
    count: int | None = None


def distribute(spots: Sequence[Spot], mode: str, count: int | None, vm_mb: int) -> list[tuple[int, int]]:
    """(spot index, the VM's number on that spot) for every VM, in batch order: spot by spot.

    per_host: each spot gets its own count, or `count`, or 1. total: `count` VMs in total, each going to the spot
    with the most free memory once the VMs already given to it are counted (ties: fewer VMs, then list order)."""
    if not spots:
        raise ConfigError("The batch has no targets.", hint="Choose at least one host, cluster or resource pool.")
    per_spot = [0] * len(spots)
    if mode == "total":
        if not count:
            raise ConfigError("batch.count is needed with distribution: total (the number of VMs in all).")
        if any(s.count for s in spots):
            raise ConfigError("batch.targets[].count only works with distribution: per_host.",
                              hint="With distribution: total, batch.count is the number of VMs in all.")
        for _ in range(count):
            best = max(range(len(spots)), key=lambda k: (spots[k].free_mb - per_spot[k] * vm_mb, -per_spot[k], -k))
            per_spot[best] += 1
    else:
        per_spot = [s.count or count or 1 for s in spots]
    return [(k, i) for k, n in enumerate(per_spot) for i in range(1, n + 1)]


# ------------------------------------------------------------------------------------------------ space
@dataclass
class SpaceUse:
    """One VM's use of its datastore: what it takes right away, and what it can grow to (thin disks)."""
    key: object  # the VM (slot)
    datastore: str
    initial: int
    full: int


def fit_datastores(uses: Sequence[SpaceUse], free: dict[str, int],
                   describe: Callable[[int], str]) -> tuple[dict[object, str], dict[str, str]]:
    """Add up the batch's VMs per datastore, in batch order. Returns ({VM: why it does not fit}, {datastore: a
    warning when the thin disks could outgrow it}). VMs that fit keep the space; one that does not is refused and
    takes none, so a smaller VM after it may still fit."""
    refused: dict[object, str] = {}
    warnings: dict[str, str] = {}
    taken: dict[str, int] = {}
    grow: dict[str, int] = {}
    for u in uses:
        have = free.get(u.datastore, 0)
        used = taken.get(u.datastore, 0)
        if used + u.initial > have:
            before = f"; the batch's VMs before this one take {describe(used)} of it" if used else ""
            refused[u.key] = (f"datastore {u.datastore} has {describe(have)} free{before}, and this VM needs "
                              f"{describe(u.initial)}")
            continue
        taken[u.datastore] = used + u.initial
        grow[u.datastore] = grow.get(u.datastore, 0) + u.full
    for ds, total in grow.items():
        if total > free.get(ds, 0):
            warnings[ds] = (f"if their thin disks fill up, the batch's VMs on {ds} can use {describe(total)} but it "
                            f"has {describe(free.get(ds, 0))} free (overcommitted storage)")
    return refused, warnings


# ------------------------------------------------------------------------------------------------ parallel limits
VCENTER_HOST_BUDGET = 8  # vCenter's concurrent provisioning cost per host (vSphere 8 documentation)


def check_parallel(vms: int, uploads: int, per_host: int, *, hosts: int, is_vcenter: bool) -> tuple[list[str], list[str]]:
    """(errors, warnings) for the parallel settings (docs/design/batch-deployment.md, section 7)."""
    errors: list[str] = []
    warnings: list[str] = []
    if per_host > VCENTER_HOST_BUDGET and is_vcenter:
        errors.append(f"batch.parallel.per_host is {per_host}: vCenter runs at most {VCENTER_HOST_BUDGET} deployments "
                      "on a host at once and queues the rest, and a queued import can time out waiting. Use "
                      f"{VCENTER_HOST_BUDGET} or less.")
    elif per_host > 2:
        warnings.append(f"{per_host} VMs at once on one host: more than 2 rarely finishes sooner (the host's disks "
                        "and network are shared), and other people's work on that host has to wait.")
    if uploads > 2:
        warnings.append(f"{uploads} uploads at once share this computer's network connection: each is slower, and "
                        "the batch rarely finishes sooner.")
    if vms > max(2, 2 * hosts):
        warnings.append(f"{vms} VMs at once for {hosts} host(s): the extra ones only wait for their host's limit.")
    return errors, warnings


# ------------------------------------------------------------------------------------------------ results
def exit_code(statuses: Sequence[str]) -> int:
    """0: every VM deployed; 4: some deployed and some not (or deployed with a problem); 1: none deployed."""
    if statuses and all(s == DEPLOYED for s in statuses):
        return 0
    if any(s in (DEPLOYED, PROBLEM) for s in statuses):
        return PARTLY_EXIT_CODE
    return 1


@dataclass
class HostTally:
    deployed: int = 0
    failed: int = 0
    skipped: int = 0
    not_started: int = 0
    problems: list[str] = field(default_factory=list)


def tally_by_host(rows: Sequence[dict]) -> dict[str, HostTally]:
    """Per host (or cluster, for DRS placement): how many VMs deployed, failed, were skipped or not started, and
    each problem as "vm: what happened"."""
    out: dict[str, HostTally] = {}
    for r in rows:
        t = out.setdefault(r.get("host") or "?", HostTally())
        status = r.get("status")
        if status == DEPLOYED:
            t.deployed += 1
        elif status == PROBLEM:
            t.deployed += 1
            t.problems.append(f"{r['name']}: deployed, but {r.get('error') or 'a later step failed'}")
        elif status == FAILED:
            t.failed += 1
            t.problems.append(f"{r['name']}: {r.get('error') or 'failed'}")
        elif status == SKIPPED:
            t.skipped += 1
            t.problems.append(f"{r['name']}: skipped, {r.get('error') or 'its checks failed'}")
        else:
            t.not_started += 1
            t.problems.append(f"{r['name']}: not started")
    return out


def retry_names(doc: dict) -> set[str]:
    """From a batch results file: the VMs to deploy again (failed, skipped or not started), by the name their
    pattern gives (`pattern_name`): name_conflict: next-free may have named web-01 web-01-2, and the retry matches
    its VMs before name clashes are resolved again."""
    if not isinstance(doc, dict) or not isinstance(doc.get("vms"), list):
        raise ConfigError("That file is not a vmdeploy batch results file (no list of VMs).")
    return {v.get("pattern_name") or v["name"] for v in doc["vms"]
            if isinstance(v, dict) and v.get("status") in RETRYABLE and v.get("name")}
