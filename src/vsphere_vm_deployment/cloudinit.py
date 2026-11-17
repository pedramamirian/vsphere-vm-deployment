"""cloud-init first-boot configuration (hostname, login user, SSH keys, static IP, timezone, NTP).

Two delivery channels, chosen per image:

* OVF properties: Ubuntu cloud OVAs declare `user-data`, `hostname`, `instance-id` (and others) as OVF
  properties that cloud-init's OVF datasource reads. VMware's Ubuntu cloud image guide uses this route.
  When an image declares these properties the tool uses them, because cloud-init then prefers the OVF
  datasource and ignores guestinfo keys.
* guestinfo extraConfig keys (`guestinfo.userdata`, `guestinfo.metadata` + `.encoding`) for cloud-init's
  VMware datasource, for every other cloud-init capable image.

Passwords are never sent in clear text: a typed password is turned into a SHA-512 crypt hash locally and
only the hash goes into user-data. The user-data is removed from guestinfo after first boot (`redact`).
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import ipaddress
import secrets
import uuid

import yaml

from .manifest import GuestSpec

# ------------------------------------------------------------------------------------------- SHA-512 crypt
_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def sha512_crypt(password: str, salt: str | None = None, rounds: int = 5000) -> str:
    """SHA-512 based crypt ($6$), per Ulrich Drepper's 'Unix crypt using SHA-256 and SHA-512' spec.
    Implemented here because Python 3.13 removed the `crypt` module and Windows never had one."""
    pw = password.encode()
    salt = (salt or "".join(secrets.choice(_B64) for _ in range(16)))[:16]
    s = salt.encode()

    b = hashlib.sha512(pw + s + pw).digest()
    a = hashlib.sha512(pw + s)
    n = len(pw)
    while n > 64:
        a.update(b)
        n -= 64
    a.update(b[:n])
    n = len(pw)
    while n:
        a.update(b if n & 1 else pw)
        n >>= 1
    a_d = a.digest()

    dp = hashlib.sha512(pw * len(pw)).digest()
    p = (dp * (len(pw) // 64 + 1))[:len(pw)]
    ds = hashlib.sha512(s * (16 + a_d[0])).digest()
    sb = (ds * (len(s) // 64 + 1))[:len(s)]

    c = a_d
    for i in range(rounds):
        h = hashlib.sha512()
        h.update(p if i & 1 else c)
        if i % 3:
            h.update(sb)
        if i % 7:
            h.update(p)
        h.update(c if i & 1 else p)
        c = h.digest()

    order = [(0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26), (6, 27, 48),
             (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13),
             (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19), (62, 20, 41)]
    out = []
    for x, y, z in order:
        v = (c[x] << 16) | (c[y] << 8) | c[z]
        for _ in range(4):
            out.append(_B64[v & 0x3F])
            v >>= 6
    v = c[63]
    for _ in range(2):
        out.append(_B64[v & 0x3F])
        v >>= 6
    prefix = "$6$" if rounds == 5000 else f"$6$rounds={rounds}$"
    return f"{prefix}{salt}${''.join(out)}"


# ------------------------------------------------------------------------------------------- rendering
def _netplan(net, mac: str | None = None) -> dict:
    """netplan for the guest. Matched by `mac` (NIC 1's address) when given: with `en*`, netplan applies the
    settings to every adapter, so a VM with several NICs would get the same static address and default route on
    each. Without a MAC (one NIC, or DHCP) `en*` is right."""
    match = {"macaddress": mac.lower()} if mac else {"name": "en*"}
    eth: dict = {"match": match, "dhcp4": net.mode == "dhcp"}
    if net.mode == "static":
        eth["addresses"] = [str(ipaddress.ip_interface(net.address))]
        if net.gateway:
            eth["routes"] = [{"to": "default", "via": net.gateway}]
    ns = {}
    if net.dns:
        ns["addresses"] = net.dns
    if net.search:
        ns["search"] = net.search
    if ns:
        eth["nameservers"] = ns
    return {"version": 2, "ethernets": {"primary": eth}}


def render_user_data(guest: GuestSpec, hostname: str, *, network_in_userdata: bool, mac: str | None = None) -> str:
    """Build #cloud-config. `network_in_userdata` writes a netplan file at first boot (OVF datasource,
    which cannot carry network-config); otherwise network goes into guestinfo metadata."""
    cfg: dict = {"hostname": hostname, "preserve_hostname": False, "manage_etc_hosts": True}
    if guest.username:
        user: dict = {"name": guest.username, "groups": ["sudo"], "shell": "/bin/bash",
                      "lock_passwd": not bool(guest.password_hash)}
        # Least privilege: passwordless sudo only when there is no password to type (key-only login).
        user["sudo"] = "ALL=(ALL) ALL" if guest.password_hash else "ALL=(ALL) NOPASSWD:ALL"
        if guest.password_hash:
            user["passwd"] = guest.password_hash
        if guest.ssh_authorized_keys:
            user["ssh_authorized_keys"] = guest.ssh_authorized_keys
        cfg["users"] = ["default", user]
        cfg["ssh_pwauth"] = bool(guest.password_hash) and not guest.ssh_authorized_keys
    if guest.timezone:
        cfg["timezone"] = guest.timezone
    if guest.ntp_servers:
        cfg["ntp"] = {"enabled": True, "servers": guest.ntp_servers}
    if guest.network and network_in_userdata and guest.network.mode == "static":
        cfg["write_files"] = [
            {"path": "/etc/netplan/60-vmdeploy.yaml", "permissions": "0600",
             "content": yaml.safe_dump({"network": _netplan(guest.network, mac)}, sort_keys=False)},
            {"path": "/etc/cloud/cloud.cfg.d/99-vmdeploy-disable-network-config.cfg",
             "content": "network: {config: disabled}\n"},
        ]
        cfg["runcmd"] = [["rm", "-f", "/etc/netplan/50-cloud-init.yaml"], ["netplan", "apply"]]
    return "#cloud-config\n" + yaml.safe_dump(cfg, sort_keys=False, default_flow_style=False)


def render_metadata(hostname: str, guest: GuestSpec, mac: str | None = None) -> str:
    md: dict = {"instance-id": f"vmdeploy-{uuid.uuid4()}", "local-hostname": hostname,
                # Remove secrets from the VM's guestinfo once cloud-init has read them (cloud-init docs:
                # 'redact', formerly 'cleanup-guestinfo').
                "redact": ["userdata", "vendordata"]}
    if guest.network:
        md["network"] = _netplan(guest.network, mac)
    return yaml.safe_dump(md, sort_keys=False)


def gzip_b64(text: str) -> str:
    return base64.b64encode(gzip.compress(text.encode(), mtime=0)).decode()


def guestinfo_extra_config(user_data: str, metadata: str) -> dict[str, str]:
    return {
        "guestinfo.metadata": gzip_b64(metadata),
        "guestinfo.metadata.encoding": "gzip+base64",
        "guestinfo.userdata": gzip_b64(user_data),
        "guestinfo.userdata.encoding": "gzip+base64",
    }


def ovf_property_values(available_keys: set[str], user_data: str, hostname: str) -> dict[str, str]:
    """Values for Ubuntu-style OVF properties (user-data is base64 encoded to fit an XML attribute)."""
    want = {
        "user-data": base64.b64encode(user_data.encode()).decode(),
        "hostname": hostname,
        "instance-id": f"vmdeploy-{uuid.uuid4()}",
    }
    out = {}
    for full_key in available_keys:
        short = full_key.split(".")[-1] if full_key not in want else full_key
        if short in want:
            out[full_key] = want[short]
    return out
