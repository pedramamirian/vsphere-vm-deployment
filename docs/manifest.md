# Manifest reference

A manifest is an optional YAML file passed with `vmdeploy deploy -f <file>`. **Every key is optional.** What a
manifest leaves out is taken from the image (OVA/OVF descriptor) or asked interactively. With `--yes`,
missing answers stop the run with the name of the key to set. Unknown keys are rejected.

Command-line image flags (`--local`, `--url`, `--preset`, `--datastore-file`, `--sha256`) override `image:`.

```yaml
profile: lab                      # connection profile (default: your default profile)

vm:
  name: web01                     # 1-80 characters, no / \ %
  notes: Free text added to the VM's Notes (the tool adds its own marker and image details below it)

image:                            # choose one source
  local: ubuntu.ova               # file in ./images, or a full path
  # url: https://example.com/appliance.ova
  # preset: ubuntu-lts            # see `vmdeploy images list`
  # datastore: "[datastore1] iso/ubuntu-24.04-live-server-amd64.iso"   # ISO or OVA on a datastore
  #                               #   (`datastore_iso:` is still accepted)
  sha256: <64 hex characters>     # optional expected SHA-256 (local, url, or a datastore file: read once to check)
  reuse_datastore_copy: true      # ISO: a local or downloaded ISO already on a datastore is offered for use there
                                  #   when its sampled contents match (its full SHA-256 is checked first).
                                  #   Unset: asked (with --yes: used). true: also a copy whose contents could not
                                  #   be sampled (still checked in full). false: always upload
  fallback_via_pc: true           # ISO: if vCenter cannot copy a datastore ISO host to host, read it through this
                                  #   computer and upload it instead. Unset: asked (yes with --yes)

placement:
  datacenter: Lab                 # needed when there are several (also when datastore names repeat across them)
  cluster: Lab-Cluster            # or a standalone host via `host:`
  host: esx02.example.com         # omit in a DRS cluster to let DRS choose
  resource_pool: Servers          # under the cluster / host
  folder: /Servers                # VM folder path, "/" = top level
  datastore: nvme-ds01

resources:
  cpu: 4
  cores_per_socket: 2             # default: from the image, else 1
  memory_gb: 8                    # decimals allowed (0.5)
  disk_gb: 60                     # primary disk; OVA disks can only grow
  disk_provisioning: thin         # thin | thick | eager-zeroed  (vSAN uses the default storage policy)
  extra_disks:                    # up to 14; on the VM's SCSI or NVMe controller
    - {size_gb: 200, provisioning: thin}   # provisioning: default = the VM's (disk_provisioning above)

hardware:                         # guest_os/firmware/secure_boot/vtpm: ISO deployments; hardware_version: all
  guest_os: ubuntu64Guest         # vSphere guest ID; omit to pick from the host's list
  firmware: efi                   # efi | bios
  secure_boot: false
  vtpm: true                      # virtual TPM 2.0 (needs efi and a key provider; Windows 11 always gets one,
                                  #   false only if Windows Setup's TPM check is bypassed: docs/windows.md)
  nested_virtualization: false    # expose hardware-assisted virtualisation (EVE-NG, GNS3, nested ESXi, Proxmox);
                                  #   omit: asked for ISO installs, suggested from the file name
  iommu: false                    # expose IOMMU (UEFI only); omit: on when the vendor asks for it (EVE-NG)
  hardware_version: default       # VM compatibility: keep | default | newest | vmx-21
                                  #   keep    = the version the OVA/OVF asks for
                                  #   default = your administrator's cluster/datacenter policy, else the host's default
                                  #   newest  = the newest the host supports
                                  # unset: asked; the suggestion is the policy if set, otherwise an upgrade for
                                  # presets and ISO installs and "keep" for vendor appliances. Never below the image.

networks:                         # one entry per NIC / per network inside the OVA
  - portgroup: VLAN20-Servers     # standard portgroup, distributed portgroup or NSX segment
    ovf_network: VM Network       # which OVA network this entry is for (default: the next one in order)
    adapter: vmxnet3              # vmxnet3 | e1000e | e1000 (ISO deployments); checked when the file is read

ovf:
  deployment_option: small        # sizes offered by the image, if any
  properties:                     # appliance settings (keys are shown in an interactive run)
    vami.ip0.MyAppliance: 198.51.100.20
  accept_eula: false              # only used with --yes; interactive runs always show the licence

guest:                            # first boot via cloud-init (images that support it)
  enabled: true                   # false = skip; default = ask / on when the keys below are set
  hostname: web01
  username: alex
  password_hash: "$6$..."         # SHA-512 crypt hash, e.g. `mkpasswd -m sha-512`; never a plain password
  ssh_authorized_keys: ["ssh-ed25519 AAAA… alex@workstation"]
  timezone: Etc/UTC
  ntp_servers: [time.cloudflare.com]
  network:                        # applies to the first network adapter (NIC 1)
    mode: static                  # dhcp | static
    address: 192.0.2.50/24
    gateway: 192.0.2.1
    dns: [192.0.2.1]
    search: [example.com]
  dhcp_identifier: mac            # with DHCP: mac (default) | image. See "DHCP and the guest's identity" below

post_deploy:
  power_on: true
  wait_for_ip: true               # wait for VMware Tools to report an IPv4 address
  wait_timeout_s: 300             # seconds to wait for an IP address (raise it for slow DHCP)
  snapshot: false                 # "clean-baseline" snapshot after first boot
```

## Batch (several VMs at once)

A `batch:` section turns the manifest into a batch (`vmdeploy deploy -f FILE`; `--batch` is implied). Everything
outside `batch:` is shared by every VM; `batch:` says where the VMs go and what differs between them. With
`batch:`, leave out `vm.name`, `placement.host`, `placement.cluster`, `placement.datastore`, `guest.hostname` and
`guest.network`: the batch sets them (the manifest is refused otherwise). `placement.datacenter`, `folder` and
`resource_pool` stay shared settings. [examples/batch.yaml](../examples/batch.yaml) is a complete example.

```yaml
batch:
  name: "web-{n:02}"              # VM names (required, or `names:`). Placeholders: {n} the VM's number in the batch,
                                  #   {i} its number on its host, {host} the host's name up to the first dot
                                  #   (a host named by its address: 192-0-2-11), {datastore}; {n:02} pads to
                                  #   01, 02, ... Names must be unique in the VM folder (see below)
  # names: [web-a, web-b]         # or one name per VM, in batch order
  start: 1                        # the first {n}
  name_conflict: skip             # a name that already exists: skip (that VM is listed with the folder and host
                                  #   of the existing one) | next-free (the next unused number) | replace (only
                                  #   VMs this tool deployed; same as --replace)
  hostname: "{name}"              # cloud-init hostname: a pattern ({name} = the VM's name, plus the placeholders
                                  #   above), a fixed name, or `skip` (left to the image). Default: {name}
  distribution: per_host          # per_host: `count` VMs on each target | total: `count` VMs in all, each going
                                  #   to the target with the most free memory
  count: 1                        # VMs per target (per_host, default 1) or in total (total, required)
  targets:                        # one selector per entry; each may add datastore, count and ovf
    - host: esx-01.example.test
      datastore: local-01         # a name, or `auto` (the usable one with the most free space). Required when
                                  #   the host has several and you run with --yes
      count: 2                    # this target's own count (per_host only)
    - cluster: Lab-Cluster        # every host of the cluster...
    - cluster: DRS-Cluster
      drs: true                   # ...or DRS places each VM (DRS must be on)
    - folder: /Lab/Hosts          # every host in a host folder
    - hosts_matching: "esx-1*"    # every host whose name matches (case-insensitive)
    - resource_pool: Compute-ResourcePool   # where hosts are hidden (hosted VMware clouds): DRS places the VMs
      ovf:
        properties: {dns_domain: example.test}   # per-target OVF property values (override `ovf.properties`)
  addresses:                      # guest IPv4 addresses (cloud-init, or OVF properties that use {address})
    mode: static                  # dhcp (the guest identifies itself by its MAC address; see guest.dhcp_identifier)
                                  #   | static
    range: 192.0.2.50-192.0.2.69  # or 192.0.2.50-69: a pool, handed out in VM order; addresses in use, the gateway
                                  #   and the DNS servers are skipped (see below)
    # list: [192.0.2.50, 192.0.2.61/24]    # or exactly one address per VM, in VM order (one in use fails its VM)
    prefix: 24
    gateway: 192.0.2.1
    dns: [192.0.2.53]
    search: [example.test]
  parallel:
    vms: 4                        # VMs built at the same time (--parallel)
    uploads: 2                    # uploads from this computer at the same time (--parallel-uploads)
    per_host: 2                   # VMs built on one host at the same time (--per-host); at most 8 on vCenter
  on_check_failure: skip          # --yes: VMs that fail their checks are skipped | cancel: nothing is deployed
  on_failure: continue            # continue | stop (--stop-on-failure): start no new VMs after a failure
  keep_failed: false              # true (--keep-failed): keep a VM that failed half-way, for troubleshooting
```

- **Names are unique per VM folder, not per host.** Every VM of a batch goes into `placement.folder` (with a
  restricted deploy account, the account's own folder), so `{i}` alone would give the VMs on different hosts the
  same name: use `{n}`, or `{host}` with `{i}` (`web-{host}-{i:02}`). A pattern that gives two VMs the same name
  is refused before the review. Renaming VMs after the deployment is fine: `vmdeploy list` and `destroy`
  recognise them by a marker in their Notes, not by name. The guest's hostname and the VM's file names on the
  datastore keep the original name.
- **A `range` is a pool.** Each VM gets the next address that is free: one already in use (a running VM's, as its
  VMware Tools report it, or a host's own) is skipped, as are the gateway, the DNS servers and the subnet's network
  and broadcast addresses, and the review lists what was skipped. A VM is only skipped when the range runs out, so
  give it a few spare addresses. A retry keeps each VM's planned address while it is free, and a VM that replaces
  another keeps that one's. vCenter does not see powered-off VMs, VMs without VMware Tools or other devices: leave
  their addresses out of the range. A retry also skips the addresses its earlier runs gave to VMs that are still
  there (deployed, kept or not deleted), even powered off: they are in the results files. A `list` is exact instead: one address per VM, in order (for addresses planned
  per VM, e.g. in DNS); an address in use there fails its VM's check.
- **OVF properties** (in `ovf.properties` or a target's `ovf`) may use `{name}`, `{hostname}`, `{address}` (the
  VM's address without its prefix) and the placeholders above, e.g. `vami.ip0.MyAppliance: "{address}"`. Each
  VM's values are checked once they are filled in.
- **Guest settings** (`guest:`) are shared by every VM. Set `guest: {enabled: false}` to just create the VMs.
- **The results file** (`batch-<date>-<time>.json`, next to the log files) lists every VM with its result, step
  and reason. `--retry-failed FILE` with the same manifest deploys only the VMs it lists as failed, skipped or not
  started, with the same names and addresses.

## Notes

- **Passwords in interactive runs** are typed twice and turned into a SHA-512 crypt hash on your machine;
  only the hash is sent.
- **Admin user privileges**: a user with only an SSH key gets passwordless `sudo` (there is no password to
  type). A user with a password must type it for `sudo`.
- **How cloud-init data reaches the VM**: images that declare `user-data` as an OVF property (Ubuntu cloud
  OVAs) receive it that way. Other cloud-init images receive it through `guestinfo.*` keys, which cloud-init
  then clears after reading.
- **DHCP and the guest's identity** (`guest.dhcp_identifier`). A DHCP server recognises a client by the identifier
  it sends, not only by its MAC address. Ubuntu's default identifier is derived from the machine, not the MAC, so
  a DHCP reservation made for the VM's MAC address does not match it, and a freshly deployed Ubuntu VM can ask
  twice during its first boot under two identities and take two addresses (the first stays reserved until its
  lease expires: 8 days by default on Windows Server DHCP). With `mac` (the default), the guest identifies itself
  by NIC 1's MAC address from its first request (on a real vCenter with Ubuntu 26.04, this stopped the second
  address: no VM changed address, against four or six of six without it). vmdeploy sets this before the first boot: in guestinfo, or, for
  images customised through OVF properties (Ubuntu's cloud OVA), through a `network-config` OVF property it adds
  to the VM. `image` keeps the image's own behaviour and writes no network settings for DHCP. Static addresses
  are not affected. In large batches on DHCP, reservations by MAC address or static addresses from a range
  (`batch.addresses`) keep every VM's address predictable.
- **Static IPs on Ubuntu OVAs** are written as a netplan file at first boot and applied. Verify this on your
  first deployment and report any problems.
- **Several network adapters**: `guest.network` configures **NIC 1** only. With a static address and more than
  one adapter, the settings are tied to NIC 1's MAC address before the first boot, so no other adapter gets the
  same address or a second default route. Configure the other adapters inside the guest.
- **How `networks:` entries are matched to an OVA's networks**: an entry with `ovf_network` is used for exactly
  that network; the remaining entries fill the image's other networks in order. Each entry is used once. An
  entry for a network the image does not have, or more entries than the image has networks, is an error. For
  ISO installs each entry is one network adapter.
