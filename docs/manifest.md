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

post_deploy:
  power_on: true
  wait_for_ip: true               # wait for VMware Tools to report an IPv4 address
  wait_timeout_s: 300             # seconds to wait for an IP address (raise it for slow DHCP)
  snapshot: false                 # "clean-baseline" snapshot after first boot
```

## Notes

- **Passwords in interactive runs** are typed twice and turned into a SHA-512 crypt hash on your machine;
  only the hash is sent.
- **Admin user privileges**: a user with only an SSH key gets passwordless `sudo` (there is no password to
  type). A user with a password must type it for `sudo`.
- **How cloud-init data reaches the VM**: images that declare `user-data` as an OVF property (Ubuntu cloud
  OVAs) receive it that way. Other cloud-init images receive it through `guestinfo.*` keys, which cloud-init
  then clears after reading.
- **Static IPs on Ubuntu OVAs** are written as a netplan file at first boot and applied. Verify this on your
  first deployment and report any problems.
- **Several network adapters**: `guest.network` configures **NIC 1** only. With a static address and more than
  one adapter, the settings are tied to NIC 1's MAC address before the first boot, so no other adapter gets the
  same address or a second default route. Configure the other adapters inside the guest.
- **How `networks:` entries are matched to an OVA's networks**: an entry with `ovf_network` is used for exactly
  that network; the remaining entries fill the image's other networks in order. Each entry is used once. An
  entry for a network the image does not have, or more entries than the image has networks, is an error. For
  ISO installs each entry is one network adapter.
