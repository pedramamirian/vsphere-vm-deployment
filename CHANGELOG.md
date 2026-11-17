# Changelog

## 0.1.0

First public release.

### Deploying

- Interactive, step-by-step deployment to vCenter Server or a licensed standalone ESXi host (vSphere 8 and 9),
  in one live view with progress bars. Nothing changes in vSphere until you confirm the plan (Deploy now /
  Change my answers / Cancel); the one exception, setting up a key provider for Windows 11, has its own plan and
  confirmation. A failed or cancelled deployment removes the half-built VM (asking first when interactive), and
  sessions are always logged out.
- Images from this computer (`--local`, `--pick-local`: OVA, OVF or ISO), a download link (`--url`: OVA or
  ISO), Ubuntu Server presets (`--preset ubuntu-lts`, `ubuntu-24.04`, `ubuntu-22.04`) or a datastore
  (`--datastore-file`: OVA, OVF or ISO).
- Integrity checks: SHA-256 for downloads and local images (vendor-published or your own), every file of an
  OVA's manifest verified before upload, and the bytes sent checked again. A local or downloaded ISO that is
  already on a datastore is used from there only after its full SHA-256 matches; files in `vmdeploy-iso/` are
  never overwritten.
- ISOs on another host's local datastore are copied once host to host by vCenter (into `vmdeploy-iso/`) and
  reused by later deployments after a check: the full SHA-256 with `--sha256`, otherwise a comparison of
  samples with the original. OVAs and OVFs on a datastore are read once through this computer, because
  vSphere's import needs the client to send the disks.
- OVA/OVF: CPU, memory, disks, networks, deployment sizes (each listed with its CPU and memory), appliance
  settings and licence agreements are read from the image; you are only asked for what is missing.
- Placement: let DRS choose or pick a host; only datastores and networks the host can use are offered;
  over-commitment gives warnings, never a block. VM compatibility (virtual hardware version): keep the image's,
  follow your cluster or datacenter policy, or use the newest the host supports.
- First boot through cloud-init: hostname, user, SSH key and/or a password hashed on your computer, static IP
  or DHCP, DNS, time zone and NTP. A static address is checked as you type and against the running VMs and
  ESXi hosts vCenter can see.
- Windows 10, 11 and Server 2016 to 2025 from your licensed ISO: UEFI with Secure Boot, NVMe, e1000e and a
  virtual TPM for Windows 11, sized with VMware's recommendations and never below Microsoft's minimums.
  Windows 11 checks the key provider first and can set one up.
- Vendor guidance for EVE-NG 7 and Cisco ISE 3.3 to 3.5, and nested virtualisation for hypervisors and
  network labs ([docs/vendor-guidance.md](docs/vendor-guidance.md)).

### Managing

- `vmdeploy list` and `destroy` (only VMs vmdeploy deployed, unless `--force`), with optional clean-up of the
  ISO copies they used; `images list`, `pull`, `prune` and `clear-cache`.
- `vmdeploy access setup`, `remove` and `audit`: a least-privilege deploy account limited to the VM folder
  (on vCenter, a new folder of its own by default), compute, datastores and networks you choose, removed again
  in one step, and a read-only report of anything vmdeploy left in vCenter or ESXi
  ([docs/least-privilege.md](docs/least-privilege.md)). On a standalone ESXi host, which has no VM folders, the
  account can manage every VM on the host.
- `vmdeploy keyprovider list`, `add`, `backup`, `default` and `remove`: Native Key Providers for virtual TPMs,
  including a backup that works where the vSphere Client's fails because vCenter is named by its IP address.
- `vmdeploy doctor` and `inventory`: connection, licence, version and privilege checks, and a read-only view
  of datacenters, clusters, hosts, datastores and networks.

### Sign-in, certificates and secrets

- Password sign-in (vsphere.local and other SSO users, local ESXi users, Active Directory) and federated SSO
  through OAuth (ADFS, Entra ID, Okta, PingFederate) ([docs/authentication.md](docs/authentication.md)).
- Certificates: trust for one run, remember (pinned and checked on every connection), or trust vCenter's root
  CA. A changed certificate is flagged, and TLS validation is never switched off.
- Passwords and client secrets are kept in the OS keychain only if you choose, and only ever used for the
  server and account they were saved for. Every run writes a log file with secrets removed.

### Automation and platforms

- `--yes` with a YAML manifest for unattended runs ([docs/manifest.md](docs/manifest.md)), `--json` output and
  meaningful exit codes.
- Windows, macOS and Linux, Python 3.11 to 3.15.

Tested against vCenter Server 8.0.3 and ESXi 8.0.3, and end to end against VMware's `vcsim` simulator
(including the vSphere 9.0 API). [docs/testing.md](docs/testing.md) lists what was tested in a real
environment and what is still to be confirmed.
