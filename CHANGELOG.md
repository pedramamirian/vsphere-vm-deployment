# Changelog

vsphere-vm-deployment is in active development (alpha). Each release below lists what changed; what is planned
next is in the README's [Known limitations and roadmap](README.md#known-limitations-and-roadmap).

## 0.2.0 (2026-11-22)

Deploying several VMs at once: one image to many hosts, clusters or resource pools in one run, with one review,
parallel builds, retries of the VMs that failed, and deleting a whole batch again.

### Deploying several VMs at once (batch)

- `vmdeploy deploy --batch` (or a manifest with a `batch:` section) deploys one image, with the same settings, to
  many targets in one run: hosts picked from a checklist, every host of a cluster, a DRS cluster, a host folder,
  hosts matching a name pattern, or a resource pool (for hosted VMware clouds, where hosts are hidden), each with
  its own datastore. The same number of VMs on every target, or a number in total spread by free memory.
- VM names, hostnames and OVF property values from patterns (`web-{n:02}`, `app-{host}-{i}`, `{address}`);
  addresses from a range (a pool: an address already in use is skipped, so it does not cost a VM) or a list (one
  per VM, in order), each answer checked as it is typed, or DHCP. Every per-VM setting can be left to the image.
- One review for the whole batch, after checks for every VM: free space added up per datastore across the batch,
  the network on each host (and the same VLAN on each), a VM compatibility every host supports, names that
  already exist (with the folder and host where they are), static addresses already in use, and privileges.
  The VMs that fail a check are listed with the reason; the others can be deployed. Nothing changes before the
  review is confirmed.
- VMs are built in parallel, each over its own session (cloned from the sign-in, so no password is passed
  around and the pinned certificate still applies), with limits for VMs at once, uploads at once and VMs per
  host (`--parallel`, `--parallel-uploads`, `--per-host`; at most 8 per host on vCenter). A VM that is built and
  only waits for its guest's address no longer counts, so the next VMs start meanwhile. VMs are started
  round-robin over the hosts, so every host is busy from the start. An ISO is placed once and copied by vCenter
  to the other datastores that need it.
- A failure stays with its VM: it is deleted (`--keep-failed` keeps it; one that cannot be deleted is reported
  as still there, and `destroy --batch` lists it), the others carry on, and
  `--stop-on-failure` starts no new VMs after one fails. Ctrl+C stops starting new VMs and asks whether to let
  the running ones finish.
- A summary per host and a list of every VM that did not deploy, with the step and the reason; a results file
  for `--retry-failed`, which deploys only the VMs that failed, were skipped or were not started. The commands
  the summary prints name the results file by its name (looked up in the log folder), so they paste as shown. Exit code 4
  means some VMs deployed and some did not.
- `vmdeploy destroy --batch RESULTS.json` deletes every VM a batch (and its retries) deployed: one sign-in, one
  list, one confirmation. VMs renamed since are still found, VMs already deleted are skipped, and only VMs
  vmdeploy deployed are deleted.
- `vmdeploy deploy --retry-failed latest` is the whole command: the manifest, image source, profile and batch
  options of the run it retries are in its results file (anything given again wins). A URL holding a password
  or token is never saved, whether given with `--url` or typed: it is asked again (with `--yes`, give `--url`).
  If that run's manifest is gone, `--yes` stops. A VM that `name_conflict: next-free` renamed is retried by the
  name its pattern gives.
- `--retry-failed` uses the answers of the run it retries (saved in its results file, never a password or a
  licence acceptance): only the password is asked, or nothing with `--yes`, and the review shows the VMs to
  retry. An answer that no longer fits (a host that is gone) is asked again. A different image (e.g. a newer
  `ubuntu-lts` build) is pointed out in the review, and refused with `--yes`. `destroy --batch` on a retry's
  results file also deletes the VMs of the run it retried.
- `latest` stands for the newest results file (`destroy --batch latest`, `--retry-failed latest`), and a
  results file's name alone is looked up in the log folder.
- Design: [docs/design/batch-deployment.md](docs/design/batch-deployment.md). Planned next: several vCenters or
  standalone hosts in one batch.

### Logs and results files

- `vmdeploy logs` shows the folder that holds logs and batch results files, and lists the recent batches (when,
  where, what image, how many VMs deployed) and log files.
- `vmdeploy logs --folder PATH` keeps them in another folder from now on, e.g. a synced or network folder that
  outlasts a logoff on a non-persistent virtual desktop and is reachable from other computers (`--folder default`
  goes back). It should be a folder only you can write to: a results file there decides what a retry deploys and
  what `destroy --batch` deletes. It warns when the folder is inside a Git repository. When the folder cannot be
  reached, a run says so and uses the standard folder; a batch's results file is saved there too rather than lost
  (also when the folder is set by `VMDEPLOY_LOG_DIR`), and never over another batch's file.

### Changed

- `access setup` grants several clusters or hosts (a checklist, or `--compute` repeated), so a restricted
  account can run batches across hosts; it allowed one.
- `access setup` warns when a chosen host would have none of the chosen datastores (or networks), so the account
  could not deploy there, and offers to choose again.
- Checklists say how to pick many at once (a selects all listed, i inverts). A list of more than 12 entries (large
  vCenters) first asks for a name pattern, e.g. `esx-east-*`, and lists only the matches, so select-all takes
  only what is listed.
- cloud-init: a VM can be deployed without a hostname, leaving the image's own.
- DHCP: the guest identifies itself to the DHCP server by NIC 1's MAC address from its first request
  (`guest.dhcp_identifier: mac`, the default; `image` keeps the image's behaviour). DHCP reservations by MAC
  address now match Ubuntu VMs, which by default send an identifier derived from the machine instead. For
  Ubuntu's cloud OVA this is set through a `network-config` OVF property added to the VM before its first boot.

### Fixed

- Yes/no questions take only a typed yes, y, no or n (then Enter); anything else, including Enter alone, asks
  again. They answered on the first y or n anywhere in stray typing, and Enter took the default.
- An ISO in a datastore's top folder was copied to other datastores as `vmdeploy-iso/[datastore] name.iso`; the
  copy is now `vmdeploy-iso/name.iso`. Batch VM names are suggested from the image's file name, not its path.

- A review left open longer than the server's idle timeout (30 minutes by default) no longer makes every VM fail
  with "The session is not authenticated": the session is checked when the review is confirmed. Interactive runs
  then ask for the password again (never the one kept from the start), so a terminal left open cannot deploy on
  its own; `--yes` runs, and a batch between its VMs, sign in again by themselves. Federated sign-ins are asked
  to run the command again. vSphere faults are shown as one line instead of pyVmomi's dump of the fault object,
  and a failed VM is only reported as "partial VM deleted" when one had been created.
- Batch: a VM being cleaned up after Ctrl+C or a failure shows "cleaning up" and what it waits for (vCenter
  removing the VM, the host releasing the disk) instead of "starting", and is counted apart until it is done.

- VM names with `/`, `\` or `%` are shown as typed (vCenter's API escapes them: `App/DB` was shown as
  `App%2fDB` when its address was in use), and match names typed for `destroy`, `--replace` and name checks.

- The step panel no longer draws over the last lines printed while it was paused (the end of a section's
  answers, or most of the review screen) when it comes back.

## 0.1.0 (2026-11-16)

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
