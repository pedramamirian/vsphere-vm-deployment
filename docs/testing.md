# Testing

## Automated tests

```bash
pip install -e ".[dev]"
pytest -m "not vcsim"                         # unit tests, no network needed
VCSIM_BIN=/path/to/vcsim pytest               # everything, incl. end-to-end tests against vcsim
ruff check src tests                          # lint
```

On Windows (PowerShell), call the venv's Python directly so the execution policy does not matter:

```powershell
.venv\Scripts\python.exe -m pip install -e ".[dev]"
.venv\Scripts\python.exe -m pytest -m "not vcsim"
$env:VCSIM_BIN = "C:\tools\vcsim.exe"; .venv\Scripts\python.exe -m pytest
.venv\Scripts\ruff.exe check src tests
```

`vcsim` is VMware's open-source vCenter / ESXi API simulator from
[govmomi](https://github.com/vmware/govmomi/tree/main/vcsim). Download the `vcsim_<OS>_<arch>` archive of
govmomi v0.54.0 (the release the tests were written against, and the one CI uses) from the govmomi releases
page (`vcsim_Windows_x86_64.zip`, `vcsim_Darwin_arm64.tar.gz` / `vcsim_Darwin_x86_64.tar.gz`,
`vcsim_Linux_x86_64.tar.gz` / `vcsim_Linux_arm64.tar.gz`). On macOS, clear the download quarantine flag before
first use: `xattr -d com.apple.quarantine vcsim`. The end-to-end tests start it automatically, in vCenter mode
and in standalone ESXi mode, emulating API 8.0.3. They cover:

- certificate pinning, sign-in, discovery, `doctor`, `inventory`
- OVA import through an NFC lease, with real HTTP disk uploads and manifest verification
- resizing, adding disks, cloud-init via OVF properties, power-on, snapshots
- ISO upload to a datastore and VM creation with the ISO attached
- duplicate names, `--replace`, licence agreements, corrupted images, missing answers in `--yes` mode
- `list` and `destroy` (refusing to delete VMs the tool did not create)

**What the simulator cannot prove**: it does not boot guests (no cloud-init, no IP address), does not model
privileges or distributed-switch uplinks, and leaves some enum values empty (worked around in
`tests/vcsim_compat.py`, test code only). So testing against a real environment is still needed.

## Real-environment checklist

Run these against a real vCenter (and, if available, a licensed standalone ESXi host). Use `-v` and keep the
log files.

| # | Scenario | Expected |
|---|---|---|
| 1 | `vmdeploy profile add`, then `vmdeploy doctor` | Certificate prompt on first connect. Choose "Trust this vCenter's root CA". Doctor shows the server, datacenters and a privilege report. |
| 2 | `vmdeploy access setup` (vCenter, existing SSO test user), then `vmdeploy doctor -p <admin>-deployer` | Plan shown before any change; role, read role and permissions created; doctor as the deploy account shows no unknown privilege IDs and mentions the setup. |
| 3 | `vmdeploy deploy --preset ubuntu-lts` (fully interactive) | Download progress bar, SHA-256 matches Canonical's value, all questions inside the step view, review plan, upload bar, VM boots, IP reported, SSH with your key works, static IP applied if chosen. |
| 4 | Same with DRS "Let DRS choose" | VM lands on a host chosen by DRS. |
| 5 | OVA on a distributed portgroup | NIC connected to the right portgroup. Uplink portgroups are not offered. |
| 6 | `--local` vendor appliance OVA with a EULA and OVF properties | Licence shown and must be accepted. Properties prompted with defaults. Passwords masked. |
| 7 | `--pick-local` ISO | ISO upload bar, VM created with the ISO attached, installer visible in the console. |
| 8 | `--datastore-file "[ds] path.iso"` (and an OVA on a datastore) | ISO: no upload, VM boots it (copied host to host if needed). OVA: read once, manifest verified, deployed. |
| 9 | Interrupt (Ctrl-C) during the disk upload | Upload aborted, vCenter removes the partial VM (or you are asked), session logged out. |
| 10 | Deploy the same name twice | Second run asks for another name (interactive) or stops (`--yes`). `--replace` works on VMs the tool created. |
| 11 | Datastore too small for the requested disk | Warning in pre-flight and in the plan; the deployment is still allowed if you confirm. |
| 12 | `--yes` with `examples/unattended.yaml` and `VMDEPLOY_PASSWORD` | No prompts; `--json` output parses. |
| 13 | Standalone licensed ESXi host | Works end to end. ESXi Host Client link printed. |
| 14 | Free-licence ESXi host | Stops at sign-in with the licence explanation (exit code 3). |
| 15 | Federated sign-in (if available) | Token exchange succeeds; `doctor` shows the federated user. |
| 16 | `vmdeploy access remove` (vCenter) | Lists the permissions, roles and local profile, then removes them; no permission for the test user remains (vSphere Client → the user's permissions). Your own permissions are untouched. |
| 17 | `vmdeploy access setup` and `remove` on a standalone ESXi host | Local user created with a generated password (shown once or saved to the keychain only if chosen); `remove` deletes the user automatically if the host reports its description, otherwise asks. Record which. |
| 18 | Item 3 (deploy) using the `-deployer` profile | Deployment succeeds without administrator privileges. |
| 19 | Vendor OVA on a datastore with deployment sizes (e.g. Cisco ISE) | Read once through this computer, manifest verified; every size listed with its CPU and memory; the chosen size's sizing is pre-filled; deployed to another host's datastore. |
| 20 | Non-Windows ISO on another host's local datastore (e.g. EVE-NG) | Guest type suggested from the name; nested virtualisation suggested; ISO copied host to host (or reused). |
| 21 | Ubuntu ISO from a URL, a local file and a datastore | Same reuse and host-to-host copy as Windows ISOs. |

vcsim limitations found while writing the access tests (not bugs in vmdeploy): it returns `0` from
`AddAuthorizationRole`, does not report permission entities, does not drop a deleted role's permissions,
and returns the user name instead of the description for local ESXi users. Items 16 and 17 check the real
behaviour.

## Results

Tested against vCenter Server 8.0.3 with ESXi 8.0.3 hosts (standalone hosts and a single-host cluster, local
VMFS datastores, standard portgroups), and directly against an ESXi 8.0.3 host. Client: Windows, Python 3.15,
mostly used as a first-time user who saves nothing (no keychain, session-only certificate trust); saving a
password in the OS keychain was tested separately. vSphere 9 is covered by the simulator only. Bugs found during
these runs were fixed and retested before release.

| # | Result | Summary |
|---|---|---|
| 1 | Pass | Certificate prompt (trust once, remember, or trust the vCenter root CA); `doctor` with server, datacenters and privilege report. `trust add --vcenter-ca` saves the CA only after it validates vCenter's certificate; a second run validates without a prompt. |
| 2 | Pass | `access setup` on vCenter: roles, scoped permissions, labelled folder, profile; rollback when a step fails. Refuses, before any change, a user that does not exist and an account that already has rights (directly, through a group or from higher up). |
| 3 | Pass | Interactive Ubuntu preset: download verified against Canonical's checksum, deploy, IP reported, SSH with the key. |
| 4, 5 | Simulator only | No DRS cluster or distributed switch was available; covered by the end-to-end simulator tests. |
| 6 | Pass | Cisco Catalyst 8000V (24 settings incl. on/off ones, 16 sizes; hostname and DHCP applied in the router), the VMware vCenter Server Appliance OVA (2 licence agreements, one about 94,000 characters; 18 sizes; 22 settings) and a test OVA with a licence (declined: nothing deployed; accepted: continues). |
| 7 | Pass | Local ISO uploaded; Ctrl+C during the upload removes the partial copy. The upload goes to a temporary name (`<name>.vmdeploy-upload-<id>.iso`) and is then moved to its own name. When a different file already had that name, the upload became `<name>-2.iso` and the other file was left untouched; the next deployment reused `<name>-2.iso` after a full SHA-256 check. |
| 8 | Pass | ISO on a datastore used in place, or copied host to host by vCenter; the next deployment reused that copy after a sampled comparison (no second copy). OVA on a datastore read once with its manifest verified, reused while unchanged ("unchanged since"), and read again after it was replaced on the datastore. |
| 9 | Pass | Ctrl+C during the disk upload: vCenter removes the partial VM, vmdeploy deletes the folder left behind (retrying while the host still holds the disk). |
| 10 | Pass | Existing name: another name offered interactively; `--replace` only for VMs the tool created. |
| 11 | Pass | Datastore too small: warned in pre-flight and the plan; vCenter's refusal reported, nothing left behind. |
| 12 | Pass | `--yes --json` with `VMDEPLOY_PASSWORD`: no prompts, JSON parses. |
| 13 | Pass | Directly to an ESXi host that a vCenter manages: size set at import, first-boot settings through guestinfo, ESXi Host Client link, orphaned-entry warning on `destroy`. |
| 14 | Out of scope | Free ESXi has a read-only API (README, requirements). |
| 15 | Not tested | No identity provider available; reports welcome. |
| 16 | Pass | `access remove` (vCenter): permissions, roles, folder and local profile removed; `access audit` confirms. With `--delete-vms --delete-iso`, the account's VMs, its emptied folder and the ISO copy they used were deleted too. With a mistyped `--role-name`, nothing was removed and the existing setup's folder was listed as not touched. A datastore folder created by hand with a `vmdeploy-` name was never deleted, only flagged by `access audit`. |
| 17 | Pass | `access setup` and `remove` on an ESXi host: local user created and deleted. |
| 18 | Pass | Deploy with the restricted account, including an Ubuntu cloud OVA with a static address on NIC 1 and SSH with the key (one network; NIC 1 among several networks is covered by unit tests), and a local ISO whose earlier copy on the VM's datastore was used after a full SHA-256 check. |
| 19 | Pass | Cisco ISE 3.4 OVA from a datastore: read through this computer, manifest verified, sizes listed, vendor rules applied. |
| 20 | Pass | EVE-NG ISO on another host's datastore: guest type and nested virtualisation suggested, copied host to host. |
| 21 | Pass | Ubuntu Server ISO from a URL with `--sha256`: verified, uploaded, booted. The reuse and copy paths are the same for every OS (items 8 and Windows 11). |

Also tested in a real environment: VM compatibility choice, the labelled account folder, "Change my answers",
static IP checks and conflict detection, `access audit` including the account reminder, ISO copy management
(`destroy` and `images prune`), Windows Server 2022 and Windows 11 (virtual TPM with a Native Key Provider on a
host in a cluster; stopped with an explanation on a host outside a cluster and on an ESXi host without vCenter),
and `keyprovider list`, `add`, `backup` (also where the vSphere Client's backup fails because vCenter is named by
its IP address) and `remove`. After the last code changes: a host name typed in other letters (the same profile
and saved certificate), a password saved in the OS keychain (used without asking, then removed with
`forget-secret`), the VM's Notes for a local image (its file name with "(local file)", no folder path, then
`image-sha256:`), the `access remove` plan listing the `vmdeploy` custom attribute before removing it with the
account's last folder, `access audit` not reporting an ISO copy a VM still uses, the log file recording what
`destroy` deleted (the VM, its ISO copy and the emptied `vmdeploy-iso` folder), and connecting by a host name the
certificate does not list (the prompt says so and offers no root CA; `trust add --vcenter-ca` stops before asking
anything).

### Still to re-test in a real environment

These changed after the runs above, or could not be run in the test environment. They pass the unit and
simulator tests; confirm them in a real environment and move each line into the table above.

| Area | How to check | Expected |
|---|---|---|
| Restricted account, several networks (item 18) | `access setup`, then deploy an Ubuntu cloud OVA with two networks and a static address | Deploys; the static address is bound to NIC 1 (the role includes `VApp.ApplicationConfig`). Tested with one network so far. |
| `keyprovider backup` | Back up to a folder you cannot write to, then to a normal folder | First: refused before anything is exported. Second: file saved; vCenter shows the provider as backed up. (The test environment had no key provider.) |
| ISO copy reuse with `--sha256` (items 8 and 20) | Deploy a datastore ISO to a host that cannot see it twice, with `--sha256` | The second run reuses the earlier copy after a full SHA-256 check. |
| "Could not be compared" | Deploy a local ISO while a file with the same name and size is on a datastore the account may not read | The log names the reason (e.g. `HTTP 403 Forbidden`); that file is not offered (only with `reuse_datastore_copy: true`). |
| "No" to an offered ISO copy | Answer No when a copy on another datastore is offered while an earlier upload is in `vmdeploy-iso/` | The question says the earlier upload is used if its full SHA-256 matches; it is, and nothing is uploaded. |
| VM name suggestion (item 10) | Deploy with a name that exists, and whose `-2` exists too | The name offered is `-3`. |
| Other files in `vmdeploy-iso/` | Put a file that is not an ISO in a `vmdeploy-iso` folder, then run `vmdeploy access audit` | Listed as another file, not as an ISO copy; an ISO copy a VM uses is not listed at all. |
| Other Windows versions | Deploy Windows 10, Server 2016, 2019 and 2025 from their ISOs | Same as Windows Server 2022 and Windows 11 (tested): Setup sees the NVMe disk and the e1000e network adapter. |
