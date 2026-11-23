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
- batches: several hosts, a DRS cluster and a standalone ESXi host as targets; name, hostname and address
  patterns; parallel builds over cloned sessions; an ISO placed once; a failure in one VM (the others deploy,
  exit code 4, `--retry-failed`); `--stop-on-failure` and `--keep-failed`; a name that already exists (listed
  with its folder and host); the parallel limits; the interactive questions (with scripted answers);
  `destroy --batch` with a batch and its retry (a renamed VM found by its id, a VM without the vmdeploy marker
  refused; `latest` for the newest results file)
- the DHCP client identifier: a `network-config` OVF property bound to NIC 1's MAC address, added before the
  first boot (and none with `dhcp_identifier: image`)

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
| 22 | `vmdeploy deploy --batch --preset ubuntu-lts` (interactive), one VM on each of several hosts, `vmdeploy-test-{n:02}` | Hosts from a checklist (hosts in maintenance mode greyed out with the reason); one review for all VMs; the table shows each VM's step and upload; every VM boots with its own hostname and address; summary per host. |
| 23 | Batch with several datastores on one host, and a port group that is missing on one host | Datastore asked once ("most free space" or per host); the VM on the host without the port group is listed in the review with the reason and skipped; the others deploy; exit code 4. |
| 24 | Batch with static addresses, one of them already in use | That VM is listed in the review with what holds the address, and skipped; the summary lists it again. |
| 25 | Batch with an ISO on one host's local datastore, VMs on several hosts | The ISO is copied once per datastore by vCenter (not uploaded again); every VM boots the installer. |
| 26 | Ctrl+C during a batch | No new VMs start; asked whether to let the running ones finish or stop and clean up; summary lists "not started". Then `--retry-failed` with the results file deploys the rest. |
| 27 | Batch through the `-deployer` profile (restricted account) | Deploys without administrator privileges (cloning the session for each VM needs no extra privilege). |
| 28 | `vmdeploy destroy --batch RESULTS.json` after a batch (rename one VM first) | One sign-in, one list (the renamed VM shown with its old name), one confirmation; every VM deleted; `access audit` finds nothing. |
| 29 | DHCP with the default `dhcp_identifier: mac` (Ubuntu preset), then a DHCP reservation for one VM's MAC address | The address reported does not change during the first boot (no second lease on the DHCP server); after a reboot the reserved VM gets its reserved address. |
| 30 | `vmdeploy logs --folder` to a synced or network folder, a batch, then `vmdeploy logs` and `destroy --batch latest` (and from a second computer with the same folder chosen) | The results file is written there and listed; `latest` names the file it took; the second computer finds and deletes the VMs. With the folder unreachable (share disconnected), a run warns and uses the standard folder. |
| 31 | Leave a batch's review open for more than 30 minutes (vCenter's default idle timeout), then deploy | Interactive: the password is asked again (nothing changed before it; Ctrl+C cancels), then every VM deploys. `--yes`: signs in again by itself. No `NotAuthenticated` failures. |
| 32 | A batch with one VM stopped or failed, then `--retry-failed latest` without a manifest, then `destroy --batch latest` | Every answer is taken from the first run ("as in the first run"), only the password is asked; the review lists only the VMs to retry, on the same hosts; `destroy --batch latest` lists the VMs of both runs. |
| 33 | After the code review fixes: `destroy --batch` with a mistyped file name; a batch on 2 hosts with "Choose for each host" (one datastore not the default), a hostname pattern and static addresses (Enter alone, too few, one in use), "Change my answers", Ctrl+C with "Let them finish"; `--retry-failed latest --parallel 4`; `vmdeploy logs`; `destroy --batch latest`; `access audit` | The mistyped file is refused before signing in; each address answer is explained and asked again; "Change my answers" pre-selects each host's own datastore; the retry replays every answer (each host's datastore, the hostname pattern, the addresses) and deploys the rest on their planned addresses; destroy takes both runs; audit clean. |
| 34 | A static range with more addresses than VMs that includes one in use; at the review, Cancel | The address in use is skipped and listed ("skipped … (used by VM …)"); every VM gets a free address and passes its checks. Nothing is deployed. |

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
| 22 | Pass | Ubuntu preset, three hosts with two VMs each (`vmdeploy-test-{host}-{i:02}`, a datastore per host), DHCP, hostnames left to the image: one review, at most two uploads at once, one session per VM (all logged out), summary per host, results file, exit code 0. Every VM's DHCP address changed once during the 30-second check (a fresh Ubuntu image asks for a second lease under another client ID), and the final address was reported. Hostnames from a pattern are still to be confirmed. A second run confirmed the fixes from the first: the review stays on screen, and the next VMs start while earlier ones wait for their addresses (the same six VMs in 2m 43s instead of 3m 28s). With first-boot settings off (nothing written to the guest), four of six VMs still changed address once: the second lease is the image's own behaviour. |
| 23 | Pass | Three hosts, one VM each, "choose for each host": asked only for the hosts with several datastores (a non-default one picked on the host with five). A port group on one host only: the two VMs on the other hosts were listed in the review with the reason, skipped, and listed again in the summary; the third deployed; exit code 4. Since then the network list marks a port group that is on only some of the chosen hosts, and a cloud image that gets no address is told to check DHCP (not the appliance note). |
| 24 | Pass | Three hosts, static range: the first address belonged to a running VM, so that VM was listed in the review with the VM and host that hold the address, skipped, and listed again in the summary. The holder's name, which contains `/`, was first shown as vCenter escapes it (`%2f`); fixed. Two earlier runs found more: a review left open past vCenter's idle timeout made every VM fail with `NotAuthenticated` (fixed: the session is renewed after the review, item 31), and the deploy was cancelled with Ctrl+C (item 26). |
| 25 | Pass | ISO found on one host's local datastore (in its top folder) and used where it was after a full SHA-256 check, nothing uploaded; vCenter copied it host to host to the two other hosts' datastores; three VMs created and powered on. Found: the copies were named `vmdeploy-iso/[datastore] name.iso` and the VM name suggestion was the local file's whole path (both fixed); a yes/no question was answered by stray typing (now only yes/y/no/n are accepted). |
| 26 | Pass | Ctrl+C during the uploads, then "Stop them and clean up": the uploads stopped within 2 s, vCenter removed both partial VMs and their folders were deleted once the hosts released the disks; nothing was left (the rows now say "cleaning up" and what they wait for). Ctrl+C with "Let them finish": the two running VMs finished, four were listed as not started (exit code 4), and `--retry-failed latest` deployed exactly those four. That retry asked every question again (now it reuses the first run's answers, item 32). |
| 27 | Pass | `access setup` for a vCenter SSO user with a new folder, three standalone hosts (it allowed only one host until then: now a checklist, and a host left without a chosen datastore or network is pointed out), their datastores and a network; `doctor` with the account listed exactly those places. A batch as that account: three VMs, one per host, DHCP with first-boot settings (including the `network-config` property), all deployed without administrator rights; `destroy --batch latest` as that account deleted them; `access remove` removed every permission (one per host), the roles, folder, attribute and profile; `access audit` clean. |
| 28 | Pass | `destroy --batch` with that run's results file: one sign-in, one list, one confirmation, six VMs deleted; `access audit` found nothing left. A second run with one VM renamed before the clean-up: listed as "(was …)", found by its id and deleted. |
| 29 | Pass (part) | Six Ubuntu VMs on DHCP with guest settings on (user, SSH key, hostnames `{name}`): the `network-config` property was set on each before its first boot, and **no VM changed address** (four and six of six had, in the runs without it); the address came about 25 s sooner. Hostnames from a pattern are configured the same way as for one VM. Still to try: a DHCP reservation for a VM's MAC address. |
| 30 | Pass (part) | `destroy --batch latest` named the file it took and found its VM already deleted ("Nothing to delete"); `access audit` clean. `logs --folder` to a synced folder outside the repository: no Git warning, the note that older files stay behind; after copying them over, `vmdeploy logs` listed the four batches (with how many VMs each deployed) and the log files. Still to try: a batch written there, a second computer, and an unreachable folder. |
| 31 | Pass | Batch reviews left open past vCenter's idle timeout (about 32 minutes), then deployed. First version: the session was renewed silently and both VMs deployed with static addresses (the third skipped, address in use); `destroy --batch latest` and `access audit` clean. Then, as decided for stricter organisations: the run said nothing had been changed and asked for the password again before going on. That run was stopped with Ctrl+C during the uploads: the rows showed "cleaning up" and what they waited for (the host releasing the disk). |
| 32 | Pass | Six VMs, Ctrl+C with "Let them finish" (two deployed, four not started), then `--retry-failed latest`: only the password was asked, every answer shown "as in the first run", and exactly the four VMs were deployed on the same hosts; `destroy --batch latest` included the run it retried (six VMs, one confirmation); `access audit` clean. A yes/no question refused "nos". The retry still needed `--batch --preset`: now the results file also keeps the manifest, image source, profile and batch options, so `deploy --retry-failed latest` is enough. Confirmed: `vmdeploy deploy --retry-failed latest` alone took the image (`--preset ubuntu-lts`), the profile and `--parallel 2` from the results file and deployed the four VMs; `destroy --batch latest` deleted all six; `access audit` clean. |
| 33 | Pass | 2 hosts x 2 VMs. The mistyped results file was refused before the sign-in. Enter alone at "Addresses" and a single address for four VMs were explained and asked again. The range's first address was in use by another VM, so its VM failed its check while the range's fifth address went unused: ranges are now a pool (item 34). "Change my answers" pre-selected each host's datastore (one not the default). Ctrl+C with "Let them finish": one deployed, three not started. `--retry-failed latest --parallel 4`: every answer "as in the first run", including each host's datastore and the hostname pattern; the three VMs deployed on their planned addresses. `vmdeploy logs` listed both runs; `destroy --batch latest` took both (four VMs, one confirmation); `access audit` clean. Seen and fixed: the summary's destroy command was broken across two lines inside a folder name and held an unquoted path with spaces (the commands now name the file alone); an ISO batch's full image path made the `vmdeploy logs` table too wide (now its file name). |
| 34 | Pass | A range of six addresses for four VMs on two hosts, the first in use by another VM: the review said it was skipped ("skipped … (used by VM …)") and gave the four VMs the next four addresses, all passing their checks. The review was not confirmed: nothing was deployed. |

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
