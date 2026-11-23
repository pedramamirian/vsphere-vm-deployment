# Design: batch deployment (phase 1)

Status: **phase 1 implemented, released in 0.2.0** (agreed decisions in section 14). Where the implementation settled a detail
differently from the first draft, this document has been updated to match it.

## 1. Goal

Deploy one image (ISO, OVA or OVF) with the same VM settings to many hosts and datastores in one run: pick the
targets, review one plan, and let the VMs be built in parallel, with failures kept separate from each other.

| Phase | Scope |
|---|---|
| **1 (this document)** | One connection (a vCenter, or one ESXi host) and many targets inside it: hosts, clusters, resource pools and their datastores |
| 1b | Several connections in one batch: several vCenters, several standalone ESXi hosts, or a mix. Adds a duplicate-MAC check across vCenters |
| 2 (to explore) | Deploy once and clone the rest (vCenter), templates, Content Library, choosing targets by vSphere tag, and a disk-copy equivalent for standalone ESXi |

Phase 1 is shaped so that 1b only adds a "connection" level above the targets; nothing in it assumes a single
server.

## 2. What the user sees

### Interactive

```
vmdeploy deploy --batch
```

1. Sign in, discover the inventory, choose the image: exactly as for one VM.
2. **Targets**: a checklist of hosts (and clusters, when there are any). Shortcuts: "all hosts in cluster X",
   "all hosts in folder Y", and a name filter. Hosts that cannot take VMs (disconnected, not responding,
   maintenance or standby mode) are listed greyed out with the reason, and cannot be ticked.
3. **How many VMs**: one per selected host (default), N per host, or N in total spread across them. A cluster with
   DRS also offers "let DRS place them".
4. **Datastore per host**: a host with one usable datastore gets it without asking. A host with several is asked
   once, with each datastore's free space shown and the one with the most free space as the default. A datastore
   shared by several hosts is listed once with "shared (3 hosts)".
5. **Shared settings**: sizing, provisioning, networks, VM compatibility, guest settings, OVF properties. These
   are the same questions as for one VM, asked once.
6. **Per-VM settings**: VM names, hostnames, addresses. Each can be skipped (section 4).
7. **Checks** for every target (section 6), then **one review** of the whole batch.
8. **Deploy**: a live table with one row per VM (section 7).
9. **Summary**: per host, per VM, and totals (section 9).

### Unattended

```
vmdeploy deploy --batch -f batch.yaml --yes [--json]
```

Every question above has a manifest field. `--yes` takes every answer from the manifest, accepts the review, skips
targets that fail their checks (section 8), deploys the rest and exits with a code a script can act on.

A manifest with a `batch:` section implies `--batch`, so `--batch` is only needed for an interactive batch
without a manifest.

## 3. Choosing targets

### Selectors

| Selector | Meaning |
|---|---|
| `host: <name>` | one host |
| `cluster: <name>` | every usable host in the cluster, or with `drs: true`, the cluster itself (DRS places each VM) |
| `folder: <host folder>` | every usable host in that host folder |
| `hosts_matching: "<pattern>"` | hosts whose name matches a shell-style pattern (`esx-east-*`) |
| `resource_pool: <path>` | a resource pool. Required where hosts are hidden (hosted VMware clouds) |

Each target can carry its own `datastore`, `count`, `networks` or `resource_pool`. Anything not given is taken
from the shared settings.

### Distribution

| Mode | Result |
|---|---|
| `per_host` (default) | `count` VMs on every selected host (default 1) |
| `total` | `count` VMs in total, spread across the selected hosts, the next VM always going to the host with the most free memory after the VMs already assigned |
| DRS (`cluster` with `drs: true`) | `count` VMs given to the cluster; DRS picks each host at power-on, as for a single VM today |

### What each kind of environment changes

| Environment | Handling |
|---|---|
| Hosts not in a cluster | Normal path: the user picks the hosts |
| Cluster without DRS | Hosts are picked; the cluster shortcut expands to its usable hosts |
| Cluster with DRS | A picked host is only where the VM starts; DRS may move it later. The review says so |
| Hosted VMware clouds (VMware Cloud on AWS, Azure VMware Solution, Google Cloud VMware Engine) | Hosts are hidden from the account. Targets are a cluster or resource pool (e.g. `Compute-ResourcePool`) |
| One ESXi host (no vCenter) | The batch is several VMs on that host, spread over its datastores |
| Shared datastores (vSAN, NFS, shared VMFS, vVols) | Only datastores the target host can see are offered. Capacity is added up across the batch (section 6) |
| Standard port groups | They exist separately on each host. The chosen name must exist on every target host, and with the same VLAN |
| Distributed port groups / NSX segments | The target host must be a member of that switch or transport zone |
| Mixed ESXi versions | The VM compatibility must be one every target host supports (section 6) |
| Datastore clusters (Storage DRS) | Not in phase 1; the member datastores can be chosen directly |

## 4. Per-VM settings, and skipping them

Every per-VM setting has three choices. Skipping is always available, so "just create the VMs" is always possible.

| Setting | Per VM | Same for all | Skip |
|---|---|---|---|
| VM name | pattern or list (required: names must be unique) | n/a | n/a |
| Hostname | pattern or list | allowed | not set: the image's default, or the DHCP server's |
| IPv4 address | range or list | n/a | `dhcp`: DHCP, the guest identified by its MAC address (with guest settings on; `guest.dhcp_identifier: image` writes nothing) |
| Guest settings (cloud-init: user, SSH key, time zone, NTP) | n/a | one block for all VMs | off: nothing is written into the guest |
| OVF properties (appliance settings) | per-target override | allowed | the image's defaults |
| Power on | n/a | yes / no | n/a (off leaves the VMs ready for manual setup before their first boot) |

The exception is an image that needs an OVF property and gives it no default value. Such a property cannot be
skipped: set it once for all VMs (`ovf.properties`) or per target. Values that use placeholders are checked
per VM once filled in; a missing required value is reported by vCenter when that VM is imported.

### Patterns

Names and hostnames are built from a pattern:

| Placeholder | Value |
|---|---|
| `{n}` | the VM's number in the batch, starting at `start` (default 1). `{n:02}` pads it: 01, 02, ... |
| `{host}` | the target host's name, up to the first dot (`esx-a.example.test` gives `esx-a`) |
| `{i}` | the VM's number on its host (1, 2, ...) |
| `{datastore}` | the datastore name, with characters a VM name may not contain replaced |
| `{name}` | hostname patterns only: the VM's name |

Examples: `web-{n:02}` gives web-01, web-02, ...; `app-{host}-{i}` gives app-esx-a-1, app-esx-a-2, app-esx-b-1.

A hostname pattern produces a valid DNS label: other characters become `-`, and it is cut to 63 characters. A
name that already exists in the inventory is handled by `name_conflict` (section 5).

### Addresses

| Mode | Behaviour |
|---|---|
| `dhcp` | DHCP; with guest settings on, the guest identifies itself by NIC 1's MAC address (`guest.dhcp_identifier`) |
| `static` with `range: 192.0.2.50-192.0.2.69` | a pool, handed out in VM order: addresses in use (as vCenter sees them), the gateway and the DNS servers are skipped, so an address in use does not cost a VM. Prefix, gateway and DNS are shared |
| `static` with `list: [...]` | exactly one address per VM, in VM order (addresses planned per VM, e.g. in DNS): one in use fails that VM's check |
| `static` with `list:` | exactly one address per VM, in VM order |

Each address goes through the existing conflict check (running VMs and ESXi hosts). An address that is taken is
**not** silently replaced by the next free one. The target fails its check, and the review says why. Addresses are
only applied through cloud-init (images that support it) or OVF properties (appliances). For an ISO install the
address is the installer's job, so the address settings are not offered.

## 5. The batch manifest

The existing sections are the shared settings. A new `batch:` section holds the targets and everything per-VM.

```yaml
profile: lab
image:
  preset: ubuntu-lts
resources:
  cpu: 2
  memory_gb: 4
  disk_gb: 40
networks:
  - portgroup: Lab
guest:
  username: vmadmin
  ssh_authorized_keys:
    - ssh-ed25519 AAAA... admin@example.test
post_deploy:
  power_on: true

batch:
  name: "web-{n:02}"              # required: VM name pattern, or `names:` with a list
  start: 1                        # first {n}
  name_conflict: skip             # skip | next-free | replace. Default skip.
                                  #   next-free: take the next unused number
                                  #   replace: as --replace (only VMs this tool deployed, with --yes)
  hostname: "{name}"              # pattern, a fixed name, or `skip` (default {name}, when guest settings are on)
  distribution: per_host          # per_host | total
  count: 1                        # VMs per host (per_host) or in total (total)

  targets:
    - host: esx-a.example.test
      datastore: local-a1
    - host: esx-b.example.test
      datastore: auto             # auto = the usable datastore with the most free space
      count: 2                    # overrides batch.count for this host
    - hosts_matching: "esx-c*"
      datastore: auto
    - cluster: cluster-01
      drs: true                   # DRS places each VM
      count: 4
      datastore: shared-vsan
      ovf:                        # per-target override of any OVF property
        properties:
          dns_domain: example.test

  addresses:
    mode: static                  # dhcp | static
    range: 192.0.2.50-192.0.2.69  # or list: [192.0.2.50, 192.0.2.61]
    prefix: 24
    gateway: 192.0.2.1
    dns: [192.0.2.53]

  parallel:
    vms: 4                        # VMs being built at the same time
    uploads: 2                    # uploads from this computer at the same time
    per_host: 2                   # VMs being built on one host at the same time

  on_check_failure: skip          # skip | cancel. Default skip
  on_failure: continue            # continue | stop. Default continue (--stop-on-failure sets stop)
  keep_failed: false              # true: keep a VM that failed half-way, for troubleshooting
```

`vm.name` and `placement.host`, `placement.cluster` and `placement.datastore` are not allowed together with
`batch:`: the batch says where each VM goes. `placement.datacenter`, `folder` and `resource_pool` stay as shared
settings that a target may override.

New command-line options: `--batch`, `--parallel N`, `--parallel-uploads N`, `--per-host N`,
`--stop-on-failure`, `--keep-failed`, `--retry-failed <results.json>`. The command line overrides the manifest.

## 6. Checks before the review

Run for every target before anything changes, and read-only as today. A target that fails a check is marked in
the review with the reason. It is skipped or the batch is cancelled, as section 8 describes.

| Check | Batch-specific rule |
|---|---|
| Host state | connected, not in maintenance or standby mode |
| Datastore capacity | **added up per datastore across the batch**: 10 VMs that each fit separately may not fit together. Thin and thick provisioning are counted as today |
| Host memory and vCPU overcommit | added up per host across the batch (warnings, as today) |
| Networks | each chosen port group exists on every target host. Standard port groups: the VLAN ID is read from each host; a different VLAN for the same name is a warning that names the hosts. Distributed / NSX: the host is a member |
| VM compatibility | one hardware version that every target host supports, shown in the review. A manifest `vmx-NN` that some host cannot run fails only those targets |
| Names | unique within the batch and not already in use (`name_conflict` decides) |
| Static addresses | unique within the batch, and the existing conflict check for each |
| OVF property values | each VM's values, once its placeholders are filled in, pass the image's own rules |
| Privileges | the existing check, for each distinct folder, resource pool, datastore and network the batch uses |
| ISO | can every target host reach the ISO, or a copy of it (section 7)? |
| Virtual TPM / key provider | checked once for the batch; every target host needs to qualify (as today for one host) |
| Parallel settings | against the limits in section 7 |

The Windows 11 key-provider exception keeps working as it does today: one key-provider change for the whole
batch, with its own plan and confirmation, before the batch review.

### The batch review

```
Review the batch (nothing has been changed yet)

Image        ubuntu-24.04-server-cloudimg-amd64.ova  [OVA]
Each VM      2 vCPU, 4 GB RAM, 40 GB disk (thin); network Lab; vmx-21; cloud-init (user vmadmin, SSH key)
After        power on, wait for IP
Parallel     4 VMs at a time, 2 uploads, 2 per host

 #  VM       Host        Datastore    Address          Check
 1  web-01   esx-a       local-a1     192.0.2.50/24    ok
 2  web-02   esx-b       local-b1     192.0.2.51/24    ok
 3  web-03   esx-b       local-b1     192.0.2.52/24    ok
 4  web-04   esx-c       local-c1     192.0.2.53/24    ✖ datastore local-c1: 30 GB free, the batch needs 84 GB there
 5  web-05   esx-d       local-d2     192.0.2.54/24    ! port group Lab is VLAN 50 here, VLAN 51 on esx-a, esx-b

4 of 5 VMs can be deployed. 1 target fails its checks.

What next?
  > Deploy the 4 VMs (skip web-04)
    Change my answers
    Cancel (nothing is changed)
```

With many VMs the table is grouped by host, with the per-VM lines folded to one line per host when the list is
longer than the screen. `--json` and the log always get the full list.

## 7. Running the batch

### Parallelism and limits

vCenter limits concurrent provisioning per host with a cost budget of 8; a deploy or clone costs 1. Work over
the budget is **queued, not failed** ("Resources currently in use by other operations"), and other people's work on
that host counts against the same budget. Standalone ESXi has no such scheduler.

| Setting | Default | User can set | Guard-rail |
|---|---|---|---|
| `parallel.vms` | 4 | yes | warning above 2 × the number of target hosts (the excess only waits) |
| `parallel.uploads` | 2 | yes | warning above 2: more uploads share the same bandwidth from this computer and finish no sooner |
| `parallel.per_host` | 2 | yes | warning above 2; **refused above 8 on vCenter** (vCenter would only queue them, and a queued import can time out waiting) |

The limits are shown in the review. A refused value is a configuration error (exit code 2) before anything is
changed.

### Images

- **The image is read once.** Download, checksum, OVA inspection and EULA acceptance happen once, before the
  review.
- **OVA / OVF**: each VM's disks are uploaded from this computer, so 10 VMs mean 10 uploads. `parallel.uploads`
  bounds them. Deploying once and cloning the rest is phase 2.
- **ISO**: before the VMs are built, a short staging step makes sure every target host can reach a copy:
  - an ISO already on a datastore the host sees is used where it is;
  - otherwise one copy is placed per datastore that needs one. The first copy is uploaded from this computer (or
    found already there, as today); the others are copied by vCenter, host to host, from that first copy, so the
    ISO leaves this computer once;
  - on a single ESXi host, every datastore is the host's own, so the first copy serves every VM.

  The copies are made one after another, before any VM is built. A failed copy fails only the VMs that needed
  it.

### Live view

```
Batch: 5 VMs on 4 hosts                         2 done, 2 running, 1 skipped    00:06:41
 web-01  esx-a  local-a1   ✔ done            192.0.2.50                      02:11
 web-02  esx-b  local-b1   ⠼ upload disks    ███████████░░░░  71%  48 MB/s   01:32
 web-03  esx-b  local-b1   … waiting (per-host limit)
 web-04  esx-c  local-c1   – skipped         datastore local-c1 too small
 web-05  esx-d  local-d2   ✔ done            192.0.2.54                      02:40
Overall  ██████████████████░░░░░░░░░░  61%
```

Without a terminal (CI, `--json`, logs) each change is one plain line: `web-02: upload disks 71%`.

## 8. Failures

### Before anything changes

| Mode | Targets that fail their checks |
|---|---|
| Interactive | the review asks: deploy the others, change answers, or cancel |
| `--yes` | `on_check_failure: skip` (default): the others are deployed, the skipped ones are in the summary and the exit code says "partly". `cancel`: nothing is deployed (exit code 2) |

A configuration error that affects every VM is not a per-target failure, and stops the batch before the review as
today. Examples: an unknown port group name, or an invalid pattern.

### While the VMs are being built

- **Each VM is separate.** A failure ends only that VM's build, and the other VMs carry on.
- **A VM that failed half-way is deleted** (the import's leftovers too), without asking. A question mid-run would
  stop every other row. With `keep_failed: true` (or `--keep-failed`) it is left in place for troubleshooting, and
  the summary lists it.
- A VM that was fully built before a later step failed (IP wait, snapshot) is kept, as today, and reported as
  "built, with a problem".
- `on_failure: stop` (or `--stop-on-failure`): after the first failure no new VM is started; VMs already being
  built finish. Meant for troubleshooting a new environment.
- A lost connection fails the VMs that were using it. In phase 1b, a batch with several servers loses only the
  VMs on the server that dropped.

### Ctrl+C

1. First Ctrl+C: no new VMs are started. Interactive runs ask: **let the running ones finish**, or **stop them and
   clean up**. `--yes` runs stop them and clean up.
2. A second Ctrl+C stops and cleans up immediately.
3. The summary is printed either way, with the ones that were never started marked "not started".

## 9. Results

### Summary

```
Batch finished in 00:07:12: 3 deployed, 1 failed, 1 skipped

Host     Deployed  Failed  Skipped  Problems
esx-a    1         0       0
esx-b    1         1       0        web-03: upload disks: connection reset by the host
esx-c    0         0       1        web-04: datastore local-c1 too small
esx-d    1         0       0        (warning) port group Lab: VLAN 50 here, 51 on other hosts

VM       Result     Host   Address       Console
web-01   deployed   esx-a  192.0.2.50    https://vcenter.example.test/ui/...
web-02   deployed   esx-b  192.0.2.51    ...
web-03   failed     esx-b  -             (partial VM deleted)
web-04   skipped    esx-c  -
web-05   deployed   esx-d  192.0.2.54    ...

Results saved: <logs folder>/batch-<date>-<time>.json
Retry the ones that were not deployed: vmdeploy deploy --retry-failed <that file>  (or --retry-failed latest)
```

On large batches the per-host table comes first, and the VM table lists only VMs that did not deploy, unless
`--verbose` is given.

### Results file and `--retry-failed`

Every batch writes a results file (no secrets, as with the log: a URL holding a password or token is never saved,
given with `--url` or typed, so a retry asks for it again): the manifest's per-VM plan, each VM's result, its error and hint, and its timings.
`--json` prints the same document. `--retry-failed <file>` runs the same batch again for only the VMs that failed,
were skipped or were not started. It uses the same names, hosts and addresses, and the checks run again first. VMs
are matched by the name their pattern gives (`pattern_name`), before name clashes are resolved again: a VM that
`name_conflict: next-free` named web-01-2 is retried as web-01. A batch started in the same second as another
writes `batch-<date>-<time>-2.json` rather than over it.

### Deleting a batch: `vmdeploy destroy --batch`

`vmdeploy destroy --batch <file> [--batch <retry file> ...]` deletes every VM the results files list as deployed
(or failed and kept, or failed and not deleted because the clean-up failed too), after one sign-in, one list and
one confirmation. VMs are found in one read per datacenter:
by their id when the file was written on the same vCenter (its instance UUID, also readable from an older file's
console links), so a VM renamed since is still found; otherwise by name. Only VMs whose Notes carry the vmdeploy
marker are deleted; VMs already gone are skipped. Deletions run one after another; a failure does not stop the
others (exit code 4 when some were not deleted). Added after the first real-vCenter run, where cleaning up six
VMs took six sign-ins.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | every VM deployed |
| 4 (new) | partly: at least one deployed, at least one failed, skipped or not started |
| 1 | none deployed |
| 2 | configuration error (nothing changed), or `on_check_failure: cancel` with a failing target |
| 130 | cancelled at the review (nothing changed) or by Ctrl+C |

## 10. How it is built

- **Planning, then building.** `Deployment` is split into the questions and checks for one VM (the plan) and the
  steps that build it (ISO staging, import or create, configure, power on, wait for IP, snapshot). A single
  deployment uses both exactly as today. A batch builds one shared plan, derives a plan per VM from it plus the
  target and pattern values, and hands each to a builder.
- **No questions while building.** A batch asks everything during planning; the builders run with a
  non-interactive prompter, whose answers come from the plan. Questions that today can come mid-run (for
  example, "read the ISO through this computer instead?") are decided during planning and shown in the review.
- **One session per builder.** pyVmomi connections are not safe to share between threads. Each builder gets its own
  session, cloned from the signed-in one with vSphere's clone-ticket mechanism (`AcquireCloneTicket` /
  `CloneSession`). It works for password and federated sign-in alike, no password is passed around, and every
  session uses the same pinned certificate through `trust.pinned_context`. Sessions are logged out at the end.
- **Threads, not processes**: the work is waiting on vCenter and on the network. Semaphores enforce
  `parallel.vms`, `parallel.uploads` and `parallel.per_host`. A VM gives its build and host slots back once it only
  waits for its guest's address (first real run: four VMs doing nothing but waiting kept the next ones queued),
  so the pool has more threads than build slots.
- **DHCP client identifier**: with DHCP, the guest identifies itself by NIC 1's MAC address from its first request
  (`guest.dhcp_identifier: mac`, set before the first boot). In the first real run every Ubuntu VM asked for an
  address twice under two identities; for large batches on DHCP that doubles the leases taken (8 days each by
  default on Windows Server DHCP), and Ubuntu's default identifier does not match reservations by MAC.
- **Logging**: one log file. Each line carries the VM's name. `register_secret()` applies to everything, as today.
- **Privileges**: phase 1 calls no new privileged APIs. Reading each host's port-group VLANs and cloning a session
  are both expected to need nothing beyond what deploy already requires. Both are to be confirmed against
  `data/privileges.yaml` and tested with the least-privilege account.

## 11. Project rules, checked

| Rule | How the batch keeps it |
|---|---|
| Nothing changes before the plan is confirmed | one batch review before any change; the Windows 11 key-provider change keeps its own plan and confirmation |
| Never disable TLS validation | every cloned session goes through `trust.pinned_context` |
| Never log secrets | unchanged; the results file holds no secrets |
| Every prompt has a manifest field | every batch question maps to a `batch:` field (section 5) |
| `privileges.yaml` in sync | checked for the VLAN read and session cloning |
| No real environment details | examples use `example.test` names and RFC 5737 addresses |

## 12. Testing

- **Unit**: pattern expansion; address ranges and lists; distribution modes; capacity added up per datastore and per
  host; the parallel guard-rails; manifest validation (including the fields not allowed with `batch:`); summary
  and exit codes; `--retry-failed` selection; Ctrl+C handling with fake builders.
- **Simulator (vcsim)**: one cluster with several hosts, plus standalone hosts; per-host and total distribution;
  DRS placement; an injected failure on one target (the others finish, the summary is correct); session cloning;
  ISO staging to several datastores.
- **Live (real vCenter with several hosts)**: `vmdeploy-test-` names; one VM per host; several datastores on one
  host; a port group missing on one host (that target is skipped); static addresses; a deliberately failing target;
  `--retry-failed`; clean-up with `vmdeploy destroy`, then `vmdeploy access audit`. Results recorded in
  `docs/testing.md` without environment details.
- **To verify while testing**: whether an OVF import counts against vCenter's per-host budget the way a clone
  does, and how long a queued import can wait before its upload times out.

## 13. Not in phase 1

- Several connections in one batch (phase 1b).
- Cloning, templates, Content Library, and targets chosen by vSphere tag (phase 2).
- Datastore clusters (Storage DRS) and storage policies.
- DRS rules (keep apart / keep together).
- IPv6 static addresses (not supported for single VMs either).

## 14. Decisions (agreed)

1. **Command shape**: `vmdeploy deploy --batch`; a `batch:` manifest section implies it.
2. **Exit code 4** means "partly deployed". The summary always lists every host and VM that was not deployed, and
   why.
3. **VMs that fail half-way are deleted automatically**, unless `--keep-failed` is given. They are still listed in
   the summary (and the results file) as failed, with the step and the reason, so the user knows where to look.
4. **Existing VM names** (`name_conflict: skip`, the default): the review lists each clash with where the existing
   VM is (folder and host), before anything changes. Interactively the user then deploys the others or changes
   the name pattern; `--yes` skips those targets. The summary lists them again.
5. **A static address already in use** fails that target. It is not moved to the next free address. The review
   shows the clash and what holds the address, and the summary lists it again so it can be fixed afterwards.
