# vsphere-vm-deployment

*Part of **Peter's Projects** · by Peter Amirian · open source under the [Apache 2.0 licence](LICENSE)*

Deploy virtual machines to **VMware vCenter Server** or a **standalone ESXi host** from an **OVA, OVF or ISO**,
entirely from your terminal (VS Code, PowerShell, macOS Terminal, any shell). No vSphere Client clicking:
the tool signs in, reads your environment, asks only for what it cannot work out itself, shows you the
plan, and then deploys with live progress bars.

```
╭─ vsphere-vm-deployment 0.1.0 ─────────────────────────────────────────────────────────────╮
│ ✔  Connect and sign in        VMware vCenter Server 8.0.3 as svc-deploy@vsphere.local      │
│ ✔  Discover inventory          Lab: 3 host(s), 4 datastore(s), 6 network(s)                │
│ ✔  Acquire and verify image    Ubuntu 24.04 LTS (noble) build 20261001  [OVA]              │
│    ↳ Integrity: SHA-256 matches Canonical's published value (downloaded)                   │
│ ✔  Inspect image               Ubuntu Server: 2 vCPU, 1 GB RAM, 1 disk, 1 network          │
│ ✔  Choose placement and sizing web01 on cluster Lab-Cluster (DRS placement)                │
│ ✔  Pre-flight checks           all checks passed                                           │
│ ✔  Review plan                 confirmed                                                   │
│ ⠼  Upload disks                ubuntu-24.04-server-cloudimg-amd64.vmdk -> 192.0.2.12       │
│      Uploading disks  ━━━━━━━━━━━━━━━━━━━━━━━╸━━━━━━━  71%  412/580 MB  48 MB/s  0:00:03   │
│ ○  Configure CPU, memory and disks                                                         │
│ ○  Power on                                                                                │
│ ○  Wait for guest IP address                                                               │
│                                                                                            │
│ Overall ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   64% │
╰────────────────────────────────────────────────────────────────────────────────────────────╯
```

> **Status: alpha (0.1.0).** Tested against real vCenter Server 8.0.3 and ESXi 8.0.3 environments (through
> vCenter and directly to a host), and covered end to end by automated tests against VMware's `vcsim`
> simulator, including the vSphere 9.0 API. A few features are so far tested with the simulator only (see
> [Known limitations](#known-limitations-and-roadmap)). Please report anything that does not work in your
> environment ([Reporting problems](#reporting-problems)).

**New here?** Read the [requirements](#before-you-start-requirements-and-licensing) just below,
[install the tool](#install), then follow [Your first deployment, step by step](#your-first-deployment-step-by-step).

**Coming back after a while, or already know vSphere?** Start at the [Quick reference](#quick-reference): every
task and command on one page. Every command is explained with examples in the [Command reference](#command-reference).

**Contents**

1. [Before you start: requirements and licensing](#before-you-start-requirements-and-licensing), and
   [what is and isn't supported](#what-is-and-isnt-supported)
2. [What it does](#what-it-does)
3. [Install](#install), [update or uninstall](#update-or-uninstall)
4. [Quick reference](#quick-reference)
5. [Your first deployment, step by step](#your-first-deployment-step-by-step)
6. [Command reference](#command-reference)
7. [Image sources and integrity](#image-sources-and-integrity)
8. [Manifests](#manifests-optional)
9. [Sign-in, certificates and secrets](#sign-in-certificates-and-secrets)
10. [Unattended / automation use](#unattended--automation-use)
11. [Troubleshooting](#troubleshooting)
12. [Where things are stored](#where-things-are-stored)
13. [Known limitations and roadmap](#known-limitations-and-roadmap)

---

## Before you start: requirements and licensing

**Read this first. The tool checks these and stops with an explanation if one is not met.**

| Requirement | Details |
|---|---|
| **A licensed vSphere: vCenter Server, or an ESXi host with a paid, VMUG Advantage or evaluation licence** | **Free ESXi is not supported.** The free "vSphere Hypervisor" licence, including Broadcom's free ESXi 8.0 Update 3e release (2025), makes the vSphere API read-only, so no API-based tool, including this one, can create VMs with it. The tool detects the free licence when connecting directly to ESXi and stops with an explanation (exit code 3). There is no free edition of ESXi 9. |
| **vSphere 8.x or 9.x** | vCenter Server and ESXi 8.0 and 9.x are supported; older versions are not. Tested in a real environment: vCenter Server 8.0.3 with ESXi 8.0.3 hosts, deploying through vCenter and directly to a host. vSphere 9 is covered by automated tests against a simulator reporting the 9.0 API, not yet by a real environment ([testing status](docs/testing.md)). |
| **Python 3.11 or newer (64-bit)** | On Windows, macOS or Linux. Supported: 3.11 to 3.15; the CI workflow tests each version on all three systems. See [Software to install first](#software-to-install-first). |
| **Network access on TCP 443** | To vCenter **and to the ESXi hosts**: during an OVA import, disk data is uploaded straight to the ESXi host that will run the VM, not through vCenter. |
| **Free disk space on your computer for OVA/OVF images** | **Every OVA or OVF passes through your computer, even one already on a datastore** (a vSphere limitation, [explained below](#why-an-ova-on-a-datastore-passes-through-your-computer)). Allow the size of the `.ova` file (plus 1 GB) in the cache folder; the tool checks before it starts and stops with an explanation if there is not enough. ISOs on a datastore never pass through your computer. |
| **An account with the right privileges** | An administrator, or better a dedicated least-privilege account: `vmdeploy access setup` creates one for you (see [docs/least-privilege.md](docs/least-privilege.md)). `vmdeploy doctor` checks your account. |
| **For Windows 11 (or any VM with a virtual TPM)** | vCenter with a key provider, and the VM's host in a vSphere cluster (one host and no DRS/HA is enough). An ESXi host without vCenter cannot run Windows 11 with a TPM. See [Virtual TPM: where it works](#virtual-tpm-where-it-works). |
| **For the `ubuntu-lts` presets** | Internet access to `cloud-images.ubuntu.com` (directly or through `HTTPS_PROXY`). |

### What is and isn't supported

| Area | Supported | Not supported (yet) |
|---|---|---|
| **vSphere** | vCenter Server and ESXi 8.0 and 9.x, deploying through vCenter or directly to a standalone host | vSphere 7.x and older |
| **Licences** | vSphere with a paid, VMUG Advantage or evaluation licence. Your own licences for Windows (your ISO, then a product key or KMS) and for vendor appliances (their licence agreement is shown and must be accepted). vmdeploy itself is free and open source (Apache 2.0) | Free ESXi (the "vSphere Hypervisor" licence makes the API read-only) |
| **Images** | OVA, OVF (with its disk files) and ISO: from your computer, a download link (OVA or ISO), the Ubuntu Server presets, or a datastore | Cloning existing VMs or templates; Content Library items (planned); multi-VM OVF packages (vApps) |
| **Guests** | Any operating system installed from its ISO in the VM console; first-boot settings through cloud-init for images that support it (e.g. Ubuntu cloud images); Windows 10, 11 and Server 2016 to 2025 with the virtual hardware Windows Setup needs; vendor appliances with their sizes, settings and licence agreements | Unattended installs from an ISO (planned); Windows guest customisation (sysprep) |
| **Networks and storage** | Standard and distributed portgroups, NSX segments; local, shared (NFS, iSCSI, FC) and vSAN datastores | Choosing a vSAN storage policy (the datastore's default is used); first-boot network settings beyond the first network adapter |
| **Virtual TPM (Windows 11)** | Through vCenter, with a key provider, on a host in a cluster ([details](#virtual-tpm-where-it-works)) | An ESXi host without vCenter; a host outside a cluster |
| **Sign-in** | vCenter SSO, local ESXi and Active Directory accounts; federated SSO through OAuth (ADFS, Entra ID, Okta, PingFederate) | Browser-based (authorization code) sign-in; Windows integrated sign-in (SSPI) |
| **Your computer** | Windows 10 and 11, macOS 13 or newer, Linux; Python 3.11 to 3.15 ([details](#supported-platforms)) | |

Tested in a real environment against vCenter Server 8.0.3 and ESXi 8.0.3. DRS clusters, distributed switches,
vSphere 9 and federated sign-in are so far covered by the simulator tests only ([testing status](docs/testing.md)).
[Known limitations and roadmap](#known-limitations-and-roadmap) has the details.

---

## What it does

- **Interactive, step-by-step deployment.** One live view shows every step. Sign-in, certificate decisions,
  licence agreements, placement, sizing, networking and first-boot settings are all asked inside that view.
- **Reads your environment first.** Datacenters, clusters (DRS/HA), hosts (state, cores, free memory, vCPU
  allocation), datastores (type, free space, provisioning), standard / distributed / NSX networks, folders,
  resource pools and existing VM names. Distributed-switch uplink portgroups are hidden because VMs cannot use them.
- **Windows 10, 11 and Server 2016/2019/2022/2025** from your licensed ISO: UEFI + Secure Boot, an NVMe disk and
  e1000e network card that Windows Setup has drivers for, and a virtual TPM for Windows 11. Windows 11 needs a
  usable key provider in vCenter and a host in a cluster: if the key provider is missing, vmdeploy stops early and
  offers to set one up on the spot (or names the `vmdeploy keyprovider` command to run); if the host is not in a
  cluster, or there is no vCenter, it stops and explains why ([where it works](#virtual-tpm-where-it-works)).
  See [docs/windows.md](docs/windows.md).
- **Images from anywhere**
  - `--local <file>` or `--pick-local`: an `.ova`, `.ovf` or `.iso` in the `images/` folder
  - `--url <https://…>`: download an `.ova` or `.iso`, with a progress bar
  - `--preset ubuntu-lts`: the newest Ubuntu Server LTS cloud image, found and verified automatically
  - `--datastore-file "[datastore1] iso/x.iso"`: an ISO, OVA or OVF already on a datastore (or pick it from a
    list). ISOs are used in place, or copied once host to host if the target host cannot see them; OVAs and OVFs
    (with their disk files) are read once through your computer, because vCenter cannot import them straight
    from a datastore, and the VM can then go to any datastore
  - an ISO you upload once is **reused** by later deployments, and an ISO from your computer that is
    **already on a datastore** is offered for use from there instead of being uploaded. Either way the copy
    is used only after its **full SHA-256** matches your image (it is read once; nothing is stored). A name
    and size are never trusted, because another account with file rights on that datastore could have put
    a different file there; a copy that does not match is left alone and yours is uploaded under a new name
    (`name-2.iso`, ...). Nothing in `vmdeploy-iso/` is ever overwritten
- **Integrity checks everywhere.** SHA-256 checks on downloads (vendor-published or yours), verification of
  every file listed in an OVA's manifest before upload, and a second check of the bytes actually sent.
- **VM compatibility you control.** Keep the image's virtual hardware version, follow your administrator's
  cluster/datacenter "Default VM Compatibility" policy, or upgrade to the newest the host supports. Never
  below what the image needs.
- **Any ISO, OVA or OVF.** Ubuntu, Windows, vendor appliances (e.g. Cisco ISE) and network labs (e.g. EVE-NG)
  go through the same steps. Common installers are recognised from their file name (Windows, Ubuntu, Debian,
  RHEL/Rocky/Alma, SUSE, ESXi, Proxmox, EVE-NG, FreeBSD/pfSense), so the guest type is suggested.
- **Uses what the image already says.** CPU, memory, disks, networks, deployment sizes and appliance settings
  are read from the OVA/OVF; you are only asked about what is missing, with the image's values as defaults.
  An appliance with several sizes (e.g. Eval / Small / Medium) lists each one with its CPU and memory.
- **Nested virtualisation** ("Expose hardware assisted virtualization to the guest OS") is offered for ISO
  installs and suggested for hypervisors and network labs (EVE-NG, GNS3, ESXi, Proxmox).
- **Vendor guidance for EVE-NG 7 and Cisco ISE 3.3 to 3.5.** Their documented sizing and VM settings become the
  defaults (EVE: sizing, IOMMU, eager-zeroed disk, portgroup security check; ISE: no snapshots, nested
  virtualisation for 3.4 and later, no IP wait), with the source shown at the review. See
  [docs/vendor-guidance.md](docs/vendor-guidance.md).
- **If vCenter cannot copy an ISO host to host**, vmdeploy says why when it can tell (e.g. a running VM has it
  attached) and offers to read it through your computer and upload it instead (`image.fallback_via_pc`).
- **Licence agreements** embedded in an OVA are shown and must be accepted.
- **Safe placement.** Lets DRS choose, or you pin a host. Only datastores and networks the host can actually
  use are offered. Over-commitment of CPU, memory or storage produces **warnings that never block you**.
- **First-boot setup (cloud-init)** for images that support it: hostname, admin user, SSH key and/or
  password (hashed locally, never sent in clear text), static IP or DHCP, DNS, timezone, NTP.
- **Static IP checks.** Addresses, prefixes, gateways and DNS servers are validated as you type (and in
  manifests). Before anything is created, the address is checked against every running VM (as reported by
  VMware Tools) and every ESXi host: the same address on the same network stops the deployment and names the
  VM, network, host and address; the same address on another network, or an address in a different subnet
  than the other VMs on that network, is a warning. Devices without VMware Tools cannot be seen by this check.
- **Plan before change.** Nothing is created until you have reviewed the plan and confirmed it.
- **Clean failure.** A failed or cancelled deployment removes the half-built VM (you are asked first when
  interactive). Sessions are always logged out.
- **Certificates handled properly.** Choose *trust once*, *trust always*, *trust vCenter's root CA*, or
  *decline*. Changed certificates trigger a warning. Validation is never switched off.
- **Any sign-in method.** Local and `vsphere.local` accounts, Active Directory (LDAP/IWA identity sources),
  and federated SSO (ADFS, Entra ID, Okta, PingFederate). Passwords can live in the OS keychain
  (Windows Credential Manager, macOS Keychain, the Linux Secret Service) or be asked for every time.
- **Least-privilege accounts made easy.** `vmdeploy access setup` creates a deploy-only account so
  day-to-day deployments never use administrator credentials.
- **Multiple vCenters / hosts** through named connection profiles.
- **Automation friendly.** Use `--yes` with a manifest for unattended runs, `--json` for machine-readable
  output, and meaningful exit codes. Every run writes a log file with secrets removed.

---

## Supported platforms

| OS | Versions | CPU | Notes |
|---|---|---|---|
| **Windows** | 10 and 11 | x64, ARM64 | PowerShell, Windows Terminal or cmd.exe. Windows Terminal shows the progress symbols best; the old console window works but may show some symbols as boxes. |
| **macOS** | 13 Ventura or newer | Apple Silicon, Intel | Terminal, iTerm2 or VS Code. Use a python.org or Homebrew Python, not the system `/usr/bin/python3` stub. |
| **Linux** | Any current distribution with glibc (Ubuntu 22.04+, Debian 12+, Fedora, RHEL/Rocky/Alma 9+) | x86-64, ARM64 | Works over SSH and on headless servers. Alpine (musl) works but may need to compile libraries. |

The same commands, manifests and profiles work on all three. CI runs every Python version from 3.11 to 3.15
on Windows, macOS and Linux.

## Install

### Software to install first

| Software | Why | Where to get it |
|---|---|---|
| **Python 3.11 or newer, 64-bit** | Runs the tool | [python.org/downloads](https://www.python.org/downloads/). **Windows:** tick *Add python.exe to PATH* in the installer, or use the `py` launcher. **Debian/Ubuntu:** `sudo apt install python3 python3-venv python3-pip`. **macOS:** the python.org installer or `brew install python`. |
| **pip 21.3 or newer** | Installs the tool and its libraries | Comes with Python. Upgrade it first: `python -m pip install --upgrade pip` |
| **Git** | Only for installing straight from GitHub (`pipx install git+…` or `git clone`) | [git-scm.com](https://git-scm.com/downloads). **macOS:** `xcode-select --install` |
| **pipx** (optional, recommended) | Installs the tool in its own isolated environment | [pipx.pypa.io](https://pipx.pypa.io/stable/installation/) |
| **An OS keychain** (optional) | Only if you want passwords remembered | Built into Windows (Credential Manager) and macOS (Keychain). **Linux** needs a Secret Service provider such as GNOME Keyring or KWallet running in your session. Headless servers usually have none. The tool then warns you and asks for the password on every run. |

You do **not** need a C compiler, Rust or Visual Studio on a mainstream platform (64-bit Windows, macOS,
or glibc-based Linux on x86-64 / ARM64) with a Python release that has been out for a few months. All
libraries then install as prebuilt "wheels". See [If pip tries to compile something](#if-pip-tries-to-compile-something)
for the exceptions.

**Opening a terminal:** on Windows, open *PowerShell* from the Start menu (or *Terminal → New Terminal* in
VS Code). On macOS, open *Terminal* from Applications → Utilities. On Linux, open your distribution's
terminal app. Every command in this README is typed there and run with Enter.

### Install the tool

Pick **one** of the two ways.

**A. With pipx (recommended for most people).** pipx keeps the tool separate from everything else on your
computer and makes `vmdeploy` available in every terminal:

```bash
pipx install git+https://github.com/pedramamirian/vsphere-vm-deployment
vmdeploy --version
```

**B. From a copy of the source (for contributors, or to try changes):**

```bash
git clone https://github.com/pedramamirian/vsphere-vm-deployment
cd vsphere-vm-deployment
python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
vmdeploy --version
```

You should see `vsphere-vm-deployment 0.1.0`. This installs the `vmdeploy` command (also available as
`vsphere-vm-deploy`).

With option B, the `vmdeploy` command only exists while the virtual environment is **activated** (your prompt
starts with `(.venv)`). In a new terminal, `cd` into the folder and activate it again first.

> **Windows PowerShell says "running scripts is disabled on this system"** when you activate the venv:
> skip activation and call the venv's programs directly, e.g. `.venv\Scripts\python.exe -m pip install -e .`
> and `.venv\Scripts\vmdeploy.exe --version`. Or allow local scripts for your account only:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

### If pip tries to compile something

pip falls back to building a library from source when no prebuilt wheel matches your Python version or
platform. This usually happens with a **Python release from the last few months** (library maintainers have
not published wheels for it yet) or an **uncommon platform** (32-bit Windows, Alpine/musl Linux, 32-bit ARM).

**PyYAML** is the most common case. The error looks like this:

```text
error: Microsoft Visual C++ 14.0 or greater is required. Get it with "Microsoft C++ Build Tools"
ERROR: Failed building wheel for pyyaml
```

On Linux/macOS it may instead say `gcc: command not found` or `xcrun: error: invalid active developer path`.
You have two options:

1. **Use PyYAML's pure-Python build (simplest, no extra software).** PyYAML's C extension only speeds up
   parsing. vmdeploy reads small files with PyYAML's safe loader and works the same without it. Set
   `PYYAML_FORCE_LIBYAML=0` and run the install command again:

   ```powershell
   # Windows PowerShell
   $env:PYYAML_FORCE_LIBYAML = "0"
   pip install -e .            # or: pipx install git+https://github.com/pedramamirian/vsphere-vm-deployment
   ```

   ```bat
   :: Windows cmd.exe
   set PYYAML_FORCE_LIBYAML=0
   pip install -e .
   ```

   ```bash
   # macOS / Linux
   PYYAML_FORCE_LIBYAML=0 pip install -e .
   ```

   The variable only matters during the install; you do not need to keep it set afterwards.

2. **Install a compiler** so pip can build the C extension:
   - **Windows:** [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/),
     with the *Desktop development with C++* workload (several GB).
   - **macOS:** `xcode-select --install`
   - **Debian/Ubuntu:** `sudo apt install build-essential python3-dev`. **Fedora/RHEL:** `sudo dnf install gcc python3-devel`

**cryptography** and **pydantic-core** are written partly in Rust. They publish wheels for every mainstream
platform, including new Python releases. If pip still tries to build them, you are on an uncommon platform.
Either use a 64-bit Python from python.org, or install the [Rust toolchain](https://rustup.rs) plus the
compiler for your OS listed above.

If nothing works, install the newest Python release that is **at least a few months old** alongside your
current one (on Windows, `py -3.13 -m venv .venv` picks a specific version) and use that for the venv.

### Update or uninstall

| | Installed with pipx (option A) | Installed from the source (option B) |
|---|---|---|
| **Update** | `pipx reinstall vsphere-vm-deployment` (fetches the latest version from GitHub) | `cd` into the folder, `git pull`, activate the venv, then `pip install -e .` |
| **Check the version** | `vmdeploy --version` | `vmdeploy --version` |
| **Uninstall** | `pipx uninstall vsphere-vm-deployment` | Delete the folder (the venv is inside it) |

Updating or uninstalling keeps your profiles, remembered certificates and keychain entries (see
[Where things are stored](#where-things-are-stored) to remove them too). After an update, the
[CHANGELOG](CHANGELOG.md) lists what changed.

---

## Quick reference

Everything you need when you come back to vmdeploy after a while. Each command is explained in the
[Command reference](#command-reference), and `vmdeploy <command> --help` lists all of its options.

**Getting started again**

1. Open a terminal. If you installed from the source (option B), `cd` into the project folder and activate
   the virtual environment: `.venv\Scripts\activate` (Windows) or `source .venv/bin/activate` (macOS/Linux).
2. Optionally [update](#update-or-uninstall) the tool.
3. `vmdeploy profile list` shows your saved connections (`*` marks the default). `vmdeploy doctor` checks that
   the default one still signs in and has the privileges it needs (`-p NAME` for another one).

| I want to… | Command |
|---|---|
| Save a connection to a vCenter or ESXi host | `vmdeploy profile add` |
| See my saved connections, or change the default | `vmdeploy profile list`, `vmdeploy profile default NAME` |
| Check a connection, its licence and the account's privileges | `vmdeploy doctor` |
| See datacenters, clusters, hosts, datastores and networks | `vmdeploy inventory` |
| Deploy the newest Ubuntu Server LTS | `vmdeploy deploy --preset ubuntu-lts` |
| Deploy an OVA, OVF or ISO from this computer | Put it in `images/`, then `vmdeploy deploy --local FILE` (or `--pick-local`) |
| Deploy from a download link | `vmdeploy deploy --url URL --sha256 HASH` |
| Deploy an ISO or OVA that is already on a datastore | `vmdeploy deploy --datastore-file "[datastore] folder/file.iso"` |
| Repeat a deployment from saved answers | `vmdeploy deploy -f my-vm.yaml` (add `--yes` for no questions at all) |
| List, or delete, the VMs this tool deployed | `vmdeploy list`, `vmdeploy destroy NAME` |
| Create a restricted, deploy-only account | `vmdeploy access setup` (as an administrator) |
| Check what vmdeploy left in vCenter or ESXi | `vmdeploy access audit` |
| Remove a deploy account (and optionally its VMs) | `vmdeploy access remove` |
| Prepare vCenter for Windows 11 (virtual TPM) | `vmdeploy keyprovider list`, then `vmdeploy keyprovider add` |
| Delete ISO copies on datastores that no VM uses | `vmdeploy images prune` |
| Free disk space on this computer | `vmdeploy images clear-cache` |
| Review or forget remembered certificates | `vmdeploy trust list`, `vmdeploy trust remove ENDPOINT` |
| Forget a saved password | `vmdeploy forget-secret PROFILE` |
| See more detail when something fails | `vmdeploy -v COMMAND …`, then open the log file printed at the end |

**Good to remember**

- Nothing changes in vCenter or ESXi until you confirm. Ctrl+C cancels at any time before that.
- Commands use your default profile; `-p NAME` picks another one.
- `--yes` never asks anything: give the answers in a manifest or as options (for scripts).
- Profiles, remembered certificates, logs and downloaded images are kept in your user folder
  ([Where things are stored](#where-things-are-stored)). Passwords are only saved if you chose to.

---

## Your first deployment, step by step

This walkthrough takes you from a fresh install to a running Ubuntu VM. It takes about 15 minutes, most of
it waiting for the download and upload. You need:

- the address of your vCenter Server or ESXi host (for example `vcsa.example.com` or `192.0.2.10`);
- a username and password for it (for example `administrator@vsphere.local`, or `root` on ESXi);
- for the Ubuntu example, an SSH key pair on your computer, or you can choose a password instead (see
  [SSH keys](#ssh-keys) below).

#### SSH keys

An SSH key pair has two halves: a **private key** that never leaves your computer, and a **public key**
(`.pub`) that you hand to servers. vmdeploy only ever reads the **public** key and puts it in the new VM.

```bash
ssh-keygen -t ed25519            # built into Windows 10/11, macOS and Linux; accept the default location
```

- **Keep keys in the default folder**, `~/.ssh` (`C:\Users\<you>\.ssh` on Windows). That is where `ssh`
  looks for them, and it is readable only by your account.
- **Never copy a private key into a project folder or a git repository**, and never paste it anywhere. If
  vmdeploy is given a private key by mistake it refuses it.
- **Protect the private key with a passphrase** when `ssh-keygen` asks for one, and let an agent remember it
  so you type it once per session: on Windows, start the *OpenSSH Authentication Agent* service and run
  `ssh-add`; on macOS, `ssh-add --apple-use-keychain`; on Linux, your desktop's agent or `ssh-add`.
- **For the strongest protection**, a hardware security key (FIDO2/YubiKey) can hold the key:
  `ssh-keygen -t ed25519-sk`. vmdeploy accepts these public keys too.

**How the questions work:** use the **arrow keys** and **Enter** to pick from a list, type answers and press
Enter, and press **Enter alone to accept the default** shown. **Ctrl+C** cancels at any time. Before your
final "yes", nothing has been changed in vSphere.

### Step 1: Save your connection details (a "profile")

A profile remembers *where* to connect and *how* to sign in, so you do not have to type it every time.
It never contains your password.

```bash
vmdeploy profile add
```

```text
── New connection profile
? vCenter Server or ESXi host (FQDN or IP): vcsa.example.com
? Profile name: vcsa
? Sign-in method: Username + password (vsphere.local, ESXi local, Active Directory over LDAP or IWA)
? Username (leave empty to be asked every time): administrator@vsphere.local
? Save the password / client secret in the OS keychain after the first successful sign-in? No
  ✔ Profile saved: vcsa -> vcsa.example.com:443 (password)
```

Answer **No** to the keychain question if you prefer to type the password each time (nothing secret is
then saved anywhere). Your first profile becomes the default, so later commands use it automatically.

### Step 2: Check the connection

```bash
vmdeploy doctor
```

The first time, the tool shows the server's certificate and asks whether to trust it:

```text
── Certificate check: vcsa.example.com:443
This server certificate is not yet trusted.
Subject: "C=US,CN=vcsa.example.com"
...
SHA-256 fingerprint: 4C:3D:58:…
1) Trust for this session   2) Trust and remember   3) Trust this vCenter's root CA (…)   4) Cancel [default]
Certificate trust choice:
```

- **What is this?** vCenter and ESXi use their own certificates, which your computer does not know yet.
  You can compare the fingerprint with the one in the vSphere Client (or your browser's certificate viewer
  for `https://vcsa.example.com`) to be sure you are talking to the right server.
- **Which to choose?** `1` if you do not want anything saved (you will be asked again next time). `3` for
  vCenter if you want it remembered: it also covers the ESXi hosts behind it and certificate renewals. `2`
  remembers this exact certificate.

Then type your password. A healthy result looks like this:

```text
  Server                 VMware vCenter Server 8.0.3 build-xxxxxxxx
  Signed in as           administrator@vsphere.local
  Certificate            pinned, this session only (vcsa.example.com)
  Datacenter Lab         1 cluster(s), 3 host(s), 4 datastore(s), 6 VM network(s)
All required privileges are granted at the top of the inventory.
Doctor finished.
```

If something is wrong (licence, version, missing privileges), doctor says what and how to fix it.

### Step 3: Look at what is there (optional)

```bash
vmdeploy inventory
```

This lists your datacenters, clusters, hosts, datastores and networks, so you know the names you will be
offered during deployment.

### Step 4: Use a restricted account for deployments (optional, recommended)

You can keep using your administrator account. If you would rather not, let the tool prepare an account that
can only deploy VMs, only where you allow it.

**On vCenter, create the user first** (the vSphere API cannot create vCenter users, so this one step is yours):
in the vSphere Client, *Administration → Single Sign On → Users and Groups → Users*, choose the domain (for
example `vsphere.local`), **Add**, enter a user name such as `deployer` and a password, then **Add**. Leave it
out of every group: vmdeploy grants exactly the rights it needs. An Active Directory user works too, if vCenter
is joined to the domain. On a standalone ESXi host there is nothing to prepare: the tool creates a local user.
If you name a vCenter user that does not exist, `access setup` says so and how to create it, before changing
anything.

**Bring your own account?** Fine, as long as it is **dedicated** to deployments. vSphere lets a permission set on
an object replace what an account would otherwise get there from its groups or from higher up, so giving an
administrator (or any account with other rights) the deploy role would quietly *reduce* what it can do. `access
setup` asks vCenter for the account's effective rights first and stops, changing nothing, if it already has more
than setup would grant.

Then run:

```bash
vmdeploy access setup
```

It asks which user (on vCenter: an existing user such as `deployer@vsphere.local`; on a standalone ESXi
host it creates a new local user for you), where the account may work (a new folder of its own, a cluster or
host, datastores and networks), shows the plan, and creates nothing until you confirm. It also creates a second profile, for example
`vcsa-deployer`, that you then use with `-p vcsa-deployer`. See [access setup](#vmdeploy-access-setup) for
details.

### Step 5: Deploy your first VM

The easiest first VM is the newest Ubuntu Server LTS, which the tool downloads and verifies for you:

```bash
vmdeploy deploy --preset ubuntu-lts
# or, with the restricted account from step 4:
vmdeploy deploy --preset ubuntu-lts -p vcsa-deployer
```

A live step-by-step view opens. You will be asked, roughly in this order (press Enter to accept a default):

| Question | What to answer |
|---|---|
| Datacenter, VM folder | Where the VM appears in vCenter |
| VM name | For example `ubuntu01` |
| Deploy to | A cluster ("Let DRS choose" picks the best host) or a specific host |
| CPU, memory, disk size | Pre-filled: an OVA's own values, or for an ISO install VMware's recommendation for the guest type you picked (never below Microsoft's minimum for Windows). The question shows both, e.g. `Memory (GB) (VMware recommends 4 GB; Microsoft minimum for Windows Server 2022 Desktop Experience: 2 GB) [4]`. Press Enter, or raise them |
| Datastore | Where the VM's disk is stored; free space is shown |
| Network | The portgroup the VM connects to |
| VM compatibility | Which ESXi versions the VM can run on (its "virtual hardware version"). Newer versions add features and security fixes; older ones let the VM move to older hosts. The suggestion is your administrator's cluster/datacenter policy if one is set, otherwise the newest the host supports for Ubuntu and ISO installs, and the image's own version for vendor appliances |
| Configure hostname, login and network for the first boot? | **Yes** for Ubuntu |
| Admin username to create | Your login name inside the VM, for example `alex` |
| How will you log in? | SSH key (point it at your `~/.ssh/id_ed25519.pub`) and/or a password |
| Guest IP addressing | DHCP (automatic) or a static address. For a static address, type it with its prefix (`192.0.2.50/24`); typos such as `192.0.2.300` or `192.0.02.5` are caught as you type, the gateway is suggested and must be in the same subnet, and before the plan the tool checks that no running VM or ESXi host on that network already uses the address |
| Take a 'clean baseline' snapshot? | Optional restore point after the first boot |

Then the **plan** is shown: name, placement, sizes, network, image and any warnings (for example a nearly
full datastore). Read it, then choose:

- **Deploy now**: only now are changes made in vSphere.
- **Change my answers**: made a mistake (say, Static instead of DHCP)? The questions are asked again with
  everything you answered **pre-selected**, so you press Enter through the right ones and fix the wrong one.
  The image is not downloaded again.
- **Cancel**: nothing is changed.

The tool downloads the image (once: later deployments reuse the download and only re-check its checksum,
which takes seconds), uploads it, applies your settings and powers the VM on. It then waits until the VM's
IP address has stayed the same for 30 seconds before reporting it, because a fresh VM often changes address
once during its first boot. At the end you get a summary like this:

```text
  VM          ubuntu01 (vm-1234)
  Where       Lab, Lab-Cluster, datastore nvme-ds01
  IP address  192.0.2.50

Deployment complete. Next step: open the VM's console to finish setting it up or to use it:
  https://vcsa.example.com/ui/app/vm;nav=v/urn:vmomi:VirtualMachine:vm-1234:…
  Or connect with SSH: ssh <user>@192.0.2.50
```

### Step 6: Use your VM

Run the `ssh` command that was printed, with `<user>` replaced by the admin username you chose (for example
`ssh alex@192.0.2.50`). If no IP address was reported, open the printed link and choose *Launch Web
Console*. For **ISO** deployments the operating system installer is waiting in that console.

### Step 7: See and remove what you created

```bash
vmdeploy list                 # VMs deployed by this tool
vmdeploy destroy ubuntu01     # power off and permanently delete it (asks first)
```

`destroy` only deletes VMs this tool created, unless you add `--force`.

**What was saved on your computer?** Only the profile (server address and username), any certificate you
chose to remember, the downloaded image (to save time next time), and a log file. See
[Where things are stored](#where-things-are-stored) to remove them.

---

## Command reference

Every command has built-in help: `vmdeploy --help`, `vmdeploy deploy --help`, `vmdeploy profile add --help`.

**All commands at a glance.** Every command works with vCenter and with a standalone ESXi host unless it says
*vCenter only*. Read-only commands never change anything; the others change vSphere only after showing you what
they will do.

| Command | What it does | What it changes |
|---|---|---|
| [`profile add`](#vmdeploy-profile-add), [`profile list`, `default`, `remove`](#vmdeploy-profile-list--profile-default--profile-remove) | Save, list, choose and delete connection profiles | This computer only |
| [`forget-secret`](#vmdeploy-forget-secret) | Delete a password saved in the OS keychain | This computer only |
| [`doctor`](#vmdeploy-doctor) | Check the connection, licence, vSphere version and the account's privileges | Nothing (read-only) |
| [`inventory`](#vmdeploy-inventory) | Show datacenters, clusters, hosts, datastores and networks | Nothing (read-only) |
| [`list`](#vmdeploy-list) | List the VMs vmdeploy deployed | Nothing (read-only) |
| [`deploy`](#vmdeploy-deploy) | Deploy a VM from an OVA, OVF or ISO | vSphere, after you confirm the plan |
| [`destroy`](#vmdeploy-destroy) | Power off and delete a VM vmdeploy deployed | vSphere, after you confirm |
| [`images list`, `pull`, `clear-cache`](#images) | Show local images and presets, download one in advance, empty the download cache | This computer only |
| [`images prune`](#vmdeploy-images-prune) | Delete the ISO copies on datastores that no VM uses | vSphere: only the copies you choose |
| [`trust list`, `add`, `remove`](#certificates) | Review, add or forget remembered certificates and vCenter root CAs | This computer only |
| [`keyprovider list`](#key-providers-virtual-tpm-windows-11) | Key providers, which VMs use them, which hosts can use them (vCenter only) | Nothing (read-only) |
| [`keyprovider add`, `backup`, `default`, `remove`](#key-providers-virtual-tpm-windows-11) | Set up and manage key providers for virtual TPMs (vCenter only) | vCenter's key providers |
| [`access setup`, `remove`](#least-privilege-deploy-account) | Create or remove a least-privilege deploy account | vSphere, after you confirm |
| [`access audit`](#vmdeploy-access-audit) | Report what vmdeploy left in vCenter or ESXi | Nothing (read-only) |

### Options that work on most commands

| Option | What it does | Example |
|---|---|---|
| `-p NAME`, `--profile NAME` | Use this connection profile instead of the default | `vmdeploy doctor -p lab-esxi` |
| `-y`, `--yes` | Never ask anything: take answers from flags/manifest and stop with a clear message if one is missing. For scripts. | `vmdeploy deploy -f vm.yaml --yes` |
| `--trust-fingerprint SHA256` | Accept a server certificate without asking (for `--yes`); compare the fingerprint first | `vmdeploy doctor --yes --trust-fingerprint 4C:3D:58:…` |
| `-v`, `-vv` | Show more detail (put it **before** the command) | `vmdeploy -v deploy --preset ubuntu-lts` |
| `--version` | Show the installed version | `vmdeploy --version` |
| `--help` | Show the command's options | `vmdeploy deploy --help` |

### Connection profiles

A profile stores where to connect and how to sign in. You can have one per vCenter or ESXi host, and more than
one for the same server when you sign in with different accounts.

**Accounts and profiles are different things.** An *account* (for example `administrator@vsphere.local`, or
a restricted `deployer@vsphere.local`) lives in vCenter or ESXi and has a password and permissions. A
*profile* lives only on your computer and is a shortcut that says "connect to this server as this account".
It never holds the password. For example, after `vmdeploy access setup`:

| Profile (on your computer) | Connects to | As account (in vCenter) | Use it for |
|---|---|---|---|
| `vcsa` (your default) | `vcsa.example.com` | `administrator@vsphere.local` | `access setup` / `access remove`, anything needing an administrator |
| `vcsa-deployer` | `vcsa.example.com` | `deployer@vsphere.local` | Day-to-day `deploy`, `list`, `destroy` |

Commands use the default profile unless you pass `-p NAME`. `vmdeploy doctor -p vcsa-deployer` shows what
that account can do and where.

#### `vmdeploy profile add`

Create a profile. Run it with no options to be asked each question, or give the answers as options.

```bash
vmdeploy profile add                                   # guided, asks each question
vmdeploy profile add --host vcsa.example.com --name vcsa --auth password --username administrator@vsphere.local --no-remember
vmdeploy profile add --host 192.0.2.20 --name esxi01 --username root --default   # standalone ESXi host, make it the default
```

| Option | Meaning |
|---|---|
| `--host` | vCenter or ESXi address (name or IP). `host:port` also works |
| `--name` | A short name you choose, used with `-p` |
| `--auth` | `password` (most people), or `oauth-password`, `oauth-client-credentials`, `oauth-token` for federated sign-in ([docs/authentication.md](docs/authentication.md)) |
| `--username` | Optional; leave it out to be asked every time (the password is then never saved, because a saved password belongs to one account) |
| `--remember` / `--no-remember` | Save the password in the OS keychain after the first successful sign-in, or never. Saving needs `--username` |
| `--default` | Make this the profile used when `-p` is not given |
| `--port`, `--token-url`, `--client-id` | Non-standard HTTPS port; federated sign-in settings |

#### `vmdeploy profile list` / `profile default` / `profile remove`

```bash
vmdeploy profile list              # all profiles; * marks the default
vmdeploy profile default esxi01    # use esxi01 when no -p is given
vmdeploy profile remove esxi01     # delete the profile and any password saved for it
```

#### `vmdeploy forget-secret`

```bash
vmdeploy forget-secret vcsa        # delete the saved password for profile "vcsa"; the profile stays
```

### Checking your environment

#### `vmdeploy doctor`

Signs in and checks the connection, certificate, licence, vSphere version and your account's privileges.
For a restricted account it lists exactly where it can deploy (folders, hosts or clusters, datastores and
networks). Run it first whenever something does not work. Changes nothing.

```bash
vmdeploy doctor
vmdeploy doctor -p vcsa-deployer          # check the restricted account
```

#### `vmdeploy inventory`

Lists datacenters, clusters, hosts, datastores and networks. Changes nothing.

```bash
vmdeploy inventory
vmdeploy inventory -p esxi01
```

#### `vmdeploy list`

Lists the VMs this tool has deployed (it marks them in the VM's notes). Changes nothing.

```bash
vmdeploy list
```

### Deploying

#### `vmdeploy deploy`

Creates a VM. Choose **one** image source; without one, you are asked where the image is.

```bash
# Newest Ubuntu Server LTS, downloaded and verified automatically
vmdeploy deploy --preset ubuntu-lts

# An image you put in the images/ folder (see `vmdeploy images list` for the folder)
vmdeploy deploy --local my-appliance.ova
vmdeploy deploy --pick-local                           # choose from a list of what is in images/

# Download from a website, optionally checking the vendor's published SHA-256
vmdeploy deploy --url https://example.com/appliance.ova --sha256 3f5a…e91c

# An ISO or OVA already on a datastore (quotes are required because of the brackets and spaces).
# Without --datastore-file, choose "A file already on a datastore" to pick one from a list.
vmdeploy deploy --datastore-file "[datastore1] iso/ubuntu-24.04-live-server-amd64.iso"
vmdeploy deploy --datastore-file "[nas-ds] library/vendor-appliance.ova"

# Windows Server 2022 from your licensed ISO on a datastore (see docs/windows.md)
vmdeploy deploy --datastore-file "[datastore1] ISO/en-us_windows_server_2022_x64_dvd.iso"

# Answers from a file (a "manifest"); anything it leaves out is asked
vmdeploy deploy -f examples/ubuntu-server.yaml

# Re-create a VM with the same name (deletes the old one after asking; with --yes only VMs this tool created)
vmdeploy deploy -f examples/minimal.yaml --replace

# Fully unattended, with a machine-readable summary
vmdeploy deploy -f examples/unattended.yaml --yes --json > result.json
```

| Option | Meaning |
|---|---|
| `--preset NAME` | `ubuntu-lts`, `ubuntu-24.04`, `ubuntu-22.04` (`vmdeploy images list` shows all) |
| `--local FILE` / `--pick-local` | A file in the images folder (a full path also works) / pick from a list |
| `--url URL` | Download an `.ova` or `.iso` |
| `--datastore-file "[ds] path"` | Use an ISO or OVA that is already on a datastore (`--datastore-iso` still works) |
| `--sha256 HASH` | The expected checksum of the image; the deployment stops if it does not match |
| `-f FILE`, `--file FILE` | A YAML manifest with your answers ([docs/manifest.md](docs/manifest.md), [examples/](examples/)) |
| `--replace` | Delete and re-create an existing VM with the same name. You are asked first; with `--yes` only VMs this tool created are replaced |
| `--json` | Print a JSON summary when done (for scripts) |
| `-p`, `--yes`, `--trust-fingerprint` | See [Options that work on most commands](#options-that-work-on-most-commands) |

### Removing VMs

#### `vmdeploy destroy`

Powers off and permanently deletes a VM and its disks, after asking you to confirm.

```bash
vmdeploy destroy ubuntu01
vmdeploy destroy ubuntu01 --datacenter Lab     # when several datacenters have a VM with that name
vmdeploy destroy old-vm --force                # also allow VMs this tool did not create
vmdeploy destroy win01 --delete-iso            # also delete the ISO copy it used (if no other VM uses it)
```

| Option | Meaning |
|---|---|
| `NAME` | The VM's name, as `vmdeploy list` shows it |
| `--datacenter NAME` | Which datacenter, when several have a VM with that name |
| `--force` | Also allow deleting a VM that vmdeploy did not deploy |
| `--delete-iso` / `--keep-iso` | Delete or keep the VM's `vmdeploy-iso/` copy without being asked (default: ask; kept with `--yes`) |
| `-p`, `--yes`, `--trust-fingerprint` | See [Options that work on most commands](#options-that-work-on-most-commands) |

If the VM was installed from an ISO that vmdeploy put in a `vmdeploy-iso/` folder (uploaded from your computer
or copied from another host), `destroy` then asks **separately** whether to delete that copy too, but only if no
other VM uses it. The default is to keep it: the next deployment to that datastore reuses it (after checking
it) instead of uploading or copying again. `--delete-iso` / `--keep-iso` answer the question in scripts.

### Images

#### `vmdeploy images list`

Shows the images folder and what is in it, previously downloaded images, and the available presets.

```bash
vmdeploy images list
```

#### `vmdeploy images pull`

Downloads an image in advance (for example before travelling to a site with a slow link). Deployments
then reuse it.

```bash
vmdeploy images pull --preset ubuntu-lts
vmdeploy images pull --url https://example.com/appliance.ova --sha256 3f5a…e91c
```

| Option | Meaning |
|---|---|
| `--preset NAME` | A preset (`vmdeploy images list` shows them) |
| `--url URL` | An `.ova` or `.iso` to download |
| `--sha256 HASH` | With `--url`: the expected checksum; the download is refused if it does not match |

#### `vmdeploy images prune`

Lists every ISO copy vmdeploy left in `vmdeploy-iso/` folders on your datastores (host first, with size and
**which VMs use it**), and lets you tick which unused copies to delete. Copies a VM still uses are never offered.
Your original images elsewhere are not touched.

```bash
vmdeploy images prune                          # list, then choose what to delete
vmdeploy images prune --yes                    # list only
vmdeploy images prune --yes --delete-unused    # delete every copy no VM uses
```

#### `vmdeploy images clear-cache`

Deletes downloaded images, and OVA/OVF copies read from datastores, from this computer's cache, and reports
the space freed. Files you put in the images folder are not touched. Nothing on vCenter is changed.

```bash
vmdeploy images clear-cache
```

### Certificates

You normally never need these: the tool asks about certificates when it connects. They are for reviewing or
changing what you chose to remember.

```bash
vmdeploy trust list                              # remembered certificates and trusted vCenter root CAs
vmdeploy trust add vcsa.example.com                # trust a server now (asks, like the first connection)
vmdeploy trust add vcsa.example.com --vcenter-ca   # trust vCenter's root CA (covers its ESXi hosts too)
vmdeploy trust remove vcsa.example.com:443         # forget it; you will be asked again next time
```

`trust add` takes `--port N` for a server that does not use HTTPS port 443. `trust remove` takes the endpoint
exactly as `trust list` shows it. With `--vcenter-ca`, a server certificate that is not trusted yet is trusted
only for the download (you are asked, and it is not remembered; the CA covers it from then on), and the command
stops before asking anything if the certificate does not list the name you gave.

### Key providers (virtual TPM, Windows 11)

A virtual TPM needs a key provider in vCenter, and vCenter only uses a Native Key Provider (free, built into
vCenter) after it has been backed up. vmdeploy can do all of it, as an administrator
([details](docs/windows.md#virtual-tpm-and-the-key-provider)):

```powershell
vmdeploy keyprovider list                                # key providers, which VMs use them, which hosts can
vmdeploy keyprovider add                                 # add a Native Key Provider, make it the default, back it up
vmdeploy keyprovider backup                              # back up an existing one (asks for a file password)
vmdeploy keyprovider backup --provider NKP-01 --out D:\Keys\nkp-01.p12
vmdeploy keyprovider default --provider NKP-01           # make an existing one the default
vmdeploy keyprovider remove --provider NKP-Old           # refused while any VM uses it; asks you to type the name
```

| Command | Options and what it does |
|---|---|
| `keyprovider list` | Each key provider's type, whether it is the default and backed up, which VMs use its keys (and any VM whose configuration cannot be read), and which hosts can use a Native Key Provider (in a cluster, with a TPM 2.0 if required). Changes nothing |
| `keyprovider add` | `--name` (default `vmdeploy-nkp`), `--tpm-required` (only hosts with a physical TPM 2.0), `--default` / `--no-default` (default: yes when vCenter has none), `--backup` / `--no-backup`, `--out FILE`, `--no-password`. Shows its plan and asks before changing anything |
| `keyprovider backup` | `--provider NAME` (default: the only one, or asked), `--out FILE` (default `<provider>-<date>.p12` in the current folder; an existing file is never overwritten), `--no-password` (not recommended) |
| `keyprovider default` | `--provider NAME`: new virtual TPMs get their keys from it |
| `keyprovider remove` | `--provider NAME`. Refused while any VM uses its keys (those VMs could not start again), or while a VM's configuration cannot be read (it might use them) |

These need vCenter, an administrator (or an account with the `Cryptographer.ManageKeyServers` privilege), and
a profile that signs in with a password. For scripts, the backup password can come from the
`VMDEPLOY_BACKUP_PASSWORD` environment variable. **Keep the `.p12` file outside vCenter, and its password
separately** (for example in a password manager), never in a project folder or git repository: without both,
VMs with a virtual TPM cannot be recovered if vCenter is lost, and whoever has both can restore the key provider.
`backup` also works when the vSphere Client's **Back up** fails because vCenter is named by its IP address.

#### Virtual TPM: where it works

Windows 11 requires a TPM 2.0, so its VM needs a **virtual TPM**. vSphere encrypts a virtual TPM with a key that
only vCenter hands out, from a **key provider**, and only to hosts in a **vSphere cluster**. vmdeploy follows
what Broadcom supports and does not work around it:

| Your environment | Windows 11 / virtual TPM | What vmdeploy does |
|---|---|---|
| **vCenter, host in a cluster**, Native Key Provider | ✅ Supported | Deploys. Missing, not backed up or no default key provider: offers to fix it (`vmdeploy keyprovider`). |
| **vCenter, host in a cluster**, External KMS (Standard Key Provider) | ✅ Supported | Deploys with vCenter's default key provider. Setting up the KMS itself is done in the vSphere Client. |
| **vCenter, host not in a cluster** | ❌ Not supported with a Native Key Provider ([KB 369538](https://knowledge.broadcom.com/external/article/369538/cannot-add-vtpm-on-virtual-machine-resid.html)) | Stops before anything is created, names the hosts that are in a cluster, and explains the fix. |
| **ESXi host without vCenter** (or a host reached directly instead of through its vCenter) | ❌ Not supported by Broadcom ([KB 414781](https://knowledge.broadcom.com/external/article/414781/cannot-boot-windows-11-virtual-machine-w.html)) | Stops and explains. Other guests deploy normally. |
| **Free ESXi** | ❌ Not supported at all (read-only API) | Stops at sign-in. |

**New to vCenter?** A *cluster* is a folder-like container for hosts in the vCenter inventory. It can hold a single
host, and its extra features (DRS, HA, vSAN) can all stay off. Putting a host in a cluster changes your vCenter
inventory, so vmdeploy leaves that decision and that change to you. Plan for it: the vSphere Client puts the
host in maintenance mode while moving it, so its running VMs must be powered off or migrated first (take care
if the host runs vCenter, your firewall or your DNS), and you take it out of maintenance mode afterwards.
Broadcom's guides:
[Create a Cluster](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-resource-management/creating-a-drs-cluster/create-a-cluster.html),
[Relocate a host](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vcenter-and-host-management/managing-hosts-in-the-vsphere-client/relocate-a-host.html)
and the [Native Key Provider requirements](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-security/configuring-and-managing-vsphere-native-key-provider/vsphere-native-key-provider-overview.html).

**Experienced?** The Native Key Provider needs vSphere 7.0 U2 or later and a cluster object; DRS, HA and a host
TPM are not required (a host TPM is required only when the key provider has "Use key provider only with TPM
protected ESXi hosts" set). One key provider serves every cluster in the vCenter: there is no per-host key provider.
vmdeploy does not create, restore or move anything outside the `keyprovider` commands, and those only change key
providers.

### Least-privilege deploy account

#### `vmdeploy access setup`

Run by an **administrator** once. Creates an account that can only deploy VMs, only where you allow it, so
day-to-day deployments never use administrator credentials. You see the full plan before anything is created.

```bash
vmdeploy access setup                     # guided: asks who and where, shows the plan, asks to confirm
```

What you will be asked on **vCenter**: the datacenter, the **existing** user who will deploy (for example
`deployer@vsphere.local`; create it first in the vSphere Client under *Administration → Single Sign On →
Users and Groups*, because vCenter users cannot be created through the vSphere API), the VM folder, the
cluster or host, and the datastores and networks (space bar to tick several, Enter to continue).

**Why the folder matters.** The folder is the boundary of what the account can change. Its deploy rights
(create, change, power on/off and delete VMs) apply only to VMs **inside the folder you choose, including its
subfolders**. Everywhere else it can only *look* (it needs to see the inventory to offer you hosts, datastores
and networks), and VMs elsewhere on the same host or cluster stay out of its reach. So:

- **Choose "Create a new folder for this account (recommended)"**, the default. A folder of its own holds only
  the VMs this account deploys. The tool suggests a name (e.g. `vmdeploy-deployer`), lets you put it at the top
  of the datacenter or inside an existing folder (e.g. `/Lab/vmdeploy-deployer`), creates it after you
  confirm, and labels it in the vSphere Client (*Custom Attributes*: `vmdeploy` = "Created by vmdeploy access
  setup for …") so anyone can see where it came from.
- **Or pick an existing folder**, if your vCenter already has a place for these VMs. The rights then cover
  every VM already in it and in its subfolders; setup tells you how many there are.
- **Finding images on every datastore.** So the account can deploy from any ISO or OVA in vCenter, setup
  scans all datastores and asks "Which datastores may the account find images on?". The default, **All
  datastores**, gives it:
  - *Browse datastore* on every datastore (role `vmdeploy-deployer-browse`): it can list and read files there,
    so every image shows up in its picker. It cannot change anything there;
  - *Browse* + *Low level file operations* where images were found (role `vmdeploy-deployer-images`), so
    those ISOs are copied server-side, host to host. Low level file operations also allows renaming or
    deleting files there, which the plan points out.

  An image added later on another datastore is still visible; it is then copied through the deploying
  computer (slower; the plan says so). Choose **Choose datastores** or **None** to limit this, e.g. in
  environments where the account should not read other VMs' files (`--image-datastore NAME…` / `none`). A
  library on a **shared** datastore (NFS, iSCSI, vSAN) is used in place by every host. The lists show the
  host first (`192.0.2.10 › datastore1 …`, or `shared (4 hosts) › …`).
- **You can rename or move the folder later** in the vSphere Client: the rights belong to the folder and move
  with it, and `access remove` still finds a folder it created. VMs you move *out* of the folder are no longer
  managed by the account.

On a **standalone ESXi host** you are only asked for a name for the new local user. The tool creates it with
a strong random password, which it shows **once** or saves in your OS keychain if you choose. ESXi has no VM
folders, so the account can also manage the VMs already on that host; setup tells you how many there are.

Either way, it creates a profile for the new account (default `<your profile>-deployer`):

```bash
vmdeploy deploy --preset ubuntu-lts -p vcsa-deployer
```

All answers can be given as options, for scripts:

```bash
vmdeploy access setup -p vcsa --yes --user deployer@vsphere.local --new-folder vmdeploy-deployer --compute Lab-Cluster \
  --datastore nvme-ds01 --datastore nas-ds02 --network "VLAN20-Servers"
vmdeploy access setup -p esxi01 --yes --user vmdeploy --no-remember     # standalone ESXi
```

| Option | Meaning |
|---|---|
| `--user` | vCenter: existing user (`user@domain`). ESXi: name of the local user to create (default `vmdeploy`) |
| `--new-folder NAME` | vCenter: create a folder just for this account (recommended), at the top (`vmdeploy-ops`) or inside an existing folder (`Lab/vmdeploy-ops`); `access remove` deletes it when empty |
| `--datacenter`, `--folder`, `--compute` | vCenter: where VMs may be created. `--folder` picks an existing folder (`/` is the datacenter's top VM folder); `--compute` is a cluster or host name |
| `--datastore`, `--network` | vCenter: which datastores and networks may be used (repeat the option for more than one) |
| `--image-datastore` | vCenter: where the account may find images. `all` (default): see every datastore, copy rights where images are; `none`; or datastore names (repeatable) for copy rights only there |
| `--new-profile NAME` | Name of the profile to create for the account |
| `--remember` / `--no-remember` | ESXi: save the generated password in the OS keychain / show it once |
| `--role-name` | Name of the role to create (default `vmdeploy-deployer`) |

Details and safety rules: [docs/least-privilege.md](docs/least-privilege.md).

#### `vmdeploy access remove`

Run by an administrator. Lists everything `access setup` created (permissions, roles, the ESXi user, the
local profile and saved password), asks to confirm, and deletes it. Permissions you created yourself are
never touched.

```bash
vmdeploy access remove
vmdeploy access remove -p esxi01 --yes --delete-user vmdeploy   # unattended (ESXi); see notes below
```

On ESXi, the local user is deleted automatically when the host confirms vmdeploy created it. Otherwise you are
asked, and with `--yes` you name it with `--delete-user`.

**VMs the account deployed.** If the account's folder still holds VMs, `access remove` lists them and asks
what to do: **keep them** (only the access is removed; the folder stays), **delete them now** (it powers them
off and deletes them in the same administrator session, but only VMs deployed by vmdeploy), or cancel. With
`--yes` the VMs are kept unless you add `--delete-vms`. A folder that setup created is deleted once it is
empty, and you can run `access remove` again later to finish the clean-up.

```bash
vmdeploy access remove                         # asks what to do with the account's VMs
vmdeploy access remove --yes --delete-vms      # unattended: delete the account's VMs, the access and its folder
```

| Option | Meaning |
|---|---|
| `--delete-vms` | Also delete the VMs in the account's folder (only VMs deployed by vmdeploy). Default: keep them |
| `--delete-iso` / `--keep-iso` | With deleted VMs: delete or keep the ISO copies they used, if nothing else uses them |
| `--delete-user NAME` | ESXi: delete this local user even when the host cannot confirm vmdeploy created it (repeatable) |
| `--role-name NAME` | The role name setup used, if it was not the default `vmdeploy-deployer` |

#### `vmdeploy access audit`

A **read-only** check of what vmdeploy has left in your vCenter or ESXi host: roles, permissions (including
any pointing at roles that no longer exist), the `vmdeploy` custom attribute, labelled or `vmdeploy…` folders,
VMs deployed by vmdeploy, open sessions of `vmdeploy` accounts, and **VM files on datastores that no VM in the
inventory uses** (for example after a VM was removed with *Remove from Inventory* instead of *Delete from
Disk*), and ISO copies in `vmdeploy-iso/` that no VM uses. Each area says "nothing found" or lists what it found
and how to remove it. Nothing is changed.

It also **reminds you about the user accounts** used with `access setup` (remembered on this computer, without
passwords) and any account whose name starts with `vmdeploy`, and says whether each still exists. That is not
a leftover, since accounts are yours to manage, but it helps you delete one created only for vmdeploy.

```bash
vmdeploy access audit            # sign in as an administrator to see everything
```

**What stays for you to delete by hand (vCenter):** the user account itself, because the vSphere API cannot
delete vCenter Single Sign-On users (*Administration → Single Sign On → Users and Groups*), and any folder you
made yourself. `access remove` reminds you.

---

## Image sources and integrity

| Source | How to use it | Integrity check |
|---|---|---|
| Local file | Put it in `images/` (ignored by git) and use `--local name.ova`, or `--pick-local` to choose. A full path also works. | SHA-256 against `--sha256` / `image.sha256` if given; otherwise the hash is computed and shown. |
| URL | `--url https://…/file.ova` or `.iso`. Cached in your user cache folder and reused on later runs. | Against `--sha256` if given. Otherwise the hash is shown and remembered, and you are warned if the file at that URL changes later. |
| Preset | `--preset ubuntu-lts`, `ubuntu-24.04`, `ubuntu-22.04` (`vmdeploy images list` shows all). | SHA-256 published in Canonical's image metadata. |
| File on a datastore | `--datastore-file "[datastore1] path/file.iso"` (ISO, OVA or OVF), or choose **"A file already on a datastore"** to pick from a list | ISO: confirmed present; with `--sha256` it is read once and checked. OVA/OVF: read once into your cache (needs that much free space on your computer, see below), then its manifest is verified like any OVA. |

For **OVA/OVF** packages, every file listed in the package's `.mf` manifest is verified **before** anything
is uploaded, and the bytes sent to the host are hashed again during upload.

### Why an OVA on a datastore passes through your computer

**ISOs and OVAs on a datastore are handled differently**, because vSphere treats them differently:

| | ISO on a datastore | OVA/OVF on a datastore |
|---|---|---|
| How the VM uses it | The VM boots the ISO **where it is**. | The OVA is a package: its disks must be **unpacked into a new VM**. |
| If the target host cannot see that datastore | vCenter **copies it host to host** into `vmdeploy-iso/` on the VM's datastore (nothing passes through your computer). Later deployments reuse that copy once it is checked: in full against `--sha256` if you give one, otherwise by comparing samples of it with the original ISO. A copy that does not match is left alone and a fresh one is made under a new name. | Not applicable: the VM can go to **any** datastore. |
| Does it pass through your computer? | **No.** | **Yes, always**, even if the OVA is on the same host you deploy to. |
| Free space needed on your computer | None. | About the size of the `.ova` file, plus 1 GB. |

**Why:** vCenter's OVA import (the same one the vSphere Client's *Deploy OVF Template* uses) cannot open a
file that is already on a datastore. vCenter creates an empty VM from the package's description, and the
*client* must then send the disk contents to the ESXi host. In the vSphere Client your browser does this; with
vmdeploy, your computer does. So vmdeploy:

1. reads the `.ova` (or the `.ovf` and its disk files) from the datastore **once** into your cache folder
   (see [Where things are stored](#where-things-are-stored)), checking first that there is room;
2. verifies the package's manifest;
3. uploads the disk data **straight to the ESXi host** that will run the VM (not through vCenter).

**What it costs:**

- The data is about the size of the `.ova` file, not the VM's disk size. A Cisco ISE OVA with a 300 GB disk is
  much smaller as a file, and its thin disk only stores what is written.
- The copy stays in your cache, so the next deployment of the same file skips step 1. `vmdeploy images
  clear-cache` deletes it (and reports the space freed). To use a bigger drive, set `VMDEPLOY_CACHE_DIR`.
- A slow link between your computer and the hosts (VPN, Wi-Fi) makes OVA deployments slow. Running vmdeploy
  on a machine close to the hosts helps.

A fully server-side alternative (importing the OVA into a vCenter Content Library and deploying from there)
is on the [roadmap](#known-limitations-and-roadmap).

**ISO deployments** create the VM (empty disk, ISO attached, chosen firmware/guest OS), power it on, and
hand over to you in the VM console to install the OS.

**OVA/OVF deployments** produce a ready VM. For cloud-init capable images (such as the Ubuntu presets)
the first-boot settings are applied automatically.

---

## Manifests (optional)

A manifest is a small text file (YAML) holding your answers, so you can repeat a deployment or run it
unattended. Anything the manifest leaves out is read from the image or asked. Unknown keys are rejected,
so typos are caught early.

```yaml
vm: {name: web01}
image: {preset: ubuntu-lts}
placement: {cluster: Lab-Cluster, datastore: nvme-ds01}
resources: {cpu: 4, memory_gb: 8, disk_gb: 60}
networks: [{portgroup: VLAN20-Servers}]
guest:
  username: alex
  ssh_authorized_keys: ["ssh-ed25519 AAAA… alex@workstation"]
  network: {mode: static, address: 192.0.2.50/24, gateway: 192.0.2.1, dns: [192.0.2.1]}
```

Use it with `vmdeploy deploy -f my-vm.yaml`. Full reference: [docs/manifest.md](docs/manifest.md).
Ready-made examples in [examples/](examples/): `minimal.yaml`, `ubuntu-server.yaml`, `appliance-ova.yaml`,
`iso-install.yaml`, `unattended.yaml`.

---

## Sign-in, certificates and secrets

- **Methods**: `password` (local, `vsphere.local`, AD over LDAP, IWA identity sources), `oauth-password`,
  `oauth-client-credentials` and `oauth-token` (federated SSO). Details and identity-provider setup are in
  [docs/authentication.md](docs/authentication.md).
- **Secrets** are never written to profiles. Choose per profile between the OS keychain and asking every
  time; a saved secret is only ever used for the server, account and sign-in method it was saved for.
  Automation can use the `VMDEPLOY_PASSWORD`, `VMDEPLOY_CLIENT_SECRET` and `VMDEPLOY_ACCESS_TOKEN`
  environment variables, and `VMDEPLOY_BACKUP_PASSWORD` for key provider backups. All of them are removed
  from logs.
- **Certificates**: nothing to set up beforehand. The first time the tool connects to a server whose
  certificate your OS does not already trust, it shows the certificate and offers these choices:
  - *Trust for this session*: nothing is saved; you are asked again next time.
  - *Trust and remember*: pins that exact certificate; if it ever changes you are warned and asked again.
  - *Trust this vCenter's root CA* (vCenter only; not for a certificate that has changed, nor for one that does
    not list the name you connected by, which no CA could make valid):
    downloads the CA bundle vCenter publishes, over a connection pinned to the certificate you are looking
    at, and saves it only if it actually validates that certificate. Best when vCenter uses its own CA
    (VMCA, the default), because it also covers its ESXi hosts and certificate renewals. Like any CA you trust,
    it then vouches for every certificate it has signed, whichever server presents it.
  - *Cancel* (the default): disconnects before any credentials are sent.

  If the certificate does not list the name you connected by (common when vCenter was installed with its IP
  address as its name and you use a host name), the prompt says so. If you know one of the names or addresses
  it lists to be this server, use that one instead (in the profile too): for that name, *Trust this vCenter's
  root CA* works, and once you have chosen it, later connections need no question.

  `vmdeploy doctor` shows which kind of trust is in use. ESXi hosts that receive disk uploads are trusted
  automatically when their certificate matches the thumbprint vCenter reports for them. Every choice is
  written to the log with the certificate's fingerprint.

## Unattended / automation use

```bash
# macOS / Linux
VMDEPLOY_PASSWORD='…' vmdeploy deploy -f examples/unattended.yaml --yes --json > result.json
```

```powershell
# Windows PowerShell
$env:VMDEPLOY_PASSWORD = '…'
vmdeploy deploy -f examples/unattended.yaml --yes --json > result.json
Remove-Item Env:VMDEPLOY_PASSWORD
```

Manifest paths may use `/` on every OS, including Windows.

- `--yes` never prompts. A missing answer stops the run before anything changes and names the manifest
  field to set (exit code 2).
- Untrusted certificates are refused in `--yes` mode. Trust them once interactively (`vmdeploy trust add`),
  or pass `--trust-fingerprint <SHA-256>` after verifying the fingerprint out-of-band.
- Exit codes: `0` success, `1` error, `2` configuration / missing input, `3` licence restriction,
  `130` cancelled or declined.

## Troubleshooting

| You see | What to do |
|---|---|
| `vmdeploy: command not found` / `The term 'vmdeploy' is not recognized` | With option B, activate the virtual environment first (`.venv\Scripts\activate` or `source .venv/bin/activate`), or run `.venv\Scripts\vmdeploy.exe`. With pipx, run `pipx ensurepath` and open a new terminal. |
| `running scripts is disabled on this system` | See the note under [Install the tool](#install-the-tool). |
| `Failed building wheel for pyyaml` | See [If pip tries to compile something](#if-pip-tries-to-compile-something). |
| `The certificate presented by … is not trusted` | You used `--yes`, which never asks. Run the same command without `--yes` once, or pass `--trust-fingerprint`. |
| `… is not trusted (Hostname mismatch …)` or `(IP address mismatch …)`, or the prompt says the certificate does not list the name | The certificate does not list the name you used (see *Names/IPs* at the prompt), e.g. a vCenter installed with its IP address as its name. If you know one of the names or addresses it lists to be this server, use that one in the profile (`vmdeploy profile add`). Otherwise check the fingerprint before choosing *Trust and remember*. |
| `A value is needed for: …` | You used `--yes` and an answer is missing. The message names the manifest field or option to add. |
| Exit code 3, licence explanation | The host has the free ESXi licence, which does not allow creating VMs through the API. |
| Privileges missing in `doctor` | Use an administrator account, or ask one to run `vmdeploy access setup` for you. |
| `Datastore '…' was not found` | Datastore names are case-sensitive and must match exactly; `vmdeploy inventory` lists them. |
| `Datastore '…' exists in several datacenters` | Datastore names repeat across datacenters (e.g. `vsanDatastore`). Name the datacenter in a manifest: `placement: {datacenter: NAME}`. |
| `The certificate of … expired` (or `is not valid before`) | TLS refuses a certificate outside its dates even when you trust it. Renew the server's certificate (vSphere Client: the host's *Configure > Certificate*; vCenter: *Administration > Certificate Management*), or check this computer's date and time. |
| Windows 11 stops: the host is not in a cluster, or there is no vCenter | See [Virtual TPM: where it works](#virtual-tpm-where-it-works). |
| `already has rights across this vCenter` in `access setup` | Use a dedicated account that is in no group (see [Step 4](#step-4-use-a-restricted-account-for-deployments-optional-recommended)). |
| No IP address reported for an appliance | Many appliances (routers, firewalls) do not report their address to vCenter; check in the VM console. |
| Anything else | Run the command again with `-v` (`vmdeploy -v deploy …`) and look at the log file printed at the end. |

## Where things are stored

Everything is kept in your own user profile, in the standard place for your operating system. Nothing is
written to the install folder, and no administrator / root rights are needed.

| What | Windows | macOS | Linux | Override |
|---|---|---|---|---|
| Profiles, trusted certificates, accounts used with `access setup` | `%LOCALAPPDATA%\vsphere-vm-deployment` | `~/Library/Application Support/vsphere-vm-deployment` | `~/.config/vsphere-vm-deployment` | `VMDEPLOY_CONFIG_DIR` |
| Downloaded images | `%LOCALAPPDATA%\vsphere-vm-deployment\Cache\images` | `~/Library/Caches/vsphere-vm-deployment/images` | `~/.cache/vsphere-vm-deployment/images` | `VMDEPLOY_CACHE_DIR` |
| Logs (secrets removed), and long licence texts (`licences/`) | `%LOCALAPPDATA%\vsphere-vm-deployment\Logs` | `~/Library/Logs/vsphere-vm-deployment` | `~/.local/state/vsphere-vm-deployment/log` | `VMDEPLOY_LOG_DIR` |
| Local images for `--local` | `.\images` in the current folder | `./images` in the current folder | `./images` in the current folder | `VMDEPLOY_IMAGES_DIR` |
| Passwords / client secrets | Credential Manager | Keychain | Secret Service (GNOME Keyring, KWallet) | Only stored if you enable it for the profile |

On Linux the standard `XDG_CONFIG_HOME`, `XDG_CACHE_HOME` and `XDG_STATE_HOME` variables are respected.
The override variables accept `~` on every OS (e.g. `VMDEPLOY_CACHE_DIR=~/vm-images`). The log path is
also printed after every run. Downloaded image files get names that are valid on all three systems.

### Using vmdeploy without saving any credentials or certificates

Nothing secret is saved unless you ask for it:

- **Passwords:** answer **No** to "Save the password … in the OS keychain" in `vmdeploy profile add` (or pass
  `--no-remember`). You are then asked for the password on every run, and it only exists in memory.
- **Certificates:** choose **1) Trust for this session** at the certificate prompt. The decision lasts until
  the command finishes, and you are asked again next time.
- **Profiles** hold only the server address, port, sign-in method and (optionally) username, never a password.

Uninstalling the tool, or deleting its virtual environment (`.venv`) or install folder, does **not** remove
saved certificates, keychain entries or profiles: they are kept in your user profile (see the table above).
To remove them:

```bash
vmdeploy trust list                       # then: vmdeploy trust remove <endpoint>
vmdeploy forget-secret <profile>          # delete a saved password from the OS keychain
vmdeploy profile remove <profile>         # delete the profile and its saved secrets
```

To remove everything after uninstalling, also delete the folders listed in the table above.

## Known limitations and roadmap

- **Application/service installation inside the VM** (e.g. Docker containers) is the
  next planned feature.
- **vSAN**: VMs get the datastore's default storage policy; choosing other SPBM policies is planned.
- **ISO installs** stop at the OS installer in the console. Keystroke-driven unattended installs are planned.
- **Windows guest customisation** (sysprep / customization specs) is not implemented yet.
- **Windows** is installed from its ISO in the VM console (with the right virtual hardware set up for you);
  an unattended install with an answer file is planned. See [docs/windows.md](docs/windows.md).
- **Multi-VM OVF packages** (vApps / VirtualSystemCollection) are not supported.
- **First-boot network settings** (`guest.network`) configure the first network adapter only; configure any
  others inside the guest.
- **OVAs/OVFs always pass through your computer**, even when already on a datastore (vSphere's import works
  that way; [details](#why-an-ova-on-a-datastore-passes-through-your-computer)). Planned: an optional vCenter
  Content Library route, so vCenter imports the OVA itself and keeps it for later deployments (vCenter only;
  standalone ESXi keeps the current method).
- **Free ESXi** (vSphere Hypervisor licence) is out of scope: its API is read-only. Revisit only if Broadcom
  changes that.
- **Virtual TPM (Windows 11)** works only through vCenter, on a host in a cluster ([details](#virtual-tpm-where-it-works)).
  vmdeploy does not create clusters, and does not offer host-local TPM keys on ESXi without vCenter (Broadcom
  does not support it). An External KMS (Standard Key Provider) on hosts outside a cluster is under review:
  Broadcom's product documentation does not state whether it needs a cluster, so vmdeploy does not block it.
- **Not yet tested in a real environment** (covered by simulator tests): DRS clusters ("Let DRS choose the
  host"), distributed switches (VDS portgroups), vSphere 9, and federated sign-in. Reports welcome.
- **Federated sign-in** follows Broadcom's documented token-exchange flow but has not yet been tested against
  a real identity provider (reports welcome); the browser-based authorization-code flow and Windows SSPI are not implemented.
- **Ubuntu preset metadata** is fetched over HTTPS and image hashes are verified, but the GPG signature of
  Canonical's metadata is not checked yet.
- **vCenter users for `access setup`** must already exist: the vSphere API cannot create vCenter Single
  Sign-On users.

## Reporting problems

Open an issue with the command you ran, what you expected, and the log file printed at the end of the run.
Passwords, tokens, session cookies and cloud-init user-data are removed from logs automatically, but please
look the log over before attaching it.

## Contributing / testing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/testing.md](docs/testing.md).

## License and trademarks

Licensed under the [Apache License 2.0](LICENSE).

VMware, vSphere, vCenter and ESXi are trademarks of Broadcom Inc. and/or its subsidiaries. Ubuntu is a
trademark of Canonical Ltd. This is an independent project, not affiliated with or endorsed by Broadcom or
Canonical; the names are used only to describe compatibility. See [NOTICE](NOTICE).
