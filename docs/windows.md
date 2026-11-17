# Windows VMs

vmdeploy installs Windows from the installation ISO, the same way as any other ISO: it creates the VM with
the right virtual hardware, boots Windows Setup, and hands over to you in the VM console. You then install
Windows, enter your product key (or activate it later), and install VMware Tools.

Supported: **Windows 10, Windows 11, Windows Server 2016, 2019, 2022 and 2025** (64-bit).

## The ISO

Use your organisation's licensed media, for example from the Microsoft 365 admin center (volume licensing) or
a Visual Studio subscription. Windows then installs as a normal edition, not an evaluation, ready for your
product key or KMS activation. Note the SHA-256 checksum your download portal shows.

| Where the ISO is | How to use it |
|---|---|
| Already on a datastore | `vmdeploy deploy --datastore-file "[datastore1] ISO/windows_server_2022.iso"`, or choose **"A file already on a datastore"** and pick it from the list. Add `--sha256 <checksum>` to have it checked (it is read once through your computer) |
| On your computer | Copy it into the `images/` folder and use `--local file.iso` or `--pick-local`, with `--sha256 <checksum from the portal>` to verify it. It is uploaded to the VM's datastore once; later deployments reuse that upload after checking its full SHA-256 |
| On an internal web server | `--url https://…/windows.iso --sha256 <checksum>` |

**ISO on another host's local datastore.** A VM can only boot an ISO from a datastore its host can see. If
you pick an ISO on, say, host 1's local `datastore1` but deploy to host 2, vmdeploy copies it once to the VM's
datastore (`vmdeploy-iso/` folder). vCenter copies it host to host, so nothing passes through your computer.
Later deployments reuse the copy after checking it: with `--sha256`, its full SHA-256; otherwise a comparison
of samples with the original ISO. A copy that does not match is left alone, and a fresh one is made under a new
name. ISOs on shared datastores (NFS, iSCSI, FC, vSAN) are used in
place. A restricted account needs *Browse datastore* and *Low level file operations* on the ISO's datastore
for the copy; pre-flight says so if it is missing.

## Sizing

The guest operating system is asked before the sizing, so vCPU, memory and disk are pre-filled with
**VMware's recommendation for that Windows version** (the values the vSphere Client's New VM wizard uses),
raised to **Microsoft's minimum** where that is higher. Each question shows both, so you can press Enter or
go higher.

| Version | Microsoft minimum (vCPU / RAM / disk) | Below the minimum |
|---|---|---|
| Windows 11 | 2 / 4 GB / 64 GB | **Blocked**: Windows 11 Setup refuses to install |
| Windows 10 | 1 / 2 GB / 32 GB | Warning |
| Windows Server 2025 | 1 / 2 GB (4 GB recommended) / 32 GB | Warning |
| Windows Server 2022, 2019, 2016 | 1 / 2 GB / 32 GB | Warning |

Server figures are for *Server with Desktop Experience*; Server Core needs less. Microsoft publishes
minimums, not recommendations ("The highly diverse scope of potential deployments makes it unrealistic to
state recommended hardware requirements"), which is why the suggested values come from VMware.
Sources: [Windows Server hardware requirements](https://learn.microsoft.com/windows-server/get-started/hardware-requirements),
[Windows 11 requirements](https://learn.microsoft.com/windows/whats-new/windows-11-requirements),
[Windows 10 system requirements](https://support.microsoft.com/windows/windows-10-system-requirements-6d4e9a79-66bf-7950-467c-795cf0386715).

## What vmdeploy sets up for Windows

The guest type is recognised from Microsoft's ISO file names (e.g. `…windows_server_2022…`, `…Win11…`,
build numbers such as `20348`), and you can always pick another one.

| Setting | Windows | Why |
|---|---|---|
| Firmware | UEFI with Secure Boot | Required by Windows 11; recommended for all |
| Disk controller | NVMe (LSI Logic SAS on VM versions older than 13) | Windows Setup has these drivers built in; it cannot see a PVSCSI disk without an extra driver |
| Network adapter | e1000e | Driver built into Windows; switch to VMXNET3 after installing VMware Tools if you want the best performance |
| Virtual TPM 2.0 | Windows 11: always. Server 2025: offered (default yes). Others: offered | Windows 11 refuses to install without TPM 2.0; BitLocker and Credential Guard use it |
| VM compatibility | The newest the host supports (or your administrator's policy) | NVMe needs version 13+, vTPM 14+ |

Everything can be set in a manifest instead (`hardware.guest_os`, `hardware.vtpm`, `networks[].adapter`, …).

## Virtual TPM and the key provider

A virtual TPM needs a **key provider** in vCenter. vCenter uses it to encrypt the VM's TPM data (the VM's
configuration files are encrypted; its disks are not). `vmdeploy doctor` shows whether one is available,
including a Native Key Provider that exists but is not backed up yet (vCenter does not use it until then).

**Windows 11 is not deployed without a virtual TPM.** vCenter would create such a VM without complaint, but
Windows 11 Setup then stops at its requirements check, so vmdeploy checks the key provider as soon as it knows the
image is Windows 11, before sizing and the review:

- **Interactively** (signed in with a password as an administrator), it explains why and offers the fix that fits:
  *back up* the Native Key Provider that exists but is not backed up, *add* one (and make it the default and back
  it up), or *make* an existing one the default. That change is separate from the deployment: it has its own plan
  and confirmation, and you can cancel instead (nothing is changed). The deployment then continues with a virtual
  TPM.
- **With `--yes`**, a restricted account, or federated sign-in, it stops before anything is created and names the
  exact `vmdeploy keyprovider ...` command to run first.
- **On a host outside a cluster**, or an ESXi host without vCenter, it stops and explains instead: a key
  provider would not help there (see below).
- The only way past it is an explicit `hardware.vtpm: false` in a manifest (for installs that bypass Setup's TPM
  check, which Microsoft does not support), and the review warns about it.

**With vmdeploy** (an administrator; vSphere 7.0 U2 and later):

```powershell
vmdeploy keyprovider add -p <vcenter-profile>     # add a Native Key Provider, make it the default, back it up
vmdeploy keyprovider list -p <vcenter-profile>    # check: Default yes, Backed up yes
```

`vmdeploy keyprovider default --provider <name>` makes an existing key provider the default.

**A Native Key Provider only works on hosts that are in a cluster.** vCenter refuses a virtual TPM on a host
outside a cluster (*"The host does not support Native Key Provider because it is not in a cluster"*,
[Broadcom KB 369538](https://knowledge.broadcom.com/external/article/369538/cannot-add-vtpm-on-virtual-machine-resid.html)).
A single-host cluster with DRS, HA and vSAN off is enough. vmdeploy does not create clusters or move hosts:
that changes your vCenter inventory, so it is your decision. Plan for it: moving a host into a cluster in the
vSphere Client (vCenter 8.0.3, cluster Quickstart > Add hosts) puts the host in **maintenance mode** first, so
its running VMs must be powered off or migrated (think of a firewall, DNS or domain controller VM on that host),
and the host must be taken out of maintenance mode afterwards before it can run VMs again. Quickstart's next
step, "Configure cluster", is not needed for a key provider (use "Skip Quickstart"). `vmdeploy keyprovider list` shows which hosts are
in a cluster, and Windows 11 on a host outside a cluster stops before anything is created, naming the hosts that
are in one. Broadcom's guides:
[Create a Cluster](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-resource-management/creating-a-drs-cluster/create-a-cluster.html),
[Relocate a host](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vcenter-and-host-management/managing-hosts-in-the-vsphere-client/relocate-a-host.html),
[Native Key Provider requirements](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-security/configuring-and-managing-vsphere-native-key-provider/vsphere-native-key-provider-overview.html).
The full support table is in the [README](../README.md#virtual-tpm-where-it-works).

Also note: the vSphere Client ticks **"Use key provider only with TPM protected ESXi hosts"** by default: such a key provider only works on hosts with a physical TPM 2.0. `vmdeploy keyprovider list` shows which hosts have one, and the pre-flight check stops a virtual-TPM VM on a host without one.

`add` shows its plan before changing anything, asks for a name (default `vmdeploy-nkp`), makes it the default
key provider when there is none, and then backs it up (`--no-backup` to skip; `backup` later). It leaves "only
hosts with a TPM" off unless you pass `--tpm-required`. `vmdeploy keyprovider remove` deletes a key provider,
but refuses while any VM still uses its keys (those VMs could not start again) or while a VM's configuration
cannot be read (it might use them), and asks you to type its name.

**Or in the vSphere Client**, to add the free **Native Key Provider**:

1. In the vSphere Client, select the vCenter Server, then **Configure → Security → Key Providers**.
2. **Add → Add Native Key Provider**, give it a name, and leave "Use key provider only with TPM protected ESXi
   hosts" unticked unless your hosts have physical TPMs.
3. Select it and click **Back up**. vCenter only uses a Native Key Provider after it has been backed up.
   Keep the `.p12` file somewhere safe outside vCenter, and its password separately (for example in a
   password manager): without both, VMs with a virtual TPM cannot be recovered if vCenter is lost.

**If "Back up" fails** with *"Back up of Native Key Provider has failed."*: this happens when vCenter was installed
with its IP address as its system name (PNID) and has no proper host name, which is common in small and test installations. The
vSphere Client builds the download link from that name, so the link points at "localhost" (Broadcom KB 312030,
KB 404088). Check on the vCenter appliance (SSH, `shell`):

```bash
/usr/lib/vmware-vmafd/bin/vmafd-cli get-pnid --server-name localhost   # an IP address here...
hostname -f                                                            # ...and "localhost" here: this case
```

Back it up with vmdeploy instead, signed in as an administrator (`vmdeploy keyprovider add` uses the same
method, so it works in this case too):

```powershell
vmdeploy keyprovider backup -p <vcenter-profile>
```

It asks for a password for the backup file (or set `VMDEPLOY_BACKUP_PASSWORD`; `--no-password` skips it, not
recommended), uses vCenter's documented API to export the key provider, downloads the file from the address you
are connected to (whatever name vCenter put in the link), and saves `<provider>-<date>.p12` in the current folder
(`--out` to choose). vCenter then shows the key provider as backed up and uses it. The lasting fix is to give
vCenter a real host name (an FQDN with DNS records, changed in the appliance management page on port 5480), which
regenerates its certificates.

A restricted deploy account also needs the *Cryptographic operations* privileges listed in
[least-privilege.md](least-privilege.md) (`vmdeploy access setup` includes them), including *Direct Access* to
open the console of a VM with a vTPM.

### Windows 11 on an ESXi host without vCenter

**Not supported.** Broadcom does not support a virtual TPM on an ESXi host that vCenter does not manage
([KB 414781](https://knowledge.broadcom.com/external/article/414781/cannot-boot-windows-11-virtual-machine-w.html)),
so vmdeploy stops and explains instead of working around it. Deploy Windows 11 through vCenter, to a host in a
cluster. The same applies when you connect straight to a host that a vCenter manages: use the vCenter's profile.
Other guests (Linux, Windows Server, earlier Windows) deploy to such hosts normally.

## After Windows is installed

1. **Install VMware Tools**: VM → Guest OS → Install VMware Tools in the vSphere Client, then run setup from
   the virtual DVD drive. It adds the VMXNET3 and PVSCSI drivers, time sync, and lets vCenter see the VM's IP
   address.
2. **Activate Windows** with your product key or KMS.
3. Optionally eject the installation ISO (VM → Edit Settings → CD/DVD drive → Client Device). If vmdeploy
   copied or uploaded it into `vmdeploy-iso/`, the copy is kept for the next deployment; `vmdeploy images prune`
   shows which copies are no longer used and deletes the ones you choose.

Unattended installation (an `autounattend.xml` answer file for a hands-off install) is planned.
