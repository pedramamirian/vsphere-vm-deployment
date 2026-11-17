# Least-privilege account

Run the tool with a dedicated account that only has the privileges it needs, granted only where it needs
them. The full list lives in
[`src/vsphere_vm_deployment/data/privileges.yaml`](../src/vsphere_vm_deployment/data/privileges.yaml), and
`vmdeploy doctor` checks it against your vCenter:

- it reports any privilege ID that your vCenter version does not know (please open an issue if you see one);
- it reports which privileges your account is missing at the top of the inventory.

During `vmdeploy deploy` the pre-flight step checks the exact folder, resource pool, datastore and network
you chose. Missing privileges are shown as warnings before anything is changed.

## Automatic setup (recommended)

An administrator runs this once. Day-to-day deployments then never use administrator credentials:

```bash
vmdeploy access setup -p <admin-profile>     # asks who and where, shows the plan, changes nothing until you confirm
vmdeploy deploy -p <admin-profile>-deployer  # deploy as the restricted account
vmdeploy access remove -p <admin-profile>    # delete everything setup created
```

What setup creates:

| | vCenter Server | Standalone ESXi host |
|---|---|---|
| Role `vmdeploy-deployer` | Exactly the deploy privileges below | Same |
| Role `vmdeploy-deployer-read` | Read-only, granted at the top of the inventory so the account can discover it | Not needed |
| Roles `vmdeploy-deployer-images`, `vmdeploy-deployer-browse` | For images on other datastores: *Browse* and *Low level file operations* where images are found, *Browse* on every other datastore (the default, "All datastores"; see the last rows of [Privileges](#privileges)) | Not needed |
| VM folder | Recommended: a **new folder** for the account (`--new-folder`, at the top or inside an existing folder), labelled with the custom attribute `vmdeploy`; `access remove` deletes it when empty. Or an existing folder (`--folder`) | Not applicable (ESXi has no VM folders) |
| Permissions | Deploy role on the VM folder you choose (also applies to VMs inside it), on the chosen cluster or host (placement only: *not* inherited by the VMs already running there), and on each datastore and network you choose | Deploy role on the host. ESXi has no VM folders, so the account can also manage the VMs already on that host; setup warns you about them |
| The account | **An existing user you name** (`user@domain`): an SSO user or an Active Directory user. vCenter Single Sign-On users cannot be created through the public vSphere API, so create one first in the vSphere Client (*Administration → Single Sign On → Users and Groups*) if needed. | **A new local user** (default `vmdeploy`) with a generated 24-character password |
| Local connection profile | `<admin-profile>-deployer` for that user; no password is saved | `<admin-profile>-deployer`. The password is shown once, or saved in the OS keychain only if you choose to |

Safety rules:

- **Nothing is created before you confirm the plan.** If any step fails, everything created so far is
  removed again.
- **The folder is the boundary.** The account can create, change, power off and delete VMs only in the folder
  you choose and its subfolders (it needs that for the VMs it creates); everywhere else it can only look. The
  default answer creates a new folder for it; if you pick an existing folder, setup warns you when it already
  holds VMs. The folder can be renamed or moved later: the permission is attached to the folder and moves with
  it.
- **Use a dedicated account.** Setup refuses to continue if the account already has a permission on any
  object it would change, because vSphere keeps one permission per account per object and setting ours would
  replace it (for example, demote an administrator). It also refuses an account that already holds more
  privileges on those objects than setup would grant, through a group (such as vCenter's Administrators) or a
  permission higher up: a permission set on an object overrides propagated ones, and a user's own permission
  overrides its groups', so setup would reduce those rights. It reads the account's effective privileges from
  vCenter before the plan; if vCenter cannot report them, it warns and continues.
- **`access remove` deletes only what setup created.** It finds everything by the names of the roles setup
  created and the folder it labelled, and never touches permissions you created yourself. On ESXi it deletes
  the local user only when the host confirms vmdeploy created it; otherwise it asks (or, with `--yes`, needs
  `--delete-user <name>`).
- `vmdeploy doctor` mentions any access setup that is still in place.

The administrator's account needs `Authorization.ModifyRoles` and `Authorization.ModifyPermissions` (and on
ESXi `Host.Local.ManageUserGroups`; for a new folder `Folder.Create`, `Folder.Delete`,
`Global.ManageCustomFields` and `Global.SetCustomField`). The deploy account never gets these.
`vmdeploy keyprovider backup` (back up a Native Key Provider) needs `Cryptographer.ManageKeyServers`, also an
administrator privilege that the deploy account never gets.

For unattended use, pass every answer on the command line, e.g.
`vmdeploy access setup -p vc-admin --yes --user svc-deploy@vsphere.local --new-folder vmdeploy-svc-deploy --compute Cluster01
--datastore ds01 --network "VM Network"`.

## Privileges

| Granted on | Privileges | Why |
|---|---|---|
| Any object (read) | `System.Anonymous`, `System.View`, `System.Read` | Discover the inventory |
| Target **VM folder** | `VirtualMachine.Inventory.Create`, `VirtualMachine.Inventory.Delete`, `VApp.Import` | Create VMs, deploy OVA/OVF, clean up failed deployments, `vmdeploy destroy` |
| Target **cluster / host / resource pool** | `Resource.AssignVMToPool`, `VApp.Import` | Place the VM |
| Target **datastore(s)** | `Datastore.AllocateSpace`, `Datastore.Browse`, `Datastore.FileManagement` | Create disks, find ISOs, upload ISOs (an upload is then moved to its name, which never replaces an existing file) |
| Target **network(s)** | `Network.Assign` | Connect the VM's NICs |
| The VM folder (applies to new VMs) | `VirtualMachine.Config.CPUCount`, `.Memory`, `.DiskExtend`, `.AddNewDisk`, `.AddRemoveDevice`, `.EditDevice`, `.AdvancedConfig`, `.Annotation`, `.Settings`, `.Resource`; `VirtualMachine.Interact.PowerOn`, `.PowerOff`, `.ConsoleInteract`, `.DeviceConnection`, `.SetCDMedia`; `VirtualMachine.State.CreateSnapshot`; `VApp.ApplicationConfig` | Size, customise, power and snapshot the VM. `.Resource` lowers an appliance's memory reservation when its memory is reduced; `VApp.ApplicationConfig` edits an imported OVA's properties (a static address bound to NIC 1) |
| The VM folder | `VirtualMachine.Config.UpgradeVirtualHardware` | Only when a deployment upgrades the image's VM compatibility |
| The VM folder | `Cryptographer.Clone`, `.Encrypt`, `.EncryptNew`, `.Migrate`, `.RegisterVM`, `.RegisterHost`, `.Access` | Only for VMs with a virtual TPM (Windows 11); `.Access` ("Direct Access") opens their console |
| The datastore holding an ISO that must be copied | `Datastore.Browse`, `Datastore.FileManagement` | Only when the ISO is on a datastore the target host cannot see (it is copied once). `access setup` grants these as **image datastores** (role `vmdeploy-deployer-images`) where images are found |
| Every other datastore (default "All datastores") | `Datastore.Browse` | See image files everywhere (role `vmdeploy-deployer-browse`); an image there is copied through the deploying computer |

## Creating the role by hand

If you prefer to manage roles yourself:

**With govc** (GUI-free; [govc](https://github.com/vmware/govmomi/tree/main/govc) is VMware's open-source CLI):

```bash
govc role.create vmdeploy-deployer \
  System.Anonymous System.View System.Read \
  VirtualMachine.Inventory.Create VirtualMachine.Inventory.Delete VApp.Import Resource.AssignVMToPool \
  Datastore.AllocateSpace Datastore.Browse Datastore.FileManagement Network.Assign \
  VirtualMachine.Config.CPUCount VirtualMachine.Config.Memory VirtualMachine.Config.DiskExtend \
  VirtualMachine.Config.AddNewDisk VirtualMachine.Config.AddRemoveDevice VirtualMachine.Config.EditDevice \
  VirtualMachine.Config.AdvancedConfig VirtualMachine.Config.Annotation VirtualMachine.Config.Settings \
  VirtualMachine.Config.Resource VApp.ApplicationConfig \
  VirtualMachine.Interact.PowerOn VirtualMachine.Interact.PowerOff VirtualMachine.Interact.ConsoleInteract \
  VirtualMachine.Interact.DeviceConnection VirtualMachine.Interact.SetCDMedia VirtualMachine.State.CreateSnapshot \
  VirtualMachine.Config.UpgradeVirtualHardware

# Grant it to the deployment account on the folder, cluster, datastore and portgroup it may use, e.g.:
govc permissions.set -principal svc-deploy@vsphere.local -role vmdeploy-deployer -propagate=true /Lab/vm/Servers
```

**With the vSphere Client**: Administration → Access Control → Roles → New, tick the privileges above, then
add permissions for the account on the objects in the table.

Keep the scope narrow: grant on the specific VM folder, cluster/resource pool, datastores and portgroups the
account should deploy to, not on the vCenter root.
