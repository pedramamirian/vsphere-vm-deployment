# Vendor guidance: EVE-NG and Cisco ISE

vmdeploy recognises some products from the image's file name (and, for OVAs, the product name inside it). It
then uses the vendor's **documented** settings as defaults, the same way it uses VMware's and Microsoft's values
for Windows. Each value below comes from the document named in its section. Where a vendor says nothing (Cisco
names no firmware or guest OS type for ISE, for example), vmdeploy keeps its usual behaviour. The plan review
shows a **Vendor guidance** row, the vendor's notes and the source link.

You can always type other values. Going below a vendor's minimum gives a warning, never a block.

## EVE-NG 7 (Professional and Freemium)

Recognised from names such as `eve-pro-prod-bm-7.0.1-21-full.iso`. In EVE-NG 7 the free edition ("Freemium")
uses the same ISO as Professional; the separate Community Edition 6.x is marked end-of-life on EVE's download
page.

Source: [EVE-NG Professional Cookbook 7.10 (October 2026)](https://www.eve-ng.net/wp-content/uploads/2026/10/EVE-PE-BOOK-7.10-2026.pdf),
sections 2.1 (hardware requirements) and 3.2.1.1 (ESXi VM setup and settings).

| Setting | EVE's guidance | What vmdeploy does |
|---|---|---|
| Sizing | Minimal VM (2.1.1): 8 vCPU as 1 socket × 8 cores, 16 GB RAM, 120 GB disk. Recommended VM (2.1.2): 1 × 16, 32 GB, 300 GB. Virtual server (2.1.3): 2 × 24 (48), 64 GB or more, 800 GB or more SSD, dedicated CPU and RAM reservations. | Suggests the recommended size when the host can hold it, otherwise the minimum. All three are shown in the questions. All cores in one socket. Warns below the minimum. |
| Guest OS | Linux / Ubuntu 64-bit | `ubuntu64Guest` |
| CPU | Expose hardware assisted virtualization ON; Expose IOMMU ON | Both on (IOMMU needs UEFI and VM version 14 or later) |
| Firmware | ESXi 8.0 or later: EFI, Secure Boot unchecked | UEFI, Secure Boot off |
| Disk | "Thick Provisioned eagerly" recommended; servers at least 500 GB | Eager-zeroed is the default (marked "recommended by EVE-NG 7"); thin can be chosen |
| Network adapter | VMXNET3 | VMXNET3 |
| Portgroup security | Promiscuous mode, forged transmits and MAC changes set to Accept, on the portgroup and vSwitch | Read-only check: a warning names any that are set to Reject. vmdeploy does not change network settings. |

## Cisco ISE 3.3, 3.4 and 3.5

Recognised from Cisco's OVA names (`Cisco-vISE-300-3.4.0.608b.ova`) or the product name inside the OVA.

Sources: Cisco ISE Installation Guide, VM requirements chapter:
[3.3](https://www.cisco.com/c/en/us/td/docs/security/ise/3-3/install_guide/b_ise_installationGuide33/b_ise_InstallationGuide33_chapter_2.html),
[3.4](https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/install_guide/b_ise_installationGuide34/b_ise_InstallationGuide_chapter_2.html),
[3.5](https://www.cisco.com/c/en/us/td/docs/security/ise/3-5/install_guide/b_ise_Installation_Guide_35/g_systemrequirements/r_vmware_appliance_size_recommendations.html).

| Setting | Cisco's guidance | What vmdeploy does |
|---|---|---|
| Sizing and reservations | "OVA template reservations": Evaluation 4 CPU / 16 GB (no reservation), Extra Small 8 / 32 GB, up to Large 48 / 256 GB, with CPU and memory reservations equal to the allocation. "If you decrease the RAM or CPU allocation for a VM, you must reimage Cisco ISE." | The OVA carries these sizes; every size is listed with its CPU and RAM and its values are used as they are. Typing less CPU or RAM than the chosen size gives a warning. |
| Disk | 300 GB templates suit dedicated Policy Service / pxGrid nodes; 600 GB and 1.2 TB are recommended for Administration or Monitoring nodes. 300 GB to 2.4 TB. | Shown as a note at the review. |
| Snapshots | "Cisco ISE does not support VM snapshots" | The baseline-snapshot question is not asked; a snapshot requested in a manifest is skipped with a warning. |
| Expose hardware-assisted virtualization | 3.4 and 3.5: "ESXi: Enable Expose hardware-assisted virtualization to the guest OS" (for pxGrid Direct containers). Not stated for 3.3. | On for 3.4 and 3.5 (asked, default yes); unchanged for 3.3. |
| IP address | ISE has no address until its console setup has run | "Wait for IP" is off unless the manifest sets `post_deploy.wait_for_ip`. |
| Power off | Use `application stop`, then `halt`, before powering off the VM | Shown as a note. |
| NIC, disk controller | VMXNET3 or E1000E; Paravirtual or LSI Logic Parallel | Kept as the OVA defines them. |

Other ISE releases and other vendors' OVAs still deploy normally with the OVA's own sizes; only the extra rules
above are specific to the versions listed.
