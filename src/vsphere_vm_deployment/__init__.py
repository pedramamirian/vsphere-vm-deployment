"""vsphere-vm-deployment: interactive, GUI-free VM deployment to vCenter Server and ESXi."""

__version__ = "0.2.0"
TOOL_NAME = "vsphere-vm-deployment"
# Marker written into the VM's Notes so `vmdeploy list` / `destroy` can recognise VMs it created.
ANNOTATION_MARKER = "[deployed-by: vsphere-vm-deployment]"
