"""SSH public key files are read the same way on every OS, whatever tool saved them."""

import pytest

from vsphere_vm_deployment.deploy import read_key_file

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey josé@host"


@pytest.mark.parametrize(
    "encoding",
    [
        "utf-8",      # ssh-keygen on every OS
        "utf-8-sig",  # Notepad / editors that add a byte-order mark
        "utf-16",     # `>` or Out-File in Windows PowerShell 5.1 (UTF-16 LE with BOM)
    ],
)
def test_reads_key_regardless_of_encoding(tmp_path, encoding):
    p = tmp_path / "id_ed25519.pub"
    p.write_bytes((KEY + "\r\n").encode(encoding))
    assert read_key_file(p) == KEY
