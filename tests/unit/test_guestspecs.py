"""Suggested sizing: VMware's recommendation for the guest type, never below Microsoft's minimum."""

from types import SimpleNamespace as NS

from vsphere_vm_deployment import guestspecs


def desc(mem_mb, disk_mb, sockets=1, cores=1):
    return NS(recommendedMemMB=mem_mb, recommendedDiskSizeMB=disk_mb, numRecommendedPhysicalSockets=sockets,
              numRecommendedCoresPerSocket=cores)


def test_vmware_recommendation_is_used():
    s = guestspecs.suggest("windows2019srvNext_64Guest", desc(4096, 92160, sockets=1, cores=2))  # Server 2022
    assert (s.cpu, s.memory_mb, s.disk_gb) == (2, 4096, 90) and "VMware" in s.source


def test_never_below_microsofts_minimum():
    s = guestspecs.suggest("windows11_64Guest", desc(2048, 32768))  # an old/low recommendation
    assert (s.cpu, s.memory_mb, s.disk_gb) == (2, 4096, 64)
    s = guestspecs.suggest("windows2022srvNext_64Guest", desc(2048, 32768))  # Server 2025: 4 GB recommended
    assert s.memory_mb == 4096


def test_fallback_without_a_host_recommendation():
    s = guestspecs.suggest("windows2019srvNext_64Guest", None)
    assert (s.cpu, s.memory_mb, s.disk_gb) == (2, 4096, 64) and "default" in s.source
    linux = guestspecs.suggest("ubuntu64Guest", None)
    assert (linux.cpu, linux.memory_mb, linux.disk_gb) == (2, 4096, 40) and linux.minimum is None


def test_hints_name_both_sources():
    s = guestspecs.suggest("windows2022srvNext_64Guest", desc(4096, 92160, cores=2))
    assert guestspecs.hint("memory", s) == (" (VMware recommends 4 GB; Microsoft minimum for Windows Server 2025 "
                                            "Desktop Experience: 2 GB, 4 GB recommended)")
    assert guestspecs.hint("cpu", guestspecs.suggest("ubuntu64Guest", None)) == ""


def test_below_minimum_is_hard_only_for_windows_11():
    problems, hard = guestspecs.below_minimum("windows11_64Guest", 1, 2048, 40)
    assert hard and len(problems) == 3
    problems, hard = guestspecs.below_minimum("windows2019srvNext_64Guest", 1, 1024, 32)
    assert not hard and problems == ["1 GB RAM (minimum 2 GB)"]
    assert guestspecs.below_minimum("ubuntu64Guest", 1, 512, 8) == ([], False)
