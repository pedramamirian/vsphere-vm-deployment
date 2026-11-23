"""Regression tests for the second, uncapped code review and the security review of the first round of fixes."""

import contextlib
import hashlib
from datetime import UTC, datetime, timedelta
from io import StringIO
from types import SimpleNamespace as NS

import pytest
import yaml
from rich.console import Console

from vsphere_vm_deployment.errors import ConfigError, DeploymentError, MissingInput, TrustError


def _render(width: int = 400) -> tuple[Console, StringIO]:
    buf = StringIO()
    return Console(file=buf, force_terminal=False, width=width, emoji=False, highlight=False), buf


# ------------------------------------------------------------------------------------------ profiles and sign-in
def test_an_ipv6_server_keeps_its_brackets_in_urls_and_on_screen(capsys):
    """'https://fd00::10:8443/ui/...' was not a valid URL, and the printed link lost '[fd00::10]' to Rich markup."""
    from vsphere_vm_deployment import cli
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment.profiles import Profile

    v6 = Profile(name="v6", host="fd00::10", port=8443)
    assert v6.endpoint == "[fd00::10]:8443" and v6.url_host == "[fd00::10]"
    assert Profile(name="v4", host="vcsa.example.com").endpoint == "vcsa.example.com:443"
    fake = NS(o=NS(profile=v6), conn=NS(is_vcenter=False))
    assert d.Deployment._console_url(fake, NS(_moId="vm-7")) == "https://[fd00::10]:8443/ui/#/host/vms/vm-7"
    fake.o.profile = Profile(name="v6", host="fd00::10")
    url = d.Deployment._console_url(fake, NS(_moId="vm-7"))
    assert url == "https://[fd00::10]/ui/#/host/vms/vm-7"
    cli._print_result({"vm": "[x] web01", "moid": "vm-7", "datacenter": "DC", "target": "host h1",
                       "datastore": "ds1", "console_url": url, "powered_on": False}, False)
    err = capsys.readouterr().err
    assert url in err and "'[x] web01'" in err


def test_conflicting_image_sources_are_refused(isolated_dirs):
    """Both datastore flags mapped to the same key, so `--datastore-iso A --datastore-file B` deployed B."""
    from typer.testing import CliRunner

    from vsphere_vm_deployment.cli import app

    r = CliRunner().invoke(app, ["deploy", "--datastore-iso", "[a] x.iso", "--datastore-file", "[b] y.ova", "--yes"])
    assert r.exit_code == 2 and "--datastore-iso, --datastore-file" in " ".join(r.output.split())
    r = CliRunner().invoke(app, ["deploy", "--local", "win.iso", "--pick-local", "--yes"])
    assert r.exit_code == 2 and "--local, --pick-local" in " ".join(r.output.split())


def test_a_new_token_endpoint_for_a_profile_name_drops_its_saved_secret(monkeypatch):
    """The saved client secret was kept when only the OAuth token URL or client ID changed, and sent there."""
    from vsphere_vm_deployment import cli, credentials
    from vsphere_vm_deployment.profiles import ProfileStore
    from vsphere_vm_deployment.ui import Prompter

    deleted = []
    monkeypatch.setattr(credentials, "delete_secret",
                        lambda profile, kind="password": deleted.append((profile.oauth.token_url, kind)) or True)
    monkeypatch.setattr(credentials, "keychain_available", lambda: True)
    store, p = ProfileStore(), Prompter(interactive=False)
    common = {"host": "vc1.example.internal", "name": "sso", "auth": "oauth-client-credentials", "remember": True,
              "client_id": "vmdeploy"}
    cli._profile_wizard(p, store, token_url="https://idp.example.com/token", **common)
    cli._profile_wizard(p, store, token_url="https://idp.example.com/token", **common)
    assert deleted == []
    cli._profile_wizard(p, store, token_url="https://other.example.net/token", **common)
    assert ("https://idp.example.com/token", "client_secret") in deleted  # the old endpoint's entry


def test_a_saved_password_is_only_used_for_the_profiles_own_username(monkeypatch):
    """With the username asked each time, one person's saved password was sent for whoever signed in next."""
    from vsphere_vm_deployment import connection, credentials
    from vsphere_vm_deployment.profiles import Profile

    monkeypatch.delenv("VMDEPLOY_PASSWORD", raising=False)
    monkeypatch.setattr(credentials, "get_secret", lambda *a: pytest.fail("the keychain was read"))
    anyone = Profile(name="lab", host="vc", username=None, remember_secret=True)
    assert not connection.uses_keychain(anyone, "password")
    asked = NS(interactive=True, password=lambda q, field_name="": "typed")
    assert connection._get_secret(anyone, asked, "password", "Password:") == ("typed", "prompt")
    assert connection.uses_keychain(Profile(name="lab", host="vc", username="alice", remember_secret=True),
                                    "password")
    assert connection.uses_keychain(anyone, "client_secret")  # tied to the profile's client ID


def test_the_profile_wizard_does_not_offer_to_save_a_password_without_a_username(monkeypatch):
    from vsphere_vm_deployment import cli, credentials
    from vsphere_vm_deployment.profiles import ProfileStore
    from vsphere_vm_deployment.ui import Prompter

    monkeypatch.setattr(credentials, "keychain_available", lambda: True)
    prof = cli._profile_wizard(Prompter(interactive=False), ProfileStore(), host="vc.example.com", name="any",
                               remember=True)
    assert prof.username is None and prof.remember_secret is False


def test_the_service_content_is_read_once_per_connection():
    from vsphere_vm_deployment.connection import Connection

    reads = []
    conn = Connection(si=NS(RetrieveContent=lambda: reads.append(1) or NS(about=NS(apiType="VirtualCenter"))),
                      profile=None, decision=None, trust=None)
    assert conn.is_vcenter and conn.content is conn.content and len(reads) == 1


def test_with_yes_a_missing_access_token_names_its_environment_variable():
    from vsphere_vm_deployment.ui import Prompter

    with pytest.raises(MissingInput) as e:
        Prompter(interactive=False).password("Paste the access token:", field_name="VMDEPLOY_ACCESS_TOKEN")
    assert "VMDEPLOY_ACCESS_TOKEN environment variable" in e.value.hint


# ------------------------------------------------------------------------------------------ VM name
def test_the_second_vm_name_is_checked_like_the_first():
    """After a name clash, 'Choose another VM name' accepted names with / \\ % or over 80 characters."""
    from vsphere_vm_deployment import deploy as d

    checks = {}

    def text(question, default=None, field_name="", validate=None):
        checks[question] = validate
        return "web02" if question.startswith("Choose") else "web01"

    fake = NS(p=NS(text=text, interactive=True, record=lambda *a: None), m=NS(vm=NS(name=None)), pkg=None, image=None,
              o=NS(replace=False))
    assert d.Deployment._ask_name(fake, NS(vm_names={"web01"}, name="DC")) == "web02"
    again = checks["Choose another VM name:"]
    assert again("web/01") is not True and again("x" * 81) is not True and again("web-03") is True


# ------------------------------------------------------------------------------------------ certificates
def _cert(sans, *, days_left=1, sha="aa" * 32):
    from vsphere_vm_deployment.trust import CertInfo

    now = datetime.now(UTC)
    return CertInfo(der=b"x", subject="vc", issuer="vc", not_before=now - timedelta(days=30),
                    not_after=now + timedelta(days=days_left), sans=list(sans), sha256=sha, sha1="00" * 20,
                    subject_dn="CN=vc", issuer_dn="CN=vc")


def test_padding_in_a_certificate_cannot_start_a_fake_fingerprint_line():
    """A name padded with spaces wrapped in the terminal, so its own 'SHA-256 fingerprint: <the real server's>'
    started a line of its own above the real fingerprint."""
    from vsphere_vm_deployment.trust import CertInfo, print_cert_details, visible

    assert visible("a" + " " * 200 + "b c　d") == "a b\\u2003c\\u3000d"
    claimed = CertInfo.pretty("bb" * 32)
    cert = _cert(["vc.example.com" + " " * 200 + f"SHA-256 fingerprint: {claimed}",
                  "x" * 300 + f" SHA-256 fingerprint: {claimed}"])
    for width in (60, 80, 120, 200):
        console, buf = _render(width)
        print_cert_details(console, cert)
        lines = buf.getvalue().splitlines()
        starts = [n for n, ln in enumerate(lines) if ln.lstrip().startswith("SHA-256 fingerprint")]
        assert len(starts) == 1  # only the real one starts a line (a narrow terminal puts its value on the next)
        assert "".join(lines[starts[0]:]).startswith(f"SHA-256 fingerprint: {CertInfo.pretty(cert.sha256)[:20]}")
        assert sum(ln.startswith("Names/IPs:") for ln in lines) == 1 and all(len(ln) <= width for ln in lines)


def _fake_prompter():
    def refuse(*a, **k):
        raise AssertionError("a trust choice was offered for a certificate TLS will refuse")

    return NS(interactive=True, section=lambda title: contextlib.nullcontext(), numbered=refuse)


def test_an_out_of_date_certificate_is_explained_instead_of_offered(monkeypatch, tmp_path):
    """TLS checks the dates even of a pinned certificate: trusting an expired one ended in a raw SSL error on every
    later connection, with a saved pin that could never work."""
    from vsphere_vm_deployment import trust

    cert = _cert(["esx01.example.com"], days_left=-3)
    monkeypatch.setattr(trust, "validates", lambda *a, **k: (False, "certificate has expired"))
    monkeypatch.setattr(trust, "fetch_peer_cert", lambda *a, **k: b"der")
    monkeypatch.setattr(trust.CertInfo, "from_der", classmethod(lambda cls, der: cert))
    store = trust.TrustStore(tmp_path / "t.json")
    with pytest.raises(TrustError, match="expired on") as e:
        trust.TrustManager(store=store, prompter=_fake_prompter()).decision("esx01.example.com", 443)
    assert "Renew" in e.value.hint and store.pin("esx01.example.com:443") is None
    store.add_pin("esx01.example.com:443", cert)  # remembered while it was still valid
    with pytest.raises(TrustError, match="expired on"):
        trust.TrustManager(store=store).decision("esx01.example.com", 443)
    with pytest.raises(TrustError, match="expired on"):
        trust.TrustManager(store=trust.TrustStore(tmp_path / "u.json"),
                           assume_fingerprints=[cert.sha256]).decision("esx01.example.com", 443)
    with pytest.raises(TrustError, match="expired on"):
        trust.TrustManager(store=trust.TrustStore(tmp_path / "v.json")).vouch("esx01.example.com", 443, "00" * 20)


def test_trust_add_vcenter_ca_saves_only_a_bundle_that_validates_the_server_by_itself(monkeypatch, tmp_path):
    """`trust add --vcenter-ca` saved whatever /certs/download.zip held, into the bundle every connection trusts."""
    from vsphere_vm_deployment import trust

    cert = _cert(["vc.example.com"])
    checked = []
    bundle_ok = {"value": False}

    def validates(host, port, cadata=None, timeout=15.0, *, os_store=True):
        checked.append(os_store)
        return (True, "valid") if os_store else (bundle_ok["value"], "unable to get local issuer certificate")

    monkeypatch.setattr(trust, "validates", validates)
    monkeypatch.setattr(trust, "lists_name", lambda *a, **k: True)  # no network in unit tests
    monkeypatch.setattr(trust, "validated_peer_cert", lambda *a, **k: b"der")
    monkeypatch.setattr(trust, "fetch_peer_cert", lambda *a, **k: b"der")
    monkeypatch.setattr(trust.CertInfo, "from_der", classmethod(lambda cls, der: cert))
    monkeypatch.setattr(trust, "download_vcenter_ca", lambda decision: ["-----BEGIN CERTIFICATE-----\nX\n"])
    monkeypatch.setattr(trust.CertInfo, "from_pem", classmethod(lambda cls, pem: cert))
    store = trust.TrustStore(tmp_path / "t.json")
    with pytest.raises(TrustError, match="Nothing was saved"):
        trust.TrustManager(store=store).trust_vcenter_ca("vc.example.com")
    assert store.ca_bundle() is None and checked[-1] is False  # checked without the OS trust store
    bundle_ok["value"] = True
    assert trust.TrustManager(store=store).trust_vcenter_ca("vc.example.com") == 1 and store.ca_bundle()


# ------------------------------------------------------------------------------------------ key provider backup
def test_a_key_provider_is_exported_only_once_its_backup_file_can_be_written(monkeypatch, tmp_path):
    """The export (which vCenter records as the backup) ran before the file was opened: an unwritable target lost
    the only copy of the backup."""
    from vsphere_vm_deployment import keyprovider

    exported = []
    monkeypatch.setattr(keyprovider, "export", lambda *a: exported.append(1) or b"P12")
    monkeypatch.setattr(keyprovider, "RestSession", lambda *a: contextlib.nullcontext("sid"))
    monkeypatch.setattr(keyprovider, "native_providers", lambda conn: [])
    conn = NS(rest_credentials=("admin", "pw"), decision=None)
    p = NS(text=lambda *a, **k: "", password=lambda *a, **k: "")
    blocker = tmp_path / "not-a-folder"
    blocker.write_text("x")
    with pytest.raises(ConfigError, match="Nothing was exported"):
        keyprovider.backup_flow(conn, p, "nkp", out=blocker / "nkp.p12", no_password=True)
    assert exported == []

    def failing_export(*a):
        raise DeploymentError("vCenter could not back up 'nkp'")

    monkeypatch.setattr(keyprovider, "export", failing_export)
    target = tmp_path / "nkp.p12"
    with pytest.raises(DeploymentError):
        keyprovider.backup_flow(conn, p, "nkp", out=target, no_password=True)
    assert not target.exists()  # no empty file left behind
    monkeypatch.setattr(keyprovider, "export", lambda *a: b"P12-BYTES")
    keyprovider.backup_flow(conn, p, "nkp", out=target, no_password=True)
    assert target.read_bytes() == b"P12-BYTES"


# ------------------------------------------------------------------------------------------ privileges
def test_every_deploy_privilege_is_documented_for_building_the_role_by_hand():
    """VApp.ApplicationConfig was used but not in the role; VirtualMachine.Config.Resource was in the role but not
    in docs/least-privilege.md. Each deploy privilege must be in its table and in the govc example."""
    from pathlib import Path

    import vsphere_vm_deployment
    from vsphere_vm_deployment.access import DEPLOY_GROUPS

    data = yaml.safe_load((Path(vsphere_vm_deployment.__file__).parent / "data" / "privileges.yaml").read_text())
    assert "VApp.ApplicationConfig" in data["virtual_machine"]
    doc = (Path(__file__).resolve().parents[2] / "docs" / "least-privilege.md").read_text(encoding="utf-8")
    table, _, rest = doc.partition("## Creating the role by hand")
    govc = rest.partition("```bash")[2].partition("```")[0]
    for group in DEPLOY_GROUPS:
        if group in ("vtpm", "compatibility_upgrade") or group not in data:
            continue
        for priv in data[group]:
            short = "." + priv.rsplit(".", 1)[1]
            assert f"`{priv}`" in table or f"`{short}`" in table, f"{priv} missing from the privileges table"
            assert priv in govc, f"{priv} missing from the govc example"


# ------------------------------------------------------------------------------------------ disks
def test_extra_disks_need_a_scsi_or_nvme_controller_and_a_free_unit():
    """A ValueError surfaced as 'Unexpected error ... probably a bug' after the whole OVA was uploaded, and SCSI
    unit numbers above 15 were sent to vCenter."""
    from pyVmomi import vim

    from vsphere_vm_deployment.vmspec import reconfigure_spec

    def vm(devices):
        return NS(config=NS(hardware=NS(device=devices, numCPU=2, numCoresPerSocket=1, memoryMB=1024)))

    sata = vim.vm.device.VirtualAHCIController(key=15000)
    with pytest.raises(DeploymentError, match="no SCSI or NVMe controller"):
        reconfigure_spec(vm([sata]), cpu=None, cores_per_socket=None, memory_mb=None, disk_gb=None,
                         extra_disks=[(5, None)], annotation=None, extra_config=None)
    scsi = vim.vm.device.ParaVirtualSCSIController(key=1000, busNumber=0)
    disk = vim.vm.device.VirtualDisk(key=2000, controllerKey=1000, unitNumber=0, capacityInKB=1)
    spec, _ = reconfigure_spec(vm([scsi, disk]), cpu=None, cores_per_socket=None, memory_mb=None, disk_gb=None,
                               extra_disks=[(5, None)] * 14, annotation=None, extra_config=None)
    assert sorted(c.device.unitNumber for c in spec.deviceChange) == [1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15]
    with pytest.raises(DeploymentError, match="no free slot"):
        reconfigure_spec(vm([scsi, disk]), cpu=None, cores_per_socket=None, memory_mb=None, disk_gb=None,
                         extra_disks=[(5, None)] * 15, annotation=None, extra_config=None)


def test_the_images_disk_controllers_are_read_from_the_descriptor():
    from vsphere_vm_deployment.ovf import parse_descriptor

    def ovf(items):
        return f"""<?xml version="1.0"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
  xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData">
  <References/><DiskSection><Info>Disks</Info></DiskSection>
  <VirtualSystem ovf:id="vm"><Info>VM</Info><Name>x</Name>
    <VirtualHardwareSection><Info>HW</Info>{items}</VirtualHardwareSection></VirtualSystem></Envelope>"""

    def item(rtype, sub=""):
        return (f"<Item><rasd:InstanceID>1</rasd:InstanceID><rasd:ResourceType>{rtype}</rasd:ResourceType>"
                + (f"<rasd:ResourceSubType>{sub}</rasd:ResourceSubType>" if sub else "") + "</Item>")

    assert parse_descriptor(ovf(item(20, "vmware.sata.ahci") + item(5))).storage_controllers() == {"sata", "ide"}
    assert parse_descriptor(ovf(item(6, "VirtualSCSI"))).storage_controllers() == {"scsi"}
    assert parse_descriptor(ovf(item(20, "vmware.nvme.controller"))).storage_controllers() == {"nvme"}
    assert parse_descriptor(ovf("")).storage_controllers() == set()


def test_more_than_fourteen_extra_disks_are_refused_when_the_manifest_is_read():
    from pydantic import ValidationError

    from vsphere_vm_deployment.manifest import Resources

    assert len(Resources(extra_disks=[{"size_gb": 1}] * 14).extra_disks) == 14
    with pytest.raises(ValidationError):
        Resources(extra_disks=[{"size_gb": 1}] * 15)


# ------------------------------------------------------------------------------------------ progress text
def test_file_names_in_progress_bars_are_shown_as_text(monkeypatch):
    """'Checking [datastore1] iso/x.iso' lost '[datastore1]' to Rich markup (or failed on a closing tag)."""
    from vsphere_vm_deployment import ui

    console, buf = _render()
    monkeypatch.setattr(ui, "console", console)
    view = ui.DeploymentView("t", [("image", "Image", 1.0)], enabled=False)
    view.start("image")
    advance = view.begin_transfer("image", "Checking [datastore1] iso/x.iso [/]", 10)
    console.print(view._transfer)
    advance(5)
    assert "Checking [datastore1] iso/x.iso [/]" in buf.getvalue()


# ------------------------------------------------------------------------------------------ ISO copies on destroy
def test_an_iso_copy_left_by_a_deleted_vm_is_deleted_in_that_vms_datacenter(monkeypatch):
    from vsphere_vm_deployment import cli, inventory, isocopies

    calls = []
    monkeypatch.setattr(isocopies, "iso_users", lambda conn: {})
    monkeypatch.setattr(inventory, "discover", lambda conn: "inv")
    monkeypatch.setattr(isocopies, "delete", lambda conn, inv, full, dc=None: calls.append((full, dc)))
    p = NS(record=lambda *a: None)
    cli._offer_iso_cleanup(None, p, [("Site-B", "[vsanDatastore] vmdeploy-iso/a.iso")], True)
    assert calls == [("[vsanDatastore] vmdeploy-iso/a.iso", "Site-B")]


def test_hashes_are_compared_in_one_canonical_form():
    from vsphere_vm_deployment.images import _norm_sha

    sha = hashlib.sha256(b"x").hexdigest()
    assert _norm_sha(f"  {':'.join(sha[i:i + 2] for i in range(0, 64, 2)).upper()}\n") == sha


# ------------------------------------------------------------------------------------------ plan and upload
def test_extra_disks_get_the_vms_provisioning_unless_they_name_their_own():
    """Extra disks without their own provisioning were always thin, even when the VM (or its vendor) asked for
    eager-zeroed; thick extra disks also count as space needed right away."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment.manifest import Provisioning

    gib = 2**30
    ds = NS(name="ds1", usable=True, hosts={"h1"}, is_vsan=False, free=100 * gib, capacity=1000 * gib,
            provisioned=0, label=lambda: "ds1")
    plan = NS(dc=NS(datastores={"ds1": ds}, datastores_for=lambda hosts: [ds]), host_names={"h1"}, cluster=None,
              host=None, warnings=[], extra_disks=[(80, None), (5, Provisioning.THIN)], provisioning=None)
    fake = NS(p=NS(record=lambda *a: None, select=lambda *a, **k: pytest.fail("asked")), appliance=None,
              m=NS(placement=NS(datastore="ds1"), resources=NS(disk_provisioning=Provisioning.EAGER)),
              pkg=None, image=NS(is_iso=False), _needed_bytes=lambda plan: 50 * gib)
    fake._ask_provisioning = lambda: d.Deployment._ask_provisioning(fake)
    fake._space_needed = lambda plan: d.Deployment._space_needed(fake, plan)
    d.Deployment._ask_datastore(fake, plan)
    assert plan.extra_disks == [(80, Provisioning.EAGER), (5, Provisioning.THIN)]
    # A thin VM with an 80 GB eager-zeroed extra disk: that disk takes its full size at once (50 + 80 > 100 GB).
    fake.m.resources.disk_provisioning = Provisioning.THIN
    plan.extra_disks, plan.warnings = [(80, Provisioning.EAGER)], []
    d.Deployment._ask_datastore(fake, plan)
    assert any("needs about 130.0 GB right away" in w for w in plan.warnings)


def test_the_review_shows_names_as_text_and_where_an_iso_copy_goes(monkeypatch):
    """The Replace row put the VM name into Rich markup unescaped ('[prod] db' showed as ' db'), and the ISO row
    named a file that a copy may not end up in (a taken name gets -2, -3, ...)."""
    from vsphere_vm_deployment import deploy as d
    from vsphere_vm_deployment.manifest import Provisioning

    console, buf = _render()
    monkeypatch.setattr(d, "console", console)
    plan = NS(name="[prod] db", folder_path="/", pool_path="Resources", cpu=2, memory_mb=4096, disk_gb=40,
              provisioning=Provisioning.THIN, extra_disks=[(80, Provisioning.EAGER), (5, Provisioning.THIN)],
              datastore=NS(label=lambda: "ds1"), networks=[], guest_id="ubuntu64Guest", firmware="efi",
              secure_boot=False, disk_controller="pvscsi", vtpm=False, nested_hv=False, iommu=False,
              iso_copy_from="[local9] iso/x.iso", iso_copy_via_pc=False, iso_found_on_datastore=False,
              iso_datastore_path="[ds1] vmdeploy-iso/x.iso", deployment_option=None, hardware_version="vmx-21",
              compat_upgrade=False, guest=None, ovf_properties={}, power_on=True, wait_for_ip=False,
              snapshot=False, replace_vm=object(), notes=[], warnings=[], blockers=[])
    fake = NS(plan=plan, image=NS(display="[local9] iso/x.iso", format="iso", is_iso=True),
              _target_label=lambda: "host h1", appliance=None, pkg=None, m=NS(guest=NS()),
              p=NS(section=lambda title: contextlib.nullcontext(), interactive=False))
    assert d.Deployment._review_plan(fake) is True
    out = " ".join(buf.getvalue().split())
    assert "existing VM '[prod] db' will be DELETED first" in out
    assert "+80 GB (eager-zeroed), +5 GB" in out
    assert "copied once into [ds1] vmdeploy-iso/ (by vCenter, host to host" in out


def test_the_upload_summary_names_disks_the_package_manifest_does_not_list(monkeypatch):
    """Disks missing from the .mf were uploaded unchecked while the step said everything was verified."""
    from vsphere_vm_deployment import deploy as d

    done = {}
    view = NS(steps={"upload_disks": NS(weight=1)}, start=lambda *a: None, update=lambda *a, **k: None,
              begin_transfer=lambda *a: (lambda n: None),
              done=lambda key, detail=None, status="done": done.update(detail=detail, status=status))
    payload = {"disk1.vmdk": b"one", "disk2.vmdk": b"two"}
    pkg = NS(manifest_entries=lambda: {"disk1.vmdk": ("sha256", hashlib.sha256(b"one").hexdigest())},
             member_size=lambda path: len(payload[path]),
             open_member=lambda path: contextlib.nullcontext(StringIO(payload[path].decode())))
    sent = []

    def upload(decision, method, path, src, size, headers, progress, timeout, digest):
        data = src.read().encode()
        if digest is not None:
            digest.update(data)
        sent.append(path)

    monkeypatch.setattr(d, "upload_stream", upload)
    lease = NS(info=NS(deviceUrl=[NS(importKey="k1", url="https://esx01.example.com/nfc/1/disk1.vmdk"),
                                  NS(importKey="k2", url="https://esx01.example.com/nfc/1/disk2.vmdk")]),
               HttpNfcLeaseProgress=lambda n: None, HttpNfcLeaseComplete=lambda: None)
    files = [NS(deviceId="k1", path="disk1.vmdk", create=False), NS(deviceId="k2", path="disk2.vmdk", create=False)]
    fake = NS(view=view, conn=NS(session_cookie="c"), pkg=pkg, o=NS(profile=NS(host="vc", port=443)),
              trust=NS(vouch=lambda host, port, thumb: "decision"))
    d.Deployment._upload_disks(fake, lease, files)
    assert len(sent) == 2 and done["status"] == "warn"
    assert "except disk2.vmdk (not listed in it)" in done["detail"]
    pkg.manifest_entries = lambda: {"disk1.vmdk": ("sha256", hashlib.sha256(b"one").hexdigest()),
                                    "disk2.vmdk": ("sha256", hashlib.sha256(b"two").hexdigest())}
    d.Deployment._upload_disks(fake, lease, files)
    assert done["status"] == "done" and done["detail"].endswith("uploaded and verified against the package manifest")
