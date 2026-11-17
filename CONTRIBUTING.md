# Contributing

Thanks for helping! Bug reports from real environments are especially valuable.

## Development setup

```bash
git clone https://github.com/pedramamirian/vsphere-vm-deployment
cd vsphere-vm-deployment
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -m "not vcsim"                                   # unit tests
VCSIM_BIN=/path/to/vcsim pytest                         # plus end-to-end tests (docs/testing.md)
ruff check src tests
```

On Windows, if PowerShell blocks `activate`, call the venv's programs directly instead:
`.venv\Scripts\python.exe -m pip install -e ".[dev]"`, then `.venv\Scripts\python.exe -m pytest -m "not vcsim"`.
If `pip install` fails building PyYAML (common on a Python release newer than PyYAML's wheels), see
[README: If pip tries to compile something](README.md#if-pip-tries-to-compile-something).

Cross-platform rules (CI runs on Windows, macOS and Linux with Python 3.11 to 3.15):

- Always pass `encoding="utf-8"` to `read_text`, `write_text` and `open` in text mode. The Windows default
  is the ANSI code page (cp1252), not UTF-8.
- Use `pathlib` for paths and never assume `/` separators or a case-sensitive filesystem.
- Per-user files go through `paths.py` (platformdirs), never hard-coded `~/.something` or `%APPDATA%` paths.
- File names built from external input (URLs, VM names) go through `images.safe_filename`.
- Keep files LF-only (`.gitattributes` enforces it). On Windows, write files with `newline=""` or
  `newline="\n"`, otherwise Python converts line endings to CRLF.
- Every documented shell command needs a Windows (PowerShell) form when its syntax differs, e.g. setting
  environment variables.
- Only use PyYAML's `safe_load` / `safe_dump`, not the `C*Loader` classes: users without a compiler run
  PyYAML's pure-Python build.

## Project layout

| Module | Responsibility |
|---|---|
| `cli.py` | Commands, error reporting, exit codes |
| `deploy.py` | The deployment orchestrator (steps, questions, plan, OVA / ISO pipelines, cleanup) |
| `ui.py` | Live step view, progress bars, prompts (interactive and `--yes`) |
| `connection.py`, `auth.py` | Sign-in (password and federated), licence and version checks, logout |
| `trust.py` | Certificate trust decisions and storage; `TrustDecision.connect`, through which every raw HTTPS request goes |
| `inventory.py` | Read-only discovery; bulk property reads (`collect`, `vm_properties`: one request, never one per object) |
| `vmnotes.py` | The Notes block on vmdeploy's VMs: the marker that identifies them, and the deployment details |
| `images.py`, `transfer.py`, `ovf.py` | Image sources, downloads/uploads with integrity checks, OVA/OVF parsing |
| `isolib.py`, `isocopies.py` | ISOs on datastores: search, host-to-host copies, `vmdeploy-iso/` copies and pruning |
| `vmspec.py`, `cloudinit.py` | vSphere config specs, cloud-init rendering |
| `compat.py`, `guestspecs.py`, `appliances.py` | VM compatibility, guest-type sizing recommendations, vendor appliance rules |
| `netcheck.py` | Static IP validation and conflict detection |
| `access.py`, `audit.py`, `privileges.py` | Least-privilege accounts (`access setup/remove`), `access audit`, privilege checks |
| `crypto.py`, `keyprovider.py` | Virtual TPM readiness, key provider management and backups |
| `manifest.py`, `profiles.py`, `credentials.py` | Manifest schema, connection profiles, OS keychain |
| `logsetup.py`, `paths.py`, `tasks.py`, `errors.py`, `units.py` | Logging with secret scrubbing, per-user folders, vSphere task waits, error types and exit codes, size and date formatting |
| `data/presets.yaml`, `data/privileges.yaml` | Image presets and required privileges (data, no code) |

## Guidelines

- Nothing may change in vCenter/ESXi before the user confirms the plan. The one exception is the Windows 11
  key-provider fix, which is its own change with its own plan and confirmation.
- Never disable TLS validation; never log secrets (`logsetup.register_secret`).
- This is a public repository: no real environment details (addresses, host, datastore, network or VM names,
  domains, certificates) in code, tests, docs or examples. Use RFC 5737 addresses (192.0.2.x, 198.51.100.x,
  203.0.113.x) and generic names.
- Every prompt needs a manifest field so `--yes` mode can answer it.
- Add tests: unit tests for logic, vcsim tests for API flows.
- New image presets only need an entry in `data/presets.yaml` (and a resolver if the metadata source is new).
