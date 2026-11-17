"""Image sources: --local, --url, --preset and --datastore-iso.

Every image that ends up on the host has passed an integrity check:
* presets: SHA-256 published in the vendor's image metadata (fetched over HTTPS);
* URLs: the --sha256 you supply, otherwise the computed hash is shown and remembered so a later
  download of the same URL that changes is flagged;
* local files: optional --sha256, otherwise the computed hash is shown;
* OVA/OVF: every file listed in the package's .mf manifest is verified before upload.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path

import yaml

from .errors import ConfigError, ImageError
from .paths import cache_dir, images_dir
from .transfer import ProgressFactory, download, http_get_json, norm_sha256, sha256_file

log = logging.getLogger(__name__)

IMAGE_SUFFIXES = (".ova", ".ovf", ".iso")
SIMPLESTREAMS_URL = "https://cloud-images.ubuntu.com/releases/streams/v1/com.ubuntu.cloud:released:download.json"
SIMPLESTREAMS_ROOT = "https://cloud-images.ubuntu.com/"
DATASTORE_PATH_RE = re.compile(r"^\[(?P<ds>[^\]]+)\]\s*(?P<path>.+)$")


@dataclass
class Preset:
    name: str
    description: str
    resolver: str
    provisioning: str | None = None
    guest_os: str | None = None
    channel: str | None = None
    release: str | None = None
    arch: str = "amd64"


@dataclass
class ResolvedImage:
    source_kind: str  # local | url | preset | datastore_iso
    display: str
    format: str  # ova | ovf | iso
    path: Path | None = None
    sha256: str | None = None
    integrity: str = ""  # human-readable description of what was verified
    provisioning: str | None = None
    guest_os: str | None = None
    datastore: str | None = None  # for datastore_iso
    datastore_path: str | None = None

    @property
    def is_iso(self) -> bool:
        return self.format == "iso"


def load_presets() -> dict[str, Preset]:
    raw = yaml.safe_load(resources.files("vsphere_vm_deployment.data").joinpath("presets.yaml").read_text(encoding="utf-8"))
    return {name: Preset(name=name, **spec) for name, spec in (raw or {}).items()}


def detect_format(name: str) -> str:
    suffix = Path(urllib.parse.urlparse(name).path).suffix.lower()
    if suffix not in IMAGE_SUFFIXES:
        raise ImageError(f"Cannot tell the image type of '{name}'.",
                         hint="Images must end in .ova, .ovf or .iso.")
    return suffix[1:]


def list_local_images() -> list[Path]:
    d = images_dir()
    if not d.exists():
        return []
    return sorted(p for p in d.iterdir() if p.is_file() and p.suffix.lower() in IMAGE_SUFFIXES)


def parse_datastore_path(value: str) -> tuple[str, str]:
    m = DATASTORE_PATH_RE.match(value.strip())
    if not m:
        raise ConfigError(f"'{value}' is not a datastore path.", hint='Use the form "[datastore1] iso/ubuntu.iso".')
    return m.group("ds"), m.group("path").strip()


# ------------------------------------------------------------------------------------------ file names
_UNSAFE_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                     *(f"LPT{i}" for i in range(1, 10))}


def safe_filename(url_path: str, fallback: str = "download") -> str:
    """A local file name for a URL path that is valid on Windows, macOS and Linux alike.

    URLs may contain characters Windows forbids in file names (`:` would even create a hidden NTFS
    alternate data stream), percent-encoding, names Windows reserves (CON, NUL, ...) and trailing dots or
    spaces, which Windows silently strips. The file extension is preserved so the image format is still detected.
    """
    name = urllib.parse.unquote(url_path.rstrip("/").rsplit("/", 1)[-1])
    name = _UNSAFE_CHARS.sub("_", name).rstrip(". ")
    if not name:
        return fallback
    if name.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
        name = "_" + name
    return name[:200]


# ------------------------------------------------------------------------------------------ cache metadata
def _meta_path(file: Path) -> Path:
    return file.with_name(file.name + ".meta.json")


def _read_meta(file: Path) -> dict:
    mp = _meta_path(file)
    return json.loads(mp.read_text(encoding="utf-8")) if mp.exists() else {}


def _write_meta(file: Path, **data) -> None:
    data["recorded"] = datetime.now(UTC).isoformat(timespec="seconds")
    _meta_path(file).write_text(json.dumps(data, indent=2), encoding="utf-8")


# The only folders vmdeploy writes in the cache. VMDEPLOY_CACHE_DIR may point at a folder that also holds the
# user's own files (e.g. a big drive), so listing and clearing never look outside these.
CACHE_SUBDIRS = ("presets", "urls", "datastore")


def _cache_files() -> list[Path]:
    root = cache_dir()
    return sorted(p for sub in CACHE_SUBDIRS for p in (root / sub).rglob("*") if p.is_file())


def cache_entries() -> list[tuple[Path, dict]]:
    return [(p, _read_meta(p)) for p in _cache_files() if p.suffix.lower() in IMAGE_SUFFIXES]


def clear_cache() -> tuple[int, int]:
    """Delete vmdeploy's cached images (downloads and files read from datastores), and nothing else in the cache
    folder. Returns (images removed, bytes freed)."""
    root = cache_dir()
    n = len(cache_entries())
    size = sum(p.stat().st_size for p in _cache_files())
    for sub in CACHE_SUBDIRS:
        shutil.rmtree(root / sub, ignore_errors=True)
    return n, size


_norm_sha = norm_sha256  # one canonical form for every SHA-256 comparison (the name other modules import)


# ------------------------------------------------------------------------------------------ resolvers
def resolve_ubuntu_simplestreams(preset: Preset, index: dict | None = None) -> tuple[str, str, str]:
    """Return (download URL, sha256, label) for the newest matching Ubuntu cloud OVA."""
    index = index or http_get_json(SIMPLESTREAMS_URL)
    products = index.get("products", {})
    candidates = []
    for key, prod in products.items():
        if prod.get("arch") != preset.arch:
            continue
        if preset.release and prod.get("release") != preset.release:
            continue
        if preset.channel == "lts" and "LTS" not in (prod.get("release_title") or ""):
            continue
        if prod.get("supported") is False:
            continue
        versions = prod.get("versions", {})
        for vkey in sorted(versions, reverse=True):
            ova = next((it for it in versions[vkey].get("items", {}).values() if it.get("ftype") == "ova"), None)
            if ova and ova.get("sha256") and ova.get("path"):
                candidates.append((_version_tuple(prod.get("version", "0")), vkey, key, prod, ova))
                break
    if not candidates:
        raise ImageError(f"No Ubuntu OVA image found for preset '{preset.name}' in Canonical's image metadata.")
    candidates.sort(key=lambda c: (c[0], c[1]))
    _v, serial, _key, prod, ova = candidates[-1]
    url = urllib.parse.urljoin(SIMPLESTREAMS_ROOT, ova["path"])
    label = f"Ubuntu {prod.get('release_title', prod.get('version'))} ({prod.get('release')}) build {serial}"
    return url, ova["sha256"], label


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)) or (0,)


# ------------------------------------------------------------------------------------------ main entry
def resolve(kind: str, value: str | None, *, sha256: str | None, prompter, progress_factory: ProgressFactory,
            hash_progress_factory: ProgressFactory | None = None, known_sha256: str | None = None) -> ResolvedImage:
    """`known_sha256`: for a local file hashed moments ago in this run (a datastore OVA read into the cache), so a
    large file is not read a second time for its SHA-256."""
    hash_progress_factory = hash_progress_factory or progress_factory
    if kind in ("datastore", "datastore_iso"):
        ds, path = parse_datastore_path(value or "")
        if not path.lower().endswith(".iso"):
            raise ConfigError("A datastore image must be an .iso, .ova or .ovf file.")
        return ResolvedImage("datastore_iso", f"[{ds}] {path}", "iso", datastore=ds, datastore_path=path,
                             integrity="already on the datastore (not re-verified)")

    if kind == "preset":
        presets = load_presets()
        if value not in presets:
            raise ConfigError(f"Unknown preset '{value}'.", hint=f"Available presets: {', '.join(presets)}")
        preset = presets[value]
        if preset.resolver != "ubuntu-simplestreams":
            raise ConfigError(f"Preset '{value}' uses unknown resolver '{preset.resolver}'.")
        url, expected, label = resolve_ubuntu_simplestreams(preset)
        dest = cache_dir() / "presets" / preset.name / safe_filename(urllib.parse.urlparse(url).path)
        sha, how = _cached_or_download(url, dest, expected, progress_factory, hash_progress_factory)
        return ResolvedImage("preset", label, detect_format(dest.name), path=dest, sha256=sha,
                             integrity=f"SHA-256 matches Canonical's published value ({how})",
                             provisioning=preset.provisioning, guest_os=preset.guest_os)

    if kind == "url":
        if not value:
            raise ConfigError("--url needs a value.")
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme not in ("https", "http"):
            raise ConfigError("Only http(s) URLs are supported.")
        fmt = detect_format(value)
        if fmt == "ovf":
            raise ConfigError("Downloading a bare .ovf is not supported (it references other files).",
                              hint="Use the .ova version of the image, or download the files and use --local.")
        url_hash = hashlib.sha256(value.encode()).hexdigest()[:16]
        dest = cache_dir() / "urls" / url_hash / safe_filename(parsed.path)
        previous = _read_meta(dest).get("sha256") if dest.exists() else None
        sha, how = _cached_or_download(value, dest, sha256, progress_factory, hash_progress_factory)
        if sha256:
            integrity = f"SHA-256 matches the value you supplied ({how})"
        else:
            integrity = f"no checksum supplied; computed SHA-256 {sha}"
            if previous and previous != sha:
                integrity += " (DIFFERENT from the previous download of this URL!)"
        if parsed.scheme == "http":
            integrity += "; downloaded over plain HTTP"
        from .logsetup import safe_url

        return ResolvedImage("url", safe_url(value) if parsed.query or "@" in parsed.netloc else value, fmt,
                             path=dest, sha256=sha, integrity=integrity)

    # local
    path: Path
    if value:
        candidate = Path(value).expanduser()
        path = candidate if candidate.exists() else images_dir() / value
        if not path.exists():
            raise ConfigError(f"Image '{value}' not found (looked in the current folder and {images_dir()}).",
                              hint="Put the file in the images/ folder or pass a full path.")
    else:
        local = list_local_images()
        if not local:
            raise ConfigError(f"No images found in {images_dir()}.",
                              hint="Copy an .ova/.ovf/.iso there, or use --url / --preset.")
        with prompter.section("Choose a local image"):
            path = prompter.select("Which image?", [(f"{p.name}  ({p.stat().st_size / 2**30:.2f} GB)", p)
                                                    for p in local], field_name="image.local")
    fmt = detect_format(path.name)
    size = path.stat().st_size
    sha = known_sha256 or sha256_file(path, hash_progress_factory(f"Checking {path.name} (SHA-256)", size))
    if sha256 and sha != _norm_sha(sha256):
        from .errors import ChecksumMismatch

        raise ChecksumMismatch(f"SHA-256 of {path.name} does not match the value you supplied.\n"
                               f"  expected {_norm_sha(sha256)}\n  got      {sha}")
    integrity = "SHA-256 matches the value you supplied" if sha256 else f"computed SHA-256 {sha}"
    return ResolvedImage("local", str(path), fmt, path=path, sha256=sha, integrity=integrity)


def _cached_or_download(url: str, dest: Path, expected: str | None, progress_factory: ProgressFactory,
                        hash_progress_factory: ProgressFactory) -> tuple[str, str]:
    if dest.exists():
        sha = sha256_file(dest, hash_progress_factory(f"Already downloaded: re-checking {dest.name} (no download)",
                                                      dest.stat().st_size))
        if not expected or sha == _norm_sha(expected):
            return sha, "cached copy re-verified"
        log.warning("Cached %s does not match expected checksum; downloading again", dest)
    sha = download(url, dest, expected_sha256=expected, progress_factory=progress_factory)
    from .logsetup import safe_url

    _write_meta(dest, url=safe_url(url), sha256=sha)
    return sha, "downloaded"
