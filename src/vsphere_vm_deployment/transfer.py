"""Byte-level transfers with progress callbacks and integrity checks.

* Downloads (internet -> local cache) use the OS trust store and honour HTTPS_PROXY / HTTP_PROXY.
  The SHA-256 is computed while downloading; the file only gets its final name once it matches.
* Uploads (local -> vCenter datastore / ESXi NFC endpoint) go over a connection whose certificate was
  validated or pinned by trust.py, and the peer certificate is re-checked on every connection.
"""

from __future__ import annotations

import hashlib
import http.client
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from . import __version__
from .errors import ChecksumMismatch, ConfigError, DeploymentError, ImageError
from .trust import TrustDecision

log = logging.getLogger(__name__)
CHUNK = 1024 * 1024
USER_AGENT = f"vsphere-vm-deployment/{__version__}"

ProgressFactory = Callable[[str, int | None], Callable[[int], None]]


def sha256_file(path: Path, progress: Callable[[int], None] | None = None) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
            if progress:
                progress(len(chunk))
    return h.hexdigest()


def norm_sha256(value: str | None) -> str:
    """A SHA-256 as typed or pasted (any case, ':' separators like a certificate fingerprint, spaces around it) in
    the one canonical form that every comparison uses."""
    return (value or "").strip().lower().replace(":", "")


def check_sha256(value: str | None, what: str = "--sha256") -> str | None:
    """A SHA-256 given by the user (--sha256 or image.sha256), in canonical form; None when none was given. Anything
    that is not 64 hex characters is refused before any file is read or downloaded, instead of ending as a
    mismatch afterwards."""
    if value is None or not value.strip():
        return None
    sha = norm_sha256(value)
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise ConfigError(f"{what} must be a SHA-256: 64 hexadecimal characters (':' separators are allowed).",
                          hint="Copy the value again from where the image is published.")
    return sha


def http_get_json(url: str, timeout: float = 30) -> dict:
    import json

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        raise ImageError(f"Could not fetch {url}: {getattr(e, 'reason', e)}") from e


def _check_complete(received: int, expected: int | None) -> None:
    """http.client returns b'' (not an error) when a connection closes before Content-Length bytes arrived, so a
    dropped download or datastore read would otherwise look complete. Raised as http.client.IncompleteRead, which
    the callers already report as an interrupted transfer (and the partial file is discarded)."""
    if expected is not None and received != expected:
        raise http.client.IncompleteRead(b"", expected - received)


def download(url: str, dest: Path, *, expected_sha256: str | None, progress_factory: ProgressFactory,
             timeout: float = 60) -> str:
    """Download `url` to `dest`. Returns the SHA-256. Raises ChecksumMismatch if `expected_sha256` differs."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    h = hashlib.sha256()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            total = resp.headers.get("Content-Length")
            expected = int(total) if total and total.isdigit() else None
            advance = progress_factory(f"Downloading {dest.name}", expected)
            got = 0
            with open(part, "wb") as out:
                while chunk := resp.read(CHUNK):
                    out.write(chunk)
                    h.update(chunk)
                    got += len(chunk)
                    advance(len(chunk))
            _check_complete(got, expected)
    except urllib.error.HTTPError as e:
        part.unlink(missing_ok=True)
        from .logsetup import safe_url

        raise ImageError(f"Download failed: HTTP {e.code} for {safe_url(url)}") from e
    except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
        part.unlink(missing_ok=True)
        from .logsetup import safe_url

        raise ImageError(f"Download failed for {safe_url(url)}: {getattr(e, 'reason', e)}",
                         hint="Check your internet connection, proxy settings (HTTPS_PROXY) and the URL, "
                              "then run the command again.") from e
    digest = h.hexdigest()
    if expected_sha256 and digest != norm_sha256(expected_sha256):
        part.unlink(missing_ok=True)
        raise ChecksumMismatch(f"SHA-256 of the downloaded file does not match the expected value.\n"
                               f"  expected {norm_sha256(expected_sha256)}\n  got      {digest}",
                               hint="The download was corrupted or the file was changed at the source. "
                                    "The partial file has been deleted; try again.")
    part.replace(dest)
    return digest


def upload_stream(decision: TrustDecision, method: str, path_and_query: str, stream: BinaryIO, size: int, *,
                  headers: dict[str, str] | None = None, progress: Callable[[int], None] | None = None,
                  timeout: float = 120, digest: hashlib._Hash | None = None) -> int:
    """Stream `size` bytes from `stream` to https://host:port/path. Returns the HTTP status.
    If `digest` is given, every byte sent is fed into it so the caller can confirm what was uploaded."""
    conn = None
    try:
        conn = decision.connect(timeout, "the upload")
        conn.putrequest(method, path_and_query, skip_accept_encoding=True)
        hdrs = {"Content-Length": str(size), "User-Agent": USER_AGENT, "Connection": "close"}
        hdrs.update(headers or {})
        for k, v in hdrs.items():
            conn.putheader(k, v)
        conn.endheaders()
        sent = 0
        while sent < size:
            chunk = stream.read(min(CHUNK, size - sent))
            if not chunk:
                raise DeploymentError(f"Source ended after {sent} of {size} bytes during upload.")
            conn.send(chunk)
            if digest is not None:
                digest.update(chunk)
            sent += len(chunk)
            if progress:
                progress(len(chunk))
        resp = conn.getresponse()
        body = resp.read(2048)
        if resp.status >= 300:
            raise DeploymentError(f"Upload to {decision.host} failed: HTTP {resp.status} {resp.reason}",
                                  hint=body.decode(errors="replace")[:300] or None)
        return resp.status
    except (OSError, http.client.HTTPException) as e:
        raise DeploymentError(f"Upload to {decision.host} was interrupted: {e}") from e
    finally:
        if conn is not None:
            conn.close()


def read_stream(decision: TrustDecision, path_and_query: str, sink: Callable[[bytes], None], *,
                headers: dict[str, str] | None = None, progress_factory: ProgressFactory | None = None,
                description: str = "Reading", timeout: float = 120) -> int:
    """GET https://host:port/path over the trusted (pinned/validated) connection, feeding every chunk to `sink`.
    Used to read files from datastores. Returns the number of bytes read."""
    conn = None
    try:
        conn = decision.connect(timeout, "reading")
        hdrs = {"User-Agent": USER_AGENT, "Connection": "close"}
        hdrs.update(headers or {})
        conn.request("GET", path_and_query, headers=hdrs)
        resp = conn.getresponse()
        if resp.status >= 300:
            raise DeploymentError(f"Reading from {decision.host} failed: HTTP {resp.status} {resp.reason}")
        total = resp.getheader("Content-Length")
        expected = int(total) if total and total.isdigit() else None
        advance = progress_factory(description, expected) if progress_factory else (lambda n: None)
        read = 0
        while chunk := resp.read(CHUNK):
            sink(chunk)
            read += len(chunk)
            advance(len(chunk))
        _check_complete(read, expected)
        return read
    except (OSError, http.client.HTTPException) as e:
        raise DeploymentError(f"Reading from {decision.host} was interrupted: {e}") from e
    finally:
        if conn is not None:
            conn.close()


def read_range(decision: TrustDecision, path_and_query: str, offset: int, length: int, *,
               headers: dict[str, str] | None = None, timeout: float = 60) -> bytes | None:
    """Read `length` bytes at `offset` with an HTTP Range request. None when the server does not honour ranges
    (the body is then not read, so a whole multi-GB file is never pulled by accident) or the read fails; a
    certificate that does not validate raises TrustError, as for every other read."""
    conn = None
    try:
        conn = decision.connect(timeout, "reading")
        hdrs = {"User-Agent": USER_AGENT, "Connection": "close", "Range": f"bytes={offset}-{offset + length - 1}"}
        hdrs.update(headers or {})
        conn.request("GET", path_and_query, headers=hdrs)
        resp = conn.getresponse()
        if resp.status != 206:  # e.g. 200 (ranges not honoured), 401/403 (no access to that datastore), 404
            log.info("Ranged read of %s refused: HTTP %s %s", path_and_query.split("?", 1)[0], resp.status,
                     resp.reason)
            return None
        return resp.read(length)
    except (OSError, http.client.HTTPException) as e:  # a certificate failure is a TrustError, not caught here
        log.info("Ranged read of %s failed: %s", path_and_query.split("?", 1)[0], e)
        return None
    finally:
        if conn is not None:
            conn.close()


def datastore_url_path(datacenter: str, datastore: str, path: str) -> str:
    """vSphere datastore HTTP access: /folder/<path>?dcPath=<datacenter>&dsName=<datastore>
    (vSphere Web Services SDK Programming Guide, 'HTTP Access to vSphere Server Files')."""
    q = urllib.parse.urlencode({"dcPath": datacenter, "dsName": datastore})
    return f"/folder/{urllib.parse.quote(path)}?{q}"
