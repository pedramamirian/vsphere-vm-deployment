# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") on this repository. You can expect an acknowledgement within a
week.

## Design notes

- TLS certificate validation is never disabled. Untrusted certificates require an explicit decision
  (trust once / always / vCenter root CA) or a fingerprint passed with `--trust-fingerprint`. Pinned
  certificates are re-checked on every connection, including uploads to ESXi hosts.
- Passwords and client secrets are never written to disk by the tool. They are kept in the OS keychain only
  when you opt in, and a saved secret is used only for the server, account and sign-in method it was saved for:
  never for whichever account is typed at the prompt, nor for another server that reuses the profile's name.
- Guest passwords are hashed (SHA-512 crypt) locally; only the hash is sent to the VM.
- cloud-init data placed in `guestinfo` is cleared by cloud-init after first boot (`redact`).
- Log files are scrubbed of passwords, tokens, session cookies, SAML assertions and user-data.
- OVF descriptors containing DTD/ENTITY declarations are rejected.
- Certificate details at the trust prompt (subject, issuer, alternative names) are shown as plain text, each
  on one line: markup, control characters, invisible Unicode formatting characters and space padding cannot
  add or hide lines, so the fingerprint you compare is always the presented certificate's own.
- A vCenter root CA bundle (`/certs/download.zip`) is downloaded only over a connection that is validated
  (chain and hostname) or pinned to the certificate you accepted, never over one checked against a certificate
  read without validation, and it is saved only if it validates that vCenter's own certificate by itself; a
  bundle that does not apply never reaches the trust store.
- An ISO already on a datastore (an earlier upload or copy in `vmdeploy-iso/`, or the same file elsewhere) is
  used instead of an upload or copy only after its full SHA-256 matches the image. Files are never trusted by
  name and size (another account with file rights on that datastore could have replaced them) and are never
  overwritten: an upload goes to a name of its own and is then moved to a free name, a move that never replaces
  a file, so two deployments of the same ISO at once cannot replace each other's copy. One exception, where no
  checksum exists: for a datastore ISO deployed without `--sha256`, the copy vmdeploy made earlier on the VM's
  own datastore is compared with the original by samples (an account that can write the VM's datastore could
  change the VM's files anyway). Give `--sha256` for a full check.
- Datastore paths are always resolved in the VM's datacenter; a datastore name used in several datacenters
  stops the run instead of reading (and checking) another datacenter's file.
- Reusing a profile name for a different server, account, sign-in method or OAuth token endpoint deletes the
  secret saved for the old one.
- The tool has no telemetry and contacts only the servers you configure, plus `cloud-images.ubuntu.com`
  for the Ubuntu presets.
