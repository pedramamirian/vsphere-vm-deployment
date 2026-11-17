# Signing in

Each connection profile has a sign-in method. Create profiles with `vmdeploy profile add`; the wizard asks
for everything below.

| Method | Use it for | What you provide |
|---|---|---|
| `password` | `administrator@vsphere.local` and other vCenter SSO users, ESXi local users (`root`), **Active Directory** users through an *AD over LDAP(S)* or *Integrated Windows Authentication* identity source | Username (`user@domain` UPN recommended) and password |
| `oauth-password` | vCenter federated with **ADFS, Microsoft Entra ID, Okta or PingFederate**, using the OAuth *password* grant | IdP token URL, client ID, username (UPN) and password |
| `oauth-client-credentials` | Federated vCenter, with a **service principal / app registration** instead of a user | IdP token URL, client ID, client secret |
| `oauth-token` | Federated vCenter where **MFA** is required: get an access token yourself (e.g. through your IdP's browser flow) and paste it | Access token (and optionally the ID token) |

## How federated sign-in works

1. The tool requests an OAuth 2.0 access token (and, with the `openid` scope, an ID token) from your
   identity provider's token endpoint. Alternatively, you paste one with `oauth-token`.
2. It exchanges that token at vCenter for a SAML token:
   `POST https://<vcenter>/api/vcenter/authentication/token` with
   `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` and
   `requested_token_type=urn:ietf:params:oauth:token-type:saml2`.
   This follows Broadcom's *vSphere Automation SDKs Programming Guide 8.0*, "Exchange JWT Tokens for a SAML
   Token and Obtain a Session Identifier".
3. It signs in to the vSphere Web Services API with that SAML token (`SessionManager.LoginByToken`).

### Identity-provider prerequisites

- The OAuth client used by vCenter must allow the grant you choose. Broadcom documents the **password grant**
  as single-factor and incompatible with MFA, and recommends it only for low-privilege service accounts,
  because the password passes through the client. Prefer `oauth-client-credentials` or `oauth-token` where
  possible.
- Use the **UPN** (`user@domain`) for federated users. Broadcom KB 427150 notes that `DOMAIN\user` does not
  work for non-browser federated sign-in.
- Since vCenter 8.0 U3h, API logins honour the identity provider's policies (MFA, geofencing), per Broadcom
  KB 430844. If MFA applies to the account, the password grant will fail: use `oauth-token`.
- If your IdP uses a certificate from a private CA, set `VMDEPLOY_IDP_CA_BUNDLE=/path/to/ca.pem`.

> Federated sign-in is implemented from the documentation above and covered by automated tests against a
> simulated identity provider and token-exchange endpoint. It has **not yet been tested against a real identity
> provider**. If you use it, please report your results, working or not: open an issue with your provider (ADFS,
> Entra ID, Okta, PingFederate), the `--auth` method, your vCenter version, and the log of a run with `-v`
> (secrets are redacted from logs).

## Secrets

- Profiles **never** contain passwords or client secrets.
- With *"Save … in the OS keychain"* enabled, the secret is stored after the first **successful** sign-in in
  Windows Credential Manager, macOS Keychain, or the Linux Secret Service. A stored password that stops
  working is removed automatically. Remove one manually with `vmdeploy forget-secret <profile>`.
- A saved secret is only ever used for the server, port, account, sign-in method, token endpoint and client ID
  it was saved for: change any of them in the profile and you are asked again.
- For automation, the environment variables `VMDEPLOY_PASSWORD`, `VMDEPLOY_CLIENT_SECRET`,
  `VMDEPLOY_ACCESS_TOKEN` and `VMDEPLOY_ID_TOKEN` take precedence over the keychain. Use your CI system's
  secret store to set them.

## Certificates

There is nothing to configure beforehand. On the first connection to a server whose certificate is not trusted
by your operating system, the tool shows the certificate's subject, issuer, names/IPs, validity and SHA-256
fingerprint, reminds you that first-use trust does not prove identity, and asks:

`1) Trust for this session   2) Trust and remember   3) Trust this vCenter's root CA (…)   4) Cancel [default]`

- **Trust for this session**: used for this run only; saved trust is not changed.
- **Trust and remember**: the exact certificate is pinned. If the server later presents a *different*
  certificate, you get a warning showing the previously trusted fingerprint and must decide again.
- **Trust this vCenter's root CA** (vCenter only): downloads the CA bundle vCenter publishes, over a connection
  pinned to the certificate shown, and saves it only if it validates that certificate on its own. It also covers
  vCenter's ESXi hosts and certificate renewals. Not offered for a certificate that has changed, nor for one that
  does not list the name you connected by: no CA can make a certificate valid for a name it does not list.
- **Cancel** (default, also on Enter): disconnect before any credentials are sent.

If the certificate does not list the name you connected by (common when vCenter was installed with its IP
address as its name), the prompt says so. If you know one of the names or addresses it lists to be this
server, use that one instead, in the profile too; if you do not, be careful: it may not be the server you meant.

Pinned certificates are enforced by the TLS layer on every connection, not just the first.

During an OVA import, vCenter reports each ESXi host's certificate thumbprint over the already-trusted vCenter
session; a host presenting exactly that certificate is trusted for the transfer automatically.

Optional: `vmdeploy trust add <vcenter> --vcenter-ca` downloads vCenter's root CA bundle from
`https://<vcenter>/certs/download.zip` (Broadcom KB 330833), which also covers the ESXi hosts it manages.
If the server's own certificate is not trusted yet, you are asked to trust it for that download only (it is
not remembered), and the command stops before asking anything if the certificate does not list the name you
gave.
`vmdeploy trust list` and `vmdeploy trust remove <host:port>` manage saved trust.

In `--yes` (unattended) mode untrusted certificates are refused: answer the prompt once interactively with
"Trust and remember", or pass `--trust-fingerprint <SHA-256>` after verifying it out-of-band.
