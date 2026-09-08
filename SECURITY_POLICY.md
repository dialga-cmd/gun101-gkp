# Security Policy

This document explains how security vulnerabilities in **GUN-101-GKP (Ghost Key
Protocol)** are handled. If you work with this library at all — even if you just
installed it once — this page is worth two minutes of your time.

---

## Supported versions

Only the **latest minor release line** receives security fixes. Older lines are
unsupported; upgrading is expected of all users.

| Version        | Supported          |
| -------------- | ------------------ |
| 3.1.x          | Yes (latest: 3.1.2) |
| 3.0.x          | No |
| 2.x            | No |
| < 2.x          | No |

When a security release is cut, it will be released for the supported line and a
clear upgrade path will be documented in the release notes (automatically
published to PyPI via the tag-triggered `publish.yml` workflow).

## Scope

GUN-101-GKP provides:

- **Confidentiality** of file contents against anyone who does not hold the
  recipient's matching RSA-4096 private key.
- **Authenticity/integrity** of the container via AES-256-GCM, including binding
  of the protocol, format version, and recipient fingerprint to the ciphertext
  (format 2.1).
- **Wrong-key rejection**: the recipient's fingerprint is verified before any RSA
  operation.
- **Sender statelessness**: the sender holds no secret material.
- **Generic failure messages**: no error-message oracle between failure modes.

The precise list of threats addressed and **explicitly not addressed** is in
`docs/THREAT_MODEL.md`; `docs/SECURITY.md` is the authoritative statement of the
security properties (and non-properties). Both documents are the definition of
scope for this policy.

**In scope:** any vulnerability in the Python source (`src/gun101gkp/`),
including the crypto primitives, container handling, identity/key handling, the
CLI, or the documented security guarantees.

**Not in scope (see the threat model for rationale):** private-key compromise by
other means, malware on the decrypting machine, side-channel attacks on the
hardware, quantum-computing attacks on RSA-4096 (Shor's algorithm), forward
secrecy, and metadata/traffic-analysis protection.

If a report falls outside the library's scope, you will still receive an honest
explanation of *why* it is out of scope.

## Reporting a vulnerability

**Do not open a public GitHub issue, discussion, or PR for a vulnerability.**
Public disclosure before a fix exists hands working exploit information to
attackers and endangers every user of the library.

Email a private report to the maintainer:

```
Aditya Raj
adityaraj1234@duck.com
```

## What to include in a report

The more precise the report, the faster it is triaged. A good report covers:

1. **Affected component** — which CLI command and/or which module
   (`gun101gkp.handler`, `gun101gkp.identity`, `gun101gkp.cipher`,
   `gun101gkp.cli`, `gun101gkp.config`), and which container format version.
2. **Description** — a clear technical account of the vulnerability and its
   impact (confidentiality break, integrity break, key recovery, error-message
   oracle, parameter weakening, DEK/private-key memory handling, etc.).
3. **Steps to reproduce** — exact CLI commands or a minimal Python snippet,
   including any crafted container/base64 payload.
4. **Potential impact** — who is affected and how severely.
5. **Suggested fix** (optional) — a concise idea, or a note that you are writing
   a patch. Patches are welcome, but coordinate first so the fix can be released
   together with the announcement.

## Response timeline

Commitment from the maintainer:

| Step                      | Deadline                                                     |
| ------------------------- | ------------------------------------------------------------ |
| Acknowledgement           | Within **48 hours** of receipt                               |
| Initial fix timeline      | Communicated within **7 days**                               |
| Fix release               | As soon as a verified fix is ready; timeline communicated    |
| Coordinated disclosure    | After a fixed version is released to PyPI                    |

If triage shows the report is not in scope or is a duplicate, you will be told so
within the same 7-day window.

## Fix release and disclosure

- Fixes are released as patch version bumps on the supported line (semver).
- A release triggers PyPI publication automatically via the `publish.yml` GitHub
  Action on a `v*` tag.
- Details of the vulnerability and the fix are published **only after** the fixed
  version is available, unless you request earlier or later disclosure. Where
  possible, severity is rated (low / moderate / high / critical).

## Credit

Security researchers who responsibly disclose a vulnerability — and who do not
request anonymity — will be credited in the `CHANGELOG.md` entry and in the README
acknowledgements section for that release. If you prefer no credit, say so and
your preference will be respected.

## Non-negotiable invariants

Contributions that attempt to weaken the following will be rejected, regardless
of intent (see `CONTRIBUTING.md`):

- RSA-4096 minimum key size; public exponent whitelist `{3, 65537}`.
- OAEP with MGF1-SHA256 / SHA-256 — no downgrade to PKCS#1 v1.5 or weaker hashes.
- DEK length 32 bytes minimum; AES-GCM nonce 12 bytes; tag 16 bytes.
- Generic `"Decryption failed"` errors (no error-message oracle).
- Zeroing of the DEK after use; PEM key file at `~/.gun101gkp/private_key.pem`
  written with `0o600`.
- Continued decryption support for container format `2.0` and `2.1`.

## Recognition that security is hard

GUN-101-GKP is maintained by a student, in public, in good faith. Constructive,
detailed reports make the library better for everyone. Malicious, misleading, or
abusive reports waste a finite amount of volunteer time; please report in the
same spirit you would like to receive.

---

Questions about this policy can be sent to `adityaraj1234@duck.com`.
For anything that is *not* a vulnerability, please use the normal GitHub issue
templates instead.