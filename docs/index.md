---
title: GUN-101-GKP
layout: default
---

# GUN-101-GKP — Ghost Key Protocol

Passwordless asymmetric encryption for files, using **RSA-4096** key encapsulation
and **AES-256-GCM** data encryption.

## What problem does it solve?

Sending a sensitive file to a specific recipient usually means agreeing on a
password or shared secret over a secure channel. GUN-101-GKP removes that step.

The recipient generates an RSA-4096 key pair and shares only a **public Identity
Token**. Anyone holding that token can encrypt a file for the recipient, but only
the holder of the matching private key can decrypt it — with no password and no
shared secret exchanged.

It is built for:

- Individuals sending sensitive files to a known recipient without exchanging
  passwords.
- Applications that need asymmetric file encryption where the recipient is known
  in advance.
- Users who want a simple, stateless scheme where the sender holds no long-term
  secrets.

## Quick start

```bash
pip install gun101-gkp

# Recipient: generate an identity once
gun101gkp generate-identity

# Sender: encrypt a file for the recipient
gun101gkp encrypt report.pdf --recipient GUN101GKP-v2-...

# Recipient: decrypt
gun101gkp decrypt report.pdf.gkp
```

Full usage is documented in the [README](https://github.com/dialga-cmd/gun101-gkp#readme)
and the [API reference](https://github.com/dialga-cmd/gun101-gkp/blob/main/docs/API.md).

## How it protects data

- **Confidentiality** — RSA-4096 with OAEP (SHA-256) and AES-256-GCM protect the
  file contents.
- **Integrity & authenticity** — the AES-GCM tag detects any modification before
  decryption proceeds.
- **Wrong-key rejection** — a recipient public-key fingerprint is verified before
  any RSA operation.
- **Fresh key per file** — a random 256-bit data encryption key (DEK) is generated
  for every encryption.

## Project status and security

This project follows secure-development best practices. See:

- [Security policy](https://github.com/dialga-cmd/gun101-gkp/blob/main/SECURITY_POLICY.md)
- [Threat model](https://github.com/dialga-cmd/gun101-gkp/blob/main/docs/THREAT_MODEL.md)
- [Security properties](https://github.com/dialga-cmd/gun101-gkp/blob/main/docs/SECURITY.md)
- [Architecture (high-level design)](https://github.com/dialga-cmd/gun101-gkp/blob/main/docs/ARCHITECTURE.md)
- [Roadmap](https://github.com/dialga-cmd/gun101-gkp/blob/main/ROADMAP.md)
- [Governance](https://github.com/dialga-cmd/gun101-gkp/blob/main/GOVERNANCE.md)
- [Code of conduct](https://github.com/dialga-cmd/gun101-gkp/blob/main/CODE_OF_CONDUCT.md)

## Achievements

[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/0/badge)](https://bestpractices.coreinfrastructure.org/projects/0)

## Contributing

Contributions are welcome. Please read the
[contributing guide](https://github.com/dialga-cmd/gun101-gkp/blob/main/CONTRIBUTING.md)
first — it explains the contribution process, coding standard, the
[Developer Certificate of Origin (DCO)](https://github.com/dialga-cmd/gun101-gkp/blob/main/DCO),
and the security invariants that must never be weakened.

To get involved:

- **Report a bug or request a feature** — open a
  [GitHub issue](https://github.com/dialga-cmd/gun101-gkp/issues).
- **Submit changes** — contribute via a
  [pull request](https://github.com/dialga-cmd/gun101-gkp/pulls); sign off your
  commits per the DCO.
- **Report a security vulnerability** — email privately
  (see the [security policy](https://github.com/dialga-cmd/gun101-gkp/blob/main/SECURITY_POLICY.md));
  do **not** open a public issue.

## License

MIT. See the [LICENSE](https://github.com/dialga-cmd/gun101-gkp/blob/main/LICENSE).
