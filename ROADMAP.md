# GUN-101-GKP Roadmap

This roadmap describes what GUN-101-GKP intends to do (and explicitly **not** do)
over the next year. It is a living document and may change as the project
evolves. Priorities and timeline are approximate and aligned with security and
maintainability.

Status legend: **Planned** · **In progress** · **Done**

## Current state (baseline)

- Protocol: Ghost Key Protocol, format `2.1` (decrypts `2.0`/`2.1`).
- Crypto: RSA-4096 key encapsulation (OAEP/SHA-256) + AES-256-GCM.
- CLI: `generate-identity`, `show-identity`, `fingerprint`, `encrypt`,
  `decrypt`, `reset-identity`.
- Covered by a security-property test suite and CI (tests, lint, type-check,
  security scans).

## Goals for the next year

### 1. Identity backup / restore (in progress)
- Add `backup-identity` and `restore-identity` CLI commands so users are not left
  with an irreversible `reset-identity` as their only option.
- **Why:** loss of a private key is permanent data loss; this is the highest-value
  usability/security improvement for end users.
- **Status:** Planned (first contribution).

### 2. Container verification without decryption (planned)
- Add a `verify` subcommand that checks a container's recipient fingerprint
  against a provided token **without** touching the private key or performing an
  RSA decrypt.
- Preserves the generic-error-message rule.
- **Status:** Planned.

### 3. Formalize binary/file-type support (planned)
- Confirm and document that the container treats plaintext as opaque bytes, with
  systematic tests for empty files, large files, images, archives, and
  executables.
- **Status:** Planned.

### 4. Cross-platform file-permission handling (planned)
- The private key is written with POSIX `0o600`. Research and implement the
  closest equivalent on Windows/macOS and add platform-guarded tests.
- **Status:** Planned.

### 5. Improve CLI error presentation (planned)
- Cleaner, concise hint messages and exit codes for malformed tokens/inputs at the
  CLI layer **without** weakening the library's generic decryption-failure
  messages.
- **Status:** Planned.

### 6. Governance and process hardening (in progress)
- Adopt a Developer Certificate of Origin (DCO).
- Maintain `GOVERNANCE.md`, `ROADMAP.md`, architecture and reference
  documentation.
- Achieve OpenSSF Best Practices Badge (Silver) and continue scorecard
  improvements.
- **Status:** In progress.

### 7. Supply-chain and release hygiene (in progress)
- Maintain CI (tests, lint, type-check, bandit, pip-audit, gitleaks).
- Publish interim (pre-release) versions and stable releases with SBOM and
  provenance.
- **Status:** In progress.

## Explicitly not in scope (for the next year)

The following are **not** planned. They are either out of scope by design or a
conscious security decision:

- **Post-quantum cryptography** — RSA-4096 is intentionally used; no PQC
  migration this year (see `THREAT_MODEL.md`).
- **Forward secrecy** for the file-encryption scheme (documented non-goal).
- **Full network protocol / streaming framework** — the library is for file
  encryption, not large streams or interactive key exchange.
- **New runtime dependencies** without strong justification and prior discussion
  (per `CONTRIBUTING.md`).
- **Weakening any protected invariant** (RSA-4096, OAEP-SHA256, 32-byte DEK,
  12-byte nonce, generic error messages, 2.0/2.1 format support) — see the
  invariants in `CONTRIBUTING.md`.

## How to contribute

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and the issue tracker for the current
list of tasks. Items above link to issues as they are created.
