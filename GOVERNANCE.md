# Governance for GUN-101-GKP

GUN-101-GKP (Ghost Key Protocol) is an open-source cryptographic library. It is
maintained publicly, in the open, and welcomes contributions from anyone who
respects the project's security invariants and code of conduct.

This document defines how the project is governed: how decisions are made, the
key roles and their responsibilities, how access is managed for continuity, and
the intended bus factor.

## Project model

The project uses a **benevolent-dictator-with-review** model in its early stage,
moving toward a maintainer-team model as contributors join. The current
maintainer is:

- **Aditya Raj** (`dialga-cmd`) — Project Lead & Maintainer
  - Contact: `adityaraj1234@duck.com`

## Key roles and responsibilities

### Maintainer / Project Lead
The maintainer is the final decision-maker for the project. Responsibilities:

- Approve and merge contributions (pull requests).
- Maintain the project roadmap and release schedule.
- Make final decisions on cryptographic design and **protected invariants**
  (see `CONTRIBUTING.md`).
- Own PyPI publishing credentials and manage release/versioning
  (see `RELEASING.md`).
- Respond to security reports within the committed timeline
  (see `SECURITY_POLICY.md`).
- Administer the repository (labels, branches, branch protection).

### Committer(s) / Core contributor(s)
Committers are trusted contributors who can help with day-to-day maintenance.
As the project grows, committers gain merge rights. Responsibilities:

- Review pull requests and provide technical feedback.
- Triage issues and respond to bug reports and enhancement requests.
- Uphold the code style, type-hint, docstring, and test requirements from
  `CONTRIBUTING.md`.
- Help maintain documentation so it stays current (see
  `documentation_current`).

The project **intends a bus factor of 2 or more**, and actively seeks additional
committers. Nominations for committer status are made by the maintainer after a
track record of high-quality, security-aware contributions.

### Account security for maintainers

Everyone with write, merge, or publishing access **must** secure their accounts
with **two-factor authentication (2FA) that uses cryptographic mechanisms** to
prevent impersonation and credential theft:

- **Hardware security keys (WebAuthn / FIDO2 / passkeys)** — always required for
  maintainers; this is the only mechanism that both satisfies this policy and
  resists phishing.
- **Authenticator apps (TOTP)** — acceptable where a hardware key is not yet
  available, since TOTP produces cryptographically derived codes on-device.
- **SMS-based 2FA is prohibited** for anyone with repository or publishing
  access: SMS is not encrypted and is subject to SIM-swap and
  SS7-based interception. SMS-only 2FA does **not** satisfy this policy.

The same requirement applies to any third-party services that hold publishing
credentials (e.g., the PyPI account that releases `gun101-gkp`): 2FA must be
enabled with a cryptographic mechanism, never SMS. Access-continuity and
credential-transfer rules are described in the
[Access continuity and bus factor](#access-continuity-and-bus-factor) section.

### Contributor
A contributor is anyone who submits a pull request, files an issue, or takes part
in discussion. Contributors who submit non-trivial code are expected to agree to
the DCO (see `DCO` / `CONTRIBUTING.md`).

## Decision-making

- **Day-to-day changes and bug fixes:** reviewed by a committer or the
  maintainer and merged once CI passes and review feedback is addressed.
- **New features:** proposed via an issue first, discussed, then implemented via
  a pull request.
- **Cryptographic or security-affecting changes:** require a written cryptographic
  justification in the pull request (see `CONTRIBUTING.md`) and are reviewed with
  extra scrutiny by the maintainer.
- **Changing a protected invariant** (e.g. reducing key size, weakening a
  parameter): requires a written justification, a semantic version major release,
  and maintainer approval.
- **Disputes:** escalated to the maintainer, whose decision is final but always
  open to challenge with evidence (in the spirit of the code of conduct).

## Code of conduct

All participants must follow the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
Report violations privately to `adityaraj1234@duck.com`.

## Access continuity and bus factor

To ensure the project can continue if any one person is unavailable, the project
maintains:

1. **Source access redundancy:** the repository is hosted on GitHub where
   multiple owners/admins can be granted access. The maintainer will grant
   admin/owner access to at least one additional trusted committer so that
   issues can be opened/closed, pull requests accepted, and releases cut without
   the original maintainer.
2. **Release-access redundancy:** PyPI publishing uses trusted publishing
   (OIDC) tied to the repository, so any maintainer with repository admin access
   can trigger a release. Publishing credentials are not held by a single
   individual.
3. **Documented handoff:** this document records the intended successors. In the
   event of the maintainer's prolonged unavailability, the maintainer's chosen
   successor(s) — as recorded in the project's GitHub settings and/or a private
   handoff note held by a trusted party — take over decision-making and release
   duties.
4. **Legal continuity:** the project is MIT-licensed by "Security Team"
   (see `LICENSE`) so the code may be forked and continued by anyone if needed,
   ensuring no single person can block the project's continuation.

Target: the project should be able to create/close issues, accept changes, and
release versions **within one week** of loss of any one person's support.

## Bus factor

The current effective bus factor is **1** (a single maintainer). This is a known
risk. The project's explicit goal is to reach a bus factor of **2 or more** by
adding additional committers with the access described above. Until then, the
access-continuity measures above mitigate the single-person risk.

## Succession

If the current maintainer steps down or is unable to continue, succession goes,
in order, to: (1) a designated committer/successor named by the maintainer;
(2) if none, a committer chosen by the remaining active contributors; (3) if no
active committers remain, the project is relicensed-compatible (MIT) and may be
forked by the community.
