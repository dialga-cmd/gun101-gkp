---
name: Feature request
about: Suggest a new feature or improvement for GUN-101-GKP
title: "[Feature] "
labels: enhancement
assignees: ''

---

> **Security vulnerability?** Do **not** open a public issue. Email
> `adityaraj1234@duck.com` instead (see `SECURITY_POLICY.md`).

**Checklist before submitting**

- [ ] I have read `SECURITY.md` and this feature does **not** weaken any existing security guarantee. *(Required.)*
- [ ] I have checked the README and `docs/THREAT_MODEL.md` to confirm this is not already supported or explicitly out of scope.
- [ ] I have searched the existing issues and this is not a duplicate.

## Description

What is the feature? Describe it clearly and concretely.

Relevant entry points today (if any): the CLI commands are
`generate-identity`, `show-identity`, `fingerprint`, `encrypt`, `decrypt`,
`reset-identity`; the library API lives in `gun101gkp.handler` and
`gun101gkp.identity`.

## Problem it solves or use case it enables

Give a concrete scenario. Example: *"A user receives a container but no longer
remembers which identity it was encrypted for; I want to check the recipient
fingerprint without decrypting."*

## Proposed implementation approach (optional but encouraged)

Roughly how would you implement it? Point at the files it would touch
(e.g. `src/gun101gkp/cli.py`, `src/gun101gkp/handler.py`, `tests/test_gkp.py`).

## Security implications

Does this feature touch **key derivation, key sealing, DEK handling, AES-GCM
usage, OAEP parameters, AAD construction, container format/version, or
fingerprint verification**?

- **No** — it is orthogonal to the cryptography (e.g. a convenience output path).
- **Yes** — provide a written cryptographic justification: the property being
  preserved, the attack considered, and why the change is safe. Per
  `CONTRIBUTING.md`, changes that weaken the protected invariants (RSA-4096,
  OAEP-SHA256, 32-byte DEK, 12-byte nonce, generic failure messages, container
  format compatibility) will not be accepted.

## Alternatives considered

What else did you consider, and why is this approach better?

## Additional context

Anything else useful: sketches, edge cases, prior art in other tools.