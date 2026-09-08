# Code Review Standards

This document defines how code review is conducted for every proposed change to
GUN-101-GKP. It is the authoritative reference for the OpenSSF
`code_review_standards` criterion and for the two-person review tracking
(`two_person_review`).

## What needs review

**Every proposed modification** to the repository — code, tests, documentation,
configuration, and workflow files — is reviewed before it is merged to `main`.
Nothing lands without a review that has been acted on.

## How review is conducted

Review happens on **pull requests** on GitHub. The flow is:

1. The author opens a PR using `.github/pull_request_template.md`, which prompts
   for: what the change does and why; a written cryptographic justification when
   cryptography is touched; how it was tested; and a security checklist.
2. CI runs automatically (`.github/workflows/ci.yml`): tests, coverage gate,
   lint (ruff), type-checking (mypy), dynamic analysis (Hypothesis fuzz suite),
   dependency/secret scans (pip-audit, bandit, gitleaks).
3. A reviewer other than the author examines the diff against the checklist
   below, asks questions, and requests changes as needed.
4. The author addresses the feedback and re-pushes.
5. The maintainer (or designated committer) merges once CI is green and all
   comments are resolved.

## What must be checked (review checklist)

A change is **acceptable** only when the reviewer has verified every applicable
item:

### Correctness and scope
- [ ] The diff does exactly what the PR description claims — no unrelated changes.
- [ ] The change is correct and fixes/implement what it claims to.
- [ ] No regression in existing behavior is introduced.

### Security invariants (see `docs/SECURITY.md` and `docs/THREAT_MODEL.md`)
- [ ] RSA key size stays ≥ 4096; public exponent stays in `{3, 65537}`.
- [ ] OAEP parameters are not weakened (MGF1-SHA256 / SHA-256).
- [ ] DEK length stays ≥ 32 bytes; AES nonce length stays ≥ 12 bytes.
- [ ] AES-GCM tag integrity is enforced before plaintext is returned.
- [ ] No secret key is stored in plaintext on disk.
- [ ] No **error-message oracle**: all validation/decryption failures remain
      generic `"Decryption failed"`; only malformed JSON/UTF-8 raises
      `"Invalid container format"`.
- [ ] Existing format versions (`SUPPORTED_FORMAT_VERSIONS`) remain decryptable.
- [ ] DEK zeroing in encrypt/decrypt paths is preserved.
- [ ] Cryptography-touching changes carry a written justification (property
      preserved, attack considered, why it is safe).

### Testing
- [ ] New functionality has tests (positive **and** negative for
      security-affecting functions).
- [ ] `pytest tests/ -v` passes locally; CI confirms it.
- [ ] Coverage gate passes (`--cov-fail-under=90` statement, `--cov-branch`
      ≥ 80% branch).

### Quality
- [ ] `ruff check .` is clean and `mypy src` reports no errors.
- [ ] New code has type hints and docstrings.
- [ ] Error-message wording is consistent with project policy.

### Process
- [ ] Every commit carries a `Signed-off-by` trailer (DCO).
- [ ] The author is **not** the sole reviewer of their own change
      (`two_person_review`).

## What makes a change acceptable (Definition of Done)

A change is merged only when **all** applicable checklist items are satisfied,
all reviewer comments are resolved, and CI is green. There are no exceptions for
small or "trivial" changes: even a one-line fix is reviewed.

## Two-person review tracking

The OpenSSF `two_person_review` criterion requires that **≥50%** of proposed
modifications are reviewed before release by a person other than the author.

- Each merged PR records its **author** and **reviewer**.
- Because of the maintainer-led single-writer structure, `AUTHORS.md` tracks the
  distinct people involved so reviews are genuinely cross-person wherever
  possible.
- Where a second person is not available (e.g., an isolated security-fix PR by
  the sole maintainer), the maintainer records this review gap explicitly in the
  PR so the proportion of independently-reviewed changes is transparent and
  documented.
- The cumulative proportion of reviewed-by-someone-else changes is tracked in
  `AUTHORS.md` / the PR log to demonstrate the ≥50% threshold.
