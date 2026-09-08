# Contributing to GUN-101-GKP

First off: thank you for considering a contribution. GUN-101-GKP is a small, focused
cryptographic library, and every careful contribution makes the whole project safer
for everyone who trusts it with their files.

This guide explains how the project works, what we need help with, and the
non-negotiable rules that keep the cryptography sound. Please read it fully before
opening an issue or pull request — especially the [security section](#security-rules-for-contributors).

If you only have five minutes, the rules that matter most are:

1. Do not weaken any cryptographic parameter (see [Protected invariants](#protected-invariants)).
2. Use only the battle-tested `cryptography` library for anything crypto-related.
3. Every new security-affecting function needs both a positive **and** a negative test.
4. Run `pytest tests/ -v` before opening a PR.
5. Report security bugs by **email**, never as a public GitHub issue.

---

## What kind of contributions help the most

- **Bug fixes** — wrong behaviour, crash on malformed input, unclear errors.
- **Correctness and security improvements** — anything that reduces the attack surface,
  hardens error handling, or closes an information leak. These get the highest priority.
- **Tests** — the suite documents the security properties the library guarantees; more of
  them is always good.
- **Documentation** — the docs (`docs/SECURITY.md`, `docs/THREAT_MODEL.md`, this guide, the
  README) must stay exactly in sync with the code.
- **Platform support** — the private key is written with permissions `0o600` on POSIX;
  Windows and macOS behaviour for file permissions, `os.open` flags, and paths needs
  verification and fixing.
- **Performance work, without touching security parameters** — e.g., avoiding redundant
  recomputation, smarter I/O. Performance is never a justification for a weaker parameter.

This project is maintained by one person alongside their studies. Be patient with review
times, and small, well-scoped PRs get reviewed much faster than large sweeping ones.

## Prerequisites

- **Python 3.8+.** The `pyproject.toml` declares `requires-python = ">=3.8"`. Note that the
  source uses built-in generic type hints (e.g. `tuple[bytes, bytes, bytes]`), so **Python 3.9+
  is strongly recommended** for developing and running tests locally.
- **pip** and a working `git` install.
- A free [GitHub](https://github.com) account.
- For running tests: no network access is needed after `pip install`.

### Fork and clone

1. Fork the repository: <https://github.com/dialga-cmd/gun101-gkp/fork>
2. Clone your fork and add the upstream remote:

   ```bash
   git clone https://github.com/<your-username>/gun101-gkp.git
   cd gun101-gkp
   git remote add upstream https://github.com/dialga-cmd/gun101-gkp.git
   ```

3. Create a branch. See [Submitting a pull request](#submitting-a-pull-request) for branch names.

### Install in editable mode with dev dependencies

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

The project uses a `src/` layout. Editable install gives you the `gun101gkp` module and the
`gun101gkp` command-line tool wired to your checkout, so changes take effect immediately.

To also run the CLI without installing, you can use:

```bash
HOME="$PWD/.testhome" PYTHONPATH=src python -m gun101gkp.cli --help
```

The identity key is stored under `~/.gun101gkp/private_key.pem`, so for any manual testing
use a throwaway `HOME` (as above) or pass `--help`/`--version` only.

## Running the test suite

```bash
pytest tests/ -v
```

A passing run ends with:

```
============================= 34 passed in ...s ==============================
```

All 34 tests currently pass on a clean checkout. The suite is deliberately slow-ish
(roughly 30–40 seconds) because several tests generate real RSA-4096 keys and exercise the
CLI end-to-end via subprocesses. It is normal and expected that the suite takes a while.

Notable points:

- Tests live in `tests/test_gkp.py`. Every test has a docstring explaining *which security
  property* it verifies.
- Several tests spawn the real CLI (`python -m gun101gkp.cli ...`) to prove behaviour at the
  interface level — e.g. that a tampered tag produces **no output file**.
- If a test fails after you changed something, read the docstring first: it almost always tells
  you exactly which guarantee you broke.

To get a coverage report:

```bash
pytest tests/ --cov=gun101gkp --cov-report=term-missing
```

## Project layout

```
src/gun101gkp/
    config.py       # Protocol constant, format versions, key sizes, paths — the security knobs
    cipher.py       # AES-256-GCM encrypt/decrypt primitives (nonce, ciphertext, tag)
    identity.py     # RSA-4096 keypair generation, token parse, fingerprint, private key handling
    handler.py      # Container build/parse: RSA-OAEP sealing + AES-GCM orchestration, AAD
    cli.py          # argparse interface: generate-identity, show-identity, fingerprint,
                    #   encrypt, decrypt, reset-identity
docs/
    SECURITY.md     # Exact security properties provided and not provided
    THREAT_MODEL.md # Assets, adversaries, threats in scope, out-of-scope, and rationale
tests/
    test_gkp.py     # 34 security-property tests
```

If you touch something in `config.py` or `handler.py`, read `docs/SECURITY.md` and
`docs/THREAT_MODEL.md` first — they describe exactly the guarantees you must not break.

## Coding standards

- **Type hints are required** on every public function signature. Parameters and return types
  should be annotated; `None` defaults are fine.
- **Docstrings are required** for all public functions and modules. Follow the existing style:
  a one-line summary, `Args:`, `Returns:`, and `Raises:` sections. Tests must also carry a
  docstring stating the security property they verify.
- Use clean, readable Python (target Python 3.8 syntax if you can, but the codebase already
  uses built-in generics, so Python 3.9+ syntax is accepted).
- **Linting and formatting:** the project uses [`ruff`](https://docs.astral.sh/ruff/).
  Config lives in `pyproject.toml` under `[tool.ruff]`. Run `ruff check .` before submitting
  a PR; CI enforces it (`ci.yml` → "Lint" job). Type checking uses `mypy` (also enforced in
  CI via the "Type check" job): run `mypy src` locally.
- **Do not add comments that merely restate the code.** The codebase uses comments only where
  they explain *why* (for example, why exponent `3` is still accepted in `load_private_key`).

## Security rules for contributors

Maintainers and contributors with merge/publishing access **must** enable
**two-factor authentication using cryptographic mechanisms** (hardware security
keys/WebAuthn, or TOTP authenticator apps — never SMS-only) on their GitHub and
PyPI accounts. See [GOVERNANCE.md](GOVERNANCE.md) → "Account security for
maintainers". This protects the repo against impersonated credentials.

### Protected invariants (never, under any circumstances, weaken these)

The following are hard floors. Changing any of them requires a written justification AND a
semver-major release, and even then will be heavily scrutinised:

- RSA key size: **4096 bits minimum** (currently exactly 4096 via `config.RSA_KEY_SIZE`).
- RSA public exponent must stay within the whitelist `{3, 65537}`; the library generates `65537`.
- RSA-OAEP must keep MGF1-SHA256 + SHA-256. No downgrade to SHA-1 or raw RSA/PKCS#1 v1.5.
- Data encryption key (DEK) length: **32 bytes (256-bit) minimum** — ever.
- AES-GCM nonce length: **12 bytes (96-bit)**.
- Authentication tag: **16 bytes (128-bit)**.
- Container bounds-fields (`protocol`, `version`, `recipient_fingerprint`, `sealed_dek`,
  `nonce`, `ciphertext`, `tag`) must stay `base64`-encoded in the JSON container.
- Current format version is `2.1`; decryption must keep accepting `2.0` and `2.1`
  (`SUPPORTED_FORMAT_VERSIONS`) as long as documented.
- The identity token prefix `GUN101GKP-v2-` must not change without a migration story.
- **Generic error messages**: all validation/decryption failures raise
  `ValueError("Decryption failed")`; only malformed JSON/UTF-8 raises
  `ValueError("Invalid container format")`. Never introduce an error-message oracle.
- The DEK must be zeroed/wiped from memory immediately after use in encrypt and decrypt paths.
- The private key file must be written with permission `0o600` and with `O_CREAT | O_EXCL`
  (no overwriting an existing identity).

### Rules for crypto-touching changes

- **Any change touching key generation, key sealing (`sealed_dek`), DEK handling, AES-GCM
  usage, OAEP parameters, AAD construction, or fingerprint verification requires a
  written cryptographic justification** in the PR description. State the attack you are
  considering, the property you are preserving, and why the change is safe.
- **No new cryptographic primitives implemented from scratch.** Use only the well-audited
  `cryptography` library (the sole runtime dependency). No hand-rolled ciphers, hashes,
  padding, or randomness. Anything else will be rejected.
- **No new runtime dependencies** without discussion. If you believe a new dependency is
  necessary, open an issue first explaining the risk/benefit trade-off.
- All randomness must come from `os.urandom` or the secure RNG exposed by `cryptography` —
  never `random`, and never a seeded or user-supplied source.

### Reporting a vulnerability

If you believe you have found a security vulnerability — **do not open a public GitHub issue**.
Email `adityaraj1234@duck.com` (see `SECURITY_POLICY.md` for the full process). You will get
an acknowledgement within 48 hours.

## Writing tests

- **Every security-affecting function must have both a positive test and a negative test.**
  Positive: "encrypt for A then decrypt as A works", round-trips preserve exact bytes,
  correct passphrase loads the key. Negative: wrong-key decryption fails, tampered
  ciphertext/nonce/tag/sealed_dek/fingerprint all fail, malformed tokens fail, unsupported
  format versions fail, wrong passphrase fails, missing key fails.
- Follow the existing pattern in `tests/test_gkp.py`:
  - use `tempfile.TemporaryDirectory()` and monkeypatch `config.PRIVATE_KEY_PATH`,
  - restore `config.PRIVATE_KEY_PATH` in a `finally` block,
  - use `pytest.raises(ValueError, match="Decryption failed")` etc.
- Name tests `test_<behaviour>` and give every one a docstring explaining the property.
- For CLI-level behaviour, model your test on `test_tampered_tag_no_output_file` or
  `test_fingerprint_cli` (subprocess + `PYTHONPATH=src`).
- Do **not** add tests that depend on wall-clock timing or that call the network.

## Good first issues

The project maintains a curated list of **small, clearly-scoped tasks** for new
or casual contributors in [`docs/TASKS.md`](docs/TASKS.md). These are ideal
first contributions: each is achievable without deep context.

Issues tagged with the GitHub label **`good first issue`** are the small tasks
that are ready to be claimed — see the
[filtered issue list](https://github.com/dialga-cmd/gun101-gkp/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22).
If you run `gh`:

```bash
gh issue list --label "good first issue"
```

Additional concrete starter tasks:

1. **Add identity backup / restore CLI commands.** `reset-identity` is irreversible. Add
   `backup-identity` (export the encrypted PEM to a user-chosen path) and `restore-identity`
   (import a PEM if no identity exists). Tie into `identity.py` and `cli.py`; validate that a
   restored key passes `load_private_key`'s checks (size, exponent).
2. **Add a `--verify` flag that checks a container's recipient fingerprint without
   decrypting.** `gun101gkp verify <file> --token <TOKEN>` should parse the container and
   compare the embedded `recipient_fingerprint` to the fingerprint of the given token,
   returning without ever touching the private key or performing an RSA decrypt. Naturally this
   must respect the generic-error-message rule.
3. **Formalise and expand support for arbitrary binary file types.** The container treats
   plaintext as opaque bytes, so images, archives, executables, etc. should work. Add
   systematic tests for a variety of binary payloads (including empty files and large files)
   and document the guarantee in the README and `docs/SECURITY.md`.
4. **Improve CLI error messages for malformed tokens.** Today the raw library messages
   (`"Token must start with prefix 'GUN101GKP-v2-'"`, `"Invalid base64"`, ...) surface in the
   CLI. Improve the CLI layer's presentation (concise hint + exit code) **without** weakening
   the library's generic decryption-failure messages. `--version`, container introspection if
   added, and `fingerprint` are the touchpoints.
5. **(Maintainer-suggested) Add Windows/macOS file-permission handling.** The key file is
   written with POSIX `0o600`. On Windows the trust model differs; research and implement the
   closest equivalent and add a platform-guarded test.

## Submitting a pull request

### Before you start

- Comment on the relevant issue, or open one, so maintainers know you are working on it.
- Pull `main` and rebase your branch on top of the latest `upstream/main`.

### Branch naming

Use a short descriptive prefix:

- `fix/<what>` — bug fixes
- `feature/<what>` or `feat/<what>` — new features
- `docs/<what>` — documentation
- `security/<what>` — security hardening (highest priority, labelled `security`)
- `test/<what>` — tests only
- `perf/<what>` — performance, no security changes

### Commit message format

- One commit per logical change. Imperative, capitalised, ≤ 72 characters:

  ```
  Fix CLI crash on truncated container
  ```

- If the change is security-related, prefix the subject with `security:`:

  ```
  security: return generic error on wrong-key decryption
  ```

- Reference issues when relevant:

  ```
  Add fingerprint verification before RSA decrypt (closes #12)
  ```

### Developer Certificate of Origin (DCO)

This project uses the **Developer Certificate of Origin** to confirm that
contributors are legally authorized to make their contributions. Every commit
must include a `Signed-off-by` trailer:

```
Signed-off-by: Your Name <you@example.com>
```

Use `git commit -s` (or `git commit --signoff`) to add it automatically, or
`git rebase --signoff` to fix an existing branch. The trailer is verified by a
DCO check in CI (see `.github/workflows/dco.yml`). See the [`DCO`](DCO) file for
the full text.

### The pull request

When you open the PR, use the template at
`.github/pull_request_template.md` and make sure you can tick every box. In the description:

- what the change does and **why**,
- for security-affecting changes: the written cryptographic justification,
- how you tested it (specific commands and their output),
- any documentation you updated.

### What review looks like

**Every proposed change is reviewed before it is merged.** This is the project's
code review policy (`code_review_standards`). A change is *accepted* only when a
reviewer other than the author has verified each of the following and the
author has addressed every comment:

1. **CI is green** — tests, lint, type-checking, dynamic analysis (Hypothesis),
   and security scans all pass (see `.github/workflows/ci.yml`).
2. **Scope is minimal** — the diff does only what the PR description claims,
   with no unrelated changes.
3. **Security invariants preserved** — the PR template's security checklist in
   `.github/pull_request_template.md` is fully ticked for `docs/SECURITY.md` and
   `docs/THREAT_MODEL.md` invariants (RSA-4096, OAEP-SHA256, AES-256-GCM, DEK
   length, nonce length, no error-message oracle, AAD binding, format-version
   compatibility).
4. **Cryptography changes carry a written justification** — the property being
   preserved, the attack considered, and why the change is safe.
5. **Tests cover the change** — positive and negative cases; security-affecting
   functions must have both. New tests pass.
6. **Code quality** — type hints and docstrings (mypy/ruff clean), no dead code,
   consistent error-message wording.
7. **DCO sign-off** — every commit carries `Signed-off-by`.

**Review conduct:**

- The maintainer (or a designated committer) reviews the PR, usually within a few days.
- Expect questions about **why** a change is safe rather than just *that* it
  works. This is not friction; it is the point of the project.
- Reviews focus on: invariants preserved, error-message consistency, memory
  wiping of keys, use of the correct library functions, and test coverage
  (positive *and* negative).
- **Two-person review:** because of the single-maintainer structure, the author
  and the reviewer must be different people to the greatest extent possible.
  When the maintainer authors a change, a second committer/contributor reviews
  it; when a contribution cannot be reviewed by a second person, the maintainer
  documents this explicitly so the review gap is visible. The project tracks
  this across pull requests to keep ≥50% of proposed modifications reviewed by
  someone other than the author before release (`two_person_review`).
- `pytest tests/ -v` must be green before merge. CI (`.github/workflows/ci.yml`)
  runs tests, lint, type-checking, dynamic analysis (the Hypothesis fuzz suite,
  `tests/test_fuzz.py`), and security scans on every pull request, so reviewers
  can trust the reported output; make it easy to verify.

A quick reference of the review checklist is also rendered as `docs/CODE_REVIEW.md`.

## Releasing

The release process — including how **interim (pre-release)** versions are cut
between stable releases to satisfy the OpenSSF `repo_interim` criterion — is
documented in [`RELEASING.md`](RELEASING.md). In short: bump `pyproject.toml`,
tag `v<version>` (stable or `a`/`rc` pre-release), push; the publish workflow
runs the full test suite **and the dynamic-analysis fuzz gate** before it
builds, SBOMs, attests, and publishes to PyPI.

## Code of conduct

By participating, you agree to abide by the
[code of conduct](CODE_OF_CONDUCT.md). Be constructive, be precise, and disagree
with the argument — never the person.

---

Questions? Open a discussion issue or email the maintainer at
`adityaraj1234@duck.com`. For anything security-related, use the email — not a public issue.