# Security Review of GUN-101-GKP

Evidence file for the Contributor Best Practices Badge criterion `security_review`.
This review considers the project's **security requirements** and **security
boundary** as documented in `docs/SECURITY.md` and `docs/THREAT_MODEL.md`, and
verifies them against the actual implementation.

| Field | Value |
|-------|-------|
| **Date of review** | 2026-09-08 |
| **Scope** | `src/gun101gkp/` (cipher, handler, identity, config, cli) |
| **Version reviewed** | `main` at time of review (post-3.1.x, container format 2.1) |
| **Method** | Manual source audit + automated tooling (below) |
| **Reviewers** | Project maintainer (Aditya Raj) + automated checks in CI |

Automated checks applied as part of this review:

- `pytest` — 69 tests, each documenting the security property it verifies.
- Coverage gate — `--cov-fail-under=90` (statement ≥ 90%, branch ≥ 80%;
  measured 91.5% statement / 91% branch).
- `mypy src` (strict-lite config in `pyproject.toml`) — 0 errors.
- `ruff check .` — clean.
- `bandit -r src` — no findings in scope.
- `pip-audit` — no known vulnerabilities in the dependency tree (run in CI).
- Hypothesis fuzz suite (`tests/test_fuzz.py`) — dynamic analysis: fuzzes
  `encrypt`/`decrypt`/`load_public_key_from_token` with arbitrary and mutated
  inputs, and asserts the only observable exceptions are the documented ones.
  Runs with assertions enabled (never `-O`) so runtime `assert`s in `src/` are
  exercised. Wired into CI and gated into the release pipeline (publish.yml),
  satisfying the `dynamic_analysis` / `dynamic_analysis_enable_assertions`
  criteria. This suite uncovered and drove the F-6 fix below.

## 1. Security requirements considered

From `docs/SECURITY.md`, the requirements the design must satisfy:

1. **Recipient confidentiality** — only the holder of the recipient's RSA-4096
   private key can decrypt a container for that recipient.
2. **Resistance to passive attacks** — an eavesdropper on the container learns
   nothing about the plaintext.
3. **Integrity and authenticity** — any tampering with a container is detected
   and rejected before plaintext is returned.
4. **Wrong-key rejection** — the container's recipient fingerprint is verified
   **before** any RSA decryption operation.
5. **Sender statelessness** — the sender holds no long-term secret material.
6. **Semantic security with fresh keys per file** — a random 256-bit DEK and a
   fresh 12-byte nonce per encryption.
7. **No error-message oracle** — validation/decryption failures must not let an
   attacker distinguish failure causes.
8. **Key-file hygiene** — private key written atomically with `0o600` permissions.

Boundary (from `THREAT_MODEL.md`): private-key compromise, malware on the
recipient machine, side-channel resistance of the underlying library, quantum
attacks, forward secrecy, metadata/length concealment, and DoS are **out of
scope**. The assumptions are: authentic token distribution (out-of-band), a
cryptographically secure RNG, a correct `cryptography` library, and a trusted
execution environment.

## 2. Verification of requirements against implementation

| Requirement | Verified in | Evidence |
|-------------|-------------|----------|
| R1 — RSA-4096 OAEP-SHA256 encapsulation | `handler.encrypt_for_recipient` / `decrypt_as_recipient` | `config.RSA_KEY_SIZE = 4096`; `_rsa_oaep_padding()` = OAEP/MGF1-SHA256 | 
| R2 — passive confidentiality | `handler.py`, `cipher.py` | AES-256-GCM under a random 32-byte DEK; `DEK_LEN = 32` |
| R3 — integrity/authenticity | `cipher.decrypt` | AES-GCM 16-byte tag verified before plaintext is returned |
| R4 — wrong-key rejection before RSA | `handler.decrypt_as_recipient` (~L149) | fingerprint compare precedes any RSA operation |
| R5 — sender statelessness | `handler.encrypt_for_recipient` | only the public token is used; DEK generated locally |
| R6 — fresh DEK + nonce | `handler.encrypt_for_recipient`, `cipher.encrypt` | `os.urandom(DEK_LEN)` and `os.urandom(AES_NONCE_LEN)` |
| R7 — no error oracle | `handler.decrypt_as_recipient` | all container-related failures raise generic `"Decryption failed"`; only malformed JSON/UTF-8 raises `"Invalid container format"` |
| R8 — key-file hygiene | `identity.generate_identity` | `os.open(..., O_CREAT|O_EXCL|O_WRONLY, 0o600)` + atomic `os.chmod` |

AAD binding: `_compute_aad` binds `protocol`, `version`, and
`recipient_fingerprint` into the AES-GCM associated data, so a container cannot
be replayed across protocol versions or recipients.

## 3. Findings

| ID | Severity | Area | Description | Resolution |
|----|----------|------|-------------|------------|
| F-1 | **Medium** | `handler.py` decrypt path | Malformed `sealed_dek` or nonce/ciphertext/tag base64 raised distinct messages (`"Invalid sealed_dek encoding"`, `"Invalid base64 in container fields"`), contradicting the documented no-oracle policy (R7). | **Fixed** — both now raise the generic `"Decryption failed"`. Tests pass (52/52). |
| F-2 | Low | `handler.py`, `cipher.py` | DEK/plaintext wiping is best-effort Python (`reassign` + `del`); Python does not guarantee memory scrubbing of immutable `bytes`. | Accepted and documented — no stronger in-guarantee exists in Python; the real boundary is `THREAT_MODEL.md` ("malware on recipient's machine" is out of scope). |
| F-3 | Low | `identity.load_public_key_from_token` on the **encrypt** path only | Public-token load does not enforce a minimum RSA key size (private-key load *does*, R8/I check in `load_private_key`). A sender encrypting to a deliberately tiny key gets weaker encapsulation — but the recipient chose/exchanged that token, which is the documented key-substitution (out-of-band) concern. | Accepted — outside the security boundary for legitimate recipients; noted for a future major review. |
| F-4 | Info | `handler.encrypt_for_recipient` | Redundant recomputation of the recipient fingerprint after RSA seal. | **Fixed** — duplicate computation removed. |
| F-5 | Info | `handler.decrypt_as_recipient` | `import hashlib` is local to the function. | Accepted — functional and harmless; cleanup only. |
| F-6 | **Medium** | `handler.py` decrypt path | A container that is valid JSON but not an object (e.g. a bare number, string, array, or `null`) crashed with an undocumented `AttributeError` (`'int' object has no attribute 'get'`). Violates R7: callers may only see documented exceptions. | **Fixed** — `decrypt_as_recipient` now rejects any non-`dict` top-level JSON with a generic `"Invalid container format"`. Found by the Hypothesis fuzz suite; guarded by `test_fuzz.py` regression tests (arbitrary-bytes + mutated-field fuzzing). |

## 4. Conclusion

The implementation is consistent with the documented security requirements
(`docs/SECURITY.md`) and operates within the declared security boundary
(`docs/THREAT_MODEL.md`). The substantive gaps found (F-1, F-6) were documented
policy/code mismatches and are now fixed — F-6 was detected by the project's
dynamic-analysis (fuzz) tooling, which must pass before every proposed release.
No cryptographic weakness was found in
the use of RSA-4096/OAEP-SHA256 or AES-256-GCM, and the out-of-scope threats are
correctly identified rather than silently unhandled.

**Verdict: PASS** — no unresolved findings above Low severity.

## 5. Re-review policy

- Re-run this review (update this document's date and re-verify F-2/F-3
  guidance) **annually**, or **before any semver-major release**.
- **Before any change** to algorithms, parameters, or container format in
  `src/gun101gkp/config.py` or `handler.py` (the protected invariants in
  `CONTRIBUTING.md`), a new security review is **required**, not optional.
- After any fix for a reported security vulnerability, add a regression test and
  note the incident in this document alongside a fresh review date.

## 6. How to reproduce the automated portion

```bash
pip install -e ".[dev]"
pytest tests/ --cov=gun101gkp --cov-branch --cov-fail-under=90
pytest tests/test_fuzz.py -v        # dynamic analysis
tox -e repro                         # reproducible build check
mypy src
ruff check .
bandit -r src
pip-audit
```