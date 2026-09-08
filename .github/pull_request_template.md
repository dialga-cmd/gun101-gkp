---
name: Pull request
about: Submit a change to GUN-101-GKP
title: ""
labels: ""
assignees: ""

---

> **Security vulnerability?** Do **not** open a PR that fixes a vulnerability in
> isolation. Email `adityaraj1234@duck.com` first — public exposure before a fix
> is released puts users at risk. See `SECURITY_POLICY.md`.

## Description

What does this change do, and why? If it fixes an issue, reference it (e.g. `Closes #12`).

### Security justification (required when cryptography is touched)

If this change touches **key generation, key sealing (`sealed_dek`), DEK handling,
AES-GCM usage, OAEP parameters, AAD construction, container format/version,
fingerprint verification, or private-key handling**, write the cryptographic
justification here: the property being preserved, the attack considered, and why
the change is safe. PRs without this will be sent back.

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Security improvement
- [ ] Test addition
- [ ] Performance improvement
- [ ] Other (please describe)

## Security review checklist

This library's documented invariants are in `docs/SECURITY.md` and
`docs/THREAT_MODEL.md`. Confirm every applicable box:

- [ ] This change does **not** reduce the RSA key size below 4096.
- [ ] This change does **not** expand the RSA public exponent whitelist beyond `{3, 65537}`.
- [ ] This change does **not** downgrade OAEP parameters (MGF1-SHA256 / SHA-256).
- [ ] This change does **not** reduce the DEK length below 32 bytes or AES nonce length below 12 bytes.
- [ ] This change does **not** store any secret key in plaintext on disk.
- [ ] This change does **not** introduce an error-message oracle (all validation/decryption failures must remain generic `"Decryption failed"`; only malformed JSON/UTF-8 raises `"Invalid container format"`).
- [ ] This change does **not** break decryption of existing format versions (`SUPPORTED_FORMAT_VERSIONS` stays supported).
- [ ] This change preserves the DEK-zeroing behaviour in encrypt/decrypt paths.
- [ ] If this change touches key derivation, sealing, or encryption logic, I have added a written justification in the description above.
- [ ] All new code has type hints and docstrings (per `CONTRIBUTING.md`); tests document the security property they verify.
- [ ] I have added tests for any new functionality (positive **and** negative for security-affecting functions).
- [ ] I have run `pytest tests/ -v` and all tests pass.
- [ ] I have read `CONTRIBUTING.md`.
- [ ] I have signed off my commits per the Developer Certificate of Origin (all commits carry a `Signed-off-by` trailer).

## How I tested

Describe the commands you ran and their output.

```bash
pytest tests/ -v
```

## Screenshots / logs (if applicable)

## Additional context

Anything reviewers should know.