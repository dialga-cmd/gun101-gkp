---
name: Bug report
about: Report a bug in GUN-101-GKP
title: "[Bug] "
labels: bug
assignees: ''

---

> **Security vulnerability?** Do **not** open a public issue. Email
> `adityaraj1234@duck.com` instead (see `SECURITY_POLICY.md`). Public disclosure of
> a vulnerability before a fix exists puts every user at risk.

**Checklist before submitting**

- [ ] I have read `SECURITY_POLICY.md` and this is **not** a security vulnerability.
- [ ] I have checked that this is not a known limitation documented in `THREAT_MODEL.md` or `SECURITY.md`. *(Required.)*
- [ ] I have searched the existing issues and this is not a duplicate.

## Description

Describe the bug clearly and concisely.

## Steps to reproduce

Give the exact CLI command or Python snippet. If it uses the library API, show the imports.
If it involves the CLI, show the exact commands in order.

```bash
# example
gun101gkp generate-identity
gun101gkp encrypt report.pdf --recipient GUN101GKP-v2-<token>
gun101gkp decrypt report.pdf.gkp
```

```python
# example
from gun101gkp import generate_identity, encrypt_for_recipient, decrypt_as_recipient
```

## Expected behaviour

What did you expect to happen?

## Actual behaviour

What actually happened, including the **exact** error message or traceback:

```text
Error: ...
```

## Environment

- OS: (e.g. Ubuntu 24.04, Windows 11, macOS 14)
- Python version: `python --version`
- Library version: `pip show gun101-gkp`
- `cryptography` version: `pip show cryptography`
- Installation method: (editable dev install `pip install -e ".[dev]"`, or `pip install gun101-gkp`)

## Additional context

Anything else relevant: file sizes, unusual file types, whether the identity was
generated with `--passphrase`, locale, filesystem, etc.

---

Helpful reminders for triage (the maintainer will fill in):

- [ ] Reproduced
- [ ] Tests affected
- [ ] Security-relevant (`src/gun101gkp/config.py` / `handler.py` / `cipher.py` / `identity.py` touched)