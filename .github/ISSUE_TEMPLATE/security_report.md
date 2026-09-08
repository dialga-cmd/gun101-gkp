---
name: Security vulnerability
about: Report a security vulnerability in GUN-101-GKP (private, by email)
title: "SECURITY: DO NOT FILE A PUBLIC ISSUE"
labels: security
assignees: ''

---

> ## Stop — read this first
>
> **Do not use this form.** Once you open a public GitHub issue, it is visible to
> everyone — including attackers. If you file a security vulnerability publicly
> before a fix exists, you effectively hand exploit instructions to the people
> the library is trying to protect its users from.
>
> **Instead, email a private report to the maintainer, Aditya Raj, at**
>
> ### `adityaraj1234@duck.com`
>
> Your report will be acknowledged **within 48 hours**, and a fix timeline will
> be communicated **within 7 days** (see `SECURITY_POLICY.md`).
>
> If you have already opened a public issue describing a vulnerability, contact
> the maintainer by email (mentioning the issue number) — the issue will be
> handled promptly and marked as sensitive.
>
> Please do **not** mention the vulnerability in commits, forks, or other public
> places until a fix has been released.

---

If you are filing a **non-security** bug or feature request, use the corresponding
template in this directory instead.

## What to include in your private email report

Use this structure (copy it into the email):

### 1. Affected component

- CLI command or library module: (e.g. `gun101gkp.handler.decrypt_as_recipient`,
  `gun101gkp.identity.load_private_key`, `gun101gkp.cli`)
- Container format version and file format: (e.g. format `2.1`, `2.0`)

### 2. Description of the vulnerability

A clear, technical description. What is the impact? (e.g. decryption with the
wrong key, error-message oracle, timing leak, weakening of a parameter, memory
handling of the DEK or private key).

### 3. Steps to reproduce

Exact CLI commands or a minimal Python snippet, plus any crafted container
payload needed (base64 of `sealed_dek`, `nonce`, `tag`, etc.).

### 4. Potential impact

Who is affected and how badly? (data confidentiality, integrity, key recovery,
denial of service.)

### 5. Suggested fix (optional but appreciated)

A concise idea for the fix — or a note that you are working on a patch.

### 6. Credit preference

Let us know whether you would like to be credited in the CHANGELOG and README
acknowledgements (default), or if you prefer to stay anonymous.

## Response commitment

- **Acknowledgement:** within 48 hours of receipt.
- **Fix timeline:** communicated within 7 days.
- **Disclosure:** coordinated — details are published only after a fixed version
  is released, unless you request otherwise.

Thank you for helping keep GUN-101-GKP safe for everyone.