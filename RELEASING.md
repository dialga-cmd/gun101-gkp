# Releasing GUN-101-GKP

This document describes how to ship a release of GUN-101-GKP. It covers both
**stable** releases and **interim (pre-release)** versions.

## Why interim versions matter

Per the OpenSSF Best Practices Badge criteria, the project must make interim
versions available for review between releases — not only final releases. We
meet this by publishing PEP 440 **pre-releases** (alphas and release candidates)
to PyPI between stable releases. Anyone can install and review these before the
final release, which enables collaborative review of work in progress.

## Versioning scheme

We use Semantic Versioning (`MAJOR.MINOR.PATCH`) and PEP 440 pre-release labels:

| Stage          | Version example | Published to PyPI |
| -------------- | --------------- | ----------------- |
| Development    | `3.2.0a1`, `3.2.0a2` (alpha)   | Yes (pre-release) |
| Release candidate | `3.2.0rc1`, `3.2.0rc2` | Yes (pre-release) |
| Stable         | `3.2.0`         | Yes (release)     |

PyPI marks any version containing `a`, `b`, or `rc` as a pre-release, so these
will never be installed by default (`pip install gun101-gkp` still gets the
latest stable). Users can opt in with `pip install gun101-gkp==3.2.0rc1`.

> The public security policy states that only the latest minor release line
> receives security fixes. Pre-releases are not a "supported line"; they are
> interim review snapshots of the upcoming release.

## Before any release

1. **Bump the version** in `pyproject.toml` (`[project] version = "..."`) to the
   target version. The version must match the tag **exactly** (the publish
   workflow validates this and fails otherwise).
2. **Update `CHANGELOG.md`** — move the unreleased section under the new version
   heading and add a "Unreleased" section for the next cycle. Keep it
   [Keep a Changelog](https://keepachangelog.com/) format.
3. **Security-affecting change?** Update `docs/SECURITY.md` and
   `docs/THREAT_MODEL.md` if the guarantees changed, and add the cryptographic
   justification to the release notes.
4. **Run the full suite locally:**
   ```bash
   pytest tests/ -v
   ```
   All tests must pass before tagging.
5. **Create and merge a PR** with these changes (bump + changelog + docs) to
   `main`. Release from `main` only.

## Cutting a release

Anything that ships is triggered by a **tag**. The GitHub workflow
`.github/workflows/publish.yml` runs tests, builds the package, generates an SBOM,
attests provenance, and publishes to PyPI.

### Stable release

After the version-bump PR is merged to `main`:

```bash
git checkout main
git pull
git tag v3.2.0
git push origin v3.2.0
```

The `test` job runs, then `build` + publish completes. Verify on PyPI.

### Interim (pre-release)

The process is identical — just tag the interim version. For example, to publish
a release candidate:

```bash
git tag v3.2.0rc1
git push origin v3.2.0
```

More often a small batch of alphas is cut first, then release candidates, then
the stable release:

```bash
git tag v3.2.0a1 && git push origin v3.2.0a1
# ... iterate a2, a3 ...
git tag v3.2.0rc1 && git push origin v3.2.0rc1
git tag v3.2.0 && git push origin v3.2.0
```

Each tag publishes a distinct, reviewable artifact to PyPI. Because the publish
workflow validates that the tag matches `pyproject.toml`, remember to bump
`pyproject.toml` to each interim version (e.g. `3.2.0a1`, then `3.2.0rc1`)
before tagging it.

## Verifying a release

- **PyPI:** confirm the version appears at <https://pypi.org/project/gun101-gkp/>.
- **SBOM:** the workflow uploads `sbom.json` alongside the release.
- **Provenance:** the build-attestation is recorded via
  `actions/attest-build-provenance`.

## Hotfixes

Patch fixes to the supported line use the same flow with a `PATCH` bump
(e.g. `3.1.3`) and are cut as stable releases. Create a branch off the
`3.1.x` release tag if the line has diverged from `main`.

## Support policy

Only the latest minor release line receives fixes (see `SECURITY_POLICY.md`).
When a new minor version ships, update the supported table there and note the
end-of-life of the previous line in `CHANGELOG.md`.
