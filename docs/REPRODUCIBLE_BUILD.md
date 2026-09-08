# Reproducible Build

The project satisfies the OpenSSF `build_reproducible` criterion: the build is
reproducible — two fresh, isolated builds of the same source produce
byte-identical artifacts (the wheel) and identical artifact *contents* (the
sdist).

## What "reproducible" means here

- **Wheel (`*.whl`):** byte-for-byte identical across builds, given a fixed
  `SOURCE_DATE_EPOCH`.
- **sdist (`*.tar.gz`):** the gzip container header embeds a wall-clock MTIME
  that the Python stdlib writes from the system clock, so the raw archive header
  bytes can differ between builds. The **contents** — every file that ships — are
  byte-for-byte identical. For a source archive, content reproducibility is the
  meaningful guarantee; this is what the checker verifies.

## Determinism controls

- `SOURCE_DATE_EPOCH` pins the timestamps setuptools records in `PKG-INFO`,
  `METADATA`, and the tar member mtimes.
- Build toolchain versions are pinned in [`constraints-build.txt`](../constraints-build.txt)
  so every build uses the same `setuptools` / `wheel` versions (see
  [`pyproject.toml`](../pyproject.toml) `[build-system]`).

## How to verify locally

```bash
tox -e repro
```

or manually:

```bash
pip install build
mkdir -p dist1 dist2
SOURCE_DATE_EPOCH=0 python -m build --outdir dist1
SOURCE_DATE_EPOCH=0 python -m build --outdir dist2
python scripts/repro_check.py dist1 dist2   # must exit 0
```

`scripts/repro_check.py` decompresses each sdist, re-serialises each member's
content with fixed metadata, fingerprints it, and compares across the two build
directories; wheels are hashed byte-for-byte.

## Enforcement in CI

The `reproducible-build` job in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
runs this check on every push and pull request, so a change that makes the build
non-reproducible fails CI before it can be released.
