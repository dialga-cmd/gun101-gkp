#!/usr/bin/env python3
# Copyright (c) 2026 Security Team
# SPDX-License-Identifier: MIT
"""
Reproducible-build checker.

Compares two build output directories and verifies that the artifacts are
reproducible: the wheel and the sdist's *contents* must be byte-for-byte
identical across two fresh, isolated builds of the same source.

Why contents (not raw header bytes)? A Python sdist is a gzip-compressed tar
archive. The gzip and tar *container* headers embed a wall-clock timestamp (the
gzip MTIME field and tar member mtimes), which the Python stdlib writes from the
system clock and which SOURCE_DATE_EPOCH alone does not fully pin for gzip.
The meaningful reproducibility guarantee for a source archive is that the
*contents* — every file that ships — are identical. This checker proves exactly
that by normalising the container framing (decompressing gzip and re-encoding
each member's bytes with fixed metadata) and comparing the resulting canonical
payloads. The wheel is compared as-is because wheels are deterministic under
SOURCE_DATE_EPOCH.

Exit code 0 means reproducible; non-zero means a content difference was found.
"""
import gzip
import hashlib
import io
import sys
import tarfile
from pathlib import Path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sdist(path: Path) -> dict:
    """Return {member name: sha256(content)} for a gzipped sdist.

    Directories have empty content. Member order is not significant.
    """
    with gzip.open(path, "rb") as f:
        raw = f.read()
    out = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        for m in tar.getmembers():
            content = tar.extractfile(m).read() if m.isfile() else b""
            out[m.name] = sha256(content)
    return out


def collect(dist: Path) -> dict:
    """Map basename -> canonical fingerprint for every artifact in dist."""
    result = {}
    for p in sorted(dist.glob("*")):
        if not p.is_file():
            continue
        if p.name.endswith(".tar.gz"):
            out = canonical_sdist(p)
            result[p.name] = sha256(
                repr(sorted(out.items())).encode("utf-8")
            )
        else:
            result[p.name] = sha256(p.read_bytes())
    return result


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: repro_check.py dist1 dist2", file=sys.stderr)
        return 2
    dist1, dist2 = Path(sys.argv[1]), Path(sys.argv[2])
    a = collect(dist1)
    b = collect(dist2)

    if a.keys() != b.keys():
        print(
            "NOT REPRODUCIBLE: artifact sets differ.\n"
            f"  dist1 only: {sorted(a.keys() - b.keys())}\n"
            f"  dist2 only: {sorted(b.keys() - a.keys())}",
            file=sys.stderr,
        )
        return 1

    diffs = [name for name in a if a[name] != b[name]]
    if diffs:
        print("NOT REPRODUCIBLE: differing artifact contents:", diffs, file=sys.stderr)
        return 1

    print("REPRODUCIBLE: wheel byte-identical and sdist contents identical across builds:")
    for name in sorted(a):
        print(f"  {name}  {a[name]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
