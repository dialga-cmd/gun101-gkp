# Small tasks for new contributors

A curated list of **small, clearly-scoped tasks** suitable for new or casual
contributors. Each task is intentionally limited so a first-time contributor
can complete it without deep context.

**How to pick one:** fork the repository, claim a task by opening an issue or
commenting on an existing "good first issue" (GitHub label: `good first issue`,
see the [issues list](https://github.com/dialga-cmd/gun101-gkp/issues)), then
follow [CONTRIBUTING.md](../CONTRIBUTING.md).

The DCO applies to every contribution: **sign off your commits** with
`git commit -s` (see [`DCO`](../DCO)).

---

## Tests

1. **Cover the remaining `identity.py` error paths.** `load_public_key_from_token`
   raises `ValueError("Invalid base64")` on malformed tokens and
   `ValueError("Failed to deserialize public key from DER")` on bad DER — the
   latter two branches are currently untested. Add negative tests. (~30 min.)
   Files: `tests/test_gkp.py`, `src/gun101gkp/identity.py`.

2. **Add error-path tests for `handler.encrypt_for_recipient`.**
   Invalid/malformed recipient tokens should fail before any key is generated.
   Assert the file is untouched on failure. (~45 min.)
   Files: `tests/test_gkp.py`, `src/gun101gkp/handler.py`.

3. **Property-style roundtrip test.** Add a parametrized test that encrypts then
   decrypts the same plaintext across a range of sizes (0 bytes, 1 byte, 16,
   256, 1 MiB, 16 MiB) to catch size-dependent bugs. (~1 h.)
   Files: `tests/test_gkp.py`.

## CLI & UX

4. **Shell completions.** Add `scripts/completions/bash/gun101gkp.bash` (and
   optionally fish/zsh) invoking `argparse._get_full_arg_string` or a static
   completion list of the five subcommands. Document in
   `docs/` and wire into the website "Installation" section. (~1 h.)
   Files: new `scripts/`, `CONTRIBUTING.md`.

5. **`--json` output flag.** Add a `--json` option to `fingerprint` and
   `show-identity` that prints machine-readable output, preserving existing
   default behaviour. Add tests. (~1 h.)
   Files: `src/gun101gkp/cli.py`, `tests/test_cli.py`.

6. **Manpage.** Write `docs/man/gun101gkp.1` (roff) covering all subcommands and
   options, referencing the CLI in `cli.py`. Wire into `pyproject.toml`
   `[project.scripts]` documentation. (~1 h.)
   Files: new `docs/man/`, `pyproject.toml`.

## Tooling & docs

7. **pre-commit hook config.** Add `.pre-commit-config.yaml` running `ruff`,
   `mypy`, `bandit`, and `pip-audit` on staged files; document usage in
   `CONTRIBUTING.md`. (~30 min.)
   Files: new `.pre-commit-config.yaml`, `CONTRIBUTING.md`.

8. **Add a `--version` smoke test.** Verify `python -m gun101gkp.cli
   --version` and `python -m gun101gkp.cli --help` exit 0 in CI (a new matrix
   dimension or a step in the existing `test` job). (~30 min.)
   Files: `.github/workflows/ci.yml`, `tests/test_cli.py`.

9. **Benchmark script.** Add `benchmarks/bench.py` (stdlib `timeit`) that
   measures encrypt/decrypt throughput for 1 KiB and 1 MiB payloads and prints a
   table; document the numbers and acceptable thresholds in
   `docs/TASKS.md`→`docs/PERFORMANCE.md`. (~1 h.)
   Files: new `benchmarks/`, `docs/PERFORMANCE.md`.

10. **Document the container format.** Expand `docs/ARCHITECTURE.md` with a
    field-by-field description of the JSON container (each field already
    documented as a protected invariant in `CONTRIBUTING.md`). (~45 min.)
    Files: `docs/ARCHITECTURE.md`, `src/gun101gkp/handler.py`.

---

## What is *not* a small task

Task that change the security properties in
`CONTRIBUTING.md` → "Protected invariants" (key sizes, formats, error-message
behaviour) should **not** be attempted as a first contribution — they require
a written justification and a semver-major release. If you are unsure, ask
first by opening an issue.