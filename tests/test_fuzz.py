# Copyright (c) 2026 Security Team
# SPDX-License-Identifier: MIT
"""
Dynamic-analysis (fuzzing) test suite using Hypothesis.

Fuzzes the public API with generated and randomly mutated inputs. The only
exceptions a caller may legitimately observe are the documented ones
(``ValueError``, ``FileNotFoundError``, and ``TypeError`` for genuinely wrong
argument types). Any other exception escaping these functions is a bug.

These tests are the project's dynamic analysis tooling: they execute the
library with adversarial inputs and are required to pass before any release
(see ``RELEASING.md`` and ``.github/workflows/publish.yml``).

Assertions are part of the check: the runtime ``assert`` statements inside
``src/gun101gkp/`` are exercised by every fuzz example, so this suite MUST run
with Python assertions enabled (i.e. **not** with ``python -O``).
"""
import json
import sys

import hypothesis.strategies as st
import pytest
from hypothesis import given, settings

from gun101gkp import config
from gun101gkp.handler import decrypt_as_recipient, encrypt_for_recipient
from gun101gkp.identity import generate_identity, load_public_key_from_token


@pytest.fixture(scope="module")
def identity(tmp_path_factory):
    """One RSA-4096 identity shared by all fuzz examples.

    Key generation is intentionally excluded from the fuzzed input space and
    performed exactly once per module so the examples stay fast.
    """
    private_path = tmp_path_factory.mktemp("fuzz") / "private_key.pem"
    config.PRIVATE_KEY_PATH = str(private_path)
    token = generate_identity()
    return token


def test_asserts_enabled_during_dynamic_analysis():
    """Dynamic analysis must run the runtime assertions inside src/.

    Python disables ``assert`` statements with ``-O`` (optimization); pytest and
    the CI jobs run without ``-O``, so asserts are live. Guarded here so a
    future ``-O`` invocation cannot silently skip them.
    """
    assert not sys.flags.optimize, "dynamic analysis must run with asserts enabled"


@given(st.binary(max_size=4096))
@settings(max_examples=150)
def test_decrypt_never_crashes_on_arbitrary_bytes(container_data: bytes) -> None:
    """Arbitrary bytes passed as a container must never crash the process."""
    try:
        result = decrypt_as_recipient(container_data)
    except (ValueError, FileNotFoundError, TypeError):
        return
    assert isinstance(result, bytes)


@given(st.binary(max_size=4096))
@settings(max_examples=150)
def test_decrypt_never_crashes_with_passphrase(container_data: bytes) -> None:
    """The passphrase branch must also only raise documented exceptions."""
    try:
        result = decrypt_as_recipient(container_data, passphrase="fuzz")
    except (ValueError, FileNotFoundError, TypeError):
        return
    assert isinstance(result, bytes)


@given(st.text(max_size=1024))
@settings(max_examples=150)
def test_token_load_never_crashes(token: str) -> None:
    """Arbitrary recipient tokens must only raise ValueError."""
    try:
        load_public_key_from_token(token)
    except ValueError:
        return
    # token is a str, so TypeError is not expected here


@given(st.text(max_size=1024), st.binary(max_size=1024))
@settings(max_examples=150)
def test_encrypt_never_crashes_on_arbitrary_token_and_data(token: str, file_data: bytes) -> None:
    """Arbitrary (token, data) pairs must only raise documented exceptions."""
    try:
        encrypt_for_recipient(file_data, token)
    except (ValueError, TypeError):
        return
    assert isinstance(token, str) and isinstance(file_data, bytes)


@given(
    mutations=st.dictionaries(
        st.sampled_from(
            ["protocol", "version", "recipient_fingerprint", "sealed_dek",
             "nonce", "ciphertext", "tag"]
        ),
        st.one_of(
            st.text(max_size=64),
            st.integers(),
            st.floats(allow_nan=False),
            st.booleans(),
            st.none(),
        ),
        min_size=1,
        max_size=7,
    )
)
@settings(max_examples=300, deadline=None)
def test_decrypt_mutated_container_fields(identity: str, mutations: dict) -> None:
    """A real container's fields, arbitrarily mutated, must only yield documented failures.

    Starts from a structurally valid container so mutations reach the decode
    and cryptographic validation paths, not just the top-level checks.
    """
    container = json.loads(encrypt_for_recipient(b"fuzz", identity))
    container.update(mutations)
    container_data = json.dumps(container).encode("utf-8")
    try:
        result = decrypt_as_recipient(container_data)
    except (ValueError, FileNotFoundError, TypeError):
        return
    assert isinstance(result, bytes)


@given(st.binary(min_size=1, max_size=8192))
@settings(max_examples=60, deadline=None)
def test_roundtrip_fuzz(identity: str, file_data: bytes) -> None:
    """Fuzzed plaintext must always round-trip through encrypt -> decrypt."""
    container = encrypt_for_recipient(file_data, identity)
    plaintext = decrypt_as_recipient(container)
    assert plaintext == file_data
