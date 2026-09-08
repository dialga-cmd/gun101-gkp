# Copyright (c) 2026 Security Team
# SPDX-License-Identifier: MIT
"""
Test suite for the GUN-101-GKP command-line interface.

Exercises each CLI subcommand through argparse to improve statement coverage and
verify end-to-end behaviour (identity generation, show, fingerprint, encrypt,
decrypt, reset).
"""
import os

import pytest

from gun101gkp import config
from gun101gkp.cli import (
    cmd_decrypt,
    cmd_encrypt,
    cmd_fingerprint,
    cmd_generate_identity,
    cmd_reset_identity,
    cmd_show_identity,
    main,
)


class _Args:
    """Minimal stand-in for argparse.Namespace attributes used by commands."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def _fresh_identity_path():
    return config.PRIVATE_KEY_PATH


def _setup(tmpdir, monkeypatch):
    """Point the private-key path into a temp dir for isolation."""
    private_path = os.path.join(tmpdir, "private_key.pem")
    monkeypatch.setattr(config, "PRIVATE_KEY_PATH", private_path)
    return private_path


def test_cmd_generate_identity_writes_key_and_token(tmpdir, monkeypatch, capsys):
    """generate-identity creates a private key and prints a token/fingerprint."""
    _setup(tmpdir, monkeypatch)
    args = _Args(passphrase=False)
    cmd_generate_identity(args)
    out = capsys.readouterr().out
    assert "Identity token:" in out
    assert "Fingerprint:" in out
    assert os.path.exists(config.PRIVATE_KEY_PATH)


def test_cmd_generate_identity_mismatched_passphrase(tmpdir, monkeypatch, capsys):
    """generate-identity rejects a mismatch between the two passphrase prompts."""
    _setup(tmpdir, monkeypatch)
    args = _Args(passphrase=True)

    values = ["secret", "different"]

    def fake_getpass(prompt):
        return values.pop(0)

    monkeypatch.setattr("getpass.getpass", fake_getpass)
    with pytest.raises(SystemExit) as exc:
        cmd_generate_identity(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Passphrases do not match" in captured.err


def test_cmd_generate_identity_when_exists(tmpdir, monkeypatch, capsys):
    """generate-identity fails if an identity already exists."""
    _setup(tmpdir, monkeypatch)
    args = _Args(passphrase=False)
    cmd_generate_identity(args)
    with pytest.raises(SystemExit) as exc:
        cmd_generate_identity(args)
    assert exc.value.code == 1
    assert "Error" in capsys.readouterr().err


def test_cmd_show_identity_without_identity(tmpdir, monkeypatch, capsys):
    """show-identity errors when no identity exists."""
    _setup(tmpdir, monkeypatch)
    args = _Args()
    with pytest.raises(SystemExit) as exc:
        cmd_show_identity(args)
    assert exc.value.code == 1
    assert "No identity found" in capsys.readouterr().err


def test_cmd_show_identity_with_identity(tmpdir, monkeypatch, capsys):
    """show-identity prints the stored identity token."""
    _setup(tmpdir, monkeypatch)
    cmd_generate_identity(_Args(passphrase=False))
    capsys.readouterr()  # discard generate-identity output
    cmd_show_identity(_Args())
    out = capsys.readouterr().out.strip()
    assert out.startswith(config.TOKEN_PREFIX)


def test_cmd_fingerprint_with_token(tmpdir, monkeypatch, capsys):
    """fingerprint prints the fingerprint for the given token."""
    _setup(tmpdir, monkeypatch)
    from gun101gkp.identity import generate_identity

    token = generate_identity()
    cmd_fingerprint(_Args(token=token))
    out = capsys.readouterr().out.strip()
    assert len(out) > 0


def test_cmd_fingerprint_default_stored(tmpdir, monkeypatch, capsys):
    """fingerprint falls back to the stored identity when no token is given."""
    _setup(tmpdir, monkeypatch)
    cmd_generate_identity(_Args(passphrase=False))
    cmd_fingerprint(_Args(token=None))
    # A stored-identity fingerprint has colon-hex format like AA:BB:...
    out = capsys.readouterr().out.strip()
    assert ":" in out


def test_cmd_encrypt_and_decrypt_roundtrip(tmpdir, monkeypatch, capsys):
    """encrypt then decrypt reproduces the original file bytes."""
    _setup(tmpdir, monkeypatch)
    cmd_generate_identity(_Args(passphrase=False))
    from gun101gkp.identity import get_identity_token

    recipient = get_identity_token()

    plain_path = os.path.join(tmpdir, "plain.txt")
    enc_path = os.path.join(tmpdir, "plain.txt.gkp")
    dec_path = os.path.join(tmpdir, "decrypted.txt")
    with open(plain_path, "wb") as f:
        f.write(b"top secret payload")

    # Encrypt to a separate output file, then decrypt.
    cmd_encrypt(_Args(file=plain_path, recipient=recipient, output=enc_path))
    assert os.path.exists(enc_path)

    cmd_decrypt(_Args(file=enc_path, output=dec_path, passphrase=False))
    with open(dec_path, "rb") as f:
        assert f.read() == b"top secret payload"


def test_cmd_encrypt_missing_file(tmpdir, monkeypatch, capsys):
    """encrypt errors when the input file does not exist."""
    _setup(tmpdir, monkeypatch)
    args = _Args(file=os.path.join(tmpdir, "nope.txt"), recipient="x", output=None)
    with pytest.raises(SystemExit) as exc:
        cmd_encrypt(args)
    assert exc.value.code == 1
    assert "not found" in capsys.readouterr().err


def test_cmd_decrypt_missing_file(tmpdir, monkeypatch, capsys):
    """decrypt errors when the input file does not exist."""
    _setup(tmpdir, monkeypatch)
    args = _Args(file=os.path.join(tmpdir, "nope.gkp"), output=None, passphrase=False)
    with pytest.raises(SystemExit) as exc:
        cmd_decrypt(args)
    assert exc.value.code == 1
    assert "not found" in capsys.readouterr().err


def test_cmd_encrypt_invalid_recipient(tmpdir, monkeypatch, capsys):
    """encrypt errors on a malformed recipient token."""
    _setup(tmpdir, monkeypatch)
    plain_path = os.path.join(tmpdir, "plain.txt")
    with open(plain_path, "wb") as f:
        f.write(b"data")
    args = _Args(file=plain_path, recipient="invalid-token", output=None)
    with pytest.raises(SystemExit) as exc:
        cmd_encrypt(args)
    assert exc.value.code == 1
    assert "Error" in capsys.readouterr().err


def test_cmd_reset_identity_without_identity(tmpdir, monkeypatch, capsys):
    """reset-identity errors when no identity exists."""
    _setup(tmpdir, monkeypatch)
    args = _Args()
    with pytest.raises(SystemExit) as exc:
        cmd_reset_identity(args)
    assert exc.value.code == 1
    assert "No identity found" in capsys.readouterr().err


def test_cmd_reset_identity_confirmation(tmpdir, monkeypatch, capsys):
    """reset-identity requires typing YES before removing the identity."""
    _setup(tmpdir, monkeypatch)
    cmd_generate_identity(_Args(passphrase=False))
    monkeypatch.setattr("builtins.input", lambda _prompt: "NO")
    with pytest.raises(SystemExit) as exc:
        cmd_reset_identity(_Args())
    assert exc.value.code == 1
    assert "Aborted" in capsys.readouterr().err


def test_cmd_reset_identity_removes_key(tmpdir, monkeypatch, capsys):
    """reset-identity with YES deletes the private key file."""
    _setup(tmpdir, monkeypatch)
    cmd_generate_identity(_Args(passphrase=False))
    assert os.path.exists(config.PRIVATE_KEY_PATH)
    monkeypatch.setattr("builtins.input", lambda _prompt: "YES")
    cmd_reset_identity(_Args())
    assert not os.path.exists(config.PRIVATE_KEY_PATH)


def test_main_no_command_shows_help(tmpdir, monkeypatch, capsys):
    """main() without a subcommand prints help and exits non-zero."""
    _setup(tmpdir, monkeypatch)
    with pytest.raises(SystemExit) as exc:
        _run_main([], monkeypatch)
    assert exc.value.code == 1
    assert "usage" in capsys.readouterr().out.lower()


def test_main_generate_and_show_identity(tmpdir, monkeypatch, capsys):
    """main() dispatches generate-identity then show-identity."""
    _setup(tmpdir, monkeypatch)
    _run_main(["generate-identity"], monkeypatch)
    capsys.readouterr()  # discard
    _run_main(["show-identity"], monkeypatch)
    out = capsys.readouterr().out.strip()
    assert out.startswith(config.TOKEN_PREFIX)


def test_main_encrypt_decrypt_roundtrip(tmpdir, monkeypatch, capsys):
    """main() end-to-end encrypt and decrypt of a file."""
    _setup(tmpdir, monkeypatch)
    _run_main(["generate-identity"], monkeypatch)
    from gun101gkp.identity import get_identity_token

    recipient = get_identity_token()

    plain_path = os.path.join(tmpdir, "m.txt")
    enc_path = os.path.join(tmpdir, "m.txt.gkp")
    dec_path = os.path.join(tmpdir, "out.txt")
    with open(plain_path, "wb") as f:
        f.write(b"main dispatch payload")

    _run_main(
        ["encrypt", plain_path, "--recipient", recipient, "--output", enc_path],
        monkeypatch,
    )
    assert os.path.exists(enc_path)

    _run_main(
        ["decrypt", enc_path, "--output", dec_path],
        monkeypatch,
    )
    with open(dec_path, "rb") as f:
        assert f.read() == b"main dispatch payload"


def test_main_fingerprint_with_token(tmpdir, monkeypatch, capsys):
    """main() dispatches fingerprint with an explicit --token."""
    _setup(tmpdir, monkeypatch)
    _run_main(["generate-identity"], monkeypatch)
    from gun101gkp.identity import get_identity_token

    token = get_identity_token()
    _run_main(["fingerprint", "--token", token], monkeypatch)
    out = capsys.readouterr().out.strip()
    assert ":" in out


def test_cmd_show_identity_errors_on_get_token_failure(tmpdir, monkeypatch, capsys):
    """show-identity surfaces a ValueError from get_identity_token."""
    _setup(tmpdir, monkeypatch)
    monkeypatch.setattr(
        "gun101gkp.cli.has_identity", lambda: True
    )
    import gun101gkp.cli as cli
    monkeypatch.setattr(
        cli, "get_identity_token", lambda: (_ for _ in ()).throw(ValueError("token missing"))
    )
    with pytest.raises(SystemExit) as exc:
        cmd_show_identity(_Args())
    assert exc.value.code == 1
    assert "token missing" in capsys.readouterr().err


def test_cmd_fingerprint_no_identity_no_token(tmpdir, monkeypatch, capsys):
    """fingerprint with no stored identity and no token errors."""
    _setup(tmpdir, monkeypatch)
    with pytest.raises(SystemExit) as exc:
        cmd_fingerprint(_Args(token=None))
    assert exc.value.code == 1
    assert "No identity found" in capsys.readouterr().err


def test_cmd_fingerprint_stored_identity_error(tmpdir, monkeypatch, capsys):
    """fingerprint surfaces errors falling back to the stored identity."""
    _setup(tmpdir, monkeypatch)
    import gun101gkp.cli as cli
    monkeypatch.setattr(cli, "has_identity", lambda: True)
    monkeypatch.setattr(
        cli, "get_identity_token", lambda: (_ for _ in ()).throw(ValueError("no token"))
    )
    with pytest.raises(SystemExit) as exc:
        cmd_fingerprint(_Args(token=None))
    assert exc.value.code == 1
    assert "no token" in capsys.readouterr().err


def test_cmd_fingerprint_invalid_token(tmpdir, monkeypatch, capsys):
    """fingerprint with a malformed token errors."""
    _setup(tmpdir, monkeypatch)
    with pytest.raises(SystemExit) as exc:
        cmd_fingerprint(_Args(token="bad-token"))
    assert exc.value.code == 1
    assert "Error" in capsys.readouterr().err


def test_cmd_encrypt_read_error(tmpdir, monkeypatch, capsys):
    """encrypt surfaces an OSError reading the input file."""
    _setup(tmpdir, monkeypatch)
    import gun101gkp.cli as cli

    def fake_open(path, mode):
        raise OSError("permission denied")

    monkeypatch.setattr(cli.os.path, "isfile", lambda p: True)
    monkeypatch.setattr("builtins.open", fake_open)
    with pytest.raises(SystemExit) as exc:
        cmd_encrypt(_Args(file="f.txt", recipient="tok", output=None))
    assert exc.value.code == 1
    assert "Cannot read file" in capsys.readouterr().err


def test_cmd_encrypt_write_error(tmpdir, monkeypatch, capsys):
    """encrypt surfaces an OSError writing the output file."""
    _setup(tmpdir, monkeypatch)
    cmd_generate_identity(_Args(passphrase=False))
    from gun101gkp.identity import get_identity_token

    recipient = get_identity_token()
    plain_path = os.path.join(tmpdir, "p.txt")
    with open(plain_path, "wb") as f:
        f.write(b"data")

    real_open = open

    def fake_open(path, mode="r", *a, **k):
        if "wb" in mode:
            raise OSError("disk full")
        return real_open(path, mode, *a, **k)

    monkeypatch.setattr("builtins.open", fake_open)
    with pytest.raises(SystemExit) as exc:
        cmd_encrypt(_Args(file=plain_path, recipient=recipient, output=None))
    assert exc.value.code == 1
    assert "Cannot write output" in capsys.readouterr().err


def test_cmd_decrypt_invalid_container(tmpdir, monkeypatch, capsys):
    """decrypt surfaces a ValueError for a malformed container."""
    _setup(tmpdir, monkeypatch)
    cmd_generate_identity(_Args(passphrase=False))
    bad_path = os.path.join(tmpdir, "bad.gkp")
    with open(bad_path, "wb") as f:
        f.write(b"not a container")
    with pytest.raises(SystemExit) as exc:
        cmd_decrypt(_Args(file=bad_path, output=None, passphrase=False))
    assert exc.value.code == 1
    assert "Error" in capsys.readouterr().err


def test_cmd_decrypt_strips_gkp_extension(tmpdir, monkeypatch, capsys):
    """decrypt to default output strips a trailing .gkp extension."""
    _setup(tmpdir, monkeypatch)
    cmd_generate_identity(_Args(passphrase=False))
    from gun101gkp.identity import get_identity_token

    recipient = get_identity_token()
    plain_path = os.path.join(tmpdir, "secret.txt")
    enc_path = plain_path + ".gkp"
    with open(plain_path, "wb") as f:
        f.write(b"payload with extension")
    cmd_encrypt(_Args(file=plain_path, recipient=recipient, output=enc_path))
    capsys.readouterr()
    cmd_decrypt(_Args(file=enc_path, output=None, passphrase=False))
    with open(plain_path, "rb") as f:
        assert f.read() == b"payload with extension"
    assert "Decrypted file written to" in capsys.readouterr().out


def test_cmd_encrypt_uses_getpass_flow(tmpdir, monkeypatch, capsys):
    """encrypt/decrypt roundtrip is unaffected by the getpass branch."""
    _setup(tmpdir, monkeypatch)
    values = ["secret", "secret"]

    def fake_getpass(prompt):
        return values.pop(0)

    monkeypatch.setattr("getpass.getpass", fake_getpass)
    cmd_generate_identity(_Args(passphrase=True))
    out = capsys.readouterr().out
    recipient = [line.split(": ", 1)[1] for line in out.splitlines()
                 if line.startswith("Identity token:")][0]

    plain_path = os.path.join(tmpdir, "gp.txt")
    enc_path = os.path.join(tmpdir, "gp.txt.gkp")
    dec_path = os.path.join(tmpdir, "gp_out.txt")
    with open(plain_path, "wb") as f:
        f.write(b"getpass flow")
    cmd_encrypt(_Args(file=plain_path, recipient=recipient, output=enc_path))
    capsys.readouterr()
    monkeypatch.setattr("getpass.getpass", lambda _prompt: "secret")
    cmd_decrypt(_Args(file=enc_path, output=dec_path, passphrase=True))
    with open(dec_path, "rb") as f:
        assert f.read() == b"getpass flow"


def test_cmd_reset_identity_error(tmpdir, monkeypatch, capsys):
    """reset-identity surfaces an error from reset_identity."""
    _setup(tmpdir, monkeypatch)
    cmd_generate_identity(_Args(passphrase=False))
    monkeypatch.setattr("builtins.input", lambda _prompt: "YES")
    import gun101gkp.cli as cli
    monkeypatch.setattr(
        cli, "reset_identity", lambda: (_ for _ in ()).throw(ValueError("boom"))
    )
    with pytest.raises(SystemExit) as exc:
        cmd_reset_identity(_Args())
    assert exc.value.code == 1
    assert "boom" in capsys.readouterr().err


def _run_main(argv, monkeypatch):
    """Run main() with a synthetic sys.argv."""
    import sys

    monkeypatch.setattr(sys, "argv", ["gun101gkp"] + argv)
    main()
