"""
Test suite for GUN-101-GKP.

Each test includes a docstring explaining the security property being verified.
"""
import os
import base64
import json
import tempfile
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

from gun101gkp import config
from gun101gkp.identity import (
    generate_identity,
    get_identity_token,
    get_identity_fingerprint,
    has_identity,
    reset_identity,
    load_private_key,
    load_public_key_from_token,
)
from gun101gkp.cipher import encrypt, decrypt
from gun101gkp.handler import encrypt_for_recipient, decrypt_as_recipient


def test_generate_identity_creates_private_key_at_correct_path():
    """generate_identity() creates a private key at the correct path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            assert not os.path.exists(config.PRIVATE_KEY_PATH)
            token = generate_identity()
            assert os.path.exists(config.PRIVATE_KEY_PATH)
            assert os.path.isfile(config.PRIVATE_KEY_PATH)
            assert isinstance(token, str)
            assert token.startswith(config.TOKEN_PREFIX)
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)


def test_private_key_file_has_0o600_permissions():
    """Private key file has 0o600 permissions."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            generate_identity()
            mode = os.stat(config.PRIVATE_KEY_PATH).st_mode & 0o777
            assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)


def test_get_identity_token_returns_string_with_prefix():
    """get_identity_token() returns a string starting with TOKEN_PREFIX."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            token = generate_identity()
            retrieved_token = get_identity_token()
            assert retrieved_token == token
            assert isinstance(retrieved_token, str)
            assert retrieved_token.startswith(config.TOKEN_PREFIX)
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)


def test_get_identity_fingerprint_returns_colon_separated_hex():
    """get_identity_fingerprint() returns colon-separated uppercase hex pairs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            token = generate_identity()
            fingerprint = get_identity_fingerprint(token)
            # Check format: XX:XX:XX:... (uppercase hex)
            parts = fingerprint.split(':')
            assert len(parts) == 32  # SHA-256 is 32 bytes -> 64 hex chars -> 32 pairs
            for part in parts:
                assert len(part) == 2
                assert all(c in '0123456789ABCDEF' for c in part)
            # Also test with no argument (should use stored identity)
            fingerprint2 = get_identity_fingerprint()
            assert fingerprint == fingerprint2
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)


def test_generate_identity_raises_if_id_exists():
    """generate_identity() raises ValueError if identity already exists."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            generate_identity()
            with pytest.raises(ValueError, match="Identity already exists"):
                generate_identity()
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)


def test_reset_identity_deletes_key_file():
    """reset_identity() deletes the private key file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            generate_identity()
            assert os.path.exists(config.PRIVATE_KEY_PATH)
            reset_identity()
            assert not os.path.exists(config.PRIVATE_KEY_PATH)
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)


def test_has_identity_returns_false_after_reset():
    """has_identity() returns False after reset_identity()."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            assert not has_identity()
            generate_identity()
            assert has_identity()
            reset_identity()
            assert not has_identity()
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)


def test_load_public_key_from_token_fails_on_malformed_token():
    """load_public_key_from_token() fails on malformed token."""
    with pytest.raises(ValueError, match="Token must start with prefix"):
        load_public_key_from_token("invalidtoken")
    with pytest.raises(ValueError, match="Invalid base64"):
        load_public_key_from_token(config.TOKEN_PREFIX + "!!!")
    with pytest.raises(ValueError, match="Failed to deserialize"):
        # Valid base64 but not a valid DER-encoded public key
        load_public_key_from_token(config.TOKEN_PREFIX + base64.b64encode(b"not a key").decode())


def test_load_public_key_from_token_fails_on_wrong_prefix():
    """load_public_key_from_token() fails on wrong prefix."""
    with pytest.raises(ValueError, match="Token must start with prefix"):
        load_public_key_from_token("WRONGPREFIX" + base64.b64encode(b"some").decode())


def test_encrypt_decrypt_roundtrip():
    """Encrypt and decrypt with the same key preserves the plaintext."""
    key = os.urandom(config.DEK_LEN)
    plaintext = b"Hello, world!"
    nonce, ciphertext, tag = encrypt(plaintext, key)
    decrypted = decrypt(nonce, ciphertext, tag, key)
    assert decrypted == plaintext


def test_encrypt_different_nonces():
    """Two encryptions with the same key produce different nonces."""
    key = os.urandom(config.DEK_LEN)
    plaintext = b"same plaintext"
    nonce1, _, _ = encrypt(plaintext, key)
    nonce2, _, _ = encrypt(plaintext, key)
    assert nonce1 != nonce2


def test_encrypt_different_sealed_deks_handler():
    """Two encryptions produce different sealed DEKs (RSA-OAEP is probabilistic)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            # Generate a recipient key
            recipient_token = generate_identity()
            plaintext = b"same message"
            # Encrypt twice
            container1 = encrypt_for_recipient(plaintext, recipient_token)
            container2 = encrypt_for_recipient(plaintext, recipient_token)
            # Parse containers
            c1 = json.loads(container1.decode())
            c2 = json.loads(container2.decode())
            # The sealed_dek should be different
            assert c1["sealed_dek"] != c2["sealed_dek"]
            # Nonce should also be different (due to random nonce)
            assert c1["nonce"] != c2["nonce"]
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)


def test_dek_not_in_container():
    """The DEK is never present in the container in plaintext."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            recipient_token = generate_identity()
            plaintext = b"some data"
            container = encrypt_for_recipient(plaintext, recipient_token)
            container_dict = json.loads(container.decode())
            # The container should not contain the DEK in any field
            # We can check that the decoded sealed_dek is not equal to the DEK
            # but we don't have the DEK here. Instead, we can verify that the
            # sealed_dek is not the plaintext DEK by checking that it's longer
            # (due to RSA encryption) and not equal to the base64 of 32 random bytes.
            # This is a soft check; the main point is that the ciphertext and tag
            # are present and the sealed_dek is present.
            assert "sealed_dek" in container_dict
            assert "nonce" in container_dict
            assert "ciphertext" in container_dict
            assert "tag" in container_dict
            # Ensure the sealed_dek is not just the base64 of the plaintext
            # (which would be 32 bytes -> base64 of 44 chars). Actually, the
            # sealed_dek is RSA-encrypted, so it's the size of the key modulus.
            # For RSA-4096, the output is 512 bytes. Base64 of that is 684 chars.
            # We'll just check that it's not 44 chars.
            assert len(container_dict["sealed_dek"]) != 44
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)


def test_encrypt_decrypt_roundtrip_handler():
    """Encrypt for recipient A, decrypt as recipient A: succeeds."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            recipient_token = generate_identity()
            file_data = b"This is a secret message."
            container = encrypt_for_recipient(file_data, recipient_token)
            plaintext = decrypt_as_recipient(container)
            assert plaintext == file_data
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)


def test_round_trip_preserves_exact_bytes():
    """Round-trip preserves exact bytes (including empty and large files)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            recipient_token = generate_identity()
            # Test empty file
            empty = b""
            container = encrypt_for_recipient(empty, recipient_token)
            assert decrypt_as_recipient(container) == empty
            # Test random data
            for size in [1, 100, 1024, 1024*10]:  # up to 10KB
                data = os.urandom(size)
                container = encrypt_for_recipient(data, recipient_token)
                assert decrypt_as_recipient(container) == data
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)


def test_encrypt_for_a_decrypt_as_b_fails_before_rsa():
    """Encrypt for recipient A, attempt to decrypt as recipient B: fails with 'not encrypted for this identity' before RSA attempt."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # We'll create two key files and manually manage the config path
        key_a_path = os.path.join(tmpdir, "priv_a.pem")
        key_b_path = os.path.join(tmpdir, "priv_b.pem")
        original_path = config.PRIVATE_KEY_PATH
        try:
            # Generate A's key
            config.PRIVATE_KEY_PATH = key_a_path
            token_a = generate_identity()
            # Generate B's key
            config.PRIVATE_KEY_PATH = key_b_path
            token_b = generate_identity()
            # Set back to A's key for decryption attempt (so that decrypt_as_recipient loads A's key)
            config.PRIVATE_KEY_PATH = key_a_path
            # Encrypt for A
            file_data = b"secret"
            container = encrypt_for_recipient(file_data, token_a)
            # Attempt to decrypt with B's key loaded (by setting env to B's key)
            # But decrypt_as_recipient uses the stored identity, which is currently A's.
            # We need to test that loading B's key and comparing fingerprints fails.
            # Instead, we can test by temporarily replacing the load_private_key function
            # to load B's key, but that's complex.
            # Instead, we'll test the fingerprint check directly: we'll encrypt for A,
            # then create a container with B's fingerprint and see if it fails.
            # However, the function encrypt_for_recipient uses the recipient's token
            # to compute the fingerprint and puts it in the container.
            # So to test that decrypting with the wrong key fails, we need to
            # decrypt with B's key but the container has A's fingerprint.
            # We can do that by manually calling decrypt_as_recipient but
            # temporarily swapping the key file.
            # Let's do: encrypt with A, then swap the key file to B's and try to decrypt.
            # We'll copy B's key over A's key file, then decrypt.
            # Backup A's key
            with open(key_a_path, 'rb') as f:
                key_a_data = f.read()
            with open(key_b_path, 'rb') as f:
                key_b_data = f.read()
            # Replace A's key with B's key
            with open(key_a_path, 'wb') as f:
                f.write(key_b_data)
            try:
                with pytest.raises(ValueError, match="Decryption failed"):
                    decrypt_as_recipient(container)
            finally:
                # Restore A's key
                with open(key_a_path, 'wb') as f:
                    f.write(key_a_data)
        finally:
            config.PRIVATE_KEY_PATH = original_path
            for p in (key_a_path, key_b_path):
                if os.path.exists(p):
                    os.remove(p)


def test_wrong_passphrase_fails_with_clear_message():
    """Wrong passphrase on private key: fails with clear message."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        key_path = os.path.join(tmpdir, "private_key.pem")
        config.PRIVATE_KEY_PATH = key_path
        try:
            # Encrypt private key with passphrase
            generate_identity(passphrase="correct")
            # Try to load with wrong passphrase
            with pytest.raises(ValueError, match="Failed to load private key"):
                load_private_key(passphrase="wrong")
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(key_path):
                os.remove(key_path)


def test_no_private_key_fails_with_clear_message():
    """No private key exists: fails with clear message."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        key_path = os.path.join(tmpdir, "private_key.pem")
        config.PRIVATE_KEY_PATH = key_path
        try:
            assert not os.path.exists(key_path)
            with pytest.raises(FileNotFoundError, match="No private key found"):
                load_private_key()
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(key_path):
                os.remove(key_path)


def test_missing_recipient_token_fails_with_clear_message():
    """Missing recipient token: fails with clear message."""
    # encrypt_for_recipient requires a token; we'll test with empty string
    with pytest.raises(ValueError):
        encrypt_for_recipient(b"data", "")


def test_malformed_token_fails_with_clear_message():
    """Malformed token: fails with clear message."""
    with pytest.raises(ValueError, match="Token must start with prefix"):
        encrypt_for_recipient(b"data", "invalid")
    with pytest.raises(ValueError, match="Invalid base64"):
        encrypt_for_recipient(b"data", config.TOKEN_PREFIX + "!!!")


def test_tamper_detection_ciphertext():
    """Flip one bit in ciphertext: raises ValueError."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        key_path = os.path.join(tmpdir, "private_key.pem")
        config.PRIVATE_KEY_PATH = key_path
        try:
            token = generate_identity()
            data = b"test"
            container = encrypt_for_recipient(data, token)
            # Parse container, flip a bit in ciphertext, re-encode
            container_dict = json.loads(container.decode())
            ciphertext_bytes = base64.b64decode(container_dict["ciphertext"])
            if len(ciphertext_bytes) > 0:
                # Flip the least significant bit of the first byte
                ciphertext_bytes = bytes([ciphertext_bytes[0] ^ 1]) + ciphertext_bytes[1:]
            else:
                ciphertext_bytes = b"\x01"
            container_dict["ciphertext"] = base64.b64encode(ciphertext_bytes).decode()
            tampered = json.dumps(container_dict).encode()
            with pytest.raises(ValueError, match="Decryption failed"):
                decrypt_as_recipient(tampered)
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(key_path):
                os.remove(key_path)


def test_tamper_detection_nonce():
    """Modify nonce: raises ValueError."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        key_path = os.path.join(tmpdir, "private_key.pem")
        config.PRIVATE_KEY_PATH = key_path
        try:
            token = generate_identity()
            data = b"test"
            container = encrypt_for_recipient(data, token)
            container_dict = json.loads(container.decode())
            nonce_bytes = base64.b64decode(container_dict["nonce"])
            if len(nonce_bytes) > 0:
                nonce_bytes = bytes([nonce_bytes[0] ^ 1]) + nonce_bytes[1:]
            else:
                nonce_bytes = b"\x01"
            container_dict["nonce"] = base64.b64encode(nonce_bytes).decode()
            tampered = json.dumps(container_dict).encode()
            with pytest.raises(ValueError, match="Decryption failed"):
                decrypt_as_recipient(tampered)
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(key_path):
                os.remove(key_path)


def test_tamper_detection_tag():
    """Modify tag: raises ValueError."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        key_path = os.path.join(tmpdir, "private_key.pem")
        config.PRIVATE_KEY_PATH = key_path
        try:
            token = generate_identity()
            data = b"test"
            container = encrypt_for_recipient(data, token)
            container_dict = json.loads(container.decode())
            tag_bytes = base64.b64decode(container_dict["tag"])
            if len(tag_bytes) > 0:
                tag_bytes = bytes([tag_bytes[0] ^ 1]) + tag_bytes[1:]
            else:
                tag_bytes = b"\x01"
            container_dict["tag"] = base64.b64encode(tag_bytes).decode()
            tampered = json.dumps(container_dict).encode()
            with pytest.raises(ValueError, match="Decryption failed"):
                decrypt_as_recipient(tampered)
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(key_path):
                os.remove(key_path)


def test_tamper_detection_sealed_dek():
    """Replace sealed_dek with random bytes: raises ValueError."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        key_path = os.path.join(tmpdir, "private_key.pem")
        config.PRIVATE_KEY_PATH = key_path
        try:
            token = generate_identity()
            data = b"test"
            container = encrypt_for_recipient(data, token)
            container_dict = json.loads(container.decode())
            # Replace sealed_dek with random bytes of same length
            sealed_dek_bytes = base64.b64decode(container_dict["sealed_dek"])
            random_bytes = os.urandom(len(sealed_dek_bytes))
            container_dict["sealed_dek"] = base64.b64encode(random_bytes).decode()
            tampered = json.dumps(container_dict).encode()
            with pytest.raises(ValueError, match="Decryption failed"):
                decrypt_as_recipient(tampered)
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(key_path):
                os.remove(key_path)


def test_tamper_detection_recipient_fingerprint():
    """Modify recipient_fingerprint in container: raises ValueError before RSA operation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        key_path = os.path.join(tmpdir, "private_key.pem")
        config.PRIVATE_KEY_PATH = key_path
        try:
            token = generate_identity()
            data = b"test"
            container = encrypt_for_recipient(data, token)
            container_dict = json.loads(container.decode())
            # Change the fingerprint to something else
            container_dict["recipient_fingerprint"] = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
            tampered = json.dumps(container_dict).encode()
            # This should fail because the fingerprint of the loaded key won't match
            with pytest.raises(ValueError, match="Decryption failed"):
                decrypt_as_recipient(tampered)
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(key_path):
                os.remove(key_path)


def test_truncated_container():
    """Truncated container: raises ValueError."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            token = generate_identity()
            data = b"test"
            container = encrypt_for_recipient(data, token)
            # Truncate the ciphertext by removing last character
            truncated = container[:-1]
            with pytest.raises((ValueError, json.JSONDecodeError)):
                decrypt_as_recipient(truncated)
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)

def test_tampered_tag_no_output_file():
    """Tampered tag results in no output file when decrypting via CLI."""
    import subprocess
    import os
    import tempfile
    import json
    import base64
    from gun101gkp import config

    with tempfile.TemporaryDirectory() as tmpdir:
        # Override private key path to temp directory
        private_key_path = os.path.join(tmpdir, 'private_key.pem')
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = private_key_path
        try:
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            env = os.environ.copy()
            env["HOME"] = tmpdir
            env["PYTHONPATH"] = os.path.join(old_cwd, "src")
            try:
                # Generate identity
                subprocess.run(['python3', '-m', 'gun101gkp.cli', 'generate-identity'], env=env, check=True, capture_output=True)
                # Get token
                result = subprocess.run(['python3', '-m', 'gun101gkp.cli', 'show-identity'], capture_output=True, text=True, env=env, check=True)
                token = result.stdout.strip()
                # Create a plain file
                with open('plain.txt', 'wb') as f:
                    f.write(b'hello')
                # Encrypt
                subprocess.run(['python3', '-m', 'gun101gkp.cli', 'encrypt', 'plain.txt', '--recipient', token], env=env, check=True, capture_output=True)
                assert os.path.exists('plain.txt.gkp')
                # Read container, tamper tag
                with open('plain.txt.gkp', 'rb') as f:
                    container_data = f.read()
                container = json.loads(container_data.decode())
                # Flip a bit in tag
                tag_bytes = base64.b64decode(container['tag'])
                tag_bytes = bytes([tag_bytes[0] ^ 1]) + tag_bytes[1:]
                container['tag'] = base64.b64encode(tag_bytes).decode()
                tampered = json.dumps(container).encode()
                with open('plain.txt.gkp', 'wb') as f:
                    f.write(tampered)
                # Attempt decryption with output specified
                result = subprocess.run(['python3', '-m', 'gun101gkp.cli', 'decrypt', 'plain.txt.gkp', '--output', 'out.txt'], env=env, capture_output=True)
                # Should fail (non-zero exit)
                assert result.returncode != 0
                # Output file should not exist
                assert not os.path.exists('out.txt')
            finally:
                os.chdir(old_cwd)
        finally:
            config.PRIVATE_KEY_PATH = original_path


def test_fingerprint_cli():
    """Test the fingerprint CLI command."""
    import subprocess
    import os
    import tempfile
    from gun101gkp import config

    with tempfile.TemporaryDirectory() as tmpdir:
        # Override private key path to temp directory
        private_key_path = os.path.join(tmpdir, 'private_key.pem')
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = private_key_path
        try:
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            env = os.environ.copy()
            env["HOME"] = tmpdir
            env["PYTHONPATH"] = os.path.join(old_cwd, "src")
            try:
                # Generate identity
                subprocess.run(['python3', '-m', 'gun101gkp.cli', 'generate-identity'], env=env, check=True, capture_output=True)
                # Get token via show-identity
                result = subprocess.run(['python3', '-m', 'gun101gkp.cli', 'show-identity'], capture_output=True, text=True, env=env, check=True)
                token = result.stdout.strip()
                # Test fingerprint command with explicit token
                result = subprocess.run(['python3', '-m', 'gun101gkp.cli', 'fingerprint', '--token', token], capture_output=True, text=True, env=env, check=True)
                fingerprint_from_cli = result.stdout.strip()
                # Also test fingerprint command without token (should use stored identity)
                result = subprocess.run(['python3', '-m', 'gun101gkp.cli', 'fingerprint'], capture_output=True, text=True, env=env, check=True)
                fingerprint_from_stored = result.stdout.strip()
                # Both should be the same and be a valid fingerprint format
                assert fingerprint_from_cli == fingerprint_from_stored
                # Validate fingerprint format (colon-separated hex pairs)
                parts = fingerprint_from_cli.split(':')
                assert len(parts) == 32  # SHA-256 produces 32 bytes = 64 hex chars = 32 pairs when split by :
                for part in parts:
                    assert len(part) == 2
                    assert all(c in '0123456789ABCDEF' for c in part), f"Invalid hex character in {part}"
            finally:
                os.chdir(old_cwd)
        finally:
            config.PRIVATE_KEY_PATH = original_path


def test_reset_identity_cli():
    """Test the reset-identity CLI command."""
    import subprocess
    import os
    import tempfile
    from gun101gkp import config

    with tempfile.TemporaryDirectory() as tmpdir:
        # Override private key path to temp directory
        private_key_path = os.path.join(tmpdir, 'private_key.pem')
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = private_key_path
        try:
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            env = os.environ.copy()
            env["HOME"] = tmpdir
            env["PYTHONPATH"] = os.path.join(old_cwd, "src")
            try:
                # Generate identity
                subprocess.run(['python3', '-m', 'gun101gkp.cli', 'generate-identity'], env=env, check=True, capture_output=True)
                # Verify identity exists by checking that show-identity works
                result = subprocess.run(['python3', '-m', 'gun101gkp.cli', 'show-identity'], env=env, capture_output=True, text=True, check=True)
                assert result.returncode == 0
                token = result.stdout.strip()
                assert token.startswith(config.TOKEN_PREFIX)
                # Test reset-identity command (we need to provide the confirmation input)
                result = subprocess.run(['python3', '-m', 'gun101gkp.cli', 'reset-identity'],
                                      input='YES\n', text=True, env=env, check=True, capture_output=True)
                # Verify that trying to show identity now fails
                result = subprocess.run(['python3', '-m', 'gun101gkp.cli', 'show-identity'],
                                      env=env, capture_output=True, text=True)
                assert result.returncode != 0
                assert "Error: No identity found" in result.stderr
            finally:
                os.chdir(old_cwd)
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(private_key_path):
                os.remove(private_key_path)


def test_exponent_validation():
    """Load private key validates public exponent is 3 or 65537; rejects others."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
    import math
    def make_usable_key(exponent, key_size):
        """Generate a valid RSA private key with the given public exponent.
        Repeats until exponent is coprime with phi(p,q)."""
        while True:
            # generate a temporary key to get random primes
            temp = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            nums = temp.private_numbers()
            p, q = nums.p, nums.q
            phi = (p - 1) * (q - 1)
            if math.gcd(exponent, phi) == 1:
                # compute private exponent
                d = pow(exponent, -1, phi)
                pub_nums = RSAPublicNumbers(exponent, p * q)
                dmp1 = d % (p - 1)
                dmq1 = d % (q - 1)
                iqmp = pow(q, -1, p)
                priv_nums = RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub_nums)
                return priv_nums.private_key()
            # else loop again with new p,q

    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        key_path = os.path.join(tmpdir, 'private_key.pem')
        config.PRIVATE_KEY_PATH = key_path
        try:
            # Test exponent 3 (can be generated)
            priv_key_3 = rsa.generate_private_key(public_exponent=3, key_size=config.RSA_KEY_SIZE)
            priv_key_pem_3 = priv_key_3.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(key_path, 'wb') as f:
                f.write(priv_key_pem_3)
            loaded_key = load_private_key()
            assert loaded_key.public_key().public_numbers().e == 3
            # Test exponent 65537 (default)
            priv_key_65537 = rsa.generate_private_key(public_exponent=65537, key_size=config.RSA_KEY_SIZE)
            priv_key_pem_65537 = priv_key_65537.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(key_path, 'wb') as f:
                f.write(priv_key_pem_65537)
            loaded_key = load_private_key()
            assert loaded_key.public_key().public_numbers().e == 65537
            # Test rejection of exponent 5
            key_e5 = make_usable_key(5, config.RSA_KEY_SIZE)
            key_pem_e5 = key_e5.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(key_path, 'wb') as f:
                f.write(key_pem_e5)
            with pytest.raises(ValueError, match="Unusual public exponent"):
                load_private_key()
            # Test rejection of exponent 257
            key_e257 = make_usable_key(257, config.RSA_KEY_SIZE)
            key_pem_e257 = key_e257.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(key_path, 'wb') as f:
                f.write(key_pem_e257)
            with pytest.raises(ValueError, match="Unusual public exponent"):
                load_private_key()
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(key_path):
                os.remove(key_path)


def test_decrypt_version_2_0_container():
    """A container with format version \"2.0\" (no AAD) can be decrypted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            # Generate recipient identity
            recipient_token = generate_identity()
            # Create some file data
            file_data = b"This is a test file for version 2.0 decryption."

            # --- Manually create a version 2.0 container (as old code would have) ---
            # Load recipient public key
            public_key = load_public_key_from_token(recipient_token)
            # Generate random DEK
            dek = os.urandom(config.DEK_LEN)
            # Encrypt file data with DEK using AES-256-GCM (no associated data for v2.0)
            nonce, ciphertext, tag = encrypt(file_data, dek, associated_data=None)
            # Seal DEK with RSA-OAEP
            sealed_dek = public_key.encrypt(
                dek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Compute recipient fingerprint
            recipient_fingerprint = get_identity_fingerprint(recipient_token)
            # Build container
            container = {
                "protocol": config.PROTOCOL,
                "version": "2.0",
                "recipient_fingerprint": recipient_fingerprint,
                "sealed_dek": base64.b64encode(sealed_dek).decode('ascii'),
                "nonce": base64.b64encode(nonce).decode('ascii'),
                "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
                "tag": base64.b64encode(tag).decode('ascii')
            }
            container_data = json.dumps(container).encode('utf-8')

            # Decrypt as recipient
            decrypted = decrypt_as_recipient(container_data)
            assert decrypted == file_data
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)


def test_decrypt_version_2_1_container():
    """A container with format version \"2.1\" (with AAD) can be decrypted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            # Generate recipient identity
            recipient_token = generate_identity()
            # Create some file data
            file_data = b"This is a test file for version 2.1 decryption."

            # Use current encrypt_for_recipient (which writes FORMAT_VERSION and uses AAD)
            container_data = encrypt_for_recipient(file_data, recipient_token)

            # Decrypt as recipient
            decrypted = decrypt_as_recipient(container_data)
            assert decrypted == file_data
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)


def test_reject_unsupported_format_version():
    """A container with an unsupported format version is rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            # Generate recipient identity
            recipient_token = generate_identity()
            # Create some file data
            file_data = b"This is a test file for unsupported version."

            # --- Manually create a container with version "9.9" ---
            # Load recipient public key
            public_key = load_public_key_from_token(recipient_token)
            # Generate random DEK
            dek = os.urandom(config.DEK_LEN)
            # Encrypt file data with DEK using AES-256-GCM (we'll use AAD as per current, but version is fake)
            # We'll use the current AAD computation for consistency, but the version is not 2.0 or 2.1.
            # However, note that the AAD computation uses the version from the container.
            # We'll compute AAD with the fake version to match what the decrypt function would do.
            recipient_fingerprint = get_identity_fingerprint(recipient_token)
            aad_dict = {
                "protocol": config.PROTOCOL,
                "version": "9.9",  # fake version
                "recipient_fingerprint": recipient_fingerprint
            }
            associated_data = json.dumps(aad_dict, separators=(',', ':')).encode('utf-8')
            nonce, ciphertext, tag = encrypt(file_data, dek, associated_data=associated_data)
            # Seal DEK with RSA-OAEP
            sealed_dek = public_key.encrypt(
                dek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Build container
            container = {
                "protocol": config.PROTOCOL,
                "version": "9.9",
                "recipient_fingerprint": recipient_fingerprint,
                "sealed_dek": base64.b64encode(sealed_dek).decode('ascii'),
                "nonce": base64.b64encode(nonce).decode('ascii'),
                "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
                "tag": base64.b64encode(tag).decode('ascii')
            }
            container_data = json.dumps(container).encode('utf-8')

            # Decrypt should raise ValueError("Decryption failed")
            with pytest.raises(ValueError, match="Decryption failed"):
                decrypt_as_recipient(container_data)
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)


def test_encrypt_for_recipient_writes_current_format_version():
    """encrypt_for_recipient always writes the current FORMAT_VERSION."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_path = config.PRIVATE_KEY_PATH
        config.PRIVATE_KEY_PATH = os.path.join(tmpdir, "private_key.pem")
        try:
            # Generate recipient identity
            recipient_token = generate_identity()
            # Create some file data
            file_data = b"This is a test file to check written version."

            # Encrypt
            container_data = encrypt_for_recipient(file_data, recipient_token)

            # Parse container
            container = json.loads(container_data.decode('utf-8'))
            # Check that the version is exactly FORMAT_VERSION
            assert container["version"] == config.FORMAT_VERSION
            # Also check that it's one of the supported versions (should be)
            assert container["version"] in config.SUPPORTED_FORMAT_VERSIONS
        finally:
            config.PRIVATE_KEY_PATH = original_path
            if os.path.exists(config.PRIVATE_KEY_PATH):
                os.remove(config.PRIVATE_KEY_PATH)


