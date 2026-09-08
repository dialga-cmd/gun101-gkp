#!/usr/bin/env python3
"""
GUN-101-GKP Command Line Interface.

Provides commands for identity management and file encryption/decryption.
"""
import argparse
import getpass
import os
import sys

from . import __version__
from .config import PRIVATE_KEY_PATH
from .handler import decrypt_as_recipient, encrypt_for_recipient
from .identity import (
    generate_identity,
    get_identity_fingerprint,
    get_identity_token,
    has_identity,
    reset_identity,
)


def cmd_generate_identity(args):
    """Generate a new identity."""
    passphrase = None
    if args.passphrase:
        passphrase = getpass.getpass("Enter passphrase to encrypt private key: ")
        # Verify passphrase
        verify = getpass.getpass("Verify passphrase: ")
        if passphrase != verify:
            print("Error: Passphrases do not match", file=sys.stderr)
            sys.exit(1)

    try:
        token = generate_identity(passphrase=passphrase)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Identity token: {token}")
    print(f"Fingerprint: {get_identity_fingerprint(token)}")
    print(
        f"Warning: Store your private key backup at {os.path.expanduser(PRIVATE_KEY_PATH)}. "
        "Losing it makes all encrypted files permanently unreadable.",
        file=sys.stderr,
    )

def cmd_show_identity(args):
    """Show the stored identity token."""
    if not has_identity():
        print("Error: No identity found. Generate one first.", file=sys.stderr)
        sys.exit(1)
    try:
        token = get_identity_token()
        print(token)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

def cmd_fingerprint(args):
    """Show the fingerprint of an identity token."""
    if args.token:
        token = args.token
    else:
        if not has_identity():
            print("Error: No identity found. Provide a token or generate one first.", file=sys.stderr)
            sys.exit(1)
        try:
            token = get_identity_token()
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        fingerprint = get_identity_fingerprint(token)
        print(fingerprint)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

def cmd_encrypt(args):
    """Encrypt a file for a recipient."""
    if not os.path.isfile(args.file):
        print(f"Error: File '{args.file}' not found.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.file, "rb") as f:
            file_data = f.read()
    except OSError as e:
        print(f"Error: Cannot read file '{args.file}': {e}", file=sys.stderr)
        sys.exit(1)

    try:
        container = encrypt_for_recipient(file_data, args.recipient)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output if args.output else args.file + ".gkp"
    try:
        with open(output_path, "wb") as f:
            f.write(container)
    except OSError as e:
        print(f"Error: Cannot write output file '{output_path}': {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Encrypted file written to: {output_path}")

def cmd_decrypt(args):
    """Decrypt a file using the recipient's private key."""
    if not os.path.isfile(args.file):
        print(f"Error: File '{args.file}' not found.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.file, "rb") as f:
            container_data = f.read()
    except OSError as e:
        print(f"Error: Cannot read file '{args.file}': {e}", file=sys.stderr)
        sys.exit(1)

    passphrase = None
    if args.passphrase:
        passphrase = getpass.getpass("Enter passphrase for private key: ")

    try:
        plaintext = decrypt_as_recipient(container_data, passphrase=passphrase)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output if args.output else args.file
    if output_path.endswith(".gkp"):
        output_path = output_path[:-4]  # remove .gkp extension if present
    try:
        with open(output_path, "wb") as f:
            f.write(plaintext)
    except OSError as e:
        print(f"Error: Cannot write output file '{output_path}': {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Decrypted file written to: {output_path}")

def cmd_reset_identity(args):
    """Remove the stored identity."""
    if not has_identity():
        print("Error: No identity found.", file=sys.stderr)
        sys.exit(1)

    print(
        "WARNING: This is irreversible. Any files encrypted for this identity will be permanently unreadable.",
        file=sys.stderr,
    )
    response = input("Type 'YES' to confirm deletion: ")
    if response.strip().upper() != "YES":
        print("Aborted.", file=sys.stderr)
        sys.exit(1)

    try:
        reset_identity()
        print("Identity removed.")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="GUN-101-GKP: Ghost Key Protocol for passwordless asymmetric encryption."
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # generate-identity
    gen_parser = subparsers.add_parser(
        "generate-identity", help="Generate a new identity key pair"
    )
    gen_parser.add_argument(
        "--passphrase",
        action="store_true",
        help="Encrypt the private key with a passphrase",
    )
    gen_parser.set_defaults(func=cmd_generate_identity)

    # show-identity
    show_parser = subparsers.add_parser(
        "show-identity", help="Show the stored identity token"
    )
    show_parser.set_defaults(func=cmd_show_identity)

    # fingerprint
    fp_parser = subparsers.add_parser(
        "fingerprint", help="Show the fingerprint of an identity token"
    )
    fp_parser.add_argument(
        "--token", help="Token to fingerprint (defaults to stored identity)"
    )
    fp_parser.set_defaults(func=cmd_fingerprint)

    # encrypt
    enc_parser = subparsers.add_parser(
        "encrypt", help="Encrypt a file for a recipient"
    )
    enc_parser.add_argument("file", help="File to encrypt")
    enc_parser.add_argument(
        "--recipient", required=True, help="Recipient's identity token"
    )
    enc_parser.add_argument(
        "--output", help="Output file path (default: input.gkp)"
    )
    enc_parser.set_defaults(func=cmd_encrypt)

    # decrypt
    dec_parser = subparsers.add_parser(
        "decrypt", help="Decrypt a file using your private key"
    )
    dec_parser.add_argument("file", help="File to decrypt")
    dec_parser.add_argument(
        "--passphrase",
        action="store_true",
        help="Private key is encrypted with a passphrase",
    )
    dec_parser.add_argument(
        "--output", help="Output file path (default: input with .gkp removed)"
    )
    dec_parser.set_defaults(func=cmd_decrypt)

    # reset-identity
    reset_parser = subparsers.add_parser(
        "reset-identity", help="Remove the stored identity (irreversible)"
    )
    reset_parser.set_defaults(func=cmd_reset_identity)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)

if __name__ == "__main__":
    main()
