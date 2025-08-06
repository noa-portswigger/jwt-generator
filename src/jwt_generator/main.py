#!/usr/bin/env python3

import json
import os
import sys

import click
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def generate_key_pair():
    """Generate ES256 key pair and save to files."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open("private.key", "wb") as f:
        f.write(private_pem)

    with open("public.key", "wb") as f:
        f.write(public_pem)

    return private_key


def load_private_key():
    """Load private key from file or generate new key pair if not exists."""
    if not os.path.exists("private.key") or not os.path.exists("public.key"):
        return generate_key_pair()

    with open("private.key", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    return private_key


def load_json_payload(file_path):
    """Load JSON payload from file."""
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{file_path}': {e}", file=sys.stderr)
        sys.exit(1)


@click.command()
@click.argument("json_file_path", type=click.Path(exists=True, readable=True))
@click.option(
    "--header", is_flag=True, help="make output suitable for including in http header"
)
def main(json_file_path, header):
    """Generate JWT token from JSON payload file."""
    try:
        private_key = load_private_key()
        payload = load_json_payload(json_file_path)

        token = jwt.encode(payload, private_key, algorithm="ES256")

        if header:
            print(f"Authorization: JWT {token}")
        else:
            print(token)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
