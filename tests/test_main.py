#!/usr/bin/env python3

import json
import os

import jwt
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from jwt_generator.main import (
    generate_key_pair,
    load_private_key,
    load_json_payload,
    main,
)


class TestKeyGeneration:
    def test_generate_key_pair_creates_files(self, tmp_path):
        """Test that generate_key_pair creates private.key and public.key files."""
        os.chdir(tmp_path)

        private_key = generate_key_pair()

        assert os.path.exists("private.key")
        assert os.path.exists("public.key")
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)

    def test_generate_key_pair_files_are_valid(self, tmp_path):
        """Test that generated key files can be loaded correctly."""
        os.chdir(tmp_path)

        generate_key_pair()

        # Test loading private key
        with open("private.key", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)

        # Test loading public key
        with open("public.key", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        assert isinstance(public_key, ec.EllipticCurvePublicKey)

    def test_load_private_key_generates_if_missing(self, tmp_path):
        """Test that load_private_key generates keys if they don't exist."""
        os.chdir(tmp_path)

        private_key = load_private_key()

        assert os.path.exists("private.key")
        assert os.path.exists("public.key")
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)

    def test_load_private_key_loads_existing(self, tmp_path):
        """Test that load_private_key loads existing keys."""
        os.chdir(tmp_path)

        # Generate initial keys
        original_key = generate_key_pair()

        # Load them back
        loaded_key = load_private_key()

        # Keys should be the same
        original_private_bytes = original_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        loaded_private_bytes = loaded_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        assert original_private_bytes == loaded_private_bytes


class TestJSONPayload:
    def test_load_json_payload_success(self, tmp_path):
        """Test successful JSON payload loading."""
        payload_file = tmp_path / "test_payload.json"
        payload_data = {"sub": "123", "name": "Test User"}

        with open(payload_file, "w") as f:
            json.dump(payload_data, f)

        result = load_json_payload(str(payload_file))
        assert result == payload_data

    def test_load_json_payload_file_not_found(self, tmp_path, capsys):
        """Test JSON payload loading with missing file."""
        missing_file = tmp_path / "missing.json"

        with pytest.raises(SystemExit) as exc_info:
            load_json_payload(str(missing_file))

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err

    def test_load_json_payload_invalid_json(self, tmp_path, capsys):
        """Test JSON payload loading with invalid JSON."""
        invalid_file = tmp_path / "invalid.json"

        with open(invalid_file, "w") as f:
            f.write("{invalid json")

        with pytest.raises(SystemExit) as exc_info:
            load_json_payload(str(invalid_file))

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Invalid JSON" in captured.err


class TestJWTGeneration:
    def test_jwt_token_generation(self, tmp_path):
        """Test that valid JWT tokens are generated."""
        os.chdir(tmp_path)

        # Create test payload
        payload_data = {"sub": "123", "name": "Test User", "exp": 9999999999}
        payload_file = tmp_path / "payload.json"
        with open(payload_file, "w") as f:
            json.dump(payload_data, f)

        # Generate keys and create token
        private_key = generate_key_pair()

        runner = CliRunner()
        result = runner.invoke(main, [str(payload_file)])

        assert result.exit_code == 0
        token = result.output.strip()

        # Verify token can be decoded with the public key
        public_key = private_key.public_key()
        decoded = jwt.decode(token, public_key, algorithms=["ES256"])
        assert decoded == payload_data

    def test_jwt_with_header_option(self, tmp_path):
        """Test JWT generation with --header option."""
        os.chdir(tmp_path)

        # Create test payload
        payload_data = {"sub": "123", "name": "Test User", "exp": 9999999999}
        payload_file = tmp_path / "payload.json"
        with open(payload_file, "w") as f:
            json.dump(payload_data, f)

        # Generate keys
        generate_key_pair()

        runner = CliRunner()
        result = runner.invoke(main, ["--header", str(payload_file)])

        assert result.exit_code == 0
        output = result.output.strip()
        assert output.startswith("Authorization: Bearer ")

        # Extract and verify token
        token = output.replace("Authorization: Bearer ", "")
        private_key = load_private_key()
        public_key = private_key.public_key()
        decoded = jwt.decode(token, public_key, algorithms=["ES256"])
        assert decoded == payload_data
