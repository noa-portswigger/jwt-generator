#!/usr/bin/env python3

import json
import os
import time

import jwt
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from jwt_generator.main import (
    add_dynamic_claims,
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


class TestDynamicClaims:
    def test_add_dynamic_claims(self):
        """Test that dynamic claims are added correctly."""
        original_payload = {"sub": "123", "name": "Test User"}

        # Record time before adding claims
        before_time = int(time.time())

        result_payload = add_dynamic_claims(original_payload.copy())

        # Record time after adding claims
        after_time = int(time.time())

        # Check that original payload fields are preserved
        assert result_payload["sub"] == "123"
        assert result_payload["name"] == "Test User"

        # Check that iat is set to current time (within reasonable range)
        assert before_time <= result_payload["iat"] <= after_time

        # Check that nbf equals iat
        assert result_payload["nbf"] == result_payload["iat"]

        # Check that exp is 10 minutes (600 seconds) after iat
        assert result_payload["exp"] == result_payload["iat"] + 600

    def test_add_dynamic_claims_overwrites_existing(self):
        """Test that dynamic claims overwrite existing timestamp claims."""
        original_payload = {"sub": "123", "iat": 1000, "nbf": 2000, "exp": 3000}

        result_payload = add_dynamic_claims(original_payload.copy())

        # Claims should be overwritten with current values
        current_time = int(time.time())
        assert result_payload["iat"] != 1000
        assert result_payload["nbf"] != 2000
        assert result_payload["exp"] != 3000
        assert abs(result_payload["iat"] - current_time) <= 1


class TestJWTGeneration:
    def test_jwt_token_generation(self, tmp_path):
        """Test that valid JWT tokens are generated with dynamic claims."""
        os.chdir(tmp_path)

        # Create test payload (without timestamp claims)
        payload_data = {"sub": "123", "name": "Test User"}
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

        # Check that original payload fields are preserved
        assert decoded["sub"] == "123"
        assert decoded["name"] == "Test User"

        # Check that dynamic claims were added
        assert "iat" in decoded
        assert "nbf" in decoded
        assert "exp" in decoded

        # Check that nbf equals iat and exp is 10 minutes later
        assert decoded["nbf"] == decoded["iat"]
        assert decoded["exp"] == decoded["iat"] + 600

    def test_jwt_with_header_option(self, tmp_path):
        """Test JWT generation with --header option."""
        os.chdir(tmp_path)

        # Create test payload (without timestamp claims)
        payload_data = {"sub": "123", "name": "Test User"}
        payload_file = tmp_path / "payload.json"
        with open(payload_file, "w") as f:
            json.dump(payload_data, f)

        # Generate keys
        generate_key_pair()

        runner = CliRunner()
        result = runner.invoke(main, ["--header", str(payload_file)])

        assert result.exit_code == 0
        output = result.output.strip()
        assert output.startswith("Authorization: JWT ")

        # Extract and verify token
        token = output.replace("Authorization: JWT ", "")
        private_key = load_private_key()
        public_key = private_key.public_key()
        decoded = jwt.decode(token, public_key, algorithms=["ES256"])

        # Check that original payload fields are preserved
        assert decoded["sub"] == "123"
        assert decoded["name"] == "Test User"

        # Check that dynamic claims were added
        assert "iat" in decoded
        assert "nbf" in decoded
        assert "exp" in decoded
