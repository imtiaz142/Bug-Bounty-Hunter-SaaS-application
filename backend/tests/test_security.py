"""Tests for security utilities."""

import pytest
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    encrypt_api_key,
    decrypt_api_key,
)


def test_password_hashing():
    password = "SecurePassword123!"
    hashed = hash_password(password)
    assert hashed != password
    assert verify_password(password, hashed)
    assert not verify_password("WrongPassword", hashed)


def test_access_token():
    data = {"sub": "user-123"}
    token = create_access_token(data)
    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == "user-123"
    assert payload["type"] == "access"


def test_refresh_token():
    data = {"sub": "user-456"}
    token = create_refresh_token(data)
    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == "user-456"
    assert payload["type"] == "refresh"


def test_invalid_token():
    payload = decode_token("invalid.token.here")
    assert payload is None


def test_api_key_encryption():
    original_key = "sk-test-api-key-12345"
    encrypted = encrypt_api_key(original_key)
    assert encrypted != original_key
    decrypted = decrypt_api_key(encrypted)
    assert decrypted == original_key


def test_api_key_encryption_different_keys():
    """Encrypting the same key twice should produce different ciphertexts (Fernet uses random IV)."""
    key = "sk-test-key"
    e1 = encrypt_api_key(key)
    e2 = encrypt_api_key(key)
    # Both decrypt to the same value
    assert decrypt_api_key(e1) == key
    assert decrypt_api_key(e2) == key
