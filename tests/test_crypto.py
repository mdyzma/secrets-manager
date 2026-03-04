from __future__ import annotations

import pytest

from pysecret.crypto import CryptoEngine
from pysecret.exceptions import ValidationError


def test_crypto_roundtrip() -> None:
    salt = CryptoEngine.generate_salt()
    key = CryptoEngine.derive_key("master-pass", salt)
    aad = b"openai|v1"
    encrypted = CryptoEngine.encrypt(key, b"sk-test-secret", aad)

    decrypted = CryptoEngine.decrypt(key, encrypted.ciphertext, encrypted.nonce, aad)
    assert decrypted == b"sk-test-secret"


def test_crypto_tamper_detected() -> None:
    salt = CryptoEngine.generate_salt()
    key = CryptoEngine.derive_key("master-pass", salt)
    aad = b"openai|v1"
    encrypted = CryptoEngine.encrypt(key, b"sk-test-secret", aad)

    tampered = bytearray(encrypted.ciphertext)
    tampered[-1] ^= 0x01

    with pytest.raises(ValidationError):
        CryptoEngine.decrypt(key, bytes(tampered), encrypted.nonce, aad)
