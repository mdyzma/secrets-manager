"""Cryptographic primitives for fallback encrypted storage."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pysecret.exceptions import ValidationError

DEFAULT_PBKDF2_ITERATIONS = 310_000


@dataclass(frozen=True)
class EncryptedPayload:
    ciphertext: bytes
    nonce: bytes


class CryptoEngine:
    @staticmethod
    def generate_salt() -> bytes:
        return os.urandom(16)

    @staticmethod
    def derive_key(
        master_password: str, salt: bytes, iterations: int = DEFAULT_PBKDF2_ITERATIONS
    ) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=SHA256(), length=32, salt=salt, iterations=iterations
        )
        return kdf.derive(master_password.encode("utf-8"))

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> EncryptedPayload:
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        return EncryptedPayload(ciphertext=ciphertext, nonce=nonce)

    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes) -> bytes:
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise ValidationError("Secret authentication failed") from exc
