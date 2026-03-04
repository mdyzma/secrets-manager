"""Encrypted SQLite fallback backend with master-password unlock."""

from __future__ import annotations

import base64
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from pysecret.crypto import CryptoEngine, DEFAULT_PBKDF2_ITERATIONS
from pysecret.exceptions import UnlockError
from pysecret.models import SecretRecordSummary, StoredSecret
from pysecret.session import SessionKeyCache
from pysecret.storage.base import StorageBackend
from pysecret.utils import from_iso8601, is_expired, mask_secret, now_utc, to_iso8601


SCHEMA_VERSION = 1
VERIFIER_PLAINTEXT = b"pysecret-verifier-v1"
VERIFIER_AAD = b"pysecret:verifier:v1"

PasswordPrompter = Callable[[str], str]


@dataclass
class UnlockState:
    salt: bytes
    iterations: int


class EncryptedSQLiteBackend(StorageBackend):
    name = "fallback"

    def __init__(
        self,
        db_path: Path,
        session_cache: SessionKeyCache,
        prompt_password: PasswordPrompter,
        max_unlock_attempts: int = 3,
    ) -> None:
        self._db_path = db_path
        self._session_cache = session_cache
        self._prompt_password = prompt_password
        self._max_unlock_attempts = max_unlock_attempts
        self._initialize()

    def _initialize(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    provider TEXT PRIMARY KEY,
                    ciphertext BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    aad BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT NULL,
                    version INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            conn.commit()
        if self._db_path.exists():
            try:
                os.chmod(self._db_path, 0o600)
            except PermissionError:
                pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _get_meta(self, conn: sqlite3.Connection, key: str) -> Optional[str]:
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        value = row["value"]
        if isinstance(value, str):
            return value
        return str(value)

    def _set_meta(self, conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value))

    def _load_unlock_state(self, conn: sqlite3.Connection) -> Optional[UnlockState]:
        salt_b64 = self._get_meta(conn, "kdf_salt")
        iterations_raw = self._get_meta(conn, "kdf_iterations")
        if salt_b64 is None or iterations_raw is None:
            return None
        return UnlockState(salt=base64.b64decode(salt_b64), iterations=int(iterations_raw))

    def _setup_new_master_password(self, conn: sqlite3.Connection) -> bytes:
        first = self._prompt_password("Create master password: ")
        second = self._prompt_password("Confirm master password: ")
        if not first or first != second:
            raise UnlockError("Master password setup failed")

        salt = CryptoEngine.generate_salt()
        key = CryptoEngine.derive_key(first, salt, DEFAULT_PBKDF2_ITERATIONS)
        encrypted = CryptoEngine.encrypt(key, VERIFIER_PLAINTEXT, VERIFIER_AAD)

        self._set_meta(conn, "kdf_salt", base64.b64encode(salt).decode("ascii"))
        self._set_meta(conn, "kdf_iterations", str(DEFAULT_PBKDF2_ITERATIONS))
        self._set_meta(conn, "kdf_hash", "sha256")
        self._set_meta(conn, "verifier_ciphertext", base64.b64encode(encrypted.ciphertext).decode("ascii"))
        self._set_meta(conn, "verifier_nonce", base64.b64encode(encrypted.nonce).decode("ascii"))
        self._set_meta(conn, "schema_version", str(SCHEMA_VERSION))
        conn.commit()
        return key

    def _unlock_existing(self, conn: sqlite3.Connection, state: UnlockState) -> bytes:
        verifier_ciphertext_b64 = self._get_meta(conn, "verifier_ciphertext")
        verifier_nonce_b64 = self._get_meta(conn, "verifier_nonce")
        if verifier_ciphertext_b64 is None or verifier_nonce_b64 is None:
            raise UnlockError("Missing verifier data")

        verifier_ciphertext = base64.b64decode(verifier_ciphertext_b64)
        verifier_nonce = base64.b64decode(verifier_nonce_b64)

        attempts = 0
        while attempts < self._max_unlock_attempts:
            password = self._prompt_password("Master password: ")
            key = CryptoEngine.derive_key(password, state.salt, state.iterations)
            attempts += 1
            try:
                plain = CryptoEngine.decrypt(key, verifier_ciphertext, verifier_nonce, VERIFIER_AAD)
            except Exception:
                continue
            if plain == VERIFIER_PLAINTEXT:
                return key
        raise UnlockError("Failed to unlock fallback backend")

    def _get_unlocked_key(self) -> bytes:
        cached = self._session_cache.get()
        if cached is not None:
            return cached

        with self._connect() as conn:
            state = self._load_unlock_state(conn)
            if state is None:
                key = self._setup_new_master_password(conn)
            else:
                key = self._unlock_existing(conn, state)
        self._session_cache.set(key)
        return key

    def _cleanup_expired(self, conn: sqlite3.Connection) -> None:
        now = to_iso8601(now_utc())
        conn.execute(
            "DELETE FROM secrets WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (now,),
        )

    def set(self, provider: str, secret: str, expires_at: Optional[datetime]) -> None:
        key = self._get_unlocked_key()
        aad = f"{provider}|v{SCHEMA_VERSION}".encode("utf-8")
        encrypted = CryptoEngine.encrypt(key, secret.encode("utf-8"), aad)
        now = to_iso8601(now_utc())
        expires_iso = to_iso8601(expires_at)

        with self._connect() as conn:
            self._cleanup_expired(conn)
            existing = conn.execute(
                "SELECT created_at FROM secrets WHERE provider = ?",
                (provider,),
            ).fetchone()
            created_at = now if existing is None else str(existing["created_at"])
            conn.execute(
                """
                INSERT OR REPLACE INTO secrets(
                    provider, ciphertext, nonce, aad, created_at, updated_at, expires_at, version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    provider,
                    encrypted.ciphertext,
                    encrypted.nonce,
                    aad,
                    created_at,
                    now,
                    expires_iso,
                    SCHEMA_VERSION,
                ),
            )
            conn.commit()

    def get(self, provider: str) -> Optional[StoredSecret]:
        key = self._get_unlocked_key()
        with self._connect() as conn:
            self._cleanup_expired(conn)
            row = conn.execute(
                "SELECT provider, ciphertext, nonce, aad, expires_at FROM secrets WHERE provider = ?",
                (provider,),
            ).fetchone()
            if row is None:
                return None
            expires_at = from_iso8601(row["expires_at"])
            if is_expired(expires_at):
                conn.execute("DELETE FROM secrets WHERE provider = ?", (provider,))
                conn.commit()
                return None
            plaintext = CryptoEngine.decrypt(
                key,
                bytes(row["ciphertext"]),
                bytes(row["nonce"]),
                bytes(row["aad"]),
            ).decode("utf-8")
            return StoredSecret(provider=provider, secret=plaintext, expires_at=expires_at, backend=self.name)

    def list(self) -> list[SecretRecordSummary]:
        key = self._get_unlocked_key()
        records: list[SecretRecordSummary] = []
        with self._connect() as conn:
            self._cleanup_expired(conn)
            rows = conn.execute(
                "SELECT provider, ciphertext, nonce, aad, expires_at FROM secrets ORDER BY provider"
            ).fetchall()
            for row in rows:
                provider = str(row["provider"])
                expires_at = from_iso8601(row["expires_at"])
                expired = is_expired(expires_at)
                if expired:
                    masked = "<expired>"
                else:
                    plaintext = CryptoEngine.decrypt(
                        key,
                        bytes(row["ciphertext"]),
                        bytes(row["nonce"]),
                        bytes(row["aad"]),
                    ).decode("utf-8")
                    masked = mask_secret(plaintext)
                records.append(
                    SecretRecordSummary(
                        provider=provider,
                        masked_preview=masked,
                        backend=self.name,
                        expires_at=expires_at,
                        is_expired=expired,
                    )
                )
        return records

    def delete(self, provider: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM secrets WHERE provider = ?", (provider,))
            conn.commit()
            return cursor.rowcount > 0

    def wipe(self) -> None:
        self._session_cache.clear()
