from __future__ import annotations

import os
from datetime import timedelta

import pytest

from pysecret.exceptions import BackendUnavailableError, SecretNotFoundError
from pysecret.manager import SecretManager
from pysecret.models import SecretRecordSummary, StoredSecret
from pysecret.secret_string import SecretString
from pysecret.storage.base import StorageBackend
from pysecret.storage.sqlite_backend import EncryptedSQLiteBackend
from pysecret.session import SessionKeyCache
from pysecret.utils import now_utc


class UnavailableBackend(StorageBackend):
    name = "keyring"

    def set(self, provider: str, secret: str, expires_at):
        raise BackendUnavailableError("no keyring")

    def get(self, provider: str):
        raise BackendUnavailableError("no keyring")

    def list(self):
        raise BackendUnavailableError("no keyring")

    def delete(self, provider: str):
        raise BackendUnavailableError("no keyring")

    def wipe(self):
        return None


def test_manager_auto_fallback(tmp_path) -> None:
    prompt_calls = iter(["master123", "master123"])

    fallback = EncryptedSQLiteBackend(
        db_path=tmp_path / "secrets.db",
        session_cache=SessionKeyCache(timeout_seconds=900),
        prompt_password=lambda _: next(prompt_calls),
    )
    manager = SecretManager(
        keyring_backend=UnavailableBackend(),
        fallback_backend=fallback,
    )

    manager.set("openai", "sk-openai")
    result = manager.get("openai")

    assert isinstance(result, SecretString)
    assert result.reveal() == "sk-openai"


def test_manager_ttl_expired_hidden(tmp_path) -> None:
    prompt_calls = iter(["master123", "master123"])
    fallback = EncryptedSQLiteBackend(
        db_path=tmp_path / "secrets.db",
        session_cache=SessionKeyCache(timeout_seconds=900),
        prompt_password=lambda _: next(prompt_calls),
    )
    manager = SecretManager(
        keyring_backend=UnavailableBackend(),
        fallback_backend=fallback,
    )

    manager.set("openai", "sk-openai", ttl_seconds=-1)
    with pytest.raises(SecretNotFoundError):
        manager.get("openai")


def test_manager_inject_env(tmp_path) -> None:
    prompt_calls = iter(["master123", "master123"])
    fallback = EncryptedSQLiteBackend(
        db_path=tmp_path / "secrets.db",
        session_cache=SessionKeyCache(timeout_seconds=900),
        prompt_password=lambda _: next(prompt_calls),
    )
    manager = SecretManager(
        keyring_backend=UnavailableBackend(),
        fallback_backend=fallback,
    )

    manager.set("openai", "sk-openai")
    manager.get("openai", inject_env=True)

    assert os.environ["OPENAI_API_KEY"] == "sk-openai"
