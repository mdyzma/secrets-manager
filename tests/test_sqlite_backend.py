from __future__ import annotations

from collections import deque
from datetime import timedelta

import pytest

from pysecret.exceptions import UnlockError
from pysecret.session import SessionKeyCache
from pysecret.storage.sqlite_backend import EncryptedSQLiteBackend
from pysecret.utils import now_utc


class PromptQueue:
    def __init__(self, responses: list[str]) -> None:
        self._responses = deque(responses)
        self.calls: list[str] = []

    def __call__(self, message: str) -> str:
        self.calls.append(message)
        if not self._responses:
            raise AssertionError("No prompt response available")
        return self._responses.popleft()


def test_sqlite_backend_setup_and_crud(tmp_path) -> None:
    prompt = PromptQueue(["master123", "master123"])
    backend = EncryptedSQLiteBackend(
        db_path=tmp_path / "secrets.db",
        session_cache=SessionKeyCache(timeout_seconds=900),
        prompt_password=prompt,
    )

    backend.set("openai", "sk-123", expires_at=None)
    record = backend.get("openai")

    assert record is not None
    assert record.secret == "sk-123"

    listed = backend.list()
    assert len(listed) == 1
    assert listed[0].provider == "openai"

    assert backend.delete("openai")
    assert backend.get("openai") is None


def test_sqlite_backend_expiration(tmp_path) -> None:
    prompt = PromptQueue(["master123", "master123"])
    backend = EncryptedSQLiteBackend(
        db_path=tmp_path / "secrets.db",
        session_cache=SessionKeyCache(timeout_seconds=900),
        prompt_password=prompt,
    )

    backend.set("openai", "sk-expired", expires_at=now_utc() - timedelta(seconds=1))
    assert backend.get("openai") is None


def test_sqlite_unlock_retry_failure(tmp_path) -> None:
    setup_prompt = PromptQueue(["master123", "master123"])
    backend = EncryptedSQLiteBackend(
        db_path=tmp_path / "secrets.db",
        session_cache=SessionKeyCache(timeout_seconds=900),
        prompt_password=setup_prompt,
    )
    backend.set("openai", "sk-123", expires_at=None)

    bad_prompt = PromptQueue(["wrong", "wrong", "wrong"])
    locked_backend = EncryptedSQLiteBackend(
        db_path=tmp_path / "secrets.db",
        session_cache=SessionKeyCache(timeout_seconds=1),
        prompt_password=bad_prompt,
    )

    with pytest.raises(UnlockError):
        locked_backend.get("openai")
