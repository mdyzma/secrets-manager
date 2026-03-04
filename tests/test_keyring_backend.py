from __future__ import annotations

from datetime import timedelta

import pytest

from pysecret.models import SecretRecordSummary
from pysecret.storage.keyring_backend import OSKeyringBackend
from pysecret.utils import now_utc


@pytest.fixture
def keyring_store(monkeypatch: pytest.MonkeyPatch) -> dict[tuple[str, str], str]:
    store: dict[tuple[str, str], str] = {}

    def fake_set_password(service: str, username: str, password: str) -> None:
        store[(service, username)] = password

    def fake_get_password(service: str, username: str) -> str | None:
        return store.get((service, username))

    def fake_delete_password(service: str, username: str) -> None:
        store.pop((service, username), None)

    monkeypatch.setattr("keyring.set_password", fake_set_password)
    monkeypatch.setattr("keyring.get_password", fake_get_password)
    monkeypatch.setattr("keyring.delete_password", fake_delete_password)
    return store


def test_keyring_backend_crud(keyring_store: dict[tuple[str, str], str]) -> None:
    backend = OSKeyringBackend("pysecret.ai.test", providers=["openai", "anthropic"])

    expected_value = "demo-token-live"
    backend.set("openai", expected_value, expires_at=None)
    stored = backend.get("openai")

    assert stored is not None
    assert stored.secret == expected_value
    assert stored.backend == "keyring"

    rows = backend.list()
    assert len(rows) == 1
    assert isinstance(rows[0], SecretRecordSummary)
    assert rows[0].provider == "openai"

    assert backend.delete("openai")
    assert backend.get("openai") is None


def test_keyring_backend_expired_cleanup(
    keyring_store: dict[tuple[str, str], str],
) -> None:
    backend = OSKeyringBackend("pysecret.ai.test", providers=["openai"])
    backend.set("openai", "demo-token-expired", expires_at=now_utc() - timedelta(seconds=5))

    assert backend.get("openai") is None
