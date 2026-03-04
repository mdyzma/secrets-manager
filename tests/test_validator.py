from __future__ import annotations

from types import SimpleNamespace

import httpx

from pysecret.providers import ProviderRegistry
from pysecret.validator import ValidationClient


class DummyClient:
    def __init__(self, status_code: int):
        self._status_code = status_code

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url: str, headers: dict[str, str], params: dict[str, str]):
        _ = (url, headers, params)
        return SimpleNamespace(status_code=self._status_code)


def test_validator_success_openai(monkeypatch) -> None:
    registry = ProviderRegistry()
    provider = registry.resolve("openai")

    monkeypatch.setattr("httpx.Client", lambda timeout: DummyClient(200))
    result = ValidationClient().check(provider, "sk-test", timeout_seconds=2.0)

    assert result.ok
    assert result.status_code == 200


def test_validator_failure_anthropic(monkeypatch) -> None:
    registry = ProviderRegistry()
    provider = registry.resolve("anthropic")

    monkeypatch.setattr("httpx.Client", lambda timeout: DummyClient(401))
    result = ValidationClient().check(provider, "sk-test", timeout_seconds=2.0)

    assert not result.ok
    assert result.status_code == 401
    assert result.error == "HTTP 401"


def test_validator_network_error(monkeypatch) -> None:
    registry = ProviderRegistry()
    provider = registry.resolve("gemini")

    class ErrorClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url: str, headers: dict[str, str], params: dict[str, str]):
            _ = (url, headers, params)
            raise httpx.RequestError("network down")

    monkeypatch.setattr("httpx.Client", lambda timeout: ErrorClient())
    result = ValidationClient().check(provider, "sk-test", timeout_seconds=2.0)

    assert not result.ok
    assert result.status_code is None
    assert result.error is not None
