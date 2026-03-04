"""Public API facade for package-level usage."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pysecret.manager import SecretManager
from pysecret.models import ProviderCheckResult, SecretRecordSummary
from pysecret.providers import Provider
from pysecret.secret_string import SecretString


@lru_cache(maxsize=1)
def _manager() -> SecretManager:
    return SecretManager()


def set(
    provider: str,
    secret: str | SecretString,
    ttl_seconds: int | None = None,
    backend: Literal["auto", "keyring", "fallback"] = "auto",
) -> None:
    _manager().set(provider, secret, ttl_seconds=ttl_seconds, backend=backend)


def get(
    provider: str,
    as_plaintext: bool = False,
    inject_env: bool = False,
) -> SecretString | str:
    return _manager().get(provider, as_plaintext=as_plaintext, inject_env=inject_env)


def list_providers(
    masked: bool = True, include_expired: bool = False
) -> list[SecretRecordSummary]:
    return _manager().list_providers(masked=masked, include_expired=include_expired)


def delete(provider: str) -> bool:
    return _manager().delete(provider)


def check(
    provider: str | None = None, timeout_seconds: float = 8.0
) -> list[ProviderCheckResult]:
    return _manager().check(provider=provider, timeout_seconds=timeout_seconds)


def wipe() -> None:
    _manager().wipe()


def providers() -> list[Provider]:
    return _manager().providers()


def get_provider_env(provider: str) -> str:
    return _manager().provider_env_var(provider)
