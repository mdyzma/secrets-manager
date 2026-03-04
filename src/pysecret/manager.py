"""High-level orchestration API."""

from __future__ import annotations

import getpass
import os
from collections.abc import Callable
from datetime import timedelta
from typing import Literal

from pysecret.config import (
    AppConfig,
    AppPaths,
    ensure_state_dir,
    get_app_paths,
    load_config,
)
from pysecret.exceptions import (
    BackendUnavailableError,
    PySecretError,
    SecretNotFoundError,
)
from pysecret.models import ProviderCheckResult, SecretRecordSummary
from pysecret.providers import Provider, ProviderRegistry
from pysecret.secret_string import SecretString
from pysecret.session import SessionKeyCache
from pysecret.storage.keyring_backend import OSKeyringBackend
from pysecret.storage.sqlite_backend import EncryptedSQLiteBackend
from pysecret.utils import now_utc
from pysecret.validator import ValidationClient

BackendMode = Literal["auto", "keyring", "fallback"]


class SecretManager:
    def __init__(
        self,
        paths: AppPaths | None = None,
        config: AppConfig | None = None,
        password_prompt: Callable[[str], str] | None = None,
        provider_registry: ProviderRegistry | None = None,
        keyring_backend: OSKeyringBackend | None = None,
        fallback_backend: EncryptedSQLiteBackend | None = None,
        validator: ValidationClient | None = None,
    ) -> None:
        self._paths = paths or get_app_paths()
        ensure_state_dir(self._paths)
        self._config = config or load_config(self._paths)
        self._provider_registry = provider_registry or ProviderRegistry()
        self._password_prompt = password_prompt or getpass.getpass
        self._validator = validator or ValidationClient()
        self._session_cache = SessionKeyCache(
            timeout_seconds=self._config.unlock_timeout_seconds
        )

        provider_names = [
            provider.canonical for provider in self._provider_registry.all()
        ]
        self._keyring_backend = keyring_backend or OSKeyringBackend(
            service_name="pysecret.ai",
            providers=provider_names,
        )
        self._fallback_backend = fallback_backend or EncryptedSQLiteBackend(
            db_path=self._paths.db_path,
            session_cache=self._session_cache,
            prompt_password=self._password_prompt,
        )

    def providers(self) -> list[Provider]:
        return sorted(self._provider_registry.all(), key=lambda item: item.canonical)

    def provider_env_var(self, provider: str) -> str:
        return self._provider_registry.resolve(provider).env_var

    def _resolve_provider_name(self, provider: str) -> str:
        return self._provider_registry.resolve(provider).canonical

    def _selected_backends(self, backend: BackendMode) -> list:
        if backend == "keyring":
            return [self._keyring_backend]
        if backend == "fallback":
            return [self._fallback_backend]
        return [self._keyring_backend, self._fallback_backend]

    @staticmethod
    def _coerce_secret(secret: str | SecretString) -> str:
        if isinstance(secret, SecretString):
            return secret.reveal()
        return secret

    def set(
        self,
        provider: str,
        secret: str | SecretString,
        ttl_seconds: int | None = None,
        backend: BackendMode = "auto",
    ) -> None:
        canonical = self._resolve_provider_name(provider)
        raw_secret = self._coerce_secret(secret)
        expires_at = None
        if ttl_seconds is not None:
            expires_at = now_utc() + timedelta(seconds=ttl_seconds)

        selected = self._selected_backends(backend)
        last_error: Exception | None = None
        for current in selected:
            try:
                current.set(canonical, raw_secret, expires_at)
                if backend == "auto" and current.name == "keyring":
                    self._fallback_backend.delete(canonical)
                return
            except BackendUnavailableError as exc:
                last_error = exc
                if backend != "auto":
                    raise
                continue

        if last_error is not None:
            raise last_error
        raise PySecretError("No backend available to store secret")

    def get(
        self,
        provider: str,
        as_plaintext: bool = False,
        inject_env: bool = False,
        backend: BackendMode = "auto",
    ) -> SecretString | str:
        provider_obj = self._provider_registry.resolve(provider)
        canonical = provider_obj.canonical

        for current in self._selected_backends(backend):
            try:
                stored = current.get(canonical)
            except BackendUnavailableError:
                if backend != "auto":
                    raise
                continue
            if stored is None:
                continue

            if inject_env:
                os.environ[provider_obj.env_var] = stored.secret
            secret_obj = SecretString(stored.secret)
            if as_plaintext:
                return secret_obj.reveal()
            return secret_obj
        raise SecretNotFoundError(f"No active secret found for provider: {canonical}")

    def list_providers(
        self, masked: bool = True, include_expired: bool = False
    ) -> list[SecretRecordSummary]:
        merged: dict[str, SecretRecordSummary] = {}
        for current in self._selected_backends("auto"):
            try:
                records = current.list()
            except BackendUnavailableError:
                continue
            for record in records:
                if record.provider in merged:
                    continue
                merged[record.provider] = record

        values = list(merged.values())
        if not include_expired:
            values = [record for record in values if not record.is_expired]

        if not masked:
            unmasked: list[SecretRecordSummary] = []
            for record in values:
                secret = self.get(record.provider, as_plaintext=True)
                if not isinstance(secret, str):
                    raise PySecretError("Unexpected secret type")
                unmasked.append(
                    SecretRecordSummary(
                        provider=record.provider,
                        masked_preview=secret,
                        backend=record.backend,
                        expires_at=record.expires_at,
                        is_expired=record.is_expired,
                    )
                )
            return sorted(unmasked, key=lambda item: item.provider)

        return sorted(values, key=lambda item: item.provider)

    def delete(self, provider: str, backend: BackendMode = "auto") -> bool:
        canonical = self._resolve_provider_name(provider)
        deleted = False
        for current in self._selected_backends(backend):
            try:
                deleted = current.delete(canonical) or deleted
            except BackendUnavailableError:
                if backend != "auto":
                    raise
                continue
        return deleted

    def check(
        self, provider: str | None = None, timeout_seconds: float = 8.0
    ) -> list[ProviderCheckResult]:
        targets: list[str]
        if provider is not None:
            targets = [self._resolve_provider_name(provider)]
        else:
            targets = [
                record.provider
                for record in self.list_providers(masked=True, include_expired=False)
            ]

        results: list[ProviderCheckResult] = []
        for target in targets:
            try:
                secret = self.get(target, as_plaintext=True)
            except SecretNotFoundError:
                results.append(
                    ProviderCheckResult(
                        provider=target,
                        ok=False,
                        status_code=None,
                        latency_ms=0.0,
                        error="No active secret",
                    )
                )
                continue
            if not isinstance(secret, str):
                raise PySecretError("Unexpected secret type")
            provider_def = self._provider_registry.resolve(target)
            results.append(self._validator.check(provider_def, secret, timeout_seconds))
        return results

    def wipe(self) -> None:
        self._keyring_backend.wipe()
        self._fallback_backend.wipe()
        SecretString.wipe_all()
