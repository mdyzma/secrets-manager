"""OS keyring backend."""

from __future__ import annotations

import json
from datetime import datetime

import keyring
from keyring.errors import KeyringError

from pysecret.exceptions import BackendUnavailableError
from pysecret.models import SecretRecordSummary, StoredSecret
from pysecret.storage.base import StorageBackend
from pysecret.utils import from_iso8601, is_expired, mask_secret, to_iso8601


class OSKeyringBackend(StorageBackend):
    name = "keyring"

    def __init__(self, service_name: str, providers: list[str]) -> None:
        self._service_name = service_name
        self._providers = providers

    def set_known_providers(self, providers: list[str]) -> None:
        self._providers = providers

    def _load_record(self, provider: str) -> dict[str, str | None] | None:
        try:
            data = keyring.get_password(self._service_name, provider)
        except KeyringError as exc:
            raise BackendUnavailableError(str(exc)) from exc
        if data is None:
            return None
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as exc:
            raise BackendUnavailableError("Corrupted keyring record") from exc
        if not isinstance(parsed, dict):
            raise BackendUnavailableError("Invalid keyring record type")
        secret = parsed.get("secret")
        if not isinstance(secret, str):
            raise BackendUnavailableError("Invalid keyring secret type")
        expires_value = parsed.get("expires_at")
        expires_str = expires_value if isinstance(expires_value, str) else None
        return {"secret": secret, "expires_at": expires_str}

    def set(self, provider: str, secret: str, expires_at: datetime | None) -> None:
        payload = {"secret": secret, "expires_at": to_iso8601(expires_at)}
        try:
            keyring.set_password(self._service_name, provider, json.dumps(payload))
        except KeyringError as exc:
            raise BackendUnavailableError(str(exc)) from exc

    def get(self, provider: str) -> StoredSecret | None:
        record = self._load_record(provider)
        if record is None:
            return None
        expires_at = from_iso8601(record["expires_at"])
        if is_expired(expires_at):
            self.delete(provider)
            return None
        secret = record["secret"]
        if secret is None:
            return None
        return StoredSecret(
            provider=provider, secret=secret, expires_at=expires_at, backend=self.name
        )

    def list(self) -> list[SecretRecordSummary]:
        records: list[SecretRecordSummary] = []
        for provider in self._providers:
            record = self._load_record(provider)
            if record is None:
                continue
            expires_at = from_iso8601(record["expires_at"])
            expired = is_expired(expires_at)
            secret = record["secret"]
            if secret is None:
                continue
            records.append(
                SecretRecordSummary(
                    provider=provider,
                    masked_preview=mask_secret(secret),
                    backend=self.name,
                    expires_at=expires_at,
                    is_expired=expired,
                )
            )
        return records

    def delete(self, provider: str) -> bool:
        existing = self._load_record(provider)
        if existing is None:
            return False
        try:
            keyring.delete_password(self._service_name, provider)
        except keyring.errors.PasswordDeleteError:
            return False
        except KeyringError as exc:
            raise BackendUnavailableError(str(exc)) from exc
        return True

    def wipe(self) -> None:
        # Keyring backend persists on purpose; wipe is runtime-only.
        return None
