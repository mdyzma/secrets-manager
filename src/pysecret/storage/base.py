"""Storage backend interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from pysecret.models import SecretRecordSummary, StoredSecret


class StorageBackend(ABC):
    name: str

    @abstractmethod
    def set(self, provider: str, secret: str, expires_at: datetime | None) -> None:
        raise NotImplementedError

    @abstractmethod
    def get(self, provider: str) -> StoredSecret | None:
        raise NotImplementedError

    @abstractmethod
    def list(self) -> list[SecretRecordSummary]:
        raise NotImplementedError

    @abstractmethod
    def delete(self, provider: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def wipe(self) -> None:
        raise NotImplementedError
