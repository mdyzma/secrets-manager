"""Public and internal data models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class SecretRecordSummary:
    provider: str
    masked_preview: str
    backend: str
    expires_at: datetime | None
    is_expired: bool


@dataclass(frozen=True)
class ProviderCheckResult:
    provider: str
    ok: bool
    status_code: int | None
    latency_ms: float
    error: str | None


@dataclass(frozen=True)
class StoredSecret:
    provider: str
    secret: str
    expires_at: datetime | None
    backend: str
