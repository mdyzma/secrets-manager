"""Public and internal data models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class SecretRecordSummary:
    provider: str
    masked_preview: str
    backend: str
    expires_at: Optional[datetime]
    is_expired: bool


@dataclass(frozen=True)
class ProviderCheckResult:
    provider: str
    ok: bool
    status_code: Optional[int]
    latency_ms: float
    error: Optional[str]


@dataclass(frozen=True)
class StoredSecret:
    provider: str
    secret: str
    expires_at: Optional[datetime]
    backend: str
