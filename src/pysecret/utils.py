"""Utility helpers."""

from __future__ import annotations

from datetime import datetime, timezone


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def to_iso8601(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def from_iso8601(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_expired(expires_at: datetime | None) -> bool:
    if expires_at is None:
        return False
    expiry = expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return now_utc() >= expiry.astimezone(timezone.utc)


def mask_secret(value: str) -> str:
    if not value:
        return "****"
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}****...{value[-4:]}"
