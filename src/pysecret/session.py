"""Session cache for unlocked fallback key material."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass
class SessionKeyCache:
    timeout_seconds: int = 900

    def __post_init__(self) -> None:
        self._key: bytearray | None = None
        self._expires_at: datetime | None = None

    def set(self, key: bytes) -> None:
        self.clear()
        self._key = bytearray(key)
        self._expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=self.timeout_seconds
        )

    def get(self) -> bytes | None:
        if self._key is None or self._expires_at is None:
            return None
        if datetime.now(timezone.utc) >= self._expires_at:
            self.clear()
            return None
        return bytes(self._key)

    def clear(self) -> None:
        if self._key is not None:
            for idx in range(len(self._key)):
                self._key[idx] = 0
        self._key = None
        self._expires_at = None
