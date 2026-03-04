"""Secret string wrapper with masked display and wipe support."""

from __future__ import annotations

import weakref


class SecretString:
    """Holds secret bytes in mutable form for best-effort wiping."""

    _instances: weakref.WeakSet[SecretString] = weakref.WeakSet()

    def __init__(self, value: str) -> None:
        self._buf = bytearray(value.encode("utf-8"))
        SecretString._instances.add(self)

    def reveal(self) -> str:
        return self._buf.decode("utf-8")

    def masked(self) -> str:
        value = self.reveal()
        if not value:
            return "****"
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}****...{value[-4:]}"

    def wipe(self) -> None:
        for idx in range(len(self._buf)):
            self._buf[idx] = 0

    def __str__(self) -> str:
        return self.masked()

    def __repr__(self) -> str:
        return f"SecretString(masked={self.masked()!r})"

    @classmethod
    def wipe_all(cls) -> None:
        for instance in list(cls._instances):
            instance.wipe()
