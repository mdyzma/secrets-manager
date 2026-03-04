from __future__ import annotations

import pytest

from pysecret.exceptions import InvalidProviderError
from pysecret.providers import ProviderRegistry


def test_provider_alias_mapping() -> None:
    registry = ProviderRegistry()

    assert registry.resolve("openai").canonical == "openai"
    assert registry.resolve("gpt").canonical == "openai"
    assert registry.resolve("claude").canonical == "anthropic"
    assert registry.resolve("google").canonical == "gemini"


def test_invalid_provider_raises() -> None:
    registry = ProviderRegistry()
    with pytest.raises(InvalidProviderError):
        registry.resolve("not-a-provider")
