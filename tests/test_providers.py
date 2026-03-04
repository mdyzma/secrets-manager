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
    assert registry.resolve("ollama").env_var == "OLLAMA_API_KEY"
    assert registry.resolve("pinecone").env_var == "PINECONE_API_KEY"


def test_invalid_provider_raises() -> None:
    registry = ProviderRegistry()
    with pytest.raises(InvalidProviderError):
        registry.resolve("not-a-provider")


def test_register_custom_provider() -> None:
    registry = ProviderRegistry()
    provider = registry.register_custom("acme-ai", "ACME_AI_KEY")

    assert provider.canonical == "acme-ai"
    assert provider.env_var == "ACME_AI_KEY"
    assert provider.source == "custom"
    assert registry.resolve("acme-ai").canonical == "acme-ai"


def test_register_custom_provider_rejects_invalid_env_var() -> None:
    registry = ProviderRegistry()
    with pytest.raises(InvalidProviderError):
        registry.register_custom("acme-ai", "invalid-env")
