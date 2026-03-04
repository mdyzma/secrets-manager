"""Provider definitions and alias resolution."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from pysecret.exceptions import InvalidProviderError


@dataclass(frozen=True)
class Provider:
    canonical: str
    aliases: tuple[str, ...]
    env_var: str
    check_url: str
    auth_style: str
    extra_headers: dict[str, str]


class ProviderRegistry:
    def __init__(self) -> None:
        providers = (
            Provider(
                canonical="openai",
                aliases=("openai", "oa", "gpt"),
                env_var="OPENAI_API_KEY",
                check_url="https://api.openai.com/v1/models",
                auth_style="bearer",
                extra_headers={},
            ),
            Provider(
                canonical="anthropic",
                aliases=("anthropic", "claude"),
                env_var="ANTHROPIC_API_KEY",
                check_url="https://api.anthropic.com/v1/models",
                auth_style="x-api-key",
                extra_headers={"anthropic-version": "2023-06-01"},
            ),
            Provider(
                canonical="gemini",
                aliases=("gemini", "google", "google-ai"),
                env_var="GEMINI_API_KEY",
                check_url="https://generativelanguage.googleapis.com/v1beta/models",
                auth_style="query-key",
                extra_headers={},
            ),
            Provider(
                canonical="mistral",
                aliases=("mistral",),
                env_var="MISTRAL_API_KEY",
                check_url="https://api.mistral.ai/v1/models",
                auth_style="bearer",
                extra_headers={},
            ),
        )
        self._providers_by_name = {
            provider.canonical: provider for provider in providers
        }
        self._alias_map: dict[str, str] = {}
        for provider in providers:
            for alias in provider.aliases:
                self._alias_map[alias.lower()] = provider.canonical

    def resolve(self, name: str) -> Provider:
        canonical = self._alias_map.get(name.lower())
        if canonical is None:
            raise InvalidProviderError(f"Unknown provider alias: {name}")
        return self._providers_by_name[canonical]

    def all(self) -> Iterable[Provider]:
        return self._providers_by_name.values()
