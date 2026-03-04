"""Provider definitions and alias resolution."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from pysecret.exceptions import InvalidProviderError

PROVIDER_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
ENV_VAR_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]*$")


@dataclass(frozen=True)
class Provider:
    canonical: str
    aliases: tuple[str, ...]
    env_var: str
    check_url: str | None
    auth_style: str
    extra_headers: dict[str, str] = field(default_factory=dict)
    source: str = "builtin"


class ProviderRegistry:
    def __init__(
        self, custom_providers: Iterable[tuple[str, str]] | None = None
    ) -> None:
        self._providers_by_name: dict[str, Provider] = {}
        self._alias_map: dict[str, str] = {}

        for provider in self._builtin_providers():
            self._add_provider(provider)

        if custom_providers is not None:
            for name, env_var in custom_providers:
                self.register_custom(name, env_var)

    @staticmethod
    def _builtin_providers() -> tuple[Provider, ...]:
        return (
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
            Provider(
                canonical="ollama",
                aliases=("ollama",),
                env_var="OLLAMA_API_KEY",
                check_url=None,
                auth_style="none",
                extra_headers={},
            ),
            Provider(
                canonical="pinecone",
                aliases=("pinecone",),
                env_var="PINECONE_API_KEY",
                check_url=None,
                auth_style="none",
                extra_headers={},
            ),
        )

    @staticmethod
    def normalize_name(name: str) -> str:
        return name.strip().lower()

    @staticmethod
    def validate_name(name: str) -> None:
        if not PROVIDER_NAME_PATTERN.fullmatch(name):
            raise InvalidProviderError(
                "Provider name must match: lowercase letters, numbers, '_' or '-', "
                "and must start with a letter or number"
            )

    @staticmethod
    def normalize_env_var(env_var: str) -> str:
        return env_var.strip().upper()

    @staticmethod
    def validate_env_var(env_var: str) -> None:
        if not ENV_VAR_PATTERN.fullmatch(env_var):
            raise InvalidProviderError(
                "Environment variable must match shell style: "
                "uppercase letters, numbers, and '_' only"
            )

    def _add_provider(self, provider: Provider) -> None:
        self._providers_by_name[provider.canonical] = provider
        for alias in provider.aliases:
            self._alias_map[alias.lower()] = provider.canonical

    def register_custom(self, name: str, env_var: str) -> Provider:
        canonical = self.normalize_name(name)
        normalized_env = self.normalize_env_var(env_var)
        self.validate_name(canonical)
        self.validate_env_var(normalized_env)

        existing = self._providers_by_name.get(canonical)
        if existing is not None and existing.source == "builtin":
            raise InvalidProviderError(
                f"Cannot redefine built-in provider: {canonical}"
            )

        provider = Provider(
            canonical=canonical,
            aliases=(canonical,),
            env_var=normalized_env,
            check_url=None,
            auth_style="none",
            extra_headers={},
            source="custom",
        )
        self._add_provider(provider)
        return provider

    def custom_providers(self) -> list[Provider]:
        providers = [
            provider
            for provider in self._providers_by_name.values()
            if provider.source == "custom"
        ]
        return sorted(providers, key=lambda item: item.canonical)

    def resolve(self, name: str) -> Provider:
        canonical = self._alias_map.get(name.lower())
        if canonical is None:
            raise InvalidProviderError(f"Unknown provider alias: {name}")
        return self._providers_by_name[canonical]

    def all(self) -> Iterable[Provider]:
        return self._providers_by_name.values()
