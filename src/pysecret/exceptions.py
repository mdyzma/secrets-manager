"""PySecret custom exceptions."""

from __future__ import annotations


class PySecretError(Exception):
    """Base exception for all package errors."""


class SecretNotFoundError(PySecretError):
    """Raised when a provider key does not exist or is expired."""


class InvalidProviderError(PySecretError):
    """Raised when provider alias cannot be resolved."""


class UnlockError(PySecretError):
    """Raised when fallback unlock fails."""


class BackendUnavailableError(PySecretError):
    """Raised when backend cannot be used."""


class ValidationError(PySecretError):
    """Raised when a secret fails cryptographic validation."""
