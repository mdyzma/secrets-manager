"""Provider key live validation client."""

from __future__ import annotations

import time

import httpx

from pysecret.models import ProviderCheckResult
from pysecret.providers import Provider


class ValidationClient:
    def check(
        self, provider: Provider, api_key: str, timeout_seconds: float
    ) -> ProviderCheckResult:
        if provider.check_url is None or provider.auth_style == "none":
            return ProviderCheckResult(
                provider=provider.canonical,
                ok=False,
                status_code=None,
                latency_ms=0.0,
                error="No validation endpoint configured for this provider",
            )

        headers = dict(provider.extra_headers)
        params: dict[str, str] = {}

        if provider.auth_style == "bearer":
            headers["Authorization"] = f"Bearer {api_key}"
        elif provider.auth_style == "x-api-key":
            headers["x-api-key"] = api_key
        elif provider.auth_style == "query-key":
            params["key"] = api_key

        start = time.perf_counter()
        status_code = None
        error = None
        ok = False
        try:
            with httpx.Client(timeout=timeout_seconds) as client:
                response = client.get(
                    provider.check_url,
                    headers=headers,
                    params=params,
                )
            status_code = response.status_code
            ok = response.status_code == 200
            if not ok:
                error = f"HTTP {response.status_code}"
        except httpx.RequestError as exc:
            error = str(exc)
        latency_ms = (time.perf_counter() - start) * 1000
        return ProviderCheckResult(
            provider=provider.canonical,
            ok=ok,
            status_code=status_code,
            latency_ms=latency_ms,
            error=error,
        )
