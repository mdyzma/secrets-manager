from __future__ import annotations

from datetime import datetime, timezone

from typer.testing import CliRunner

from pysecret.cli import app
from pysecret.models import ProviderCheckResult, SecretRecordSummary
from pysecret.providers import Provider
from pysecret.secret_string import SecretString


runner = CliRunner()


def test_cli_set_uses_hidden_input(monkeypatch) -> None:
    captured = {}

    def fake_set(provider: str, secret: str, ttl_seconds, backend) -> None:
        captured["provider"] = provider
        captured["secret"] = secret
        captured["ttl"] = ttl_seconds
        captured["backend"] = backend

    monkeypatch.setattr("pysecret.cli.getpass.getpass", lambda _: "sk-hidden-secret")
    monkeypatch.setattr("pysecret.cli.api.set", fake_set)

    result = runner.invoke(app, ["set", "openai", "--ttl", "60"])

    assert result.exit_code == 0
    assert "sk-hidden-secret" not in result.output
    assert captured["provider"] == "openai"


def test_cli_list_masked(monkeypatch) -> None:
    monkeypatch.setattr(
        "pysecret.cli.api.list_providers",
        lambda masked, include_expired: [
            SecretRecordSummary(
                provider="openai",
                masked_preview="sk-****...1234",
                backend="fallback",
                expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
                is_expired=False,
            )
        ],
    )

    result = runner.invoke(app, ["list"])

    assert result.exit_code == 0
    assert "sk-****...1234" in result.output


def test_cli_check_mixed_results(monkeypatch) -> None:
    monkeypatch.setattr(
        "pysecret.cli.api.check",
        lambda provider=None, timeout_seconds=8.0: [
            ProviderCheckResult("openai", True, 200, 12.3, None),
            ProviderCheckResult("anthropic", False, 401, 10.0, "HTTP 401"),
        ],
    )

    result = runner.invoke(app, ["check"])

    assert result.exit_code == 0
    assert "openai" in result.output
    assert "anthropic" in result.output
    assert "FAIL" in result.output


def test_cli_wipe(monkeypatch) -> None:
    state = {"called": False}

    def fake_wipe() -> None:
        state["called"] = True

    monkeypatch.setattr("pysecret.cli.api.wipe", fake_wipe)

    result = runner.invoke(app, ["wipe"])

    assert result.exit_code == 0
    assert state["called"]


def test_cli_providers(monkeypatch) -> None:
    monkeypatch.setattr(
        "pysecret.cli.api.providers",
        lambda: [
            Provider(
                canonical="openai",
                aliases=("openai", "gpt"),
                env_var="OPENAI_API_KEY",
                check_url="https://api.openai.com/v1/models",
                auth_style="bearer",
                extra_headers={},
            )
        ],
    )

    result = runner.invoke(app, ["providers"])

    assert result.exit_code == 0
    assert "OPENAI_API_KEY" in result.output


def test_cli_get_plain(monkeypatch) -> None:
    monkeypatch.setattr(
        "pysecret.cli.api.get",
        lambda provider, as_plaintext=False, inject_env=False: "sk-plain"
        if as_plaintext
        else SecretString("sk-plain"),
    )

    result = runner.invoke(app, ["get", "openai", "--plain"])

    assert result.exit_code == 0
    assert "sk-plain" in result.output
