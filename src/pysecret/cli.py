"""CLI entrypoint for PySecret."""

from __future__ import annotations

import getpass
from datetime import timezone
from typing import Optional

import typer

from pysecret.exceptions import PySecretError
from pysecret.manager import BackendMode
from pysecret import api

app = typer.Typer(help="Local-first secrets manager for AI API keys", no_args_is_help=True)


@app.command("set")
def set_secret(
    provider: str,
    ttl: Optional[int] = typer.Option(None, help="TTL in seconds"),
    backend: BackendMode = typer.Option("auto", help="Storage backend"),
) -> None:
    try:
        secret = getpass.getpass("API key: ")
        if not secret:
            raise typer.BadParameter("Secret cannot be empty")
        api.set(provider, secret, ttl_seconds=ttl, backend=backend)
        typer.echo(f"Stored secret for {provider}")
    except PySecretError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)


@app.command("get")
def get_secret(
    provider: str,
    plain: bool = typer.Option(False, "--plain", help="Print plaintext secret"),
    inject_env: bool = typer.Option(False, "--inject-env", help="Inject into environment variable"),
) -> None:
    try:
        value = api.get(provider, as_plaintext=plain, inject_env=inject_env)
        if plain:
            typer.echo(value)
        else:
            typer.echo(str(value))
        if inject_env:
            env_var = api.get_provider_env(provider)
            typer.echo(f"Injected into {env_var}")
    except PySecretError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)


@app.command("list")
def list_providers(show_expired: bool = typer.Option(False, help="Include expired secrets")) -> None:
    try:
        records = api.list_providers(masked=True, include_expired=show_expired)
    except PySecretError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)

    if not records:
        typer.echo("No secrets found")
        return

    for record in records:
        expiry = "never"
        if record.expires_at is not None:
            expiry = record.expires_at.astimezone(timezone.utc).isoformat()
        status = "expired" if record.is_expired else "active"
        typer.echo(
            f"{record.provider:<10} {record.backend:<8} {status:<7} {record.masked_preview:<20} expires={expiry}"
        )


@app.command("delete")
def delete_secret(provider: str) -> None:
    try:
        deleted = api.delete(provider)
    except PySecretError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)

    if deleted:
        typer.echo(f"Deleted secret for {provider}")
    else:
        typer.echo(f"No secret found for {provider}")


@app.command("check")
def check_secret(
    provider: Optional[str] = typer.Argument(None),
    timeout: float = typer.Option(8.0, help="Network timeout in seconds"),
) -> None:
    try:
        results = api.check(provider=provider, timeout_seconds=timeout)
    except PySecretError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)

    if not results:
        typer.echo("No keys to validate")
        return

    for result in results:
        status = "OK" if result.ok else "FAIL"
        detail = f"status={result.status_code}" if result.status_code is not None else "status=n/a"
        if result.error:
            detail = f"{detail} error={result.error}"
        typer.echo(f"{result.provider:<10} {status:<4} {detail} latency_ms={result.latency_ms:.1f}")


@app.command("wipe")
def wipe() -> None:
    api.wipe()
    typer.echo("Cleared in-memory secret state")


@app.command("providers")
def providers() -> None:
    for provider in api.providers():
        aliases = ",".join(provider.aliases)
        typer.echo(f"{provider.canonical:<10} env={provider.env_var:<20} aliases={aliases}")


if __name__ == "__main__":
    app()
