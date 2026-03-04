"""CLI entrypoint for PySecret."""

from __future__ import annotations

import getpass
from datetime import timezone
from typing import Annotated

import typer

from pysecret import api
from pysecret.exceptions import PySecretError
from pysecret.manager import BackendMode

app = typer.Typer(
    help="Local-first secrets manager for AI API keys", no_args_is_help=True
)


@app.command("set")
def set_secret(
    provider: str,
    ttl: Annotated[int | None, typer.Option(help="TTL in seconds")] = None,
    backend: Annotated[BackendMode, typer.Option(help="Storage backend")] = "auto",
) -> None:
    try:
        secret = getpass.getpass("API key: ")
        if not secret:
            raise typer.BadParameter("Secret cannot be empty")
        api.set(provider, secret, ttl_seconds=ttl, backend=backend)
        typer.echo(f"Stored secret for {provider}")
    except PySecretError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command("set-custom")
def set_custom_secret(
    name: str,
    env_var: str,
    ttl: Annotated[int | None, typer.Option(help="TTL in seconds")] = None,
    backend: Annotated[BackendMode, typer.Option(help="Storage backend")] = "auto",
) -> None:
    try:
        secret = getpass.getpass("API key: ")
        if not secret:
            raise typer.BadParameter("Secret cannot be empty")
        api.set_custom(name, env_var, secret, ttl_seconds=ttl, backend=backend)
        typer.echo(f"Stored secret for custom provider {name}")
    except PySecretError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command("add-provider")
def add_provider(name: str, env_var: str) -> None:
    try:
        api.register_provider(name, env_var)
        typer.echo(f"Registered custom provider {name} with {env_var}")
    except PySecretError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command("get")
def get_secret(
    provider: str,
    plain: Annotated[bool, typer.Option("--plain", help="Print plaintext secret")] = False,
    inject_env: Annotated[
        bool, typer.Option("--inject-env", help="Inject into environment variable")
    ] = False,
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
        raise typer.Exit(code=1) from exc


@app.command("list")
def list_providers(
    show_expired: Annotated[bool, typer.Option(help="Include expired secrets")] = False,
) -> None:
    try:
        records = api.list_providers(masked=True, include_expired=show_expired)
    except PySecretError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if not records:
        typer.echo("No secrets found")
        return

    for record in records:
        expiry = "never"
        if record.expires_at is not None:
            expiry = record.expires_at.astimezone(timezone.utc).isoformat()
        status = "expired" if record.is_expired else "active"
        line = (
            f"{record.provider:<10} {record.backend:<8} {status:<7} "
            f"{record.masked_preview:<20} expires={expiry}"
        )
        typer.echo(line)


@app.command("delete")
def delete_secret(provider: str) -> None:
    try:
        deleted = api.delete(provider)
    except PySecretError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if deleted:
        typer.echo(f"Deleted secret for {provider}")
    else:
        typer.echo(f"No secret found for {provider}")


@app.command("check")
def check_secret(
    provider: Annotated[str | None, typer.Argument()] = None,
    timeout: Annotated[float, typer.Option(help="Network timeout in seconds")] = 8.0,
) -> None:
    try:
        results = api.check(provider=provider, timeout_seconds=timeout)
    except PySecretError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if not results:
        typer.echo("No keys to validate")
        return

    for result in results:
        status = "OK" if result.ok else "FAIL"
        detail = (
            f"status={result.status_code}"
            if result.status_code is not None
            else "status=n/a"
        )
        if result.error:
            detail = f"{detail} error={result.error}"
        typer.echo(
            f"{result.provider:<10} {status:<4} {detail} latency_ms={result.latency_ms:.1f}"
        )


@app.command("wipe")
def wipe() -> None:
    api.wipe()
    typer.echo("Cleared in-memory secret state")


@app.command("providers")
def providers() -> None:
    for provider in api.providers():
        aliases = ",".join(provider.aliases)
        typer.echo(
            f"{provider.canonical:<12} {provider.source:<8} "
            f"env={provider.env_var:<20} aliases={aliases}"
        )


if __name__ == "__main__":
    app()
