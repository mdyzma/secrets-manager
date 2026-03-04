# PySecret-AI v1 Plan (Local-First Secrets Manager for AI Keys)

## Summary
Build a secure, local-first Python package and CLI named `pysecret` from an empty repository, targeting Python 3.10+, with:

1. Primary storage via OS keyring (`keyring` library).
2. Fallback storage via AES-256-GCM encrypted SQLite using a master password.
3. Safe CLI flows (`getpass` masked input), provider alias mapping, TTL expirations, live key validation (`check`), environment injection, and best-effort memory wipe.
4. Secure-by-default API returning a `SecretString` wrapper, with explicit opt-in for plaintext.

This plan intentionally scopes v1 to **CLI + core API** (no SDK wrappers yet), while defining extension points for Phase 3 wrappers and Phase 4 GUI.

## Implementation Scope (Decision-Complete)

## 1) Repository Bootstrap
Create initial project scaffold:

- `pyproject.toml` with package metadata and tooling.
- `src/pysecret/` package layout.
- `tests/` for unit/integration tests.
- `README.md`, `SECURITY.md`, `CHANGELOG.md`.

Dependencies:

- Runtime: `cryptography`, `keyring`, `typer`, `httpx`, `platformdirs`, `pydantic` (or dataclasses only if minimizing deps), `rich` (optional CLI output).
- Dev: `pytest`, `pytest-cov`, `pytest-mock`, `respx` (HTTP mocking), `mypy`, `ruff`.

## 2) Core Architecture
Implement layered design:

1. `ProviderRegistry`: alias normalization + provider metadata.
2. `SecretManager`: high-level API used by CLI and library consumers.
3. `StorageBackends`:
- `OSKeyringBackend` (primary).
- `EncryptedSQLiteBackend` (fallback).
4. `CryptoEngine`: PBKDF2-SHA256 + AES-256-GCM encryption/decryption.
5. `SessionKeyCache`: in-memory derived-key cache with timeout.
6. `ValidationClient`: provider-specific `/models` endpoint checks.
7. `SecretString`: controlled reveal + wipe hooks.

Backend selection rules:

1. Try OS keyring first.
2. If unavailable/error, auto-fallback to encrypted SQLite.
3. Optional CLI/API flag to force fallback for portability testing.

## 3) Data Model and Storage
SQLite fallback schema (`state_dir/pysecret/secrets.db`):

- `secrets(provider TEXT PRIMARY KEY, ciphertext BLOB, nonce BLOB, aad BLOB, created_at TEXT, updated_at TEXT, expires_at TEXT NULL, version INTEGER)`
- `meta(key TEXT PRIMARY KEY, value TEXT)` for KDF params and verifier info.

Required `meta` keys:

- `kdf_salt` (base64)
- `kdf_iterations` (integer; default 310000+)
- `kdf_hash` (`sha256`)
- `verifier_ciphertext`, `verifier_nonce` (encrypted sentinel for password verification)
- `schema_version`

Non-secret config path (`state_dir/pysecret/config.toml`):

- default unlock timeout, preferred backend, and migration flags.
- no plaintext secret material ever stored.

## 4) Crypto and Password Flow
On first fallback use:

1. Prompt for master password + confirmation (`getpass`).
2. Generate installation salt.
3. Derive 32-byte key via PBKDF2-HMAC-SHA256.
4. Encrypt sentinel value to store verifier.
5. Cache derived key in memory with timeout (default 15 minutes).

On unlock:

1. Prompt once when cache expired.
2. Re-derive key and verify sentinel.
3. Reject on failure with bounded retry policy.

Encryption details:

- AES-256-GCM with unique random 96-bit nonce per secret.
- AAD includes provider name + schema version to bind context.
- Rotate nonce every write.
- Reject decrypt on auth failure.

## 5) Public API (Initial Contract)
Expose from `pysecret`:

- `set(provider: str, secret: str | SecretString, ttl_seconds: int | None = None, backend: Literal["auto","keyring","fallback"]="auto") -> None`
- `get(provider: str, as_plaintext: bool = False, inject_env: bool = False) -> SecretString | str`
- `list_providers(masked: bool = True, include_expired: bool = False) -> list[SecretRecordSummary]`
- `delete(provider: str) -> bool`
- `check(provider: str | None = None, timeout_seconds: float = 8.0) -> list[ProviderCheckResult]`
- `wipe() -> None` (clears session cache and internal mutable buffers)

Types:

- `SecretString`: `reveal()`, `masked()`, `wipe()`, `__str__` returns masked representation.
- `SecretRecordSummary`: provider, masked preview, backend, expires_at, is_expired.
- `ProviderCheckResult`: provider, ok, status_code, latency_ms, error.

Default behavior decisions:

- `get()` returns `SecretString` by default.
- Plain string requires `as_plaintext=True`.
- `inject_env=True` sets provider’s env var and returns `SecretString`.

## 6) CLI Specification (Typer)
Commands:

- `pysecret set <provider> [--ttl 3600] [--backend auto|keyring|fallback]`
- `pysecret get <provider> [--plain] [--inject-env]`
- `pysecret list [--show-expired]`
- `pysecret delete <provider>`
- `pysecret check [provider] [--timeout 8]`
- `pysecret wipe`
- `pysecret providers` (show aliases + env var mapping)

CLI behaviors:

- All secret entry via masked prompt (`getpass`).
- No command echoes plaintext secret.
- Mask output as prefix+suffix only (e.g., `sk-****...abcd`).
- Expired secrets are excluded by default and treated as unavailable.

## 7) Provider Registry + Validation
Initial built-ins:

- `openai` -> env `OPENAI_API_KEY`
- `anthropic` -> env `ANTHROPIC_API_KEY`
- `gemini` -> env `GEMINI_API_KEY`
- `mistral` -> env `MISTRAL_API_KEY`

Validation adapters (`check`):

- OpenAI: `GET /v1/models`
- Anthropic: `GET /v1/models` with required headers
- Gemini: model-list endpoint with API key query/header as required
- Mistral: `GET /v1/models`

Implementation detail:

- Use provider adapter objects that define endpoint, headers, auth placement, and success status rules.
- Network failures and 401/403 should return structured failures, not crash CLI.

## 8) TTL and Expiration Semantics
TTL stored as absolute UTC `expires_at`.

Rules:

1. `get()` on expired secret behaves as missing.
2. `list()` marks expiration state.
3. `check()` skips expired entries unless explicitly requested.
4. Optional eager cleanup path removes expired secrets on write/list/check.
5. TTL applies regardless of backend.

## 9) Security Controls
Implement and document:

- Zero-persistence guarantee: no plaintext writes.
- Best-effort memory hygiene:
- Handle secrets as `bytearray` internally where feasible.
- Overwrite mutable buffers on `wipe()` and object finalization hooks.
- Explicit caveat: Python runtime cannot guarantee complete immutable string erasure.
- Audit-safe logging:
- Never log secret bytes, full masked values, or raw headers.
- Structured errors without secret leakage.
- File permissions:
- Ensure state dir/file mode restricted to user where supported.

## 10) Testing Plan
Unit tests:

1. Crypto roundtrip success/failure (tamper nonce/ciphertext/AAD).
2. KDF and verifier logic (valid/invalid password).
3. Provider alias normalization and env mapping.
4. TTL transitions and expiration enforcement.
5. Masking behavior and `SecretString` leakage safeguards.

Backend tests:

1. Keyring backend happy-path + failure fallback.
2. Encrypted SQLite CRUD + migration version checks.
3. Session key timeout and re-prompt conditions.

CLI tests:

1. `set` uses hidden input path (mocked getpass).
2. `list` never prints full secrets.
3. `check` returns per-provider statuses on mixed pass/fail.
4. `wipe` clears cache and invalidates unlocked state.

Integration tests:

1. End-to-end fallback mode with temp state dir.
2. Multi-provider storage/read/check/delete flows.
3. Expired secrets are inaccessible and reported correctly.

## 11) Milestones
1. Milestone A: project scaffold, types, provider registry, API skeleton.
2. Milestone B: crypto engine + encrypted SQLite + master password flow.
3. Milestone C: keyring backend + backend selection orchestration.
4. Milestone D: Typer CLI commands + masking + TTL UX.
5. Milestone E: live `check` adapters + error normalization.
6. Milestone F: test hardening, docs, release candidate.

## 12) Out of Scope for v1
- Direct SDK wrappers/adapters for OpenAI/Anthropic clients.
- Desktop GUI masked viewer.
- Cloud sync / multi-device secret replication.
- Hardware-backed key providers (future enhancement).

## Assumptions and Defaults Chosen
1. Fallback store is encrypted SQLite (not JSON).
2. CLI framework is Typer.
3. `pysecret check` performs live network validation by default.
4. API default return is `SecretString`; plaintext is explicit opt-in.
5. Minimum Python version is 3.10.
6. Initial deliverable is CLI + core API only.
7. Master-password unlock uses session cache with timeout (default 15 min).
8. If OS keyring is unavailable, fallback auto-activates without blocking user.
