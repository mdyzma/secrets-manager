# PySecret-AI

Local-first Python secrets manager for AI API keys.

## Features

- OS keyring as primary backend.
- AES-256-GCM encrypted SQLite fallback backend.
- Master-password unlock with session cache timeout.
- Typer CLI (`pysecret`) with masked input.
- Provider aliases for OpenAI, Anthropic, Gemini, and Mistral.
- TTL expiration support.
- Live provider validation (`check`) against models endpoints.

## Install

```bash
pip install -e .
```

## Quick Start

```bash
pysecret set openai
pysecret list
pysecret get openai --inject-env
pysecret check
```

```python
import pysecret

key = pysecret.get("openai")
```

## Security Notes

- Fallback storage never writes plaintext secrets to disk.
- In-memory wiping is best-effort due to Python runtime behavior.
