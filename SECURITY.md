# Security Policy

## Guarantees

- Plaintext secrets are not written to disk in fallback mode.
- Fallback encryption uses AES-256-GCM with random nonce per write.
- Key derivation uses PBKDF2-HMAC-SHA256 with install-specific salt.

## Limits

- Python cannot guarantee complete memory zeroization for immutable strings.
- OS keyring security depends on the host platform implementation.

## Reporting

Open a security issue privately with reproduction details and impact.
