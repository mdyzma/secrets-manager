from __future__ import annotations

from pysecret.secret_string import SecretString


def test_secret_string_mask_and_wipe() -> None:
    secret = SecretString("sk-this-is-a-secret")

    assert str(secret).startswith("sk-t")
    assert secret.reveal() == "sk-this-is-a-secret"

    secret.wipe()
    assert secret.reveal() != "sk-this-is-a-secret"
