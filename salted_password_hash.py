"""Hash passwords with a per-user random salt.

A fresh 16-byte salt is generated per password so that identical passwords hash
to different values, defeating rainbow-table and duplicate-detection attacks.
The salt is returned in hex alongside the SHA-256 hex digest for storage.
"""

import hashlib
import hmac
import os

SALT_BYTES = 16
SALT_HEX_LENGTH = 32
HASH_HEX_LENGTH = 64


def hash_password(password: str) -> tuple[str, str]:
    """Hash ``password`` with a fresh random salt.

    Args:
        password: The plaintext password to hash.

    Returns:
        A ``(salt_hex, hash_hex)`` tuple where ``salt_hex`` is the 32-character
        hex salt and ``hash_hex`` is the 64-character hex SHA-256 digest.

    Raises:
        ValueError: If ``password`` is not a ``str``.
    """
    if not isinstance(password, str):
        raise ValueError("password must be a str")
    salt = os.urandom(SALT_BYTES)
    hash_val = hashlib.sha256(salt + password.encode("utf-8")).hexdigest()
    return salt.hex(), hash_val


def verify_password(stored_salt_hex: str, stored_hash: str, password: str) -> bool:
    """Recompute the salted hash and compare it to ``stored_hash``.

    Args:
        stored_salt_hex: The 32-character hex salt stored alongside the hash.
        stored_hash: The 64-character hex SHA-256 digest to match against.
        password: The plaintext password to verify.

    Returns:
        ``True`` if ``password`` matches ``stored_hash``, else ``False``.

    Raises:
        ValueError: If ``stored_salt_hex`` or ``stored_hash`` have invalid
            lengths/types, or if ``password`` is not a ``str``.
    """
    if not isinstance(stored_salt_hex, str) or len(stored_salt_hex) != SALT_HEX_LENGTH:
        raise ValueError("stored_salt_hex must be a 32-char hex string")
    if not isinstance(stored_hash, str) or len(stored_hash) != HASH_HEX_LENGTH:
        raise ValueError("stored_hash must be a 64-char hex string")
    if not isinstance(password, str):
        raise ValueError("password must be a str")
    recomputed = hashlib.sha256(
        bytes.fromhex(stored_salt_hex) + password.encode("utf-8")
    ).hexdigest()
    return hmac.compare_digest(recomputed, stored_hash)


def run_tests() -> None:
    password = "MySecurePass123"
    salt_hex, hash_hex = hash_password(password)
    assert len(salt_hex) == SALT_HEX_LENGTH
    assert len(hash_hex) == HASH_HEX_LENGTH

    recomputed = hashlib.sha256(
        bytes.fromhex(salt_hex) + password.encode("utf-8")
    ).hexdigest()
    assert recomputed == hash_hex
    assert verify_password(salt_hex, hash_hex, password) is True
    assert verify_password(salt_hex, hash_hex, "wrong-password") is False

    salt_hex_2, hash_hex_2 = hash_password(password)
    assert salt_hex_2 != salt_hex
    assert hash_hex_2 != hash_hex
    assert verify_password(salt_hex_2, hash_hex_2, password) is True

    try:
        hash_password(123)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError for non-str password")

    print("All password-hashing tests passed.")


if __name__ == "__main__":
    user_password = "MySecurePass123"
    salt, hashed_pw = hash_password(user_password)
    print("Salt (hex):", salt)
    print("Hashed Password:", hashed_pw)
    print("Verified:", verify_password(salt, hashed_pw, user_password))
    run_tests()
