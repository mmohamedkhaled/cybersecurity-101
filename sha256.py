"""Compute SHA-256 digests of strings.

Wraps :mod:`hashlib` to deterministically map an arbitrary Unicode string to
its 256-bit (64 hex-character) SHA-256 fingerprint, with input validation.
"""

import hashlib

HEX_DIGEST_LENGTH = 64


def sha256_digest(message: str) -> str:
    """Return the lowercase hex SHA-256 digest of ``message``.

    Args:
        message: The UTF-8 string to hash. Must not be ``None``.

    Returns:
        The 64-character lowercase hexadecimal SHA-256 digest.

    Raises:
        ValueError: If ``message`` is not a ``str``.
    """
    if not isinstance(message, str):
        raise ValueError("message must be a str")
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def run_tests() -> None:
    empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    abc_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_digest("") == empty_hash
    assert sha256_digest("abc") == abc_hash
    assert len(sha256_digest("Hello world!")) == HEX_DIGEST_LENGTH
    assert sha256_digest("same") == sha256_digest("same")
    assert sha256_digest("a") != sha256_digest("b")
    try:
        sha256_digest(123)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError for non-str input")
    print("All SHA-256 tests passed.")


if __name__ == "__main__":
    sample = "Hello world!"
    print("SHA-256 hash:", sha256_digest(sample))
    run_tests()
