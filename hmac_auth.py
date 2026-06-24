"""Generate and verify HMAC-SHA256 message authentication codes.

A MAC proves both the integrity and the authenticity of a message by mixing a
shared secret key into the hash. Verification uses :func:`hmac.compare_digest`
to avoid timing side-channels.
"""

import hashlib
import hmac

HASH_ALGORITHM = hashlib.sha256


def generate_mac(secret_key: bytes, message: bytes) -> str:
    """Return the hex HMAC-SHA256 of ``message`` under ``secret_key``.

    Args:
        secret_key: The shared secret as raw bytes.
        message: The message to authenticate as raw bytes.

    Returns:
        The lowercase hexadecimal HMAC digest.

    Raises:
        ValueError: If ``secret_key`` or ``message`` is not ``bytes``.
    """
    if not isinstance(secret_key, bytes):
        raise ValueError("secret_key must be bytes")
    if not isinstance(message, bytes):
        raise ValueError("message must be bytes")
    return hmac.new(secret_key, message, HASH_ALGORITHM).hexdigest()


def verify_mac(secret_key: bytes, message: bytes, received_mac: str) -> bool:
    """Constant-time check that ``received_mac`` matches the real MAC.

    Args:
        secret_key: The shared secret as raw bytes.
        message: The message to authenticate as raw bytes.
        received_mac: The hex MAC claimed by the sender.

    Returns:
        ``True`` if the MAC is valid, ``False`` otherwise.

    Raises:
        ValueError: If any argument has an invalid type.
    """
    if not isinstance(secret_key, bytes):
        raise ValueError("secret_key must be bytes")
    if not isinstance(message, bytes):
        raise ValueError("message must be bytes")
    if not isinstance(received_mac, str):
        raise ValueError("received_mac must be str")
    computed_mac = hmac.new(secret_key, message, HASH_ALGORITHM).hexdigest()
    return hmac.compare_digest(computed_mac, received_mac)


def run_tests() -> None:
    secret_key = b"supersecretkey"
    message = b"Hello, this is a secure message."
    tampered_message = b"Hello, this is a secure text."
    wrong_key = b"supersecretkeyyf"

    mac = generate_mac(secret_key, message)
    assert verify_mac(secret_key, message, mac) is True
    assert verify_mac(wrong_key, message, mac) is False
    assert verify_mac(secret_key, tampered_message, mac) is False
    assert len(mac) == 64
    assert generate_mac(secret_key, message) == mac

    try:
        generate_mac("not-bytes", message)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError for non-bytes key")

    print("All MAC tests passed.")


if __name__ == "__main__":
    demo_key = b"supersecretkey"
    demo_message = b"Hello, this is a secure message."
    demo_mac = generate_mac(demo_key, demo_message)
    print(f"Generated HMAC: {demo_mac}")
    print(verify_mac(demo_key, demo_message, demo_mac))
    run_tests()
