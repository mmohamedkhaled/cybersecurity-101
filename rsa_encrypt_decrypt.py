"""RSA public/private key encryption and decryption round-trip.

Generates a fresh 2048-bit RSA key pair and uses OAEP (with SHA-256) to encrypt
a message with the public key and recover it with the private key.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PUBLIC_EXPONENT = 65537
KEY_SIZE = 2048


def build_oaep_padding() -> padding.OAEP:
    """Return the OAEP padding object used for encryption and decryption.

    Returns:
        An :class:`OAEP` instance configured with MGF1 and SHA-256.
    """
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def generate_key_pair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a fresh RSA key pair.

    Returns:
        A ``(private_key, public_key)`` tuple.
    """
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT, key_size=KEY_SIZE
    )
    return private_key, private_key.public_key()


def encrypt_message(public_key: rsa.RSAPublicKey, message: bytes) -> bytes:
    """Encrypt ``message`` with ``public_key`` using OAEP+SHA-256.

    Args:
        public_key: The RSA public key to encrypt with.
        message: The plaintext bytes to encrypt.

    Returns:
        The ciphertext bytes.

    Raises:
        ValueError: If ``message`` is empty or too long for the key.
    """
    if not isinstance(message, bytes):
        raise ValueError("message must be bytes")
    if len(message) == 0:
        raise ValueError("message must not be empty")
    max_len = (KEY_SIZE // 8) - 2 * hashes.SHA256.digest_size - 2
    if len(message) > max_len:
        raise ValueError("message too long for the configured RSA key size")
    return public_key.encrypt(message, build_oaep_padding())


def decrypt_message(
    private_key: rsa.RSAPrivateKey, ciphertext: bytes
) -> bytes:
    """Decrypt ``ciphertext`` with ``private_key`` using OAEP+SHA-256.

    Args:
        private_key: The RSA private key to decrypt with.
        ciphertext: The ciphertext bytes produced by :func:`encrypt_message`.

    Returns:
        The recovered plaintext bytes.
    """
    return private_key.decrypt(ciphertext, build_oaep_padding())


def run_tests() -> None:
    private_key, public_key = generate_key_pair()
    message = b"May Allah help us all"
    ciphertext = encrypt_message(public_key, message)
    assert ciphertext != message
    plaintext = decrypt_message(private_key, ciphertext)
    assert plaintext == message

    try:
        encrypt_message(public_key, "")  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError for empty message")

    print("All RSA public/private key tests passed.")


if __name__ == "__main__":
    private_key, public_key = generate_key_pair()
    message = b"May Allah help us all"
    ciphertext = encrypt_message(public_key, message)
    plaintext = decrypt_message(private_key, ciphertext)
    print(plaintext)
    run_tests()
