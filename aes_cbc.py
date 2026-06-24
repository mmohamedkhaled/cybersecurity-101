"""AES-CBC encryption and decryption round trip using pycryptodome.

Generates a random 128-bit key and IV, encrypts a sample message with AES in
CBC mode, and decrypts the ciphertext back to verify correctness. Requires the
``pycryptodome`` package (imported as ``Crypto``).
"""

import base64

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
    PYCRYPTODOME_AVAILABLE = True
except ImportError:
    PYCRYPTODOME_AVAILABLE = False


KEY_SIZE = 16
IV_SIZE = 16


def cbc_encrypt(plaintext: str, key: bytes, iv: bytes) -> bytes:
    """Encrypt ``plaintext`` with AES-CBC using PKCS#7 padding.

    Args:
        plaintext: The UTF-8 message to encrypt.
        key: The AES key (16, 24, or 32 bytes).
        iv: The initialization vector (``AES.block_size`` bytes).

    Returns:
        The raw ciphertext bytes.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext.encode(), AES.block_size))


def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    """Decrypt AES-CBC ciphertext and strip PKCS#7 padding.

    Args:
        ciphertext: The raw ciphertext bytes produced by ``cbc_encrypt``.
        key: The AES key used for encryption.
        iv: The initialization vector used for encryption.

    Returns:
        The recovered plaintext string.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


def run_tests() -> None:
    """Verify the AES-CBC encrypt/decrypt round trip."""
    try:
        from Crypto.Random import get_random_bytes

        key = get_random_bytes(KEY_SIZE)
        iv = get_random_bytes(IV_SIZE)
        message = "Hello, this is a secret message!"
        ciphertext = cbc_encrypt(message, key, iv)
        assert cbc_decrypt(ciphertext, key, iv) == message, "round trip failed"
        assert len(ciphertext) % AES.block_size == 0, "ciphertext not block aligned"
        print("All AES-CBC round-trip tests passed.")
    except ImportError:
        print("AES-CBC tests skipped (missing dependency: pycryptodome).")


if __name__ == "__main__":
    if PYCRYPTODOME_AVAILABLE:
        key = get_random_bytes(KEY_SIZE)
        iv = get_random_bytes(IV_SIZE)
        plaintext = "Hello, this is a secret message!"
        ciphertext = cbc_encrypt(plaintext, key, iv)
        decrypted = cbc_decrypt(ciphertext, key, iv)
        print(f"Secret Key (Base64): {base64.b64encode(key).decode()}")
        print(f"IV (Base64): {base64.b64encode(iv).decode()}")
        print(f"Original Plaintext: {plaintext}")
        print(f"Encrypted (Base64): {base64.b64encode(ciphertext).decode()}")
        print(f"Decrypted Plaintext: {decrypted}")
    else:
        print("Demo skipped (missing dependency: pycryptodome).")
    run_tests()
