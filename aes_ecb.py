"""AES-ECB encryption and decryption round trip using pycryptodome.

Uses AES in ECB mode to encrypt a short message and decrypt it back,
demonstrating the (insecure) ECB round trip. Requires the ``pycryptodome``
package (imported as ``Crypto``).
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


def ecb_encrypt(plaintext: str, key: bytes) -> bytes:
    """Encrypt ``plaintext`` with AES-ECB and PKCS#7 padding.

    Args:
        plaintext: The UTF-8 message to encrypt.
        key: The AES key (16, 24, or 32 bytes).

    Returns:
        The raw ciphertext bytes.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext.encode(), AES.block_size))


def ecb_decrypt(ciphertext: bytes, key: bytes) -> str:
    """Decrypt AES-ECB ciphertext and strip PKCS#7 padding.

    Args:
        ciphertext: The raw ciphertext bytes produced by ``ecb_encrypt``.
        key: The AES key used for encryption.

    Returns:
        The recovered plaintext string.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


def run_tests() -> None:
    """Verify the AES-ECB encrypt/decrypt round trip."""
    try:
        from Crypto.Random import get_random_bytes

        key = get_random_bytes(KEY_SIZE)
        message = "VIP"
        ciphertext = ecb_encrypt(message, key)
        assert ecb_decrypt(ciphertext, key) == message, "round trip failed"
        assert len(ciphertext) % AES.block_size == 0, "ciphertext not block aligned"
        print("All AES-ECB round-trip tests passed.")
    except ImportError:
        print("AES-ECB tests skipped (missing dependency: pycryptodome).")


if __name__ == "__main__":
    if PYCRYPTODOME_AVAILABLE:
        key = get_random_bytes(KEY_SIZE)
        plaintext = "VIP"
        ciphertext = ecb_encrypt(plaintext, key)
        decrypted = ecb_decrypt(ciphertext, key)
        print(f"Original Plaintext: {plaintext}")
        print(f"Encrypted (Base64): {base64.b64encode(ciphertext).decode()}")
        print(f"Decrypted Plaintext: {decrypted}")
    else:
        print("Demo skipped (missing dependency: pycryptodome).")
    run_tests()
