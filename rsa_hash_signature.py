"""Hash-then-sign with RSA over a SHA-256 digest.

Signs a SHA-256 hash of a text message with an RSA private key and verifies
such signatures with the matching public key. The hash is reduced modulo n so
that signing-then-verifying round-trips correctly while remaining trivially
falsifiable if the message is tampered with.
"""

import hashlib

RSA_P = 61
RSA_Q = 53
RSA_E = 17

PublicKey = tuple[int, int]
PrivateKey = tuple[int, int]


def modinv(a: int, m: int) -> int:
    """Return the modular inverse of a modulo m via the extended Euclidean algorithm.

    Args:
        a: The value whose inverse is sought.
        m: The modulus.

    Returns:
        An integer x with (a * x) % m == 1.

    Raises:
        ValueError: If m < 1 or a has no inverse modulo m (gcd(a, m) != 1).
    """
    if m < 1:
        raise ValueError(f"modulus must be >= 1, got {m}")
    original_m = m
    current_a = a % m
    prev_x, curr_x = 0, 1
    while current_a > 1:
        if m == 0:
            raise ValueError(f"{a} has no inverse modulo {original_m}")
        quotient = current_a // m
        current_a, m = m, current_a % m
        prev_x, curr_x = curr_x - quotient * prev_x, prev_x
    if current_a != 1:
        raise ValueError(f"{a} has no inverse modulo {original_m}")
    return curr_x % original_m


def generate_rsa_keys() -> tuple[PublicKey, PrivateKey]:
    """Generate a fixed RSA key pair for the demo primes and public exponent.

    Returns:
        A tuple (public_key, private_key) where each key is an (exp, n) pair.
    """
    n = RSA_P * RSA_Q
    phi = (RSA_P - 1) * (RSA_Q - 1)
    d = modinv(RSA_E, phi)
    return (RSA_E, n), (d, n)


def sha256_hash(message: str) -> int:
    """Return the integer value of the SHA-256 digest of message.

    Args:
        message: The UTF-8 text to hash.

    Returns:
        The SHA-256 digest interpreted as a big-endian integer.
    """
    return int(hashlib.sha256(message.encode("utf-8")).hexdigest(), 16)


def rsa_sign(message: int, priv_key: PrivateKey) -> int:
    """Sign an integer message with an RSA private key.

    Args:
        message: The integer to sign; must satisfy 0 <= message < n.
        priv_key: The private key as an (d, n) pair.

    Returns:
        The RSA signature pow(message, d, n).

    Raises:
        ValueError: If message is not in [0, n).
    """
    d, n = priv_key
    if not (0 <= message < n):
        raise ValueError(f"message must be in [0, {n}), got {message}")
    return pow(message, d, n)


def rsa_verify(signature: int, pub_key: PublicKey) -> int:
    """Recover the signed message from a signature with the RSA public key.

    Args:
        signature: The integer signature to verify.
        pub_key: The public key as an (e, n) pair.

    Returns:
        The recovered message pow(signature, e, n).
    """
    e, n = pub_key
    return pow(signature, e, n)


def sign_with_hash(message: str, priv_key: PrivateKey) -> int:
    """Hash message, reduce the digest mod n, and sign it with the private key.

    Args:
        message: The text to sign.
        priv_key: The private key as an (d, n) pair.

    Returns:
        The RSA signature of the reduced SHA-256 digest.
    """
    _, n = priv_key
    digest = sha256_hash(message) % n
    return rsa_sign(digest, priv_key)


def verify_with_hash(message: str, signature: int, pub_key: PublicKey) -> bool:
    """Verify an RSA signature over the SHA-256 digest of message.

    Args:
        message: The text whose signature is being checked.
        signature: The integer signature to verify.
        pub_key: The public key as an (e, n) pair.

    Returns:
        True iff the signature matches the digest of message.
    """
    _, n = pub_key
    digest = sha256_hash(message) % n
    return rsa_verify(signature, pub_key) == digest


def run_tests() -> None:
    pub, priv = generate_rsa_keys()
    assert pub == (17, 3233)

    message = "Hello Alice"
    signature = sign_with_hash(message, priv)
    assert verify_with_hash(message, signature, pub) is True

    tampered = "Hello Bob"
    assert verify_with_hash(tampered, signature, pub) is False

    signature_b = sign_with_hash(tampered, priv)
    assert verify_with_hash(tampered, signature_b, pub) is True
    assert verify_with_hash(message, signature_b, pub) is False

    assert verify_with_hash("Hello Alice", sign_with_hash("Hello Alice", priv), pub) is True

    assert (RSA_E * modinv(RSA_E, (RSA_P - 1) * (RSA_Q - 1))) % (
        (RSA_P - 1) * (RSA_Q - 1)
    ) == 1
    try:
        modinv(2, 4)
        raise AssertionError("modinv should reject non-coprime input")
    except ValueError:
        pass

    print("All hash-with-digital-signature tests passed.")


if __name__ == "__main__":
    msg = "Hello Alice"
    public_key, private_key = generate_rsa_keys()
    signature = sign_with_hash(msg, private_key)
    valid = verify_with_hash(msg, signature, public_key)
    print(f"Signature valid: {valid}")
    print()
    run_tests()
