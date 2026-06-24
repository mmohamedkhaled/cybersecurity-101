"""RSA digital signatures on small integer messages.

Demonstrates RSA key generation, signing, and verification plus enumeration of
valid public exponents e (coprime to phi(n)) for a given pair of primes. The
modular inverse helper raises a clear error when no inverse exists.
"""

import math

MIN_PRIME = 2

RSA_P = 61
RSA_Q = 53
RSA_E = 17


PublicKey = tuple[int, int]
PrivateKey = tuple[int, int]


def valid_e_values(p: int, q: int) -> list[int]:
    """Return every public exponent e in [2, phi(n) - 1] coprime to phi(n).

    Args:
        p: First prime factor.
        q: Second prime factor.

    Returns:
        A sorted list of valid public exponents.

    Raises:
        ValueError: If p or q < 2.
    """
    if p < MIN_PRIME:
        raise ValueError(f"p must be >= {MIN_PRIME}, got {p}")
    if q < MIN_PRIME:
        raise ValueError(f"q must be >= {MIN_PRIME}, got {q}")
    phi = (p - 1) * (q - 1)
    return [e for e in range(2, phi) if math.gcd(e, phi) == 1]


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


def run_tests() -> None:
    pub, priv = generate_rsa_keys()
    assert pub == (17, 3233)
    assert priv[1] == 3233

    for message in (0, 1, 42, 100, 3232):
        signature = rsa_sign(message, priv)
        assert rsa_verify(signature, pub) == message

    signature_42 = rsa_sign(42, priv)
    assert rsa_verify(rsa_sign(42, priv), pub) == 42
    assert rsa_verify(signature_42, pub) == rsa_verify(rsa_sign(42, priv), pub)

    es = valid_e_values(61, 53)
    assert len(es) > 0
    phi = (61 - 1) * (53 - 1)
    for e in es:
        assert math.gcd(e, phi) == 1
    assert 17 in es

    assert modinv(17, 3120) == 2753
    assert (17 * modinv(17, 3120)) % 3120 == 1
    try:
        modinv(2, 4)
        raise AssertionError("modinv should reject non-coprime input")
    except ValueError:
        pass

    try:
        rsa_sign(3233, priv)
        raise AssertionError("rsa_sign should reject message >= n")
    except ValueError:
        pass

    print("All RSA digital-signature tests passed.")


if __name__ == "__main__":
    message = 42
    public_key, private_key = generate_rsa_keys()
    signature = rsa_sign(message, private_key)
    recovered = rsa_verify(signature, public_key)

    print(f"Message: {message}")
    print(f"Signature: {signature}")
    print(f"Recovered message: {recovered}")

    es = valid_e_values(RSA_P, RSA_Q)
    print(f"Valid e values for p={RSA_P}, q={RSA_Q} (phi(n) = {(RSA_P - 1) * (RSA_Q - 1)}):")
    print(es)
    print()
    run_tests()
