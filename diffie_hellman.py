"""Diffie-Hellman key exchange over a shared prime modulus.

Implements the textbook Diffie-Hellman protocol: two parties derive an identical
shared secret from a public prime p and generator a using their private
exponents, without ever transmitting those private values.
"""


MIN_MODULUS = 2

DEFAULT_PRIME = 29
DEFAULT_GENERATOR = 10
DEFAULT_ALICE_PRIVATE = 7
DEFAULT_BOB_PRIVATE = 4


def diffie_hellman(
    p: int, a: int, x: int, y: int
) -> tuple[int, int, int, int]:
    """Compute the public values and shared secret for a Diffie-Hellman exchange.

    Args:
        p: The public prime modulus.
        a: The public generator (base).
        x: Alice's private exponent.
        y: Bob's private exponent.

    Returns:
        A tuple (alice_public, bob_public, alice_secret, bob_secret) where both
        secret values are equal for a correctly executed exchange.

    Raises:
        ValueError: If p < 2, a is not in [1, p - 1], or a private exponent
            is less than 1.
    """
    if p < MIN_MODULUS:
        raise ValueError(f"prime modulus p must be >= {MIN_MODULUS}, got {p}")
    if not (1 <= a <= p - 1):
        raise ValueError(f"generator a must be in [1, {p - 1}], got {a}")
    if x < 1:
        raise ValueError(f"Alice's private exponent must be >= 1, got {x}")
    if y < 1:
        raise ValueError(f"Bob's private exponent must be >= 1, got {y}")

    alice_public = pow(a, x, p)
    bob_public = pow(a, y, p)
    alice_secret = pow(bob_public, x, p)
    bob_secret = pow(alice_public, y, p)
    return alice_public, bob_public, alice_secret, bob_secret


def run_tests() -> None:
    alice_pub, bob_pub, alice_key, bob_key = diffie_hellman(
        DEFAULT_PRIME, DEFAULT_GENERATOR, DEFAULT_ALICE_PRIVATE, DEFAULT_BOB_PRIVATE
    )
    assert alice_pub == 17
    assert bob_pub == 24
    assert alice_key == bob_key
    assert alice_key == 1

    other_pub_a, other_pub_b, other_ka, other_kb = diffie_hellman(23, 5, 6, 15)
    assert other_ka == other_kb
    assert pow(5, 6, 23) == other_pub_a
    assert pow(5, 15, 23) == other_pub_b

    try:
        diffie_hellman(1, 1, 1, 1)
        raise AssertionError("diffie_hellman should reject p < 2")
    except ValueError:
        pass

    try:
        diffie_hellman(23, 0, 4, 5)
        raise AssertionError("diffie_hellman should reject a < 1")
    except ValueError:
        pass

    try:
        diffie_hellman(23, 5, 0, 5)
        raise AssertionError("diffie_hellman should reject x < 1")
    except ValueError:
        pass

    print("All Diffie-Hellman tests passed.")


if __name__ == "__main__":
    alice_public, bob_public, key_alice, key_bob = diffie_hellman(
        DEFAULT_PRIME, DEFAULT_GENERATOR, DEFAULT_ALICE_PRIVATE, DEFAULT_BOB_PRIVATE
    )
    print(f"Alice sends X = {alice_public}")
    print(f"Bob sends Y = {bob_public}")
    print(f"Shared secret (Alice): {key_alice}")
    print(f"Shared secret (Bob): {key_bob}")
    print()
    run_tests()
