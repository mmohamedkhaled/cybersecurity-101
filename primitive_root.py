"""Primitive-root utilities for modular arithmetic.

Provides helpers to test whether an integer admits primitive roots, to check if
a given value is a primitive root modulo n, and to enumerate every primitive
root of n. The primitive-root test uses Euler's totient together with the
prime-factorization of phi(n) so it is robust rather than purely brute force.
"""

import math

MIN_MODULUS = 2


def is_prime(n: int) -> bool:
    """Return True when n is a prime number.

    Args:
        n: An integer to test for primality.

    Returns:
        True if n is prime, False otherwise (including n < 2).
    """
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    for divisor in range(3, int(n ** 0.5) + 1, 2):
        if n % divisor == 0:
            return False
    return True


def phi(n: int) -> int:
    """Compute Euler's totient phi(n).

    Args:
        n: A positive integer (n >= 1).

    Returns:
        The count of integers in [1, n] that are coprime to n.

    Raises:
        ValueError: If n < 1.
    """
    if n < 1:
        raise ValueError(f"phi is defined for n >= 1, got {n}")
    result = n
    value = n
    candidate = MIN_MODULUS
    while candidate * candidate <= value:
        if value % candidate == 0:
            while value % candidate == 0:
                value //= candidate
            result -= result // candidate
        candidate += 1
    if value > 1:
        result -= result // value
    return result


def get_prime_factors(n: int) -> set[int]:
    """Return the set of distinct prime factors of n.

    Args:
        n: A positive integer (n >= 1).

    Returns:
        A set of the prime divisors of n (empty for n == 1).

    Raises:
        ValueError: If n < 1.
    """
    if n < 1:
        raise ValueError(f"prime factors are defined for n >= 1, got {n}")
    factors: set[int] = set()
    value = n
    candidate = MIN_MODULUS
    while candidate * candidate <= value:
        while value % candidate == 0:
            factors.add(candidate)
            value //= candidate
        candidate += 1
    if value > 1:
        factors.add(value)
    return factors


def has_primitive_root(n: int) -> bool:
    """Return True if the multiplicative group modulo n is cyclic.

    A positive integer has a primitive root iff it equals 1, 2, 4, p**k, or
    2 * p**k for an odd prime p and k >= 1.

    Args:
        n: An integer to test.

    Returns:
        True when n admits at least one primitive root, else False.
    """
    if n < 1:
        return False
    if n in (1, 2, 4):
        return True
    odd_part = n
    if odd_part % 2 == 0:
        odd_part //= 2
        if odd_part % 2 == 0:
            return False
    smallest = 3
    while smallest * smallest <= odd_part:
        if odd_part % smallest == 0:
            break
        smallest += 2
    else:
        smallest = odd_part
    if smallest < MIN_MODULUS:
        return False
    while odd_part % smallest == 0:
        odd_part //= smallest
    return odd_part == 1


def is_primitive_root(g: int, p: int) -> bool:
    """Return True if g is a primitive root modulo p.

    Uses the prime-factor test: g is a primitive root iff g**(phi(p)//q) != 1
    (mod p) for every prime divisor q of phi(p).

    Args:
        g: The candidate primitive root.
        p: The modulus.

    Returns:
        True when g generates every unit modulo p, else False.

    Raises:
        ValueError: If g < 1 or p < 1.
    """
    if g < 1:
        raise ValueError(f"g must be >= 1, got {g}")
    if p < 1:
        raise ValueError(f"p must be >= 1, got {p}")
    if not has_primitive_root(p):
        return False
    if math.gcd(g, p) != 1:
        return False
    phi_p = phi(p)
    for factor in get_prime_factors(phi_p):
        if pow(g, phi_p // factor, p) == 1:
            return False
    return True


def find_primitive_roots(n: int) -> list[int]:
    """Return every primitive root of n in ascending order.

    Args:
        n: The modulus.

    Returns:
        A list of primitive roots in [1, n); empty when none exist.

    Raises:
        ValueError: If n < 1.
    """
    if n < 1:
        raise ValueError(f"n must be >= 1, got {n}")
    if not has_primitive_root(n):
        return []
    return [g for g in range(1, n) if is_primitive_root(g, n)]


def check_primitive_root_verbose(g: int, p: int) -> None:
    """Print each power of g mod p and state whether g is a primitive root.

    Args:
        g: The candidate primitive root.
        p: The modulus.

    Raises:
        ValueError: If g < 1 or p < 2.
    """
    if g < 1:
        raise ValueError(f"g must be >= 1, got {g}")
    if p < MIN_MODULUS:
        raise ValueError(f"p must be >= {MIN_MODULUS}, got {p}")
    print(f"Is {g} a primitive root of {p}?")
    seen: set[int] = set()
    for exponent in range(1, p):
        value = pow(g, exponent, p)
        marker = "   <- duplicate result" if value in seen else ""
        print(f"{g}^{exponent} mod {p} = {value}{marker}")
        seen.add(value)
    if len(seen) == p - 1:
        print(f"\nAll {p - 1} values are distinct, so {g} IS a primitive root of {p}")
    else:
        print(f"\nValues are NOT distinct, so {g} is NOT a primitive root of {p}")


def run_tests() -> None:
    assert is_prime(2) is True
    assert is_prime(7) is True
    assert is_prime(17) is True
    assert is_prime(1) is False
    assert is_prime(0) is False
    assert is_prime(-5) is False
    assert is_prime(9) is False

    assert phi(1) == 1
    assert phi(7) == 6
    assert phi(9) == 6
    assert phi(12) == 4
    try:
        phi(0)
        raise AssertionError("phi(0) should raise")
    except ValueError:
        pass

    assert get_prime_factors(1) == set()
    assert get_prime_factors(7) == {7}
    assert get_prime_factors(12) == {2, 3}
    try:
        get_prime_factors(0)
        raise AssertionError("get_prime_factors(0) should raise")
    except ValueError:
        pass

    assert has_primitive_root(7) is True
    assert has_primitive_root(9) is True
    assert has_primitive_root(18) is True
    assert has_primitive_root(2) is True
    assert has_primitive_root(8) is False
    assert has_primitive_root(12) is False
    assert has_primitive_root(0) is False

    assert find_primitive_roots(7) == [3, 5]
    assert find_primitive_roots(2) == [1]
    assert find_primitive_roots(12) == []
    assert find_primitive_roots(1) == []
    try:
        find_primitive_roots(0)
        raise AssertionError("find_primitive_roots(0) should raise")
    except ValueError:
        pass

    assert is_primitive_root(3, 7) is True
    assert is_primitive_root(5, 7) is True
    assert is_primitive_root(1, 7) is False
    assert is_primitive_root(2, 7) is False
    assert find_primitive_roots(9) == [2, 5]
    assert find_primitive_roots(18) == [5, 11]
    assert is_primitive_root(2, 9) is True
    assert is_primitive_root(3, 9) is False
    assert is_primitive_root(6, 9) is False
    try:
        is_primitive_root(0, 7)
        raise AssertionError("is_primitive_root(0, 7) should raise")
    except ValueError:
        pass

    print("All primitive-root tests passed.")


if __name__ == "__main__":
    SAMPLE_MODULUS = 7
    print(f"Primitive roots of {SAMPLE_MODULUS}: {find_primitive_roots(SAMPLE_MODULUS)}")
    print()
    check_primitive_root_verbose(6, 17)
    print()
    run_tests()
