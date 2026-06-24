"""Check whether two integers are congruent modulo n.

Two integers ``a`` and ``b`` are congruent modulo ``n`` when they share the
same remainder upon division by ``n``; this module validates the modulus and
reports that relationship as a boolean.
"""

DEFAULT_A = 100
DEFAULT_B = 34
DEFAULT_MODULUS = 11


def are_congruent(a: int, b: int, n: int) -> bool:
    """Return whether ``a`` and ``b`` are congruent modulo ``n``.

    Args:
        a: First integer.
        b: Second integer.
        n: Positive modulus.

    Returns:
        ``True`` if ``a % n == b % n`` else ``False``.

    Raises:
        ValueError: If ``n`` is not a positive modulus.
    """
    if n <= 0:
        raise ValueError("Modulus n must be a positive integer.")
    return a % n == b % n


def run_tests() -> None:
    """Run assertions covering standard and edge cases for congruence checks."""
    assert are_congruent(100, 34, 11) is True
    assert are_congruent(100, 35, 11) is False
    assert are_congruent(10, 10, 7) is True
    assert are_congruent(0, 14, 7) is True
    assert are_congruent(1, 2, 7) is False
    for bad_n in (0, -3):
        try:
            are_congruent(1, 2, bad_n)
            raise AssertionError("Expected ValueError")
        except ValueError:
            pass
    print("All congruence tests passed.")


if __name__ == "__main__":
    print(
        f"{DEFAULT_A} ≈ {DEFAULT_B} mod {DEFAULT_MODULUS}? "
        f"{are_congruent(DEFAULT_A, DEFAULT_B, DEFAULT_MODULUS)}"
    )
    run_tests()
