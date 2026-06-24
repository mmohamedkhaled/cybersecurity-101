"""Reduce a base raised to an exponent modulo n.

Implements modular exponentiation via step-by-step iteration so the running
product is reduced after every multiplication, mirroring the textbook method
used to introduce modular reduction.
"""

DEFAULT_BASE = 5
DEFAULT_EXPONENT = 17
DEFAULT_MODULUS = 16


def modular_exponentiation(base: int, exponent: int, modulus: int) -> int:
    """Return ``(base ** exponent) mod modulus`` computed iteratively.

    Args:
        base: The base integer.
        exponent: Non-negative integer exponent.
        modulus: Positive modulus.

    Returns:
        ``base`` raised to ``exponent`` reduced modulo ``modulus``.

    Raises:
        ValueError: If ``modulus`` is not positive or ``exponent`` is negative.
    """
    if modulus <= 0:
        raise ValueError("Modulus must be a positive integer.")
    if exponent < 0:
        raise ValueError("Exponent must be non-negative.")
    result = 1 % modulus
    for _ in range(exponent):
        result = (result * base) % modulus
    return result


def run_tests() -> None:
    """Run assertions covering standard and edge cases for modular reduction."""
    assert modular_exponentiation(5, 17, 16) == 5
    assert modular_exponentiation(5, 17, 16) == pow(5, 17, 16)
    assert modular_exponentiation(2, 10, 1000) == 24
    assert modular_exponentiation(7, 0, 13) == 1
    assert modular_exponentiation(0, 5, 13) == 0
    assert modular_exponentiation(3, 1, 1) == 0
    assert modular_exponentiation(3, 0, 1) == 0
    assert modular_exponentiation(7, 0, 1) == pow(7, 0, 1)
    for base, exponent, modulus in ((5, 17, 0), (5, -1, 16)):
        try:
            modular_exponentiation(base, exponent, modulus)
            raise AssertionError("Expected ValueError")
        except ValueError:
            pass
    print("All modulo reduction tests passed.")


if __name__ == "__main__":
    result = modular_exponentiation(DEFAULT_BASE, DEFAULT_EXPONENT, DEFAULT_MODULUS)
    print(
        f"Final Result: {DEFAULT_BASE}^{DEFAULT_EXPONENT} mod {DEFAULT_MODULUS} = {result}"
    )
    run_tests()
