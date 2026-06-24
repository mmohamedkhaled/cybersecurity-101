"""Modular addition and multiplication.

Exposes validated helpers for performing addition and multiplication under a
fixed positive modulus, the building blocks of modular arithmetic used in many
cryptographic constructions.
"""

DEFAULT_A = 12
DEFAULT_B = 8
DEFAULT_MODULUS = 5


def modular_add(a: int, b: int, n: int) -> int:
    """Return ``(a + b) mod n``.

    Args:
        a: First addend.
        b: Second addend.
        n: Positive modulus.

    Returns:
        The sum of ``a`` and ``b`` reduced modulo ``n``.

    Raises:
        ValueError: If ``n`` is not a positive integer modulus.
    """
    if n <= 0:
        raise ValueError("Modulus n must be a positive integer.")
    return (a + b) % n


def modular_mul(a: int, b: int, n: int) -> int:
    """Return ``(a * b) mod n``.

    Args:
        a: First factor.
        b: Second factor.
        n: Positive modulus.

    Returns:
        The product of ``a`` and ``b`` reduced modulo ``n``.

    Raises:
        ValueError: If ``n`` is not a positive integer modulus.
    """
    if n <= 0:
        raise ValueError("Modulus n must be a positive integer.")
    return (a * b) % n


def run_tests() -> None:
    """Run assertions covering standard and edge cases for modular arithmetic."""
    assert modular_add(12, 8, 5) == 0
    assert modular_mul(12, 8, 5) == 1
    assert modular_add(2, 3, 5) == 0
    assert modular_mul(2, 3, 5) == 1
    assert modular_add(0, 0, 7) == 0
    assert modular_mul(0, 100, 7) == 0
    for bad_n in (0, -1):
        try:
            modular_add(1, 1, bad_n)
            raise AssertionError("Expected ValueError for modular_add")
        except ValueError:
            pass
        try:
            modular_mul(1, 1, bad_n)
            raise AssertionError("Expected ValueError for modular_mul")
        except ValueError:
            pass
    print("All modular arithmetic tests passed.")


if __name__ == "__main__":
    print(
        f"Modular Addition: {DEFAULT_A} + {DEFAULT_B} mod {DEFAULT_MODULUS} = "
        f"{modular_add(DEFAULT_A, DEFAULT_B, DEFAULT_MODULUS)}"
    )
    print(
        f"Modular Multiplication: {DEFAULT_A} * {DEFAULT_B} mod {DEFAULT_MODULUS} = "
        f"{modular_mul(DEFAULT_A, DEFAULT_B, DEFAULT_MODULUS)}"
    )
    run_tests()
