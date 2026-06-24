"""Compute the remainder of integer division.

This module provides a small helper that wraps Python's modulo operator with
input validation, raising a clear error when the divisor is zero.
"""

DEFAULT_DIVIDEND = 10
DEFAULT_DIVISOR = 3


def modulo(dividend: int, divisor: int) -> int:
    """Return the remainder of ``dividend`` divided by ``divisor``.

    Args:
        dividend: The integer being divided.
        divisor: The integer to divide by.

    Returns:
        The remainder ``dividend % divisor``.

    Raises:
        ValueError: If ``divisor`` is zero.
    """
    if divisor == 0:
        raise ValueError("Divisor must be non-zero; cannot compute modulo by zero.")
    return dividend % divisor


def run_tests() -> None:
    """Run assertions covering standard and edge cases for ``modulo``."""
    assert modulo(10, 3) == 1
    assert modulo(7, 7) == 0
    assert modulo(0, 5) == 0
    assert modulo(-1, 5) == 4
    try:
        modulo(10, 0)
        raise AssertionError("Expected ValueError for zero divisor")
    except ValueError:
        pass
    print("All modulo operation tests passed.")


if __name__ == "__main__":
    result = modulo(DEFAULT_DIVIDEND, DEFAULT_DIVISOR)
    print(f"The modulo of {DEFAULT_DIVIDEND} and {DEFAULT_DIVISOR} is: {result}")
    run_tests()
