"""Compute Euler's totient function phi(n).

Euler's totient ``phi(n)`` counts the positive integers up to ``n`` that are
coprime to ``n``; this module returns both the count and the list of those
coprime integers so callers can inspect or test the result.
"""

import math


def phi(n: int) -> tuple[int, list[int]]:
    """Return Euler's totient of ``n`` and the list of coprime integers.

    Args:
        n: A positive integer (``n >= 1``).

    Returns:
        A tuple ``(count, elements)`` where ``count`` equals ``phi(n)`` and
        ``elements`` lists the integers in ``[1, n]`` coprime to ``n``.

    Raises:
        ValueError: If ``n`` is less than 1.
    """
    if n < 1:
        raise ValueError("n must be a positive integer (n >= 1).")
    if n == 1:
        return 1, [1]
    coprime_elements = [i for i in range(1, n) if math.gcd(n, i) == 1]
    return len(coprime_elements), coprime_elements


def run_tests() -> None:
    """Run assertions covering standard and edge cases for Euler's totient."""
    assert phi(9) == (6, [1, 2, 4, 5, 7, 8])
    assert phi(1) == (1, [1])
    assert phi(7) == (6, [1, 2, 3, 4, 5, 6])
    assert phi(12) == (4, [1, 5, 7, 11])
    assert phi(2) == (1, [1])
    for bad_n in (0, -5):
        try:
            phi(bad_n)
            raise AssertionError("Expected ValueError")
        except ValueError:
            pass
    print("All Euler totient (phi) tests passed.")


if __name__ == "__main__":
    demo_n = 9
    totient, elements = phi(demo_n)
    print(f"phi({demo_n}) = {totient}")
    print(f"The elements that are relatively prime to {demo_n} are: {elements}")
    run_tests()
