"""Compute the modular inverse via the extended Euclidean algorithm.

The extended Euclidean algorithm recovers the Bezout coefficients of two
integers; when they are coprime the coefficient of the input gives its
multiplicative inverse modulo the other, which is essential for RSA key
generation and other cryptographic schemes.
"""


def extended_euclidean_algorithm(
    a: int, m: int
) -> tuple[int | None, list[tuple[int, int, int, int, int, int, int]]]:
    """Return the modular inverse of ``a`` modulo ``m`` plus a step trace.

    Args:
        a: The integer whose inverse is sought (non-negative).
        m: The positive modulus.

    Returns:
        A tuple ``(inverse, steps)`` where ``inverse`` is the inverse of ``a``
        modulo ``m`` (or ``None`` when ``a`` and ``m`` are not coprime) and
        ``steps`` records each iteration as
        ``(q, r0, r1, s0, s1, t0, t1)``.

    Raises:
        ValueError: If ``m`` is not positive or ``a`` is negative.
    """
    if m <= 0:
        raise ValueError("Modulus m must be a positive integer.")
    if a < 0:
        raise ValueError("Input a must be a non-negative integer.")
    r0, r1 = m, a
    s0, s1 = 1, 0
    t0, t1 = 0, 1
    steps: list[tuple[int, int, int, int, int, int, int]] = []
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        s0, s1 = s1, s0 - q * s1
        t0, t1 = t1, t0 - q * t1
        steps.append((q, r0, r1, s0, s1, t0, t1))
    if r0 != 1:
        return None, steps
    inverse = t0 % m
    return inverse, steps


def run_tests() -> None:
    """Run assertions covering standard and edge cases for modular inverse."""
    inverse_19, _ = extended_euclidean_algorithm(19, 170)
    assert inverse_19 == 9
    assert (19 * inverse_19) % 170 == 1

    inverse_3, _ = extended_euclidean_algorithm(3, 11)
    assert inverse_3 == 4
    assert (3 * inverse_3) % 11 == 1

    inverse_none, _ = extended_euclidean_algorithm(2, 4)
    assert inverse_none is None

    inverse_1, _ = extended_euclidean_algorithm(1, 7)
    assert inverse_1 == 1

    for a_arg, m_arg in ((19, 0), (19, -5), (-1, 170)):
        try:
            extended_euclidean_algorithm(a_arg, m_arg)
            raise AssertionError("Expected ValueError")
        except ValueError:
            pass
    print("All modular inverse (extended Euclidean) tests passed.")


if __name__ == "__main__":
    demo_a, demo_m = 19, 170
    inverse, _ = extended_euclidean_algorithm(demo_a, demo_m)
    if inverse is not None:
        print(f"The modular inverse of {demo_a} mod {demo_m} is: {inverse}")
        print(f"Verification: ({demo_a} * {inverse}) % {demo_m} = {(demo_a * inverse) % demo_m}")
    else:
        print(f"{demo_a} has no modular inverse modulo {demo_m}")
    run_tests()
