"""Columnar transposition cipher implementation.

Encrypts a message by writing it row-wise into a grid whose column
count equals the length of a numeric key, padding the final row with
'X', then reading each column out in the order specified by the key.
"""

import math

PAD_CHAR = "X"
COL_SEPARATOR = " "


def columnar_transposition_encrypt(message: str, key: str) -> str:
    """Encrypt ``message`` using a columnar transposition cipher.

    Args:
        message: The plaintext to encrypt. Internal spaces are removed
            and all letters are upper-cased before being placed in the
            grid.
        key: Space-separated integers describing the read order of the
            columns, e.g. ``"2 1"`` reads column index 1 first and
            column index 0 second.

    Returns:
        The ciphertext as space-separated column strings, where each
        column appears in the order defined by sorting the key values.

    Raises:
        ValueError: If ``message`` is empty (or has no characters after
            removing spaces), or if ``key`` is empty, contains tokens
            that are not integers, or is not a permutation of 1..n.
    """
    cleaned = message.replace(" ", "").upper()
    if not cleaned:
        raise ValueError("message must contain at least one character")

    try:
        key_order: list[int] = [int(token) for token in key.split()]
    except ValueError as exc:
        raise ValueError("key must contain only space-separated integers") from exc
    if not key_order:
        raise ValueError("key must contain at least one column index")
    if sorted(key_order) != list(range(1, len(key_order) + 1)):
        raise ValueError(
            "key must be a permutation of 1..n (each column index used once)"
        )

    cols = len(key_order)
    rows = math.ceil(len(cleaned) / cols)
    padded_length = rows * cols
    cleaned += PAD_CHAR * (padded_length - len(cleaned))

    matrix: list[list[str]] = [
        [cleaned[r * cols + c] for c in range(cols)] for r in range(rows)
    ]

    order = sorted((num, idx) for idx, num in enumerate(key_order))
    parts: list[str] = []
    for _, idx in order:
        parts.append("".join(matrix[r][idx] for r in range(rows)))

    return COL_SEPARATOR.join(parts)


def run_tests() -> None:
    assert columnar_transposition_encrypt("ABCD", "2 1") == "BD AC"
    assert columnar_transposition_encrypt("a b c d", "2 1") == "BD AC"
    assert columnar_transposition_encrypt("ABCDE", "1 2") == "ACE BDX"

    result = columnar_transposition_encrypt("Comfortistheenemyofachievement", "7 5 3 2 1 4 6")
    assert all(ch.isupper() or ch == COL_SEPARATOR for ch in result)
    cols_count = 7
    total_chars = len(result.replace(COL_SEPARATOR, ""))
    assert total_chars % cols_count == 0

    try:
        columnar_transposition_encrypt("", "2 1")
    except ValueError:
        pass
    else:
        raise AssertionError("empty message should raise ValueError")

    try:
        columnar_transposition_encrypt("   ", "2 1")
    except ValueError:
        pass
    else:
        raise AssertionError("whitespace-only message should raise ValueError")

    try:
        columnar_transposition_encrypt("ABCD", "")
    except ValueError:
        pass
    else:
        raise AssertionError("empty key should raise ValueError")

    try:
        columnar_transposition_encrypt("ABCD", "2 x")
    except ValueError:
        pass
    else:
        raise AssertionError("non-integer key should raise ValueError")

    try:
        columnar_transposition_encrypt("ABCDEFGH", "1 1")
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate key values should raise ValueError")

    try:
        columnar_transposition_encrypt("ABCDEFGH", "1 3")
    except ValueError:
        pass
    else:
        raise AssertionError("non-contiguous key should raise ValueError")

    print("All columnar transposition tests passed.")


if __name__ == "__main__":
    demo_message = "Comfortistheenemyofachievement"
    demo_key = "7 5 3 2 1 4 6"
    print("Encrypted Message:", columnar_transposition_encrypt(demo_message, demo_key))
    run_tests()
