"""Bitwise XOR checksum for hexadecimal strings.

Computes a single-nibble checksum by XOR-ing every hex digit of a
message together, producing a value commonly used as a simple
integrity tag appended to the transmitted message.
"""

HEX_BASE = 16
NIBBLE_BITS = 4


def bit_by_bit_xor_trace(hex_str: str) -> int:
    """XOR every hex digit of ``hex_str`` together and trace each step.

    Args:
        hex_str: A string of hexadecimal digits (whitespace is ignored).

    Returns:
        The integer XOR-fold of all hex digits, in the range ``[0, 15]``.

    Raises:
        ValueError: If ``hex_str`` is empty or contains a character
            that is not a hexadecimal digit.
    """
    cleaned = "".join(hex_str.split()).upper()
    if not cleaned:
        raise ValueError("hex_str must contain at least one hexadecimal digit")

    try:
        blocks = [int(ch, HEX_BASE) for ch in cleaned]
    except ValueError as exc:
        raise ValueError("hex_str must contain only hexadecimal digits") from exc

    result = blocks[0]
    print(f"{cleaned[0]} = {result:0{NIBBLE_BITS}b}")
    for i in range(1, len(blocks)):
        b = blocks[i]
        result ^= b
        print(f"\u2295 {cleaned[i]} = {b:0{NIBBLE_BITS}b} \u2192 {result:0{NIBBLE_BITS}b}")
    return result


def run_tests() -> None:
    assert bit_by_bit_xor_trace("B37F19") == 8
    assert bit_by_bit_xor_trace("0000") == 0
    assert bit_by_bit_xor_trace("F") == 15
    assert bit_by_bit_xor_trace("FF") == 0
    assert bit_by_bit_xor_trace("FFFF") == 0
    assert bit_by_bit_xor_trace("1234") == (1 ^ 2 ^ 3 ^ 4)
    assert bit_by_bit_xor_trace("b37f19") == 8
    assert bit_by_bit_xor_trace("  B37F19  ") == 8
    assert bit_by_bit_xor_trace("B3 7F 19") == 8
    assert 0 <= bit_by_bit_xor_trace("ABCDEF") <= 15

    try:
        bit_by_bit_xor_trace("")
    except ValueError:
        pass
    else:
        raise AssertionError("empty hex_str should raise ValueError")

    try:
        bit_by_bit_xor_trace("   ")
    except ValueError:
        pass
    else:
        raise AssertionError("whitespace-only hex_str should raise ValueError")

    try:
        bit_by_bit_xor_trace("GHIJ")
    except ValueError:
        pass
    else:
        raise AssertionError("non-hex characters should raise ValueError")

    print("All XOR hash value tests passed.")


if __name__ == "__main__":
    msg = "B37F19"
    hash_val = bit_by_bit_xor_trace(msg)
    print("Final hash (hex):", format(hash_val, "X"))
    print("Transmitted message:", msg + format(hash_val, "X"))
    run_tests()
