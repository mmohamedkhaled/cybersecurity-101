"""Forward and inverse AES SubBytes on a 4x4 state matrix.

Each byte of a 4x4 state is substituted through the standard AES S-box and then
recovered with the inverse S-box. The S-box and its inverse are generated from
the AES specification (GF(2^8) multiplicative inverse followed by the affine
map) so they are exact, complete (256 entries) and mutual inverses.
"""

State = list[list[int]]


def _gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) modulo the AES polynomial 0x11B."""
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B
        b >>= 1
    return product


def _gf_inverse(a: int) -> int:
    """Return the multiplicative inverse of ``a`` in GF(2^8); 0 maps to 0."""
    if a == 0:
        return 0
    result, base, exponent = 1, a, 254  # a^254 == a^-1 in GF(2^8)
    while exponent:
        if exponent & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exponent >>= 1
    return result


def _affine_transform(b: int) -> int:
    """Apply the AES affine transformation to byte ``b``."""
    out = 0
    for i in range(8):
        bit = (
            ((b >> i) & 1)
            ^ ((b >> ((i + 4) % 8)) & 1)
            ^ ((b >> ((i + 5) % 8)) & 1)
            ^ ((b >> ((i + 6) % 8)) & 1)
            ^ ((b >> ((i + 7) % 8)) & 1)
            ^ ((0x63 >> i) & 1)
        )
        out |= bit << i
    return out


# Standard AES S-box generated from the spec; inverse derived by permutation.
_S_BOX_FLAT = [_affine_transform(_gf_inverse(i)) for i in range(256)]
_INV_S_BOX_FLAT = [0] * 256
for _i, _v in enumerate(_S_BOX_FLAT):
    _INV_S_BOX_FLAT[_v] = _i

# Row = high nibble, column = low nibble (the classic 16x16 layout).
S_BOX = [_S_BOX_FLAT[i * 16:(i + 1) * 16] for i in range(16)]
INV_S_BOX = [_INV_S_BOX_FLAT[i * 16:(i + 1) * 16] for i in range(16)]


def _table_lookup(table: list[list[int]], byte: int) -> int:
    """Substitute ``byte`` using a 16x16 nibble-indexed table.

    Args:
        table: 16 rows of 16 byte values.
        byte: The byte value to substitute (0-255).

    Returns:
        The substituted byte value.
    """
    row = (byte >> 4) & 0x0F
    col = byte & 0x0F
    return table[row][col]


def sub_bytes(state: State) -> State:
    """Apply the AES S-box substitution to each byte of ``state``.

    Args:
        state: A 4x4 state matrix of byte values.

    Returns:
        A new 4x4 state matrix with the substitution applied.
    """
    return [[_table_lookup(S_BOX, byte) for byte in row] for row in state]


def inverse_sub_bytes(state: State) -> State:
    """Apply the inverse AES S-box substitution to each byte of ``state``.

    Args:
        state: A 4x4 state matrix of byte values.

    Returns:
        A new 4x4 state matrix with the inverse substitution applied.
    """
    return [[_table_lookup(INV_S_BOX, byte) for byte in row] for row in state]


def run_tests() -> None:
    """Verify the S-box is the standard one and that SubBytes round-trips."""
    assert S_BOX[0][0] == 0x63, "S-box[0x00] should be 0x63"
    assert _table_lookup(S_BOX, 0x10) == 0xCA, "S-box[0x10] should be 0xCA"
    assert len(_S_BOX_FLAT) == 256 and len(set(_S_BOX_FLAT)) == 256, "S-box must be a permutation"

    # Every byte must round-trip through SubBytes then inverse SubBytes.
    for byte in range(256):
        assert _table_lookup(INV_S_BOX, _table_lookup(S_BOX, byte)) == byte

    test_state: State = [
        [0x32, 0x88, 0x31, 0xe0],
        [0x43, 0x5a, 0x31, 0x37],
        [0xf6, 0x30, 0x98, 0x07],
        [0xa8, 0x8d, 0xa2, 0x34],
    ]
    assert inverse_sub_bytes(sub_bytes(test_state)) == test_state, "state round-trip failed"
    print("All SubBytes reverse tests passed.")


if __name__ == "__main__":
    demo_state: State = [
        [0x32, 0x88, 0x31, 0xe0],
        [0x43, 0x5a, 0x31, 0x37],
        [0xf6, 0x30, 0x98, 0x07],
        [0xa8, 0x8d, 0xa2, 0x34],
    ]
    print("Original state:")
    for row in demo_state:
        print([hex(v) for v in row])
    subbed = sub_bytes(demo_state)
    print("\nState after SubBytes:")
    for row in subbed:
        print([hex(v) for v in row])
    recovered = inverse_sub_bytes(subbed)
    print("\nState after Inverse SubBytes (matches original):")
    for row in recovered:
        print([hex(v) for v in row])
    run_tests()
