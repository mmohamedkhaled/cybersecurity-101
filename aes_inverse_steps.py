"""AES round transformations and their inverses, worked by hand.

Demonstrates the four AES round operations -- SubBytes, ShiftRows, MixColumns,
AddRoundKey -- together with their exact inverses, on a 4x4 state. Because each
inverse is correct over GF(2^8), applying a forward round and then the inverse
round recovers the original state. The state is stored row-major for clarity
(the transforms are self-consistent, which is what the round-trip tests check).

``pycryptodome`` is used only for an optional real-encryption comparison in the
``__main__`` demo; the tests themselves are pure standard library.
"""

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad
    PYCRYPTODOME_AVAILABLE = True
except ImportError:
    PYCRYPTODOME_AVAILABLE = False


State = list[list[int]]
AES_BLOCK_BYTES = 16


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
    result, base, exponent = 1, a, 254
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


S_BOX = [_affine_transform(_gf_inverse(i)) for i in range(256)]
INV_S_BOX = [0] * 256
for _i, _v in enumerate(S_BOX):
    INV_S_BOX[_v] = _i


def text_to_state(text: str) -> State:
    """Convert a 16-character block into a 4x4 state matrix of byte values.

    Args:
        text: Exactly 16 characters representing one AES block.

    Returns:
        A 4x4 list of lists of integer byte values.

    Raises:
        ValueError: If ``text`` is not exactly 16 characters long.
    """
    if len(text) != AES_BLOCK_BYTES:
        raise ValueError("a single AES state requires exactly 16 characters")
    rows = [text[i:i + 4] for i in range(0, AES_BLOCK_BYTES, 4)]
    return [[ord(char) for char in row] for row in rows]


def sub_bytes(state: State) -> State:
    """Apply the AES S-box substitution to each byte of ``state``."""
    return [[S_BOX[byte] for byte in row] for row in state]


def inverse_sub_bytes(state: State) -> State:
    """Apply the inverse AES S-box substitution to each byte of ``state``."""
    return [[INV_S_BOX[byte] for byte in row] for row in state]


def shift_rows(state: State) -> State:
    """Cyclically shift row ``r`` of the state left by ``r`` positions."""
    return [state[r][r:] + state[r][:r] for r in range(4)]


def inverse_shift_rows(state: State) -> State:
    """Cyclically shift row ``r`` of the state right by ``r`` positions."""
    return [state[r] if r == 0 else state[r][-r:] + state[r][:-r] for r in range(4)]


def _mix_column(column: list[int], factors: list[list[int]]) -> list[int]:
    """Multiply a 4-byte column by a 4x4 matrix over GF(2^8)."""
    return [
        _gf_mul(factors[i][0], column[0])
        ^ _gf_mul(factors[i][1], column[1])
        ^ _gf_mul(factors[i][2], column[2])
        ^ _gf_mul(factors[i][3], column[3])
        for i in range(4)
    ]


_MIX_COLUMNS_MATRIX = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02],
]
_INV_MIX_COLUMNS_MATRIX = [
    [0x0E, 0x0B, 0x0D, 0x09],
    [0x09, 0x0E, 0x0B, 0x0D],
    [0x0D, 0x09, 0x0E, 0x0B],
    [0x0B, 0x0D, 0x09, 0x0E],
]


def mix_columns(state: State) -> State:
    """Apply the AES MixColumns transformation to each column of ``state``."""
    out: State = [[0] * 4 for _ in range(4)]
    for c in range(4):
        column = [state[r][c] for r in range(4)]
        new_column = _mix_column(column, _MIX_COLUMNS_MATRIX)
        for r in range(4):
            out[r][c] = new_column[r]
    return out


def inverse_mix_columns(state: State) -> State:
    """Apply the inverse AES MixColumns transformation to each column."""
    out: State = [[0] * 4 for _ in range(4)]
    for c in range(4):
        column = [state[r][c] for r in range(4)]
        new_column = _mix_column(column, _INV_MIX_COLUMNS_MATRIX)
        for r in range(4):
            out[r][c] = new_column[r]
    return out


def add_round_key(state: State, key: State) -> State:
    """XOR each byte of the state with the corresponding round-key byte."""
    return [
        [state[row][col] ^ key[row][col] for col in range(4)]
        for row in range(4)
    ]


def forward_round(state: State, key: State) -> State:
    """Apply one AES forward round: SubBytes, ShiftRows, MixColumns, AddRoundKey."""
    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, key)
    return state


def inverse_round(state: State, key: State) -> State:
    """Invert one AES round: AddRoundKey, InvMixColumns, InvShiftRows, InvSubBytes."""
    state = add_round_key(state, key)
    state = inverse_mix_columns(state)
    state = inverse_shift_rows(state)
    state = inverse_sub_bytes(state)
    return state


def run_tests() -> None:
    """Verify every inverse transform undoes its forward counterpart."""
    assert S_BOX[0x00] == 0x63, "S-box[0x00] should be 0x63"
    assert S_BOX[0x10] == 0xCA, "S-box[0x10] should be 0xCA"

    state: State = [
        [0x32, 0x88, 0x31, 0xE0],
        [0x43, 0x5A, 0x31, 0x37],
        [0xF6, 0x30, 0x98, 0x07],
        [0xA8, 0x8D, 0xA2, 0x34],
    ]
    key: State = [
        [0x2B, 0x28, 0xAB, 0x09],
        [0x7E, 0xAE, 0xF7, 0xCF],
        [0x15, 0xD2, 0x15, 0x4F],
        [0x16, 0xA6, 0x88, 0x3C],
    ]

    assert inverse_sub_bytes(sub_bytes(state)) == state, "SubBytes round-trip failed"
    assert inverse_shift_rows(shift_rows(state)) == state, "ShiftRows round-trip failed"
    assert inverse_mix_columns(mix_columns(state)) == state, "MixColumns round-trip failed"
    assert inverse_round(forward_round(state, key), key) == state, "full round-trip failed"
    print("All AES inverse-step tests passed.")


if __name__ == "__main__":
    if PYCRYPTODOME_AVAILABLE:
        key_bytes = get_random_bytes(AES_BLOCK_BYTES)
        plaintext = "HelloAES1234567"
        ciphertext = AES.new(key_bytes, AES.MODE_ECB).encrypt(pad(plaintext.encode(), AES.block_size))
        print(f"Real AES-ECB encryption of {plaintext!r} (hex): {ciphertext.hex()}")
        print("The hand-worked inverse transforms above are tested for self-consistency.")
    else:
        print("pycryptodome demo skipped (missing dependency); running self-tests only.")
    run_tests()
