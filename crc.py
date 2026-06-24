"""CRC generator and validator.

Encodes and checks messages with a cyclic redundancy check (CRC) defined by a
binary generator polynomial. The generator appends the polynomial remainder to
the message, and the validator recomputes the syndrome to detect transmission
errors.
"""

BITS_PER_HEX_DIGIT = 4
BIT_GROUP_SIZE = 4


def polynomial_to_binary(poly_expr: str) -> str:
    """Convert a human-readable polynomial into its binary coefficient string.

    Args:
        poly_expr: Polynomial like "x^3 + x^2 + 1" (whitespace is ignored).

    Returns:
        Binary string of coefficients, highest power first (e.g. "1101").

    Raises:
        ValueError: If ``poly_expr`` is empty or contains an unparseable term.
    """
    cleaned = poly_expr.replace(" ", "")
    if not cleaned:
        raise ValueError("Polynomial expression must not be empty.")
    terms = cleaned.split('+')

    powers: list[int] = []
    max_power = 0
    for term in terms:
        if term == '1':
            power = 0
        elif term == 'x':
            power = 1
        elif term.startswith('x^'):
            power = int(term[2:])
        else:
            raise ValueError(f"Invalid polynomial term: {term!r}")
        if power < 0:
            raise ValueError(f"Polynomial power must be non-negative: {power}")
        powers.append(power)
        max_power = max(max_power, power)

    binary = ['0'] * (max_power + 1)
    for power in powers:
        binary[max_power - power] = '1'
    return ''.join(binary)


def _xor_division(
    dividend: str, divisor: str
) -> tuple[list[tuple[list[str], int]], str]:
    """Perform binary polynomial long division (XOR-based).

    Args:
        dividend: Binary string to divide.
        divisor: Binary generator polynomial string.

    Returns:
        A tuple ``(table, remainder)`` where ``table`` holds the step rows used
        for verbose display and ``remainder`` is the trailing CRC bits.
    """
    dividend_bits = list(dividend)
    divisor_len = len(divisor)
    table: list[tuple[list[str], int]] = []

    for i in range(len(dividend_bits) - divisor_len + 1):
        if dividend_bits[i] == '1':
            row = [' '] * len(dividend_bits)
            for j in range(divisor_len):
                row[i + j] = dividend_bits[i + j]
                dividend_bits[i + j] = str(
                    int(dividend_bits[i + j]) ^ int(divisor[j])
                )
            table.append((row.copy(), i))

    remainder = ''.join(dividend_bits[-(divisor_len - 1):])
    return table, remainder


def _format_bin(binary: str) -> str:
    """Group a binary string into fixed-size chunks for readable display."""
    return ' '.join(
        binary[i:i + BIT_GROUP_SIZE]
        for i in range(0, len(binary), BIT_GROUP_SIZE)
    )


def crc(hex_message: str, poly_expr: str, verbose: bool = False) -> str:
    """Generate the CRC remainder for a hex message.

    Args:
        hex_message: Message encoded as a hexadecimal string (e.g. "ACE").
        poly_expr: Generator polynomial expression (e.g. "x^3 + x^2 + 1").
        verbose: When True, print the division steps and intermediate values.

    Returns:
        The CRC remainder as an upper-case hex string (e.g. "1").

    Raises:
        ValueError: If ``hex_message`` is empty or not valid hexadecimal.
    """
    if not hex_message:
        raise ValueError("hex_message must not be empty.")

    try:
        message_value = int(hex_message, 16)
    except ValueError as exc:
        raise ValueError(
            f"hex_message must be hexadecimal: {hex_message!r}"
        ) from exc

    bin_msg = bin(message_value)[2:].zfill(len(hex_message) * BITS_PER_HEX_DIGIT)
    divisor = polynomial_to_binary(poly_expr)
    crc_len = len(divisor) - 1
    padded = bin_msg + '0' * crc_len

    if verbose:
        print(f"Message: {hex_message} = {_format_bin(bin_msg)}")
        print(f"Polynomial: {poly_expr} = {divisor}")
        print(f"Append {crc_len} zeros: {_format_bin(padded)}\n")
        print("Division steps:")

    table, remainder = _xor_division(padded, divisor)

    if verbose:
        for row, shift in table:
            print(' ' * shift + ''.join(row) + '   (XOR)')

    remainder = remainder.zfill(crc_len)
    rem_hex = hex(int(remainder, 2))[2:].upper()

    if verbose:
        print(f"\nRemainder ({crc_len} bits): {remainder}")
        print(f"Remainder (hex): {rem_hex}")
        print(f"Appended message: {_format_bin(bin_msg + remainder)}")
        print(f"Final transmitted message: {hex_message}{rem_hex}")

    return rem_hex


def validate_crc(
    appended_bin_msg: str, poly_expr: str, verbose: bool = False
) -> bool:
    """Validate a binary message that already includes the CRC bits.

    Args:
        appended_bin_msg: Binary message with the CRC bits appended.
        poly_expr: Generator polynomial expression used to create the CRC.
        verbose: When True, print the division steps and the syndrome.

    Returns:
        True when the recomputed syndrome is all zeros (no error detected),
        False otherwise.

    Raises:
        ValueError: If ``appended_bin_msg`` is empty, contains non-binary
            characters, or is shorter than the CRC length.
    """
    if not appended_bin_msg:
        raise ValueError("appended_bin_msg must not be empty.")
    if any(bit not in '01' for bit in appended_bin_msg):
        raise ValueError("appended_bin_msg must contain only 0 and 1 characters.")

    divisor = polynomial_to_binary(poly_expr)
    crc_len = len(divisor) - 1
    if len(appended_bin_msg) < crc_len:
        raise ValueError(
            f"appended_bin_msg has {len(appended_bin_msg)} bits, need at "
            f"least {crc_len} for this polynomial."
        )

    if verbose:
        print(f"Appended message: {_format_bin(appended_bin_msg)}")
        print(f"Polynomial: {poly_expr} = {divisor}\n")
        print("Division steps:")

    table, remainder = _xor_division(appended_bin_msg, divisor)

    if verbose:
        for row, shift in table:
            print(' ' * shift + ''.join(row) + '   (XOR)')

    syndrome = remainder.zfill(crc_len)
    is_valid = set(syndrome) == {'0'}

    if verbose:
        print(f"\nSyndrome: {syndrome}")
        if is_valid:
            print("No errors detected. The message is VALID.")
        else:
            print("Transmission error detected.")

    return is_valid


def run_tests() -> None:
    """Run inline sanity checks for the CRC implementation."""
    assert polynomial_to_binary("x^3 + x^2 + 1") == "1101"
    assert polynomial_to_binary("x^4 + x^3 + x^1 + 1") == "11011"
    assert polynomial_to_binary("1") == "1"
    assert polynomial_to_binary("x") == "10"

    assert crc("ACE", "x^3 + x^2 + 1") == "1"
    assert "ACE" + crc("ACE", "x^3 + x^2 + 1") == "ACE1"
    assert crc("ABC", "x^4 + x^3 + x^1 + 1") == "8"

    assert validate_crc("101000001110", "x^3 + x^2 + 1") is True
    assert validate_crc("101011001110001", "x^3 + x^2 + 1") is True

    corrupted = list("101000001110")
    corrupted[0] = '0' if corrupted[0] == '1' else '1'
    assert validate_crc(''.join(corrupted), "x^3 + x^2 + 1") is False

    try:
        crc("", "x^3 + x^2 + 1")
        raise AssertionError("expected ValueError for empty message")
    except ValueError:
        pass

    try:
        crc("XYZ", "x^3 + x^2 + 1")
        raise AssertionError("expected ValueError for non-hex message")
    except ValueError:
        pass

    try:
        validate_crc("1012", "x^3 + x^2 + 1")
        raise AssertionError("expected ValueError for non-binary message")
    except ValueError:
        pass

    print("All CRC tests passed.")


if __name__ == "__main__":
    crc("ACE", "x^3 + x^2 + 1", verbose=True)
    print()
    crc("ABC", "x^4 + x^3 + x^1 + 1", verbose=True)
    print()
    validate_crc("101000001110", "x^3 + x^2 + 1", verbose=True)
    print()
    run_tests()
