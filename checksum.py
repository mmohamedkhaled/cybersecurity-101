"""N-bit checksum generation and validation.

Implements an Internet-style checksum for 4-bit or 8-bit data words: the
running sum of all words is complemented (two's complement) to produce the
checksum word(s). Includes an optional step-by-step addition trace.
"""

SUPPORTED_BITS = (4, 8)


def _hex_to_bin(hex_chunk: str, bits: int) -> str:
    """Convert a single hex word into a fixed-width binary string."""
    return format(int(hex_chunk, 16), f'0{bits}b')


def _bin_add(a: str, b: str, bits: int) -> tuple[str, str]:
    """Add two binary words modulo 2**bits; return (result, carry)."""
    total = int(a, 2) + int(b, 2)
    carry = '1' if total > (2 ** bits - 1) else ' '
    result = format(total % (2 ** bits), f'0{bits}b')
    return result, carry


def _twos_complement(bin_str: str, bits: int) -> str:
    """Return the two's complement of a binary word."""
    inverted = ''.join('1' if c == '0' else '0' for c in bin_str)
    return format((int(inverted, 2) + 1) % (2 ** bits), f'0{bits}b')


def _split_chunks(message_hex: str, bits: int) -> list[str]:
    """Split a hex string into per-word chunks (1 digit for 4-bit, 2 for 8-bit)."""
    chunk_size = bits // 4
    return [message_hex[i:i + chunk_size] for i in range(0, len(message_hex), chunk_size)]


def _header(bits: int) -> str:
    """Build the column header (e.g. 'b3  b2  b1  b0')."""
    return '  '.join(f'b{i}' for i in reversed(range(bits)))


def checksum(message_hex: str, bits: int = 4, verbose: bool = True) -> str:
    """Generate the checksum word for a hex message.

    Args:
        message_hex: Hex string of the message. Each nibble (4-bit) or byte
            (8-bit) is one word.
        bits: Checksum width; must be 4 or 8.
        verbose: If True, print a step-by-step addition table.

    Returns:
        The checksum as an uppercase hex string.

    Raises:
        ValueError: If ``message_hex`` is empty or ``bits`` is unsupported.
    """
    if bits not in SUPPORTED_BITS:
        raise ValueError(f"bits must be one of {SUPPORTED_BITS}, got {bits}")
    if not message_hex:
        raise ValueError("message_hex must not be empty")

    chunks = _split_chunks(message_hex, bits)
    if verbose:
        print(f"\nChecksum {bits}-bit Table:\n")
        print(f"{'':<5} {'c':<2} {_header(bits)}")
        print('-' * (8 + bits * 3))

    running_sum = '0' * bits
    for i, chunk in enumerate(chunks):
        label = '+' + chunk if i else chunk
        bin_val = _hex_to_bin(chunk, bits)
        if verbose:
            print(f"{label:<5} {' ':<2} {'  '.join(bin_val)}")
        running_sum, carry = _bin_add(running_sum, bin_val, bits)
        if verbose:
            print(f"{'=':<5} {carry:<2} {'  '.join(running_sum)}")

    comp = _twos_complement(running_sum, bits)
    hex_width = (bits + 3) // 4
    checksum_hex = format(int(comp, 2), f'0{hex_width}X')
    if verbose:
        print(f"\nFinal {bits}-bit sum: {running_sum}")
        print(f"Two's complement: {comp}")
        print(f"Checksum (hex): {checksum_hex}")
        print(f"Final transmitted message: {message_hex}{checksum_hex}")
    return checksum_hex


def validate_checksum(message_hex: str, bits: int = 4, verbose: bool = True) -> bool:
    """Validate a hex message that already includes its checksum word(s).

    Args:
        message_hex: Hex string of the received message including the checksum.
        bits: Checksum width; must be 4 or 8.
        verbose: If True, print a step-by-step addition table.

    Returns:
        True if the recomputed running sum is all zeros (valid), else False.

    Raises:
        ValueError: If ``message_hex`` is empty or ``bits`` is unsupported.
    """
    if bits not in SUPPORTED_BITS:
        raise ValueError(f"bits must be one of {SUPPORTED_BITS}, got {bits}")
    if not message_hex:
        raise ValueError("message_hex must not be empty")

    chunks = _split_chunks(message_hex, bits)
    if verbose:
        print(f"\nChecksum {bits}-bit Validation Table:\n")
        print(f"{'':<5} {'c':<2} {_header(bits)}")
        print('-' * (8 + bits * 3))

    running_sum = '0' * bits
    for i, chunk in enumerate(chunks):
        label = '+' + chunk if i else chunk
        bin_val = _hex_to_bin(chunk, bits)
        if verbose:
            print(f"{label:<5} {' ':<2} {'  '.join(bin_val)}")
        running_sum, carry = _bin_add(running_sum, bin_val, bits)
        if verbose:
            print(f"{'=':<5} {carry:<2} {'  '.join(running_sum)}")

    is_valid = running_sum == '0' * bits
    if verbose:
        print(f"\nFinal {bits}-bit sum: {running_sum}")
        print("VALID - message was not corrupted." if is_valid
              else "FAILED - message is corrupted.")
    return is_valid


def run_tests() -> None:
    """Sanity checks for checksum generation and validation."""
    # Hand-verified known checksum values
    assert checksum("12345", bits=4, verbose=False) == "1", "4-bit known value mismatch"
    assert checksum("C8C093", bits=8, verbose=False) == "E5", "8-bit known value mismatch"

    # Known-intact messages validate as valid
    assert validate_checksum("D54B87", bits=4, verbose=False) is True, "4-bit valid case failed"
    assert validate_checksum("12345678EC", bits=8, verbose=False) is True, "8-bit valid case failed"

    # Round-trip: appending the generated checksum yields a valid message
    msg4 = "9A1F"
    assert validate_checksum(msg4 + checksum(msg4, bits=4, verbose=False), bits=4, verbose=False) is True
    msg8 = "C8C093"
    assert validate_checksum(msg8 + checksum(msg8, bits=8, verbose=False), bits=8, verbose=False) is True

    # A single flipped bit/word must be detected as corruption
    valid4 = "D54B87"
    flipped = "0" if valid4[-1] != "0" else "1"
    assert validate_checksum(valid4[:-1] + flipped, bits=4, verbose=False) is False, \
        "corruption not detected"

    # Invalid arguments raise ValueError
    for bad_bits in (0, 5, 16):
        try:
            checksum("1234", bits=bad_bits)
            raise AssertionError(f"expected ValueError for bits={bad_bits}")
        except ValueError:
            pass
    try:
        checksum("", bits=4)
        raise AssertionError("expected ValueError for empty message")
    except ValueError:
        pass

    print("All checksum tests passed.")


if __name__ == "__main__":
    checksum("12345", bits=4)
    checksum("C8C093", bits=8)
    run_tests()
