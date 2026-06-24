"""Playfair cipher implementation.

Builds a 5x5 key-square from a keyword (merging the letter 'J' into
'I') and encrypts plaintext bigrams using the classical same-row,
same-column, and rectangle substitution rules.
"""


ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
MATRIX_SIZE = 5
MATRIX_CELLS = MATRIX_SIZE * MATRIX_SIZE
FILLER_CHAR = "X"


def build_playfair_matrix(keyword: str) -> list[list[str]]:
    """Build the 5x5 Playfair key-square from ``keyword``.

    Args:
        keyword: A string whose unique alphabetic letters (with 'J'
            treated as 'I') are placed at the front of the key-square,
            followed by the remaining letters of the alphabet.

    Returns:
        A 5x5 nested list of single-character strings.

    Raises:
        ValueError: If ``keyword`` contains no alphabetic characters.
    """
    cleaned = "".join(ch for ch in keyword.upper() if ch.isalpha())
    if not cleaned:
        raise ValueError("keyword must contain at least one alphabetic character")

    seen = set()
    flat: list[str] = []
    for ch in cleaned:
        if ch == "J":
            ch = "I"
        if ch not in seen and ch in ALPHABET:
            seen.add(ch)
            flat.append(ch)
    for ch in ALPHABET:
        if ch not in seen:
            seen.add(ch)
            flat.append(ch)

    return [flat[i:i + MATRIX_SIZE] for i in range(0, MATRIX_CELLS, MATRIX_SIZE)]


def find_position(matrix: list[list[str]], char: str) -> tuple[int, int] | None:
    """Return the ``(row, col)`` position of ``char`` within ``matrix``.

    Args:
        matrix: A Playfair key-square produced by ``build_playfair_matrix``.
        char: The single uppercase letter to locate ('J' is mapped to
            'I' before searching).

    Returns:
        A ``(row, column)`` tuple, or ``None`` if the character is not
        present in the matrix.
    """
    if char == "J":
        char = "I"
    for r, row in enumerate(matrix):
        if char in row:
            return r, row.index(char)
    return None


def process_plaintext(text: str) -> list[str]:
    """Split ``text`` into Playfair bigrams with no duplicate letters.

    Args:
        text: The plaintext to split. It is upper-cased, non-alphabetic
            characters are removed, and 'J' is replaced by 'I'.

    Returns:
        A list of two-character bigrams. A trailing single letter or a
        repeated letter in a pair is padded with the filler character.

    Raises:
        ValueError: If ``text`` is empty after cleaning.
    """
    cleaned = "".join(ch for ch in text.upper() if ch.isalpha())
    cleaned = cleaned.replace("J", "I")
    if not cleaned:
        raise ValueError("text must contain at least one character")

    bigrams: list[str] = []
    i = 0
    while i < len(cleaned):
        a = cleaned[i]
        b = cleaned[i + 1] if i + 1 < len(cleaned) else FILLER_CHAR
        if a == b:
            b = FILLER_CHAR
            i += 1
        else:
            i += 2
        bigrams.append(a + b)
    return bigrams


def encrypt_bigram(matrix: list[list[str]], bigram: str) -> str:
    """Encrypt a single two-character ``bigram`` using ``matrix``.

    Args:
        matrix: A Playfair key-square produced by ``build_playfair_matrix``.
        bigram: A two-character string of uppercase letters.

    Returns:
        The encrypted two-character bigram, applying the same-row,
        same-column, or rectangle rule as appropriate.
    """
    a, b = bigram[0], bigram[1]
    pos1 = find_position(matrix, a)
    pos2 = find_position(matrix, b)
    if pos1 is None or pos2 is None:
        raise ValueError(
            "bigram must contain only letters present in the key-square"
        )
    row1, col1 = pos1
    row2, col2 = pos2

    if row1 == row2:
        return matrix[row1][(col1 + 1) % MATRIX_SIZE] + matrix[row2][(col2 + 1) % MATRIX_SIZE]
    if col1 == col2:
        return matrix[(row1 + 1) % MATRIX_SIZE][col1] + matrix[(row2 + 1) % MATRIX_SIZE][col2]
    return matrix[row1][col2] + matrix[row2][col1]


def playfair_encrypt(keyword: str, message: str) -> str:
    """Encrypt ``message`` with the Playfair cipher derived from ``keyword``.

    Args:
        keyword: The keyword used to build the Playfair key-square.
        message: The plaintext to encrypt.

    Returns:
        The ciphertext as space-separated encrypted bigrams.
    """
    matrix = build_playfair_matrix(keyword)
    bigrams = process_plaintext(message)
    encrypted = [encrypt_bigram(matrix, pair) for pair in bigrams]
    return " ".join(encrypted)


def run_tests() -> None:
    matrix = build_playfair_matrix("PLAYFAIREXAMPLE")
    assert len(matrix) == MATRIX_SIZE
    assert all(len(row) == MATRIX_SIZE for row in matrix)
    flat = [ch for row in matrix for ch in row]
    assert len(flat) == MATRIX_CELLS
    assert len(set(flat)) == MATRIX_CELLS
    assert "J" not in flat

    controlled = [
        ["A", "B", "C", "D", "E"],
        ["F", "G", "H", "I", "K"],
        ["L", "M", "N", "O", "P"],
        ["Q", "R", "S", "T", "U"],
        ["V", "W", "X", "Y", "Z"],
    ]
    assert find_position(controlled, "A") == (0, 0)
    assert find_position(controlled, "Z") == (4, 4)
    assert find_position(controlled, "J") == (1, 3)
    assert find_position(controlled, "!") is None

    assert encrypt_bigram(controlled, "AB") == "BC"
    assert encrypt_bigram(controlled, "AG") == "BF"
    assert encrypt_bigram(controlled, "AL") == "FQ"

    assert process_plaintext("HELLO") == ["HE", "LX", "LO"]
    assert process_plaintext("BALL") == ["BA", "LX", "LX"]
    assert process_plaintext("A B C") == ["AB", "CX"]
    assert process_plaintext("HI!") == ["HI"]
    assert process_plaintext("A1B2C3") == ["AB", "CX"]

    ciphertext = playfair_encrypt("KEYWORD", "HELLO")
    assert all(len(pair) == 2 for pair in ciphertext.split())

    try:
        build_playfair_matrix("123")
    except ValueError:
        pass
    else:
        raise AssertionError("non-alphabetic keyword should raise ValueError")

    try:
        process_plaintext("")
    except ValueError:
        pass
    else:
        raise AssertionError("empty text should raise ValueError")

    print("All playfair tests passed.")


if __name__ == "__main__":
    demo_keyword = "MOTORBIKE"
    demo_message = "skater"
    print("Playfair Matrix:")
    for row in build_playfair_matrix(demo_keyword):
        print(row)
    print("Encrypted Message:", playfair_encrypt(demo_keyword, demo_message))
    run_tests()
