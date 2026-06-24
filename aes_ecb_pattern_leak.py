"""AES-ECB pattern-leak demonstration.

Shows that AES in ECB mode preserves plaintext structure: identical 16-byte
plaintext blocks produce identical ciphertext blocks, which leaks patterns. The
demo encrypts a repeating message, detects the duplicate ciphertext blocks, and
optionally visualizes them as an image. Requires ``pycryptodome`` (as
``Crypto``) and ``matplotlib``; ``numpy`` is available for the image array.
"""


import numpy as np

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    PYCRYPTODOME_AVAILABLE = True
except ImportError:
    PYCRYPTODOME_AVAILABLE = False

try:
    import matplotlib
    matplotlib.use("Agg")  # headless backend: never block on a GUI window
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


BLOCK_SIZE = 16

PLAINTEXT_BLOCK = b"TOP SECRET MSG!!"


def split_blocks(ciphertext: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """Split ``ciphertext`` into consecutive ``block_size``-byte blocks.

    Args:
        ciphertext: The raw ciphertext bytes.
        block_size: The block size in bytes (default 16 for AES).

    Returns:
        A list of byte-string blocks.

    Raises:
        ValueError: If ``block_size`` is non-positive, ``ciphertext`` is empty,
            or its length is not a multiple of ``block_size``.
    """
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    if len(ciphertext) == 0:
        raise ValueError("ciphertext must not be empty")
    if len(ciphertext) % block_size != 0:
        raise ValueError("ciphertext length must be a multiple of block_size")
    return [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]


def detect_ecb_repetition(ciphertext: bytes, block_size: int = BLOCK_SIZE) -> bool:
    """Detect whether ``ciphertext`` contains repeated blocks (an ECB leak).

    Args:
        ciphertext: The raw ciphertext bytes.
        block_size: The block size in bytes.

    Returns:
        True if any two ciphertext blocks are identical, False otherwise.
    """
    blocks = split_blocks(ciphertext, block_size)
    return len(set(blocks)) < len(blocks)


def blocks_to_image(ciphertext: bytes, block_size: int = BLOCK_SIZE) -> np.ndarray:
    """Convert ciphertext blocks into a 2-D uint8 array for visualization.

    Args:
        ciphertext: The raw ciphertext bytes.
        block_size: The block size in bytes.

    Returns:
        A numpy array of shape ``(num_blocks, block_size)`` with dtype uint8.
    """
    blocks = split_blocks(ciphertext, block_size)
    return np.array([list(block) for block in blocks], dtype=np.uint8)


def run_tests() -> None:
    """Verify the ECB repetition detector (requires pycryptodome)."""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        plaintext = PLAINTEXT_BLOCK * 3
        key = b"ThisIsA16ByteKey"
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
        assert detect_ecb_repetition(ciphertext, BLOCK_SIZE), "expected ECB repetition"
        blocks = split_blocks(ciphertext, BLOCK_SIZE)
        assert len(set(blocks)) < len(blocks), "duplicate blocks not found"
        print("All ECB pattern-leak tests passed.")
    except ImportError:
        print("ECB pattern-leak tests skipped (missing dependency: pycryptodome).")


if __name__ == "__main__":
    if PYCRYPTODOME_AVAILABLE:
        plaintext = PLAINTEXT_BLOCK * 3
        key = b"ThisIsA16ByteKey"
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
        for index, block in enumerate(split_blocks(ciphertext)):
            print(f"Block {index}: {block.hex()}")
        blocks = split_blocks(ciphertext)
        unique_blocks = set(blocks)
        print(f"\nNumber of Unique Blocks: {len(unique_blocks)}")
        print(f"Number of Total Blocks: {len(blocks)}")
        if detect_ecb_repetition(ciphertext):
            print("ECB Mode Detected: Repeating patterns found! Vulnerable to attack.")
        if MATPLOTLIB_AVAILABLE:
            image = blocks_to_image(ciphertext)
            plt.imshow(image, cmap="gray", interpolation="nearest")
            plt.title("Encrypted Data Pattern (ECB Mode)")
            plt.savefig("ecb_pattern.png")
            print("Saved visualization to ecb_pattern.png")
    else:
        print("ECB demo skipped (missing dependency: pycryptodome).")
    run_tests()
