from typing import Final

AES_BLOCK_SIZE: Final[int] = 16
"""AES block size in bytes."""

AES_WORD_SIZE: Final[int] = 4
"""Word size in bytes."""

AES_128_KEY_SIZE: Final[int] = 16
"""Key length in bytes for AES-128."""

AES_128_ROUND_COUNT: Final[int] = 10
"""Number of rounds for AES-128."""

AES_192_KEY_SIZE: Final[int] = 24
"""Key length in bytes for AES-192."""

AES_192_ROUND_COUNT: Final[int] = 12
"""Number of rounds for AES-192."""

AES_256_KEY_SIZE: Final[int] = 32
"""Key length in bytes for AES-256."""

AES_256_ROUND_COUNT: Final[int] = 14
"""Number of rounds for AES-256."""

ROUND_CONSTANTS: Final[tuple[int, ...]] = (
    0x00,
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1B,
    0x36,
)
"""Predefined values used during the AES key expansion."""
