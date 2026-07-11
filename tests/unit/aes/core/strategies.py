from typing import Final

from hypothesis.strategies import binary, integers, SearchStrategy, tuples

from purepython_aes.const import AES_BLOCK_SIZE

byte_values: Final[SearchStrategy[int]] = integers(min_value=0x00, max_value=0xFF)
columns: Final[SearchStrategy[tuple[int, int, int, int]]] = tuples(
    byte_values, byte_values, byte_values, byte_values
)
aes_blocks: Final[SearchStrategy[bytes]] = binary(
    min_size=AES_BLOCK_SIZE,
    max_size=AES_BLOCK_SIZE,
)
