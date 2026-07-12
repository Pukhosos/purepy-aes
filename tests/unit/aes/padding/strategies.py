from typing import Final

from hypothesis.strategies import binary, composite, DrawFn, integers, SearchStrategy

from purepython_aes.const import AES_BLOCK_SIZE


@composite
def aligned_messages(draw: DrawFn) -> bytes:
    return draw(binary()) * AES_BLOCK_SIZE


byte_values: Final[SearchStrategy[int]] = integers(min_value=1, max_value=255)
