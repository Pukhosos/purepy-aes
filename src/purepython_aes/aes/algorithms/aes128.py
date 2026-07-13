from typing import ClassVar

from purepython_aes.aes.core import AesCore
from purepython_aes.const import AES_128_KEY_SIZE, AES_128_ROUND_COUNT


class Aes128(AesCore):
    """AES-128 encryption algorithm."""

    __key_size__: ClassVar[int] = AES_128_KEY_SIZE
    __round_count__: ClassVar[int] = AES_128_ROUND_COUNT
