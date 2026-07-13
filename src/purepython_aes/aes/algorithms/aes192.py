from dataclasses import dataclass
from typing import ClassVar

from purepython_aes.aes.core import AesCore
from purepython_aes.const import AES_192_KEY_SIZE, AES_192_ROUND_COUNT


@dataclass(init=False, slots=True)
class Aes192(AesCore):
    """AES-192 encryption algorithm."""

    __key_size__: ClassVar[int] = AES_192_KEY_SIZE
    __round_count__: ClassVar[int] = AES_192_ROUND_COUNT
