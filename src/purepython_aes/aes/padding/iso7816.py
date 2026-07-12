from typing import Final

from purepython_aes.aes.padding._base import BasePadding
from purepython_aes.const import AES_BLOCK_SIZE

PADDING_START_BYTE: Final[int] = 0x80


class Iso7816Padding(BasePadding):
    """Implement ISO/IEC 7816-4 block padding."""

    def pad(self, data: bytes) -> bytes:
        padding_size: int = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
        zero_padding: bytes = bytes(padding_size - 1)
        return data + bytes([PADDING_START_BYTE]) + zero_padding

    def unpad(self, data: bytes) -> bytes:
        padding_start_index: int = len(data) - 1
        while padding_start_index >= 0 and data[padding_start_index] == 0:
            padding_start_index -= 1
        if padding_start_index < 0:
            raise ValueError('ISO/IEC 7816-4 padding marker not found')
        if data[padding_start_index] != PADDING_START_BYTE:
            raise ValueError('invalid ISO/IEC 7816-4 padding marker')
        if (len(data) - padding_start_index) > AES_BLOCK_SIZE:
            raise ValueError('invalid ISO/IEC 7816-4 padding size')
        return data[:padding_start_index]
