from secrets import token_bytes

from purepython_aes.aes.padding._base import BaseGuardedPadding
from purepython_aes.const import AES_BLOCK_SIZE


class Iso10126Padding(BaseGuardedPadding):
    """Implement legacy ISO 10126 block padding."""

    def pad(self, data: bytes) -> bytes:
        padding_size: int = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
        random_padding: bytes = token_bytes(padding_size - 1)
        length_byte: bytes = bytes([padding_size])
        return data + random_padding + length_byte

    def unpad(self, data: bytes) -> bytes:
        padding_size: int = data[-1]
        if padding_size < 1 or padding_size > AES_BLOCK_SIZE:
            raise ValueError('invalid ISO 10126 padding size')
        return data[:(-padding_size)]
