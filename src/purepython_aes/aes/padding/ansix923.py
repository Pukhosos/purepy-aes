from purepython_aes.aes.padding._base import BasePadding
from purepython_aes.const import AES_BLOCK_SIZE


class AnsiX923Padding(BasePadding):
    """Implement deterministic ANSI X9.23 block padding."""

    def pad(self, data: bytes) -> bytes:
        padding_size: int = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
        zero_padding: bytes = bytes(padding_size - 1)
        length_byte: bytes = bytes([padding_size])
        return data + zero_padding + length_byte

    def unpad(self, data: bytes) -> bytes:
        if len(data) == 0:
            raise ValueError('ANSI X9.23 padding expects non-empty data')
        padding_size: int = data[-1]
        if padding_size < 1 or padding_size > AES_BLOCK_SIZE:
            raise ValueError('invalid ANSI X9.23 padding size')
        zero_padding: bytes = data[(-padding_size):(-1)]
        if zero_padding != bytes(padding_size - 1):
            raise ValueError('invalid ANSI X9.23 padding bytes')
        return data[:(-padding_size)]
