from purepython_aes.aes.padding._base import BasePadding
from purepython_aes.const import AES_BLOCK_SIZE


class ZeroPadding(BasePadding):
    """Implement ambiguous zero-byte padding."""

    def pad(self, data: bytes) -> bytes:
        remainder_size: int = len(data) % AES_BLOCK_SIZE
        if remainder_size == 0:
            return data
        return data + bytes(AES_BLOCK_SIZE - remainder_size)

    def unpad(self, data: bytes) -> bytes:
        if len(data) % AES_BLOCK_SIZE != 0:
            raise ValueError(
                f'expected len(data) % {AES_BLOCK_SIZE} == 0, got {len(data)}'
            )
        unpadded_size: int = len(data)
        while unpadded_size > 0 and data[unpadded_size - 1] == 0:
            unpadded_size -= 1
        return data[:unpadded_size]
