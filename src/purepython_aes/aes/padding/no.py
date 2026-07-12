from purepython_aes.aes.padding._base import BasePadding
from purepython_aes.const import AES_BLOCK_SIZE


class NoPadding(BasePadding):
    """Require callers to provide block-aligned data."""

    def pad(self, data: bytes) -> bytes:
        if len(data) % AES_BLOCK_SIZE != 0:
            raise ValueError(
                f'expected len(data) % {AES_BLOCK_SIZE} == 0, got {len(data)}'
            )
        return data

    def unpad(self, data: bytes) -> bytes:
        return data
