from purepython_aes.aes.padding._base import BasePadding
from purepython_aes.const import AES_BLOCK_SIZE


class Pkcs7Padding(BasePadding):
    """Implement PKCS#7/CMS block padding."""

    def pad(self, data: bytes) -> bytes:
        padding_size: int = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
        padding: bytes = bytes([padding_size]) * padding_size
        return data + padding

    def unpad(self, data: bytes) -> bytes:
        padding_size: int = data[-1]
        if padding_size < 1 or padding_size > AES_BLOCK_SIZE:
            raise ValueError('invalid PKCS#7 padding size')
        if not data.endswith(bytes([padding_size]) * padding_size):
            raise ValueError('invalid PKCS#7 padding bytes')
        return data[:(-padding_size)]
