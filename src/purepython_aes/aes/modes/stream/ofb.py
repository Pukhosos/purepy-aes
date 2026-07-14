from dataclasses import dataclass
from typing import final

from purepython_aes.aes.modes.stream._base import StreamCipherMode
from purepython_aes.const import AES_BLOCK_SIZE


@final
@dataclass(slots=True)
class OfbMode(StreamCipherMode):
    """Output FeedBack mode of operation."""

    def __encrypt_stream__(
        self,
        initialization_value: bytes,
        plaintext: bytes,
    ) -> bytes:
        return self.__transform_stream__(initialization_value, plaintext)

    def __decrypt_stream__(
        self,
        initialization_value: bytes,
        ciphertext: bytes,
    ) -> bytes:
        return self.__transform_stream__(initialization_value, ciphertext)

    def __transform_stream__(
        self,
        initialization_value: bytes,
        data: bytes,
    ) -> bytes:
        """XOR data with the OFB keystream."""

        feedback_register: bytes = initialization_value
        data_size: int = len(data)
        transformed_data: bytearray = bytearray(data_size)
        for block_start in range(0, data_size, AES_BLOCK_SIZE):
            block_end: int = min(block_start + AES_BLOCK_SIZE, data_size)
            block_length: int = block_end - block_start
            feedback_register = self.algorithm.encrypt_block(feedback_register)
            for block_index in range(block_length):
                transformed_data[block_start + block_index] = (
                    data[block_start + block_index] ^ feedback_register[block_index]
                )
        return bytes(transformed_data)
