from dataclasses import dataclass
from typing import final

from purepython_aes.aes.modes.stream._base import StreamCipherMode
from purepython_aes.const import AES_BLOCK_SIZE
from purepython_aes.types import CfbSegmentSize


@final
@dataclass(slots=True)
class CfbMode(StreamCipherMode):
    """Cipher FeedBack mode of operation."""

    segment_size: CfbSegmentSize = AES_BLOCK_SIZE  # type: ignore[assignment]
    """Feedback segment size in bytes."""

    def __post_init__(self) -> None:
        if self.segment_size < 1 or self.segment_size > AES_BLOCK_SIZE:
            raise ValueError(
                ', '.join(
                    (
                        f'expected 1 <= segment_size <= {AES_BLOCK_SIZE}',
                        f'got {self.segment_size}',
                    )
                )
            )

    def transform_for_encryption(
        self,
        initialization_value: bytes,
        plaintext: bytes,
    ) -> bytes:
        feedback_register: bytes = initialization_value
        plaintext_size: int = len(plaintext)
        ciphertext: bytearray = bytearray(plaintext_size)
        for segment_start in range(0, plaintext_size, self.segment_size):
            segment_end: int = min(segment_start + self.segment_size, plaintext_size)
            segment_length: int = segment_end - segment_start
            encrypted_register: bytes = self.algorithm.encrypt_block(feedback_register)
            for segment_index in range(segment_length):
                ciphertext[segment_start + segment_index] = (
                    plaintext[segment_start + segment_index]
                    ^ encrypted_register[segment_index]
                )
            ciphertext_segment: bytes = bytes(ciphertext[segment_start:segment_end])
            feedback_register = (
                feedback_register[segment_length:] + bytes(ciphertext_segment)
                if segment_length != AES_BLOCK_SIZE
                else ciphertext_segment
            )
        return bytes(ciphertext)

    def transform_for_decryption(
        self,
        initialization_value: bytes,
        ciphertext: bytes,
    ) -> bytes:
        feedback_register: bytes = initialization_value
        ciphertext_size: int = len(ciphertext)
        plaintext: bytearray = bytearray(ciphertext_size)
        for segment_start in range(0, ciphertext_size, self.segment_size):
            segment_end: int = min(segment_start + self.segment_size, ciphertext_size)
            segment_length: int = segment_end - segment_start
            encrypted_register: bytes = self.algorithm.encrypt_block(feedback_register)
            for segment_index in range(segment_length):
                plaintext[segment_start + segment_index] = (
                    ciphertext[segment_start + segment_index]
                    ^ encrypted_register[segment_index]
                )
            ciphertext_segment: bytes = ciphertext[segment_start:segment_end]
            feedback_register = (
                feedback_register[segment_length:] + ciphertext_segment
                if segment_length != AES_BLOCK_SIZE
                else ciphertext_segment
            )
        return bytes(plaintext)
