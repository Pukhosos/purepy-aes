from dataclasses import dataclass
from secrets import token_bytes
from typing import final

from purepython_aes.aes.modes.block._base import BlockCipherMode
from purepython_aes.aes.modes.operations import split_into_blocks, xor
from purepython_aes.const import AES_BLOCK_SIZE


@final
@dataclass(slots=True)
class CbcMode(BlockCipherMode):
    """Cipher Block Chaining mode of operation."""

    def __encrypt_blocks__(self, padded_plaintext: bytes) -> bytes:
        initialization_vector: bytes = token_bytes(AES_BLOCK_SIZE)
        previous_ciphertext_block: bytes = initialization_vector
        ciphertext_blocks: list[bytes] = [initialization_vector]
        for block in split_into_blocks(padded_plaintext):
            chained_block: bytes = xor(block, previous_ciphertext_block)
            ciphertext_block: bytes = self.algorithm.encrypt_block(chained_block)
            ciphertext_blocks.append(ciphertext_block)
            previous_ciphertext_block = ciphertext_block
        return bytes(0).join(ciphertext_blocks)

    def __decrypt_blocks__(self, ciphertext: bytes) -> bytes:
        initialization_vector, *ciphertext_blocks = split_into_blocks(ciphertext)
        previous_ciphertext_block: bytes = initialization_vector
        plaintext_blocks: list[bytes] = []
        for block in ciphertext_blocks:
            decrypted_block: bytes = self.algorithm.decrypt_block(block)
            plaintext_block: bytes = xor(decrypted_block, previous_ciphertext_block)
            plaintext_blocks.append(plaintext_block)
            previous_ciphertext_block = block
        return bytes(0).join(plaintext_blocks)
