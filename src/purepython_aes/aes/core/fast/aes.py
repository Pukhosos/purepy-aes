from collections.abc import Iterator
from dataclasses import dataclass

from purepython_aes.aes.core.fast.expansion import (
    expand_aes128_key,
    expand_aes192_key,
    expand_aes256_key,
)
from purepython_aes.aes.core.fast.keys import (
    build_decryption_round_keys,
    RoundKey,
    RoundKeys,
)
from purepython_aes.aes.core.fast.ttables import (
    DECRYPTION_TABLE_0,
    DECRYPTION_TABLE_1,
    DECRYPTION_TABLE_2,
    DECRYPTION_TABLE_3,
    ENCRYPTION_TABLE_0,
    ENCRYPTION_TABLE_1,
    ENCRYPTION_TABLE_2,
    ENCRYPTION_TABLE_3,
)
from purepython_aes.aes.core.interface import Aes
from purepython_aes.const import (
    AES_128_KEY_SIZE,
    AES_192_KEY_SIZE,
    AES_256_KEY_SIZE,
    AES_BLOCK_SIZE,
    INVERSE_SBOX,
    SBOX,
)
from purepython_aes.types import IntLookupTable256


@dataclass(init=False, slots=True)
class FastAesCore(Aes):
    """Implement optimized `encrypt_block` and `decrypt_block` methods."""

    __encryption_round_keys: RoundKeys
    __final_encryption_key: RoundKey
    __decryption_round_keys: RoundKeys
    __final_decryption_key: RoundKey

    def __init__(self, key: bytes) -> None:
        if len(key) != self.__key_size__:
            raise ValueError(
                f'expected len(key) == {self.__key_size__}, got {len(key)}'
            )
        key_size: int = len(key)
        if key_size == AES_128_KEY_SIZE:
            (
                *self.__encryption_round_keys,
                self.__final_encryption_key,
            ) = expand_aes128_key(key)
        if key_size == AES_192_KEY_SIZE:
            (
                *self.__encryption_round_keys,
                self.__final_encryption_key,
            ) = expand_aes192_key(key)
        if key_size == AES_256_KEY_SIZE:
            (
                *self.__encryption_round_keys,
                self.__final_encryption_key,
            ) = expand_aes256_key(key)
        (
            *self.__decryption_round_keys,
            self.__final_decryption_key,
        ) = build_decryption_round_keys(
            self.__encryption_round_keys + [self.__final_encryption_key]
        )

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt one 16-byte block using fused T-table rounds."""

        if len(plaintext) != AES_BLOCK_SIZE:
            raise ValueError(
                f'expected len(plaintext) == {AES_BLOCK_SIZE}, got {len(plaintext)}'
            )
        encryption_table_0: IntLookupTable256 = ENCRYPTION_TABLE_0
        encryption_table_1: IntLookupTable256 = ENCRYPTION_TABLE_1
        encryption_table_2: IntLookupTable256 = ENCRYPTION_TABLE_2
        encryption_table_3: IntLookupTable256 = ENCRYPTION_TABLE_3
        sbox: IntLookupTable256 = SBOX
        round_keys: Iterator[RoundKey] = iter(self.__encryption_round_keys)
        plaintext_integer: int = int.from_bytes(plaintext, byteorder='big')
        initial_round_key: RoundKey = next(round_keys)
        state_0: int = (plaintext_integer >> 96) ^ initial_round_key[0]
        state_1: int = ((plaintext_integer >> 64) & 0xFFFFFFFF) ^ initial_round_key[1]
        state_2: int = ((plaintext_integer >> 32) & 0xFFFFFFFF) ^ initial_round_key[2]
        state_3: int = (plaintext_integer & 0xFFFFFFFF) ^ initial_round_key[3]
        for word_0, word_1, word_2, word_3 in round_keys:
            state_0, state_1, state_2, state_3 = (
                (
                    encryption_table_0[(state_0 >> 24) & 0xFF]
                    ^ encryption_table_1[(state_1 >> 16) & 0xFF]
                    ^ encryption_table_2[(state_2 >> 8) & 0xFF]
                    ^ encryption_table_3[state_3 & 0xFF]
                    ^ word_0
                ),
                (
                    encryption_table_0[(state_1 >> 24) & 0xFF]
                    ^ encryption_table_1[(state_2 >> 16) & 0xFF]
                    ^ encryption_table_2[(state_3 >> 8) & 0xFF]
                    ^ encryption_table_3[state_0 & 0xFF]
                    ^ word_1
                ),
                (
                    encryption_table_0[(state_2 >> 24) & 0xFF]
                    ^ encryption_table_1[(state_3 >> 16) & 0xFF]
                    ^ encryption_table_2[(state_0 >> 8) & 0xFF]
                    ^ encryption_table_3[state_1 & 0xFF]
                    ^ word_2
                ),
                (
                    encryption_table_0[(state_3 >> 24) & 0xFF]
                    ^ encryption_table_1[(state_0 >> 16) & 0xFF]
                    ^ encryption_table_2[(state_1 >> 8) & 0xFF]
                    ^ encryption_table_3[state_2 & 0xFF]
                    ^ word_3
                ),
            )
        word_0, word_1, word_2, word_3 = self.__final_encryption_key
        output_integer: int = (
            (
                (
                    (
                        (sbox[(state_0 >> 24) & 0xFF] << 24)
                        | (sbox[(state_1 >> 16) & 0xFF] << 16)
                        | (sbox[(state_2 >> 8) & 0xFF] << 8)
                        | sbox[state_3 & 0xFF]
                    )
                    ^ word_0
                )
                << 96
            )
            | (
                (
                    (
                        (sbox[(state_1 >> 24) & 0xFF] << 24)
                        | (sbox[(state_2 >> 16) & 0xFF] << 16)
                        | (sbox[(state_3 >> 8) & 0xFF] << 8)
                        | sbox[state_0 & 0xFF]
                    )
                    ^ word_1
                )
                << 64
            )
            | (
                (
                    (
                        (sbox[(state_2 >> 24) & 0xFF] << 24)
                        | (sbox[(state_3 >> 16) & 0xFF] << 16)
                        | (sbox[(state_0 >> 8) & 0xFF] << 8)
                        | sbox[state_1 & 0xFF]
                    )
                    ^ word_2
                )
                << 32
            )
            | (
                (
                    (sbox[(state_3 >> 24) & 0xFF] << 24)
                    | (sbox[(state_0 >> 16) & 0xFF] << 16)
                    | (sbox[(state_1 >> 8) & 0xFF] << 8)
                    | sbox[state_2 & 0xFF]
                )
                ^ word_3
            )
        )
        return output_integer.to_bytes(AES_BLOCK_SIZE, byteorder='big')

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt one block using equivalent-inverse T-table rounds."""

        if len(ciphertext) != AES_BLOCK_SIZE:
            raise ValueError(
                f'expected len(ciphertext) == {AES_BLOCK_SIZE}, got {len(ciphertext)}'
            )
        decryption_table_0: IntLookupTable256 = DECRYPTION_TABLE_0
        decryption_table_1: IntLookupTable256 = DECRYPTION_TABLE_1
        decryption_table_2: IntLookupTable256 = DECRYPTION_TABLE_2
        decryption_table_3: IntLookupTable256 = DECRYPTION_TABLE_3
        inverse_sbox: IntLookupTable256 = INVERSE_SBOX
        round_keys: Iterator[RoundKey] = iter(self.__decryption_round_keys)
        ciphertext_integer: int = int.from_bytes(ciphertext, byteorder='big')
        initial_round_key: RoundKey = next(round_keys)
        state_0: int = (ciphertext_integer >> 96) ^ initial_round_key[0]
        state_1: int = ((ciphertext_integer >> 64) & 0xFFFFFFFF) ^ initial_round_key[1]
        state_2: int = ((ciphertext_integer >> 32) & 0xFFFFFFFF) ^ initial_round_key[2]
        state_3: int = (ciphertext_integer & 0xFFFFFFFF) ^ initial_round_key[3]
        for word_0, word_1, word_2, word_3 in round_keys:
            state_0, state_1, state_2, state_3 = (
                (
                    decryption_table_0[(state_0 >> 24) & 0xFF]
                    ^ decryption_table_1[(state_3 >> 16) & 0xFF]
                    ^ decryption_table_2[(state_2 >> 8) & 0xFF]
                    ^ decryption_table_3[state_1 & 0xFF]
                    ^ word_0
                ),
                (
                    decryption_table_0[(state_1 >> 24) & 0xFF]
                    ^ decryption_table_1[(state_0 >> 16) & 0xFF]
                    ^ decryption_table_2[(state_3 >> 8) & 0xFF]
                    ^ decryption_table_3[state_2 & 0xFF]
                    ^ word_1
                ),
                (
                    decryption_table_0[(state_2 >> 24) & 0xFF]
                    ^ decryption_table_1[(state_1 >> 16) & 0xFF]
                    ^ decryption_table_2[(state_0 >> 8) & 0xFF]
                    ^ decryption_table_3[state_3 & 0xFF]
                    ^ word_2
                ),
                (
                    decryption_table_0[(state_3 >> 24) & 0xFF]
                    ^ decryption_table_1[(state_2 >> 16) & 0xFF]
                    ^ decryption_table_2[(state_1 >> 8) & 0xFF]
                    ^ decryption_table_3[state_0 & 0xFF]
                    ^ word_3
                ),
            )
        word_0, word_1, word_2, word_3 = self.__final_decryption_key
        output_integer: int = (
            (
                (
                    (
                        (inverse_sbox[(state_0 >> 24) & 0xFF] << 24)
                        | (inverse_sbox[(state_3 >> 16) & 0xFF] << 16)
                        | (inverse_sbox[(state_2 >> 8) & 0xFF] << 8)
                        | inverse_sbox[state_1 & 0xFF]
                    )
                    ^ word_0
                )
                << 96
            )
            | (
                (
                    (
                        (inverse_sbox[(state_1 >> 24) & 0xFF] << 24)
                        | (inverse_sbox[(state_0 >> 16) & 0xFF] << 16)
                        | (inverse_sbox[(state_3 >> 8) & 0xFF] << 8)
                        | inverse_sbox[state_2 & 0xFF]
                    )
                    ^ word_1
                )
                << 64
            )
            | (
                (
                    (
                        (inverse_sbox[(state_2 >> 24) & 0xFF] << 24)
                        | (inverse_sbox[(state_1 >> 16) & 0xFF] << 16)
                        | (inverse_sbox[(state_0 >> 8) & 0xFF] << 8)
                        | inverse_sbox[state_3 & 0xFF]
                    )
                    ^ word_2
                )
                << 32
            )
            | (
                (
                    (inverse_sbox[(state_3 >> 24) & 0xFF] << 24)
                    | (inverse_sbox[(state_2 >> 16) & 0xFF] << 16)
                    | (inverse_sbox[(state_1 >> 8) & 0xFF] << 8)
                    | inverse_sbox[state_0 & 0xFF]
                )
                ^ word_3
            )
        )
        return output_integer.to_bytes(AES_BLOCK_SIZE, byteorder='big')
