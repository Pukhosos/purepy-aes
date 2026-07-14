from purepython_aes.aes.core.fast.ttables import (
    DECRYPTION_TABLE_0,
    DECRYPTION_TABLE_1,
    DECRYPTION_TABLE_2,
    DECRYPTION_TABLE_3,
)
from purepython_aes.const import SBOX
from purepython_aes.types import IntLookupTable256, RoundKey, RoundKeys


def build_decryption_round_keys(
    encryption_round_keys: RoundKeys,
    final_encryption_key: RoundKey,
) -> tuple[RoundKeys, RoundKey]:
    """Build the equivalent-inverse decryption key schedule."""

    decryption_table_0: IntLookupTable256 = DECRYPTION_TABLE_0
    decryption_table_1: IntLookupTable256 = DECRYPTION_TABLE_1
    decryption_table_2: IntLookupTable256 = DECRYPTION_TABLE_2
    decryption_table_3: IntLookupTable256 = DECRYPTION_TABLE_3
    sbox: IntLookupTable256 = SBOX
    round_count: int = len(encryption_round_keys)
    decryption_round_keys: list[RoundKey] = [final_encryption_key]
    for encryption_round_index in range(round_count - 1, 0, -1):
        word_0, word_1, word_2, word_3 = encryption_round_keys[encryption_round_index]
        decryption_round_keys.append(
            (
                (
                    decryption_table_0[sbox[(word_0 >> 24) & 0xFF]]
                    ^ decryption_table_1[sbox[(word_0 >> 16) & 0xFF]]
                    ^ decryption_table_2[sbox[(word_0 >> 8) & 0xFF]]
                    ^ decryption_table_3[sbox[word_0 & 0xFF]]
                ),
                (
                    decryption_table_0[sbox[(word_1 >> 24) & 0xFF]]
                    ^ decryption_table_1[sbox[(word_1 >> 16) & 0xFF]]
                    ^ decryption_table_2[sbox[(word_1 >> 8) & 0xFF]]
                    ^ decryption_table_3[sbox[word_1 & 0xFF]]
                ),
                (
                    decryption_table_0[sbox[(word_2 >> 24) & 0xFF]]
                    ^ decryption_table_1[sbox[(word_2 >> 16) & 0xFF]]
                    ^ decryption_table_2[sbox[(word_2 >> 8) & 0xFF]]
                    ^ decryption_table_3[sbox[word_2 & 0xFF]]
                ),
                (
                    decryption_table_0[sbox[(word_3 >> 24) & 0xFF]]
                    ^ decryption_table_1[sbox[(word_3 >> 16) & 0xFF]]
                    ^ decryption_table_2[sbox[(word_3 >> 8) & 0xFF]]
                    ^ decryption_table_3[sbox[word_3 & 0xFF]]
                ),
            )
        )
    return decryption_round_keys, encryption_round_keys[0]
