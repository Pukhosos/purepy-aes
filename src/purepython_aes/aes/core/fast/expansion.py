from struct import unpack
from typing import Final

from purepython_aes.const import AES_128_ROUND_COUNT, AES_256_ROUND_COUNT, SBOX
from purepython_aes.types import IntLookupTable256, RoundKey, RoundKeys

AES_192_EXPANSION_COUNT: Final[int] = 8

ROUND_CONSTANT_WORDS: Final[tuple[int, ...]] = (
    0x00000000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1B000000,
    0x36000000,
)


def expand_aes128_key(key: bytes) -> tuple[RoundKeys, RoundKey]:
    """Expand one AES-128 key directly into four-word round keys."""

    sbox: IntLookupTable256 = SBOX
    round_constant_words: tuple[int, ...] = ROUND_CONSTANT_WORDS
    initial_words: tuple[int, ...] = unpack('>4I', key)
    round_keys: list[RoundKey] = [initial_words]  # type: ignore[list-item]
    word_0, word_1, word_2, word_3 = initial_words
    for round_index in range(1, AES_128_ROUND_COUNT):
        transformed_word: int = (
            (sbox[(word_3 >> 16) & 0xFF] << 24)
            | (sbox[(word_3 >> 8) & 0xFF] << 16)
            | (sbox[word_3 & 0xFF] << 8)
            | sbox[(word_3 >> 24) & 0xFF]
        ) ^ round_constant_words[round_index]
        word_0 ^= transformed_word
        word_1 ^= word_0
        word_2 ^= word_1
        word_3 ^= word_2
        round_keys.append((word_0, word_1, word_2, word_3))
    transformed_word = (
        (sbox[(word_3 >> 16) & 0xFF] << 24)
        | (sbox[(word_3 >> 8) & 0xFF] << 16)
        | (sbox[word_3 & 0xFF] << 8)
        | sbox[(word_3 >> 24) & 0xFF]
    ) ^ 0x36000000
    word_0 ^= transformed_word
    word_1 ^= word_0
    word_2 ^= word_1
    return round_keys, (word_0, word_1, word_2, word_3 ^ word_2)


def expand_aes192_key(key: bytes) -> tuple[RoundKeys, RoundKey]:
    """Expand one AES-192 key directly into four-word round keys."""

    sbox: IntLookupTable256 = SBOX
    round_constant_words: tuple[int, ...] = ROUND_CONSTANT_WORDS
    (
        source_word_0,
        source_word_1,
        source_word_2,
        source_word_3,
        source_word_4,
        source_word_5,
    ) = unpack('>6I', key)
    leftover_word_0: int = source_word_4
    leftover_word_1: int = source_word_5
    round_keys: list[RoundKey] = [
        (source_word_0, source_word_1, source_word_2, source_word_3),
    ]
    for round_constant_index in range(1, AES_192_EXPANSION_COUNT):
        transformed_word: int = (
            (sbox[(source_word_5 >> 16) & 0xFF] << 24)
            | (sbox[(source_word_5 >> 8) & 0xFF] << 16)
            | (sbox[source_word_5 & 0xFF] << 8)
            | sbox[(source_word_5 >> 24) & 0xFF]
        ) ^ round_constant_words[round_constant_index]
        next_word_0: int = source_word_0 ^ transformed_word
        next_word_1: int = source_word_1 ^ next_word_0
        next_word_2: int = source_word_2 ^ next_word_1
        next_word_3: int = source_word_3 ^ next_word_2
        next_word_4: int = source_word_4 ^ next_word_3
        next_word_5: int = source_word_5 ^ next_word_4
        if round_constant_index % 2 == 1:
            round_keys.append(
                (leftover_word_0, leftover_word_1, next_word_0, next_word_1),
            )
            round_keys.append((next_word_2, next_word_3, next_word_4, next_word_5))
        else:
            round_keys.append((next_word_0, next_word_1, next_word_2, next_word_3))
            leftover_word_0 = next_word_4
            leftover_word_1 = next_word_5
        source_word_0 = next_word_0
        source_word_1 = next_word_1
        source_word_2 = next_word_2
        source_word_3 = next_word_3
        source_word_4 = next_word_4
        source_word_5 = next_word_5
    final_transformed_word: int = (
        (sbox[(source_word_5 >> 16) & 0xFF] << 24)
        | (sbox[(source_word_5 >> 8) & 0xFF] << 16)
        | (sbox[source_word_5 & 0xFF] << 8)
        | sbox[(source_word_5 >> 24) & 0xFF]
    ) ^ 0x80000000
    final_word_0: int = source_word_0 ^ final_transformed_word
    final_word_1: int = source_word_1 ^ final_word_0
    final_word_2: int = source_word_2 ^ final_word_1
    return round_keys, (
        final_word_0,
        final_word_1,
        final_word_2,
        source_word_3 ^ final_word_2,
    )


def expand_aes256_key(key: bytes) -> tuple[RoundKeys, RoundKey]:
    """Expand one AES-256 key directly into four-word round keys."""

    sbox: IntLookupTable256 = SBOX
    round_constant_words: tuple[int, ...] = ROUND_CONSTANT_WORDS
    (
        source_word_0,
        source_word_1,
        source_word_2,
        source_word_3,
        previous_word_0,
        previous_word_1,
        previous_word_2,
        previous_word_3,
    ) = unpack('>8I', key)
    round_keys: list[RoundKey] = [
        (source_word_0, source_word_1, source_word_2, source_word_3),
        (previous_word_0, previous_word_1, previous_word_2, previous_word_3),
    ]
    for round_index in range(2, AES_256_ROUND_COUNT):
        transformed_word: int = (
            (
                (
                    (sbox[(previous_word_3 >> 16) & 0xFF] << 24)
                    | (sbox[(previous_word_3 >> 8) & 0xFF] << 16)
                    | (sbox[previous_word_3 & 0xFF] << 8)
                    | sbox[(previous_word_3 >> 24) & 0xFF]
                )
                ^ round_constant_words[round_index >> 1]
            )
            if round_index & 0x01 == 0
            else (
                (sbox[(previous_word_3 >> 24) & 0xFF] << 24)
                | (sbox[(previous_word_3 >> 16) & 0xFF] << 16)
                | (sbox[(previous_word_3 >> 8) & 0xFF] << 8)
                | sbox[previous_word_3 & 0xFF]
            )
        )
        next_word_0: int = source_word_0 ^ transformed_word
        next_word_1: int = source_word_1 ^ next_word_0
        next_word_2: int = source_word_2 ^ next_word_1
        next_word_3: int = source_word_3 ^ next_word_2
        round_keys.append((next_word_0, next_word_1, next_word_2, next_word_3))
        source_word_0 = previous_word_0
        source_word_1 = previous_word_1
        source_word_2 = previous_word_2
        source_word_3 = previous_word_3
        previous_word_0 = next_word_0
        previous_word_1 = next_word_1
        previous_word_2 = next_word_2
        previous_word_3 = next_word_3
    transformed_word = (
        (sbox[(previous_word_3 >> 16) & 0xFF] << 24)
        | (sbox[(previous_word_3 >> 8) & 0xFF] << 16)
        | (sbox[previous_word_3 & 0xFF] << 8)
        | sbox[(previous_word_3 >> 24) & 0xFF]
    ) ^ 0x40000000
    next_word_0 = source_word_0 ^ transformed_word
    next_word_1 = source_word_1 ^ next_word_0
    next_word_2 = source_word_2 ^ next_word_1
    return round_keys, (
        next_word_0,
        next_word_1,
        next_word_2,
        source_word_3 ^ next_word_2,
    )
