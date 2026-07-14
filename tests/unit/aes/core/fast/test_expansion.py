from hypothesis import given
from pytest import mark

from purepython_aes.aes.core.fast.expansion import (
    expand_aes128_key,
    expand_aes192_key,
    expand_aes256_key,
)
from purepython_aes.aes.core.reference.expansion import (
    expand_key as reference_expand_key,
)
from purepython_aes.const import (
    AES_128_ROUND_COUNT,
    AES_192_ROUND_COUNT,
    AES_256_ROUND_COUNT,
    AES_BLOCK_SIZE,
)
from purepython_aes.types import RoundKeys
from tests.unit.aes.strategies import aes128key, aes192key, aes256key


def serialize_round_keys(
    round_keys: RoundKeys,
) -> tuple[bytes, ...]:
    serialized_round_keys: list[bytes] = []
    for round_key in round_keys:
        round_key_integer: int = (
            (round_key[0] << 96)
            | (round_key[1] << 64)
            | (round_key[2] << 32)
            | round_key[3]
        )
        serialized_round_keys.append(
            round_key_integer.to_bytes(
                AES_BLOCK_SIZE,
                byteorder='big',
            )
        )
    return tuple(serialized_round_keys)


@mark.quick
class TestFastKeyExpansion:
    @staticmethod
    @given(key=aes128key)
    def test_aes128_matches_reference(key: bytes) -> None:
        encryption_round_keys, final_encryption_key = expand_aes128_key(key)
        assert serialize_round_keys(
            encryption_round_keys + [final_encryption_key]
        ) == reference_expand_key(key, AES_128_ROUND_COUNT)

    @staticmethod
    @given(key=aes192key)
    def test_aes192_matches_reference(key: bytes) -> None:
        encryption_round_keys, final_encryption_key = expand_aes192_key(key)
        assert serialize_round_keys(
            encryption_round_keys + [final_encryption_key]
        ) == reference_expand_key(key, AES_192_ROUND_COUNT)

    @staticmethod
    @given(key=aes256key)
    def test_aes256_matches_reference(key: bytes) -> None:
        encryption_round_keys, final_encryption_key = expand_aes256_key(key)
        assert serialize_round_keys(
            encryption_round_keys + [final_encryption_key]
        ) == reference_expand_key(key, AES_256_ROUND_COUNT)
