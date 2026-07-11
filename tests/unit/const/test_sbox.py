from typing import Final

from pytest import mark

from purepython_aes.const import INVERSE_SBOX, SBOX

SBOX_SIZE: Final[int] = 256


@mark.quick
def test_sbox_size() -> None:
    assert len(SBOX) == SBOX_SIZE


@mark.quick
def test_inverse_sbox_size() -> None:
    assert len(INVERSE_SBOX) == SBOX_SIZE


@mark.quick
def test_sbox_entries_are_valid_bytes() -> None:
    for n in SBOX:
        assert 0x00 <= n <= 0xFF


@mark.quick
def test_inverse_sbox_entries_are_valid_bytes() -> None:
    for n in INVERSE_SBOX:
        assert 0x00 <= n <= 0xFF


@mark.quick
def test_sbox_is_permutation() -> None:
    assert set(SBOX) == set(range(SBOX_SIZE))


@mark.quick
def test_inverse_sbox_is_permutation() -> None:
    assert set(INVERSE_SBOX) == set(range(SBOX_SIZE))


@mark.quick
def test_inverse_sbox_inverts_sbox() -> None:
    for n in range(SBOX_SIZE):
        assert INVERSE_SBOX[SBOX[n]] == n


@mark.quick
def test_sbox_inverts_inverse_sbox() -> None:
    for n in range(SBOX_SIZE):
        assert SBOX[INVERSE_SBOX[n]] == n
