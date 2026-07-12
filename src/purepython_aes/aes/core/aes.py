from dataclasses import dataclass

from purepython_aes.aes.core.expansion import expand_key
from purepython_aes.aes.core.state import AesState
from purepython_aes.aes.interface import Aes
from purepython_aes.const import AES_BLOCK_SIZE


@dataclass(slots=True)
class AesCore(Aes):
    """Implement `encrypt_block` and `decrypt_block` methods."""

    __round_keys: tuple[bytes, ...]

    def __init__(self, key: bytes) -> None:
        if len(key) != self.key_size:
            raise ValueError(f'expected len(key) == {self.key_size}, got {len(key)}')
        self.__round_keys = expand_key(key, self.round_count)

    def encrypt_block(self, plaintext: bytes) -> bytes:
        if len(plaintext) != AES_BLOCK_SIZE:
            raise ValueError(
                f'Expected len(plaintext) == {AES_BLOCK_SIZE}, got {len(plaintext)}'
            )
        state: AesState = AesState.from_bytes(plaintext)
        state.add_round_key(self.__round_keys[0])
        for round_index in range(1, self.round_count):
            state.subs_bytes()
            state.shift_rows()
            state.mix_columns()
            state.add_round_key(self.__round_keys[round_index])
        state.subs_bytes()
        state.shift_rows()
        state.add_round_key(self.__round_keys[self.round_count])
        return state.to_bytes()

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != AES_BLOCK_SIZE:
            raise ValueError(
                f'Expected len(ciphertext) == {AES_BLOCK_SIZE}, got {len(ciphertext)}'
            )
        state: AesState = AesState.from_bytes(ciphertext)
        state.add_round_key(self.__round_keys[self.round_count])
        for round_index in range(self.round_count - 1, 0, -1):
            state.inverse_shift_rows()
            state.inverse_subs_bytes()
            state.add_round_key(self.__round_keys[round_index])
            state.inverse_mix_columns()
        state.inverse_shift_rows()
        state.inverse_subs_bytes()
        state.add_round_key(self.__round_keys[0])
        return state.to_bytes()
