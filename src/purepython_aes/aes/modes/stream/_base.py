from abc import ABC, abstractmethod
from dataclasses import dataclass
from secrets import token_bytes

from purepython_aes.aes.modes._base import CipherMode
from purepython_aes.const import AES_BLOCK_SIZE


@dataclass(slots=True)
class StreamCipherMode(CipherMode, ABC):
    def encrypt(self, plaintext: bytes) -> bytes:
        iv: bytes = token_bytes(AES_BLOCK_SIZE)
        ciphertext: bytes = self.__encrypt_stream__(iv, plaintext)
        return iv + ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.__decrypt_stream__(
            initialization_value=ciphertext[:AES_BLOCK_SIZE],
            ciphertext=ciphertext[AES_BLOCK_SIZE:],
        )

    @abstractmethod
    def __encrypt_stream__(
        self,
        initialization_value: bytes,
        plaintext: bytes,
    ) -> bytes:
        """Transform plaintext into ciphertext."""

        raise NotImplementedError

    @abstractmethod
    def __decrypt_stream__(
        self,
        initialization_value: bytes,
        ciphertext: bytes,
    ) -> bytes:
        """Transform ciphertext into plaintext."""

        raise NotImplementedError
