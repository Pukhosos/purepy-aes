from abc import ABC, abstractmethod


class Aes(ABC):
    """Base class for AES-128, AES-192, and AES-256 algorithms."""

    @property
    @abstractmethod
    def key_size(self) -> int:
        """AES key length in bytes."""

        raise NotImplementedError

    @property
    @abstractmethod
    def round_count(self) -> int:
        """Number of AES rounds."""

        raise NotImplementedError

    @abstractmethod
    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt one 16-byte AES block."""

        raise NotImplementedError

    @abstractmethod
    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt one 16-byte AES block."""

        raise NotImplementedError
