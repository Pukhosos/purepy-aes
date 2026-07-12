from abc import ABC, abstractmethod


class BasePadding(ABC):
    """Reversible block-padding algorithm."""

    @abstractmethod
    def pad(self, data: bytes) -> bytes:
        """Pad data to a multiple of 16 bytes."""

        raise NotImplementedError

    @abstractmethod
    def unpad(self, data: bytes) -> bytes:
        """Remove padding from block-aligned data."""

        raise NotImplementedError
