from abc import ABC, abstractmethod
from collections.abc import Callable
from functools import wraps
from typing import Any

from purepython_aes.const import AES_BLOCK_SIZE


def guard_unpad(
    unpad: Callable[[Any, bytes], bytes],
) -> Callable[[Any, bytes], bytes]:
    @wraps(unpad)
    def wrapper(self: Any, data: bytes) -> bytes:
        if len(data) == 0:
            raise ValueError('padded data must not be empty')
        if len(data) % AES_BLOCK_SIZE != 0:
            raise ValueError(
                f'expected len(data) % {AES_BLOCK_SIZE} == 0, got {len(data)}'
            )
        return unpad(self, data)

    return wrapper


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


class BaseGuardedPadding(BasePadding):
    def __init_subclass__(cls) -> None:
        setattr(cls, 'unpad', guard_unpad(cls.unpad))  # noqa: B010
