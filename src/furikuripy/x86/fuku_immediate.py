from __future__ import annotations

import ctypes

from pydantic import BaseModel

from furikuripy.common import rng
from furikuripy.x86.misc import FukuOperandSize


class FukuImmediate(BaseModel):
    relocate: bool = False
    immediate_value: int = 0

    def __init__(self, immediate_value: int = 0, relocate: bool = False):
        super().__init__(
            immediate_value = immediate_value,
            relocate = relocate
        )

    @property
    def is_8(self) -> bool:
        return -0x80 <= self.immediate_value <= 0x7F

    @property
    def is_16(self) -> bool:
        return -0x8000 <= self.immediate_value <= 0x7FFF

    @property
    def is_32(self) -> bool:
        return -0x80000000 <= self.immediate_value <= 0x7FFFFFFF

    @property
    def is_64(self) -> bool:
        return (self.immediate_value & 0xFFFFFFFF00000000) != 0

    @property
    def size(self):
        if self.is_8:
            return FukuOperandSize.SIZE_8
        if self.is_16:
            return FukuOperandSize.SIZE_16
        if self.is_32:
            return FukuOperandSize.SIZE_32
        if self.is_64:
            return FukuOperandSize.SIZE_64

        return FukuOperandSize.SIZE_0

    @property
    def is_relocate(self):
        return self.relocate

    @property
    def immediate8(self):
        return ctypes.c_uint8(self.immediate_value & 0xFF).value

    @property
    def immediate16(self):
        return ctypes.c_uint16(self.immediate_value & 0xFFFF).value

    @property
    def immediate32(self):
        return ctypes.c_uint32(self.immediate_value & 0xFFFFFFFF).value

    @property
    def immediate64(self):
        return ctypes.c_uint64(self.immediate_value).value

    @property
    def signed_value8(self):
        return self.immediate_value & 0xFF

    @property
    def signed_value16(self):
        return self.immediate_value & 0xFFFF

    @property
    def signed_value32(self):
        return self.immediate_value & 0xFFFFFFFF

    @property
    def signed_value64(self):
        return self.immediate_value

    @staticmethod
    def get_random_x64(size: FukuOperandSize) -> FukuImmediate:
        sw = rng.randint(0, size.value * 4)

        match sw:
            case 0:
                return FukuImmediate(rng.randint(1, size.value * 0xFF) * 4)

            case 1:
                return FukuImmediate(rng.randint(1, 0xFFFFFFFF))

            case (
                2 | 3 | 4 | 5 |
                6 | 7 | 8 | 9 |
                10 | 11 | 12 | 13 |
                14 | 15 | 16
            ):
                return FukuImmediate(rng.randint(1, 0xF) * (1 << ((sw - 2) * 4)))

            case _:
                return FukuImmediate(rng.randint(1, 0xFFFFFFFF))
