from __future__ import annotations

import ctypes

from pydantic import BaseModel

from furikuripy.common import rng
from furikuripy.x86.misc import FukuOperandSize


class FukuImmediate(BaseModel):
    relocate: bool = False
    immediate_value: int = 0

    def __init__(self, immediate_value: int = 0, relocate: bool = False):
        super().__init__(immediate_value=immediate_value, relocate=relocate)

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
        return -0x8000000000000000 <= self.immediate_value <= 0x7FFFFFFFFFFFFFFF

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
        max = min(
            pow(2, pow(2, 3) * min(size.value, FukuOperandSize.SIZE_32.value)) - 1,
            0x7FFFFFFF,
        )
        value = rng.randint(1, max)
        return FukuImmediate(value)

    def to_iced(self) -> int:
        return self.immediate_value

    def to_iced_name(self) -> str:
        p = "i" if self.immediate_value < 0 else "u"
        s = "64" if self.size == FukuOperandSize.SIZE_64 else "32"
        return f"{p}{s}"

    def to_iced_code(self, is_used_short_imm, size: int) -> str:
        imm_size = 0
        if self.is_8:
            imm_size = 8
        else:
            imm_size = 32

        imm_size = min(imm_size, size)
        return f"IMM{imm_size}"
