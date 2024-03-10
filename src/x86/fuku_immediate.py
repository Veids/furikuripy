import ctypes

from pydantic import BaseModel

from x86.misc import FukuOperandSize


class FukuImmediate(BaseModel):
    relocate: bool = False
    immediate_value: int = 0

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
            return FukuOperandSize.FUKU_OPERAND_SIZE_8
        if self.is_16:
            return FukuOperandSize.FUKU_OPERAND_SIZE_16
        if self.is_32:
            return FukuOperandSize.FUKU_OPERAND_SIZE_32
        if self.is_64:
            return FukuOperandSize.FUKU_OPERAND_SIZE_64

        return FukuOperandSize.FUKU_OPERAND_SIZE_0

    @property
    def is_relocate(self):
        return self.relocate

    @property
    def immediate8(self):
        return ctypes.c_uint8(self.immediate_value & 0xFF).value

    @property
    def immediate16(self):
        return ctypes.c_uint8(self.immediate_value & 0xFFFF).value

    @property
    def immediate32(self):
        return ctypes.c_uint8(self.immediate_value & 0xFFFFFFFF).value

    @property
    def immediate64(self):
        return ctypes.c_uint8(self.immediate_value).value

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
