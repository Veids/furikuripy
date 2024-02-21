from enum import Enum
from pydantic import BaseModel

from x86.misc import FukuOperandSize
from x86.fuku_register import FukuRegister, FukuRegisterEnum
from x86.fuku_immediate import FukuImmediate


class FukuPrefix(Enum):
    FUKU_PREFIX_NONE             = 0
    FUKU_PREFIX_LOCK             = 0xF0
    FUKU_PREFIX_REPE             = 0xF3
    FUKU_PREFIX_REPNE            = 0xF2
    FUKU_PREFIX_CS               = 0x2E
    FUKU_PREFIX_SS               = 0x36
    FUKU_PREFIX_DS               = 0x3E
    FUKU_PREFIX_ES               = 0x26
    FUKU_PREFIX_FS               = 0x64
    FUKU_PREFIX_GS               = 0x65
    FUKU_PREFIX_OVERRIDE_DATA    = 0x66
    FUKU_PREFIX_OVERRIDE_ADDRESS = 0x67


class FukuOperandScale(Enum):
    FUKU_OPERAND_SCALE_1 = 0 # [index * 1]
    FUKU_OPERAND_SCALE_2 = 1 # [index * 2]
    FUKU_OPERAND_SCALE_4 = 2 # [index * 4]
    FUKU_OPERAND_SCALE_8 = 3 # [index * 8]


class FukuMemOperandType(Enum):
    FUKU_MEM_OPERAND_BASE_ONLY = 0
    FUKU_MEM_OPERAND_DISP_ONLY = 1
    FUKU_MEM_OPERAND_BASE_DISP = 2
    FUKU_MEM_OPERAND_INDEX_DISP = 3
    FUKU_MEM_OPERAND_BASE_INDEX = 4
    FUKU_MEM_OPERAND_BASE_INDEX_DISP = 5


class FukuOperand(BaseModel):
    base: FukuRegister
    index: FukuRegister
    scale: FukuOperandScale
    disp: FukuImmediate
    size: FukuOperandSize
    segment: FukuPrefix

    @property
    def type(self) -> FukuMemOperandType:
        if self.base.reg != FukuRegisterEnum.FUKU_REG_NONE:
            if self.index.reg != FukuRegisterEnum.FUKU_REG_NONE:
                if self.disp.immediate64:
                    return FukuMemOperandType.FUKU_MEM_OPERAND_BASE_INDEX_DISP
                else:
                    return FukuMemOperandType.FUKU_MEM_OPERAND_BASE_INDEX
            else:
                if self.disp.immediate64:
                    return FukuMemOperandType.FUKU_MEM_OPERAND_BASE_DISP
                else:
                    return FukuMemOperandType.FUKU_MEM_OPERAND_BASE_ONLY
        else:
            if self.index.reg != FukuRegisterEnum.FUKU_REG_NONE:
                return FukuMemOperandType.FUKU_MEM_OPERAND_INDEX_DISP
            else:
                return FukuMemOperandType.FUKU_MEM_OPERAND_DISP_ONLY

    @property
    def low_rex(self) -> int:
        return ((1 if self.index.is_ext64 else 0) << 1) | (1 if self.base.is_ext64 else 0)
