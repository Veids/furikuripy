from __future__ import annotations

from enum import Enum
from pydantic import BaseModel
from capstone.x86 import X86Op
from capstone import x86_const

from x86.misc import FukuOperandSize
from x86.fuku_register import FukuRegister, FukuRegisterEnum, CAP_TO_FUKU_TABLE
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

    @staticmethod
    def from_capstone_mem_segment(val: int) -> FukuPrefix:
        if val == x86_const.X86_REG_GS:
            return FukuPrefix.FUKU_PREFIX_GS


class FukuOperandScale(Enum):
    FUKU_OPERAND_SCALE_1 = 0 # [index * 1]
    FUKU_OPERAND_SCALE_2 = 1 # [index * 2]
    FUKU_OPERAND_SCALE_4 = 2 # [index * 4]
    FUKU_OPERAND_SCALE_8 = 3 # [index * 8]

    @staticmethod
    def from_capstone(val: int) -> FukuOperandScale:
        match val:
            case 1:
                return FukuOperandScale.FUKU_OPERAND_SCALE_1

            case 2:
                return FukuOperandScale.FUKU_OPERAND_SCALE_2

            case 4:
                return FukuOperandScale.FUKU_OPERAND_SCALE_4

            case 8:
                return FukuOperandScale.FUKU_OPERAND_SCALE_8


class FukuMemOperandType(Enum):
    FUKU_MEM_OPERAND_BASE_ONLY = 0
    FUKU_MEM_OPERAND_DISP_ONLY = 1
    FUKU_MEM_OPERAND_BASE_DISP = 2
    FUKU_MEM_OPERAND_INDEX_DISP = 3
    FUKU_MEM_OPERAND_BASE_INDEX = 4
    FUKU_MEM_OPERAND_BASE_INDEX_DISP = 5


class FukuOperand(BaseModel):
    base: FukuRegister = FukuRegister(FukuRegisterEnum.FUKU_REG_NONE)
    index: FukuRegister = FukuRegister(FukuRegisterEnum.FUKU_REG_NONE)
    scale: FukuOperandScale = FukuOperandScale.FUKU_OPERAND_SCALE_1
    disp: FukuImmediate = FukuImmediate(0)
    size: FukuOperandSize
    segment: FukuPrefix = FukuPrefix.FUKU_PREFIX_NONE

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

    @staticmethod
    def from_capstone(op: X86Op) -> FukuOperand:
        base = FukuRegisterEnum.FUKU_REG_NONE
        index = FukuRegisterEnum.FUKU_REG_NONE
        scale = FukuOperandScale.FUKU_OPERAND_SCALE_1
        imm = FukuImmediate()
        size = FukuOperandSize.SIZE_0
        segment = FukuPrefix.FUKU_PREFIX_NONE
        
        if op.type == x86_const.X86_OP_MEM:
            size = FukuOperandSize(op.size)

            if op.mem.base != x86_const.X86_REG_INVALID:
                base = CAP_TO_FUKU_TABLE[op.mem.base]

            if op.mem.index != x86_const.X86_REG_INVALID:
                index = CAP_TO_FUKU_TABLE[op.mem.index]
                scale = FukuOperandScale.from_capstone(op.mem.scale)

            if op.mem.segment != x86_const.X86_REG_INVALID:
                segment = FukuPrefix.from_capstone_mem_segment(op.mem.segment)

            imm = FukuImmediate(op.mem.disp)

        return FukuOperand(
            base = FukuRegister(base),
            index = FukuRegister(index),
            scale = scale,
            disp = imm,
            size = size,
            segment = segment
        )

def qword_ptr(
        **kwargs
    ) -> FukuOperand:
    return FukuOperand(
        size = FukuOperandSize.SIZE_64,
        **kwargs
    )
