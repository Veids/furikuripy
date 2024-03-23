from __future__ import annotations

from enum import Enum
from pydantic import BaseModel
from typing import Optional

from x86.fuku_register import FukuRegister, FukuRegisterEnum
from x86.fuku_immediate import FukuImmediate
from x86.fuku_operand import FukuOperand, FukuOperandScale, FukuOperandSize, FukuPrefix
from x86.fuku_register_math import get_random_bit_by_mask


class FukuT0Types(Enum):
    FUKU_T0_NONE = 0
    FUKU_T0_REGISTER = 1
    FUKU_T0_OPERAND = 2
    FUKU_T0_IMMEDIATE = 3


class FukuType(BaseModel):
    type: FukuT0Types

    base: FukuRegister
    index: FukuRegister
    scale: FukuOperandScale
    disp: FukuImmediate
    size: FukuOperandSize
    segment: FukuPrefix

    @property
    def register(self) -> FukuRegister:
        return self.base

    @property
    def operand(self) -> FukuOperand:
        return FukuOperand(
            base = self.base,
            index = self.index,
            scale = self.scale,
            disp = self.disp,
            size = self.size,
            segment = self.segment
        )

    @property
    def immediate(self) -> FukuImmediate:
        return self.disp

    def get_mask_register(self):
        match self.type:
            case FukuT0Types.FUKU_T0_REGISTER:
                return self.register.get_flag_complex(FukuOperandSize.SIZE_64)

            case FukuT0Types.FUKU_T0_OPERAND:
                op = self.operand

                # TODO: fix computation
                result = 0

                if op.base.reg != FukuRegisterEnum.REG_NONE:
                    result &= op.base.get_flag_complex(FukuOperandSize.SIZE_64)

                if op.index.reg != FukuRegisterEnum.REG_NONE:
                    result &= op.index.get_flag_complex(FukuOperandSize.SIZE_64)

                return result

        return 0

    @staticmethod
    def get_random_operand_dst_x64(allow_inst: int, size: FukuOperandSize, allow_regs: int, disallow_regs: int) -> Optional[FukuType]:
        if not allow_inst:
            return None

        match get_random_bit_by_mask(allow_inst, 0, 2):
            case 0:
                op = FukuRegisterEnum.get_random_free_register_x64(allow_regs, size, disallow_regs)
                if op != FukuRegisterEnum.REG_NONE:
                    return FukuRegister(op).ftype

        return None

    @staticmethod
    def get_random_operand_src_x64(allow_inst: int, size: FukuOperandSize, disallow_regs: int) -> Optional[FukuType]:
        if not allow_inst:
            return None

        match get_random_bit_by_mask(allow_inst, 0, 2):
            case 0:
                op = FukuRegisterEnum.get_random_register(size, False, disallow_regs)
                if op != FukuRegisterEnum.REG_NONE:
                    return FukuRegister(op).ftype

            case 2:
                return FukuImmediate.get_random_x64(size).ftype

        return None


def reg_to_fuku_type(reg: FukuRegister) -> FukuType:
    return FukuType(
        segment = FukuPrefix.FUKU_PREFIX_NONE,
        base = reg,
        index = FukuRegister(FukuRegisterEnum.REG_NONE),
        scale = FukuOperandScale.FUKU_OPERAND_SCALE_1,
        disp = FukuImmediate(),
        size = reg.size,
        type = FukuT0Types.FUKU_T0_REGISTER
    )

def operand_to_fuku_type(op: FukuOperand) -> FukuType:
    return FukuType(
        segment = op.segment,
        base = op.base,
        index = op.index,
        scale = op.scale,
        disp = op.disp,
        size = op.size,
        type = FukuT0Types.FUKU_T0_OPERAND
    )

def immediate_to_fuku_type(imm: FukuImmediate) -> FukuType:
    return FukuType(
        segment = FukuPrefix.FUKU_PREFIX_NONE,
        base = FukuRegister(FukuRegisterEnum.REG_NONE),
        index = FukuRegister(FukuRegisterEnum.REG_NONE),
        scale = FukuOperandScale.FUKU_OPERAND_SCALE_1,
        disp = imm,
        size = FukuOperandSize.SIZE_0,
        type = FukuT0Types.FUKU_T0_IMMEDIATE
    )

FukuRegister.ftype = property(reg_to_fuku_type)
FukuOperand.ftype = property(operand_to_fuku_type)
FukuImmediate.ftype = property(immediate_to_fuku_type)
