from enum import Enum
from pydantic import BaseModel

from x86.fuku_register import FukuRegister
from x86.fuku_immediate import FukuImmediate
from x86.fuku_operand import FukuOperand, FukuOperandScale, FukuOperandSize, FukuPrefix


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
