from enum import Enum
from pydantic import BaseModel

from x86.misc import FukuOperandSize, FukuCondition


class FukuRegisterEnum(Enum):
    FUKU_REG_NONE = 0
    FUKU_REG_RAX = 1
    FUKU_REG_EAX = 2
    FUKU_REG_AX = 3
    FUKU_REG_AH = 4
    FUKU_REG_AL = 5
    FUKU_REG_RCX = 6
    FUKU_REG_ECX = 7
    FUKU_REG_CX = 8
    FUKU_REG_CH = 9
    FUKU_REG_CL = 10
    FUKU_REG_RDX = 11
    FUKU_REG_EDX = 12
    FUKU_REG_DX = 13
    FUKU_REG_DH = 14
    FUKU_REG_DL = 15
    FUKU_REG_RBX = 16
    FUKU_REG_EBX = 17
    FUKU_REG_BX = 18
    FUKU_REG_BH = 19
    FUKU_REG_BL = 20
    FUKU_REG_RSP = 21
    FUKU_REG_ESP = 22
    FUKU_REG_SP = 23
    FUKU_REG_SPL = 24
    FUKU_REG_RBP = 25
    FUKU_REG_EBP = 26
    FUKU_REG_BP = 27
    FUKU_REG_BPL = 28
    FUKU_REG_RSI = 29
    FUKU_REG_ESI = 30
    FUKU_REG_SI = 31
    FUKU_REG_SIL = 32
    FUKU_REG_RDI = 33
    FUKU_REG_EDI = 34
    FUKU_REG_DI = 35
    FUKU_REG_DIL = 36
    FUKU_REG_R8 = 37
    FUKU_REG_R8D = 38
    FUKU_REG_R8W = 39
    FUKU_REG_R8B = 40
    FUKU_REG_R9 = 41
    FUKU_REG_R9D = 42
    FUKU_REG_R9W = 43
    FUKU_REG_R9B = 44
    FUKU_REG_R10 = 45
    FUKU_REG_R10D = 46
    FUKU_REG_R10W = 47
    FUKU_REG_R10B = 48
    FUKU_REG_R11 = 49
    FUKU_REG_R11D = 50
    FUKU_REG_R11W = 51
    FUKU_REG_R11B = 52
    FUKU_REG_R12 = 53
    FUKU_REG_R12D = 54
    FUKU_REG_R12W = 55
    FUKU_REG_R12B = 56
    FUKU_REG_R13 = 57
    FUKU_REG_R13D = 58
    FUKU_REG_R13W = 59
    FUKU_REG_R13B = 60
    FUKU_REG_R14 = 61
    FUKU_REG_R14D = 62
    FUKU_REG_R14W = 63
    FUKU_REG_R14B = 64
    FUKU_REG_R15 = 65
    FUKU_REG_R15D = 66
    FUKU_REG_R15W = 67
    FUKU_REG_R15B = 68
    FUKU_REG_MAX = 69


class FukuRegisterIndex(Enum):
    FUKU_REG_INDEX_AX = 0
    FUKU_REG_INDEX_R8 = 0
    FUKU_REG_INDEX_CX = 1
    FUKU_REG_INDEX_R9 = 1
    FUKU_REG_INDEX_DX = 2
    FUKU_REG_INDEX_R10 = 2
    FUKU_REG_INDEX_BX = 3
    FUKU_REG_INDEX_R11 = 3
    FUKU_REG_INDEX_SP = 4
    FUKU_REG_INDEX_R12 = 4
    FUKU_REG_INDEX_BP = 5
    FUKU_REG_INDEX_R13 = 5
    FUKU_REG_INDEX_SI = 6
    FUKU_REG_INDEX_R14 = 6
    FUKU_REG_INDEX_DI = 7
    FUKU_REG_INDEX_R15 = 7

    FUKU_REG_INDEX_INVALID = -1


class FukuRegister(BaseModel):
    reg: FukuRegisterEnum
    index: FukuRegisterIndex
    size: FukuOperandSize

    is_ext64: bool
    is_arch64: bool
