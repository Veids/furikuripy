from enum import Enum
from capstone import x86_const

from x86.fuku_register_math_tables import CAPSTONE_JCC, CAPSTONE_SETCC, CAPSTONE_MOVCC

class FukuOperandSize(Enum):
    FUKU_OPERAND_SIZE_0 = 0
    FUKU_OPERAND_SIZE_8 = 1
    FUKU_OPERAND_SIZE_16 = 2
    FUKU_OPERAND_SIZE_32 = 4
    FUKU_OPERAND_SIZE_64 = 8


class FukuAsmShortCfg(Enum):
    FUKU_ASM_SHORT_CFG_USE_EAX_SHORT = 1
    FUKU_ASM_SHORT_CFG_USE_DISP_SHORT = 2
    FUKU_ASM_SHORT_CFG_USE_IMM_SHORT = 4


class FukuToCapConvertType(Enum):
    CONVERT_TYPE_JCC = 0
    CONVERT_TYPE_SETCC = 1
    CONVERT_TYPE_CMOVCC = 2


class FukuCondition(Enum):
    FUKU_NO_CONDITION = -1;                jmp = -1

    FUKU_CONDITION_OVERFLOW        = 0;    jo   = 0;             # (OF == 1)
    FUKU_CONDITION_NO_OVERFLOW     = 1;    jno  = 1;             # (OF != 1)
    FUKU_CONDITION_BELOW           = 2;    jb   = 2;             # (CF == 1)
    FUKU_CONDITION_ABOVE_EQUAL     = 3;    jae  = 3;    jnc = 3  # (CF != 1)
    FUKU_CONDITION_EQUAL           = 4;    je   = 4;    jz  = 4  # (ZF == 1)
    FUKU_CONDITION_NOT_EQUAL       = 5;    jne  = 5;    jnz = 5  # (ZF != 1)
    FUKU_CONDITION_BELOW_EQUAL     = 6;    jbe  = 6;    jna = 6  # (CF == 1 || ZF == 1)
    FUKU_CONDITION_ABOVE           = 7;    jnbe = 7;    ja  = 7  # (CF != 1 && ZF != 1)
    FUKU_CONDITION_NEGATIVE        = 8;    js   = 8;             # (SF == 1)
    FUKU_CONDITION_POSITIVE        = 9;    jns  = 9;             # (SF != 1)
    FUKU_CONDITION_PARITY_EVEN     = 10;   jp   = 10;            # (PF == 1)
    FUKU_CONDITION_PARITY_ODD      = 11;   jnp  = 11;   jpo = 11 # (PF != 1)
    FUKU_CONDITION_LESS            = 12;   jnge = 12;   jl  = 12 # (SF != OF)
    FUKU_CONDITION_GREATER_EQUAL   = 13;   jge  = 13;   jnl = 13 # (SF == OF)
    FUKU_CONDITION_LESS_EQUAL      = 14;   jng  = 14;   jle = 14 # (ZF == 1 || (SF != OF) )
    FUKU_CONDITION_GREATER         = 15;   jnle = 15;   jg  = 15 # (ZF != 1 && (SF == OF) )

    FUKU_CONDITION_MAX = 16

    def to_capstone_cc(self, type: FukuToCapConvertType):
        if self in [FukuCondition.FUKU_NO_CONDITION, FukuCondition.FUKU_CONDITION_MAX]:
            return x86_const.X86_INS_INVALID

        if type == FukuCondition.CONVERT_TYPE_CMOVCC:
            return CAPSTONE_MOVCC[self.value]
        elif type == FukuCondition.CONVERT_TYPE_SETCC:
            return CAPSTONE_SETCC[self.value]
        else:
            return CAPSTONE_JCC[self.value]
