from enum import Enum
from capstone import x86_const

from furikuripy.x86.fuku_register_math_tables import (
    CAPSTONE_JCC,
    CAPSTONE_SETCC,
    CAPSTONE_MOVCC,
    ICED_CONDCC,
)


class FukuOperandSize(Enum):
    SIZE_0 = 0
    SIZE_8 = 1
    SIZE_16 = 2
    SIZE_32 = 4
    SIZE_64 = 8


class FukuAsmShortCfg(Enum):
    USE_EAX_SHORT = 1
    USE_DISP_SHORT = 2
    USE_IMM_SHORT = 4


class FukuToCapConvertType(Enum):
    JCC = 0
    SETCC = 1
    CMOVCC = 2


class FukuCondition(Enum):
    NO_CONDITION = -1
    jmp = -1

    OVERFLOW = 0
    jo = 0  # (OF == 1)
    NO_OVERFLOW = 1
    jno = 1  # (OF != 1)
    BELOW = 2
    jb = 2  # (CF == 1)
    ABOVE_EQUAL = 3
    jae = 3
    jnc = 3  # (CF != 1)
    EQUAL = 4
    je = 4
    jz = 4  # (ZF == 1)
    NOT_EQUAL = 5
    jne = 5
    jnz = 5  # (ZF != 1)
    BELOW_EQUAL = 6
    jbe = 6
    jna = 6  # (CF == 1 || ZF == 1)
    ABOVE = 7
    jnbe = 7
    ja = 7  # (CF != 1 && ZF != 1)
    NEGATIVE = 8
    js = 8  # (SF == 1)
    POSITIVE = 9
    jns = 9  # (SF != 1)
    PARITY_EVEN = 10
    jp = 10  # (PF == 1)
    PARITY_ODD = 11
    jnp = 11
    jpo = 11  # (PF != 1)
    LESS = 12
    jnge = 12
    jl = 12  # (SF != OF)
    GREATER_EQUAL = 13
    jge = 13
    jnl = 13  # (SF == OF)
    LESS_EQUAL = 14
    jng = 14
    jle = 14  # (ZF == 1 || (SF != OF) )
    GREATER = 15
    jnle = 15
    jg = 15  # (ZF != 1 && (SF == OF) )

    CONDITION_MAX = 16

    def to_capstone_cc(self, type: FukuToCapConvertType):
        if self in [FukuCondition.NO_CONDITION, FukuCondition.CONDITION_MAX]:
            return x86_const.X86_INS_INVALID

        if type == FukuToCapConvertType.CMOVCC:
            return CAPSTONE_MOVCC[self.value]
        elif type == FukuToCapConvertType.SETCC:
            return CAPSTONE_SETCC[self.value]
        else:
            return CAPSTONE_JCC[self.value]

    def to_iced_cc(self) -> str:
        if self in [FukuCondition.NO_CONDITION, FukuCondition.CONDITION_MAX]:
            raise TypeError(self)

        return ICED_CONDCC[self.value]

    @staticmethod
    def from_capstone(id: int):
        match id:
            case (
                x86_const.X86_INS_JO | x86_const.X86_INS_SETO | x86_const.X86_INS_CMOVO
            ):
                return FukuCondition.jo
            case (
                x86_const.X86_INS_JNO
                | x86_const.X86_INS_SETNO
                | x86_const.X86_INS_CMOVNO
            ):
                return FukuCondition.jno
            case (
                x86_const.X86_INS_JB | x86_const.X86_INS_SETB | x86_const.X86_INS_CMOVB
            ):
                return FukuCondition.jb
            case (
                x86_const.X86_INS_JAE
                | x86_const.X86_INS_SETAE
                | x86_const.X86_INS_CMOVAE
            ):
                return FukuCondition.jae
            case (
                x86_const.X86_INS_JE | x86_const.X86_INS_SETE | x86_const.X86_INS_CMOVE
            ):
                return FukuCondition.je
            case (
                x86_const.X86_INS_JNE
                | x86_const.X86_INS_SETNE
                | x86_const.X86_INS_CMOVNE
            ):
                return FukuCondition.jne
            case (
                x86_const.X86_INS_JBE
                | x86_const.X86_INS_SETBE
                | x86_const.X86_INS_CMOVBE
            ):
                return FukuCondition.jbe
            case (
                x86_const.X86_INS_JA | x86_const.X86_INS_SETA | x86_const.X86_INS_CMOVA
            ):
                return FukuCondition.ja
            case (
                x86_const.X86_INS_JS | x86_const.X86_INS_SETS | x86_const.X86_INS_CMOVS
            ):
                return FukuCondition.js
            case (
                x86_const.X86_INS_JNS
                | x86_const.X86_INS_SETNS
                | x86_const.X86_INS_CMOVNS
            ):
                return FukuCondition.jns
            case (
                x86_const.X86_INS_JP | x86_const.X86_INS_SETP | x86_const.X86_INS_CMOVP
            ):
                return FukuCondition.jp
            case (
                x86_const.X86_INS_JNP
                | x86_const.X86_INS_SETNP
                | x86_const.X86_INS_CMOVNP
            ):
                return FukuCondition.jnp
            case (
                x86_const.X86_INS_JL | x86_const.X86_INS_SETL | x86_const.X86_INS_CMOVL
            ):
                return FukuCondition.jl
            case (
                x86_const.X86_INS_JGE
                | x86_const.X86_INS_SETGE
                | x86_const.X86_INS_CMOVGE
            ):
                return FukuCondition.jge
            case (
                x86_const.X86_INS_JLE
                | x86_const.X86_INS_SETLE
                | x86_const.X86_INS_CMOVLE
            ):
                return FukuCondition.jle
            case (
                x86_const.X86_INS_JG | x86_const.X86_INS_SETG | x86_const.X86_INS_CMOVG
            ):
                return FukuCondition.jg
            case _:
                return FukuCondition.jmp
