from enum import Enum
from typing import ForwardRef
from pydantic import BaseModel
from capstone.x86 import X86Op

from x86.misc import FukuOperandSize
from x86.fuku_register_math import bit_scan_forward, get_random_bit_by_mask
from x86.fuku_register_math_metadata import FlagRegisterIndex
from x86.fuku_register_math_tables import FULL_INCLUDE_FLAGS_TABLE, SIZE_TO_INDEXSZ

FukuRegisterIndex = ForwardRef("FukuRegisterIndex")
FukuRegisterEnum = ForwardRef("FukuRegisterEnum")


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

    @property
    def size(self) -> FukuOperandSize:
        if self in [FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_MAX]:
            return FukuOperandSize.FUKU_OPERAND_SIZE_0

        return FUKU_EXT_REGISTER_INFO[self.value].register_size

    @property
    def index(self) -> FukuRegisterIndex:
        if self in [FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_MAX]:
            return FukuRegisterIndex.FUKU_REG_INDEX_INVALID

        return FUKU_EXT_REGISTER_INFO[self.value].register_index

    @property
    def is_x64_arch(self) -> bool:
        if self in [FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_MAX]:
            return False

        return FUKU_EXT_REGISTER_INFO[self.value].is_x64_arch

    @property
    def is_x32_arch(self) -> bool:
        return not self.is_x64_arch

    @property
    def is_x64_arch_ext(self) -> bool:
        if self in [FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_MAX]:
            return False

        return FUKU_EXT_REGISTER_INFO[self.value].is_x64_arch_ext

    def set_grade(self, target_size: FukuOperandSize) -> FukuRegisterEnum:
        reg = 1 << (SIZE_TO_INDEXSZ[target_size.value] * 16 + CONVERT_FUKU_REGISTER_TO_FLAG[self.value] % 16)
        index = bit_scan_forward(0, reg) 
        if index:
            return CONVERT_FLAG_REGISTER_TO_FUKU[index]

        return FukuRegisterEnum.FUKU_REG_NONE

    @staticmethod
    def get_rand_free_register_index(
        inst_regs: int,
        min_idx: int,
        max_idx: int
    ):
        if not (index := bit_scan_forward(min_idx, inst_regs)):
            return -1

        if index > max_idx:
            if max_idx + 16 >= 63:
                return -1

            index = FukuRegisterEnum.get_rand_free_register_index(inst_regs, min_idx + 16, max_idx + 16)

            if index == -1:
                return -1

            return index - 16
        else:
            return get_random_bit_by_mask(inst_regs, min_idx, max_idx)

    @staticmethod
    def get_random_free_register(
        reg_flags: int,
        reg_size: FukuOperandSize,
        x86_only: bool,
        exclude_regs: int = 0 # FukuRegisterEnum.FUKU_REG_NONE
    ) -> FukuRegisterEnum:
        reg_flags &= ~(exclude_regs)

        returned_idx = -1
        if not reg_flags:
            return FukuRegisterEnum.FUKU_REG_NONE

        match reg_size:
            case FukuOperandSize.FUKU_OPERAND_SIZE_8:
                if x86_only:
                    returned_idx = FukuRegisterEnum.get_rand_free_register_index(reg_flags, FlagRegisterIndex.FLAG_REGISTER_IDX_AL, FlagRegisterIndex.FLAG_REGISTER_IDX_BL)
                else:
                    returned_idx = FukuRegisterEnum.get_rand_free_register_index(reg_flags, FlagRegisterIndex.FLAG_REGISTER_IDX_AL, FlagRegisterIndex.FLAG_REGISTER_IDX_R15B)

            case FukuOperandSize.FUKU_OPERAND_SIZE_16:
                if x86_only:
                    returned_idx = FukuRegisterEnum.get_rand_free_register_index(reg_flags, FlagRegisterIndex.FLAG_REGISTER_IDX_AX, FlagRegisterIndex.FLAG_REGISTER_IDX_DI)
                else:
                    returned_idx = FukuRegisterEnum.get_rand_free_register_index(reg_flags, FlagRegisterIndex.FLAG_REGISTER_IDX_AX, FlagRegisterIndex.FLAG_REGISTER_IDX_R15W)

            case FukuOperandSize.FUKU_OPERAND_SIZE_32:
                if x86_only:
                    returned_idx = FukuRegisterEnum.get_rand_free_register_index(reg_flags, FlagRegisterIndex.FLAG_REGISTER_IDX_EAX, FlagRegisterIndex.FLAG_REGISTER_IDX_EDI)
                else:
                    returned_idx = FukuRegisterEnum.get_rand_free_register_index(reg_flags, FlagRegisterIndex.FLAG_REGISTER_IDX_EAX, FlagRegisterIndex.FLAG_REGISTER_IDX_R15D)

            case FukuOperandSize.FUKU_OPERAND_SIZE_64:
                if x86_only:
                    returned_idx = get_rand_free_register_index(reg_flags, FlagRegisterIndex.FLAG_REGISTER_IDX_RAX, FlagRegisterIndex.FLAG_REGISTER_IDX_RDI)
                else:
                    returned_idx = get_rand_free_register_index(reg_flags, FlagRegisterIndex.FLAG_REGISTER_IDX_RAX, FlagRegisterIndex.FLAG_REGISTER_IDX_R15)

        if returned_idx == -1:
            return FukuRegisterEnum.FUKU_REG_NONE

        return FukuRegisterEnum(CONVERT_FLAG_REGISTER_TO_FUKU[returned_idx])

    @staticmethod
    def get_random_free_register_x64(
        reg_flags: int,
        reg_size: FukuOperandSize,
        exclude_regs: int = 0 # FukuRegisterEnum.FUKU_REG_NONE
    ) -> FukuRegisterEnum:
        reg: FukuRegisterEnum = FukuRegisterEnum.get_random_free_register(
            reg_flags,
            FukuOperandSize.FUKU_OPERAND_SIZE_64 if reg_size == FukuOperandSize.FUKU_OPERAND_SIZE_32 else reg_size,
            exclude_regs
        )

        if reg != FukuRegisterEnum.FUKU_REG_NONE and reg_size == FukuOperandSize.FUKU_OPERAND_SIZE_32:
            return reg.set_grade(FukuOperandSize.FUKU_OPERAND_SIZE_32)

        return reg

    @staticmethod
    def from_capstone(op: X86Op) -> FukuRegisterEnum:
        return CAP_TO_FUKU_TABLE[op.reg]


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
    reg: FukuRegisterEnum = FukuRegisterEnum.FUKU_REG_NONE
    index: FukuRegisterIndex = FukuRegisterIndex.FUKU_REG_INDEX_INVALID
    size: FukuOperandSize = FukuOperandSize.FUKU_OPERAND_SIZE_0

    arch64: bool = False
    is_ext64: bool = False

    def __init__(self, inp: FukuRegisterEnum):
        super().__init__()

        if isinstance(inp, FukuRegisterEnum):
            self.set_reg(inp)

    def set_reg(self, reg: FukuRegisterEnum):
        self.reg = reg
        self.index = reg.index
        self.size = reg.size
        self.arch64 = reg.is_x64_arch

        if self.arch64:
            self.is_ext64 = reg.is_x64_arch_ext
        else:
            self.is_ext64 = False


    def get_flag_complex(self, size: FukuOperandSize) -> int:
        match size:
            case FukuOperandSize.FUKU_OPERAND_SIZE_8:
                return FULL_INCLUDE_FLAGS_TABLE[self.index.value + (FukuOperandSize.FUKU_OPERAND_SIZE_64.value if self.is_ext64 else FukuOperandSize.FUKU_OPERAND_SIZE_0.value)] & 0xFFFF

            case FukuOperandSize.FUKU_OPERAND_SIZE_16:
                return FULL_INCLUDE_FLAGS_TABLE[self.index.value + (FukuOperandSize.FUKU_OPERAND_SIZE_64.value if self.is_ext64 else FukuOperandSize.FUKU_OPERAND_SIZE_0.value)] & 0xFFFFFFFF

            case FukuOperandSize.FUKU_OPERAND_SIZE_32:
                return FULL_INCLUDE_FLAGS_TABLE[self.index.value + (FukuOperandSize.FUKU_OPERAND_SIZE_64.value if self.is_ext64 else FukuOperandSize.FUKU_OPERAND_SIZE_0.value)] & 0xFFFFFFFFFFFF

            case FukuOperandSize.FUKU_OPERAND_SIZE_64:
                return FULL_INCLUDE_FLAGS_TABLE[self.index.value + (FukuOperandSize.FUKU_OPERAND_SIZE_64.value if self.is_ext64 else FukuOperandSize.FUKU_OPERAND_SIZE_0.value)]


class FukuExtRegisterInfo(BaseModel):
    register_: FukuRegisterEnum
    register_index: FukuRegisterIndex
    register_size: FukuOperandSize
    is_x64_arch: bool
    is_x64_arch_ext: bool

    def __init__(
        self,
        a: FukuRegisterEnum,
        b: FukuRegisterIndex,
        c: FukuOperandSize,
        d: bool,
        e: bool,
        **kwargs
    ):
        super().__init__(
            register_ = a,
            register_index = b,
            register_size = c,
            is_x64_arch = d,
            is_x64_arch_ext = e,
            **kwargs
        )

FUKU_EXT_REGISTER_INFO = [
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterIndex(-1), FukuOperandSize.FUKU_OPERAND_SIZE_0, False, False),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_RAX, FukuRegisterIndex.FUKU_REG_INDEX_AX, FukuOperandSize.FUKU_OPERAND_SIZE_64, True , False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_EAX, FukuRegisterIndex.FUKU_REG_INDEX_AX, FukuOperandSize.FUKU_OPERAND_SIZE_32, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_AX,  FukuRegisterIndex.FUKU_REG_INDEX_AX, FukuOperandSize.FUKU_OPERAND_SIZE_16, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_AH,  FukuRegisterIndex.FUKU_REG_INDEX_AX, FukuOperandSize.FUKU_OPERAND_SIZE_8,	False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_AL,  FukuRegisterIndex.FUKU_REG_INDEX_AX, FukuOperandSize.FUKU_OPERAND_SIZE_8,	False, False),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_RCX, FukuRegisterIndex.FUKU_REG_INDEX_CX, FukuOperandSize.FUKU_OPERAND_SIZE_64, True, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_ECX, FukuRegisterIndex.FUKU_REG_INDEX_CX, FukuOperandSize.FUKU_OPERAND_SIZE_32, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_CX,  FukuRegisterIndex.FUKU_REG_INDEX_CX, FukuOperandSize.FUKU_OPERAND_SIZE_16, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_CH,  FukuRegisterIndex.FUKU_REG_INDEX_CX, FukuOperandSize.FUKU_OPERAND_SIZE_8,	False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_CL,  FukuRegisterIndex.FUKU_REG_INDEX_CX, FukuOperandSize.FUKU_OPERAND_SIZE_8,	False, False),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_RDX, FukuRegisterIndex.FUKU_REG_INDEX_DX, FukuOperandSize.FUKU_OPERAND_SIZE_64, True, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_EDX, FukuRegisterIndex.FUKU_REG_INDEX_DX, FukuOperandSize.FUKU_OPERAND_SIZE_32, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_DX,  FukuRegisterIndex.FUKU_REG_INDEX_DX, FukuOperandSize.FUKU_OPERAND_SIZE_16, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_DH,  FukuRegisterIndex.FUKU_REG_INDEX_DX, FukuOperandSize.FUKU_OPERAND_SIZE_8,	False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_DL,  FukuRegisterIndex.FUKU_REG_INDEX_DX, FukuOperandSize.FUKU_OPERAND_SIZE_8,	False, False),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_RBX, FukuRegisterIndex.FUKU_REG_INDEX_BX, FukuOperandSize.FUKU_OPERAND_SIZE_64, True, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_EBX, FukuRegisterIndex.FUKU_REG_INDEX_BX, FukuOperandSize.FUKU_OPERAND_SIZE_32, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_BX,  FukuRegisterIndex.FUKU_REG_INDEX_BX, FukuOperandSize.FUKU_OPERAND_SIZE_16, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_BH,  FukuRegisterIndex.FUKU_REG_INDEX_BX, FukuOperandSize.FUKU_OPERAND_SIZE_8,	False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_BL,  FukuRegisterIndex.FUKU_REG_INDEX_BX, FukuOperandSize.FUKU_OPERAND_SIZE_8,	False, False),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_RSP, FukuRegisterIndex.FUKU_REG_INDEX_SP, FukuOperandSize.FUKU_OPERAND_SIZE_64, True, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_ESP, FukuRegisterIndex.FUKU_REG_INDEX_SP, FukuOperandSize.FUKU_OPERAND_SIZE_32, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_SP,  FukuRegisterIndex.FUKU_REG_INDEX_SP, FukuOperandSize.FUKU_OPERAND_SIZE_16, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_SPL, FukuRegisterIndex.FUKU_REG_INDEX_SP, FukuOperandSize.FUKU_OPERAND_SIZE_8,	True, False),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_RBP, FukuRegisterIndex.FUKU_REG_INDEX_BP, FukuOperandSize.FUKU_OPERAND_SIZE_64, True, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_EBP, FukuRegisterIndex.FUKU_REG_INDEX_BP, FukuOperandSize.FUKU_OPERAND_SIZE_32, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_BP,  FukuRegisterIndex.FUKU_REG_INDEX_BP, FukuOperandSize.FUKU_OPERAND_SIZE_16, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_BPL, FukuRegisterIndex.FUKU_REG_INDEX_BP, FukuOperandSize.FUKU_OPERAND_SIZE_8,	True, False),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_RSI, FukuRegisterIndex.FUKU_REG_INDEX_SI, FukuOperandSize.FUKU_OPERAND_SIZE_64, True, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_ESI, FukuRegisterIndex.FUKU_REG_INDEX_SI, FukuOperandSize.FUKU_OPERAND_SIZE_32, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_SI,  FukuRegisterIndex.FUKU_REG_INDEX_SI, FukuOperandSize.FUKU_OPERAND_SIZE_16, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_SIL, FukuRegisterIndex.FUKU_REG_INDEX_SI, FukuOperandSize.FUKU_OPERAND_SIZE_8,	True, False),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_RDI, FukuRegisterIndex.FUKU_REG_INDEX_DI, FukuOperandSize.FUKU_OPERAND_SIZE_64, True, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_EDI, FukuRegisterIndex.FUKU_REG_INDEX_DI, FukuOperandSize.FUKU_OPERAND_SIZE_32, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_DI,  FukuRegisterIndex.FUKU_REG_INDEX_DI, FukuOperandSize.FUKU_OPERAND_SIZE_16, False, False),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_DIL, FukuRegisterIndex.FUKU_REG_INDEX_DI, FukuOperandSize.FUKU_OPERAND_SIZE_8,	True, False),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R8,  FukuRegisterIndex.FUKU_REG_INDEX_R8, FukuOperandSize.FUKU_OPERAND_SIZE_64, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R8D, FukuRegisterIndex.FUKU_REG_INDEX_R8, FukuOperandSize.FUKU_OPERAND_SIZE_32, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R8W, FukuRegisterIndex.FUKU_REG_INDEX_R8, FukuOperandSize.FUKU_OPERAND_SIZE_16, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R8B, FukuRegisterIndex.FUKU_REG_INDEX_R8, FukuOperandSize.FUKU_OPERAND_SIZE_8,	True, True),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R9,  FukuRegisterIndex.FUKU_REG_INDEX_R9, FukuOperandSize.FUKU_OPERAND_SIZE_64, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R9D, FukuRegisterIndex.FUKU_REG_INDEX_R9, FukuOperandSize.FUKU_OPERAND_SIZE_32, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R9W, FukuRegisterIndex.FUKU_REG_INDEX_R9, FukuOperandSize.FUKU_OPERAND_SIZE_16, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R9B, FukuRegisterIndex.FUKU_REG_INDEX_R9, FukuOperandSize.FUKU_OPERAND_SIZE_8,	True, True),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R10,  FukuRegisterIndex.FUKU_REG_INDEX_R10, FukuOperandSize.FUKU_OPERAND_SIZE_64, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R10D, FukuRegisterIndex.FUKU_REG_INDEX_R10, FukuOperandSize.FUKU_OPERAND_SIZE_32, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R10W, FukuRegisterIndex.FUKU_REG_INDEX_R10, FukuOperandSize.FUKU_OPERAND_SIZE_16, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R10B, FukuRegisterIndex.FUKU_REG_INDEX_R10, FukuOperandSize.FUKU_OPERAND_SIZE_8,  True, True),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R11,  FukuRegisterIndex.FUKU_REG_INDEX_R11, FukuOperandSize.FUKU_OPERAND_SIZE_64, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R11D, FukuRegisterIndex.FUKU_REG_INDEX_R11, FukuOperandSize.FUKU_OPERAND_SIZE_32, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R11W, FukuRegisterIndex.FUKU_REG_INDEX_R11, FukuOperandSize.FUKU_OPERAND_SIZE_16, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R11B, FukuRegisterIndex.FUKU_REG_INDEX_R11, FukuOperandSize.FUKU_OPERAND_SIZE_8,  True, True),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R12,  FukuRegisterIndex.FUKU_REG_INDEX_R12, FukuOperandSize.FUKU_OPERAND_SIZE_64, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R12D, FukuRegisterIndex.FUKU_REG_INDEX_R12, FukuOperandSize.FUKU_OPERAND_SIZE_32, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R12W, FukuRegisterIndex.FUKU_REG_INDEX_R12, FukuOperandSize.FUKU_OPERAND_SIZE_16, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R12B, FukuRegisterIndex.FUKU_REG_INDEX_R12, FukuOperandSize.FUKU_OPERAND_SIZE_8,  True, True),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R13,  FukuRegisterIndex.FUKU_REG_INDEX_R13, FukuOperandSize.FUKU_OPERAND_SIZE_64, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R13D, FukuRegisterIndex.FUKU_REG_INDEX_R13, FukuOperandSize.FUKU_OPERAND_SIZE_32, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R13W, FukuRegisterIndex.FUKU_REG_INDEX_R13, FukuOperandSize.FUKU_OPERAND_SIZE_16, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R13B, FukuRegisterIndex.FUKU_REG_INDEX_R13, FukuOperandSize.FUKU_OPERAND_SIZE_8,  True, True),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R14,  FukuRegisterIndex.FUKU_REG_INDEX_R14, FukuOperandSize.FUKU_OPERAND_SIZE_64, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R14D, FukuRegisterIndex.FUKU_REG_INDEX_R14, FukuOperandSize.FUKU_OPERAND_SIZE_32, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R14W, FukuRegisterIndex.FUKU_REG_INDEX_R14, FukuOperandSize.FUKU_OPERAND_SIZE_16, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R14B, FukuRegisterIndex.FUKU_REG_INDEX_R14, FukuOperandSize.FUKU_OPERAND_SIZE_8,  True, True),

    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R15,  FukuRegisterIndex.FUKU_REG_INDEX_R15, FukuOperandSize.FUKU_OPERAND_SIZE_64, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R15D, FukuRegisterIndex.FUKU_REG_INDEX_R15, FukuOperandSize.FUKU_OPERAND_SIZE_32, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R15W, FukuRegisterIndex.FUKU_REG_INDEX_R15, FukuOperandSize.FUKU_OPERAND_SIZE_16, True, True),
    FukuExtRegisterInfo(FukuRegisterEnum.FUKU_REG_R15B, FukuRegisterIndex.FUKU_REG_INDEX_R15, FukuOperandSize.FUKU_OPERAND_SIZE_8,  True, True),
]

CAP_TO_FUKU_TABLE = [
    FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_AH, FukuRegisterEnum.FUKU_REG_AL, FukuRegisterEnum.FUKU_REG_AX, FukuRegisterEnum.FUKU_REG_BH, FukuRegisterEnum.FUKU_REG_BL,
    FukuRegisterEnum.FUKU_REG_BP, FukuRegisterEnum.FUKU_REG_BPL, FukuRegisterEnum.FUKU_REG_BX, FukuRegisterEnum.FUKU_REG_CH, FukuRegisterEnum.FUKU_REG_CL,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_CX, FukuRegisterEnum.FUKU_REG_DH, FukuRegisterEnum.FUKU_REG_DI, FukuRegisterEnum.FUKU_REG_DIL,
    FukuRegisterEnum.FUKU_REG_DL, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_DX, FukuRegisterEnum.FUKU_REG_EAX, FukuRegisterEnum.FUKU_REG_EBP,
    FukuRegisterEnum.FUKU_REG_EBX, FukuRegisterEnum.FUKU_REG_ECX, FukuRegisterEnum.FUKU_REG_EDI, FukuRegisterEnum.FUKU_REG_EDX, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_ESI, FukuRegisterEnum.FUKU_REG_ESP,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_RAX,
    FukuRegisterEnum.FUKU_REG_RBP, FukuRegisterEnum.FUKU_REG_RBX, FukuRegisterEnum.FUKU_REG_RCX, FukuRegisterEnum.FUKU_REG_RDI, FukuRegisterEnum.FUKU_REG_RDX,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_RSI, FukuRegisterEnum.FUKU_REG_RSP, FukuRegisterEnum.FUKU_REG_SI,
    FukuRegisterEnum.FUKU_REG_SIL, FukuRegisterEnum.FUKU_REG_SP, FukuRegisterEnum.FUKU_REG_SPL, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_R8, FukuRegisterEnum.FUKU_REG_R9, FukuRegisterEnum.FUKU_REG_R10, FukuRegisterEnum.FUKU_REG_R11,
    FukuRegisterEnum.FUKU_REG_R12, FukuRegisterEnum.FUKU_REG_R13, FukuRegisterEnum.FUKU_REG_R14, FukuRegisterEnum.FUKU_REG_R15,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_NONE,
    FukuRegisterEnum.FUKU_REG_NONE, FukuRegisterEnum.FUKU_REG_R8B, FukuRegisterEnum.FUKU_REG_R9B, FukuRegisterEnum.FUKU_REG_R10B, FukuRegisterEnum.FUKU_REG_R11B,
    FukuRegisterEnum.FUKU_REG_R12B, FukuRegisterEnum.FUKU_REG_R13B, FukuRegisterEnum.FUKU_REG_R14B, FukuRegisterEnum.FUKU_REG_R15B, FukuRegisterEnum.FUKU_REG_R8D,
    FukuRegisterEnum.FUKU_REG_R9D, FukuRegisterEnum.FUKU_REG_R10D, FukuRegisterEnum.FUKU_REG_R11D, FukuRegisterEnum.FUKU_REG_R12D, FukuRegisterEnum.FUKU_REG_R13D,
    FukuRegisterEnum.FUKU_REG_R14D, FukuRegisterEnum.FUKU_REG_R15D, FukuRegisterEnum.FUKU_REG_R8W, FukuRegisterEnum.FUKU_REG_R9W, FukuRegisterEnum.FUKU_REG_R10W,
    FukuRegisterEnum.FUKU_REG_R11W, FukuRegisterEnum.FUKU_REG_R12W, FukuRegisterEnum.FUKU_REG_R13W, FukuRegisterEnum.FUKU_REG_R14W, FukuRegisterEnum.FUKU_REG_R15W,

    FukuRegisterEnum.FUKU_REG_MAX
]


CONVERT_FLAG_REGISTER_TO_FUKU = [
    FukuRegisterEnum.FUKU_REG_AL,
    FukuRegisterEnum.FUKU_REG_CL,
    FukuRegisterEnum.FUKU_REG_DL,
    FukuRegisterEnum.FUKU_REG_BL,
    FukuRegisterEnum.FUKU_REG_SPL,
    FukuRegisterEnum.FUKU_REG_BPL,
    FukuRegisterEnum.FUKU_REG_SIL,
    FukuRegisterEnum.FUKU_REG_DIL,
    FukuRegisterEnum.FUKU_REG_R8B,
    FukuRegisterEnum.FUKU_REG_R9B,
    FukuRegisterEnum.FUKU_REG_R10B,
    FukuRegisterEnum.FUKU_REG_R11B,
    FukuRegisterEnum.FUKU_REG_R12B,
    FukuRegisterEnum.FUKU_REG_R13B,
    FukuRegisterEnum.FUKU_REG_R14B,
    FukuRegisterEnum.FUKU_REG_R15B,
    # word
    FukuRegisterEnum.FUKU_REG_AX,
    FukuRegisterEnum.FUKU_REG_CX,
    FukuRegisterEnum.FUKU_REG_DX,
    FukuRegisterEnum.FUKU_REG_BX,
    FukuRegisterEnum.FUKU_REG_SP,
    FukuRegisterEnum.FUKU_REG_BP,
    FukuRegisterEnum.FUKU_REG_SI,
    FukuRegisterEnum.FUKU_REG_DI,
    FukuRegisterEnum.FUKU_REG_R8W,
    FukuRegisterEnum.FUKU_REG_R9W,
    FukuRegisterEnum.FUKU_REG_R10W,
    FukuRegisterEnum.FUKU_REG_R11W,
    FukuRegisterEnum.FUKU_REG_R12W,
    FukuRegisterEnum.FUKU_REG_R13W,
    FukuRegisterEnum.FUKU_REG_R14W,
    FukuRegisterEnum.FUKU_REG_R15W,
    # dword
    FukuRegisterEnum.FUKU_REG_EAX,
    FukuRegisterEnum.FUKU_REG_ECX,
    FukuRegisterEnum.FUKU_REG_EDX,
    FukuRegisterEnum.FUKU_REG_EBX,
    FukuRegisterEnum.FUKU_REG_ESP,
    FukuRegisterEnum.FUKU_REG_EBP,
    FukuRegisterEnum.FUKU_REG_ESI,
    FukuRegisterEnum.FUKU_REG_EDI,
    FukuRegisterEnum.FUKU_REG_R8D,
    FukuRegisterEnum.FUKU_REG_R9D,
    FukuRegisterEnum.FUKU_REG_R10D,
    FukuRegisterEnum.FUKU_REG_R11D,
    FukuRegisterEnum.FUKU_REG_R12D,
    FukuRegisterEnum.FUKU_REG_R13D,
    FukuRegisterEnum.FUKU_REG_R14D,
    FukuRegisterEnum.FUKU_REG_R15D,
    # qword
    FukuRegisterEnum.FUKU_REG_RAX,
    FukuRegisterEnum.FUKU_REG_RCX,
    FukuRegisterEnum.FUKU_REG_RDX,
    FukuRegisterEnum.FUKU_REG_RBX,
    FukuRegisterEnum.FUKU_REG_RSP,
    FukuRegisterEnum.FUKU_REG_RBP,
    FukuRegisterEnum.FUKU_REG_RSI,
    FukuRegisterEnum.FUKU_REG_RDI,
    FukuRegisterEnum.FUKU_REG_R8,
    FukuRegisterEnum.FUKU_REG_R9,
    FukuRegisterEnum.FUKU_REG_R10,
    FukuRegisterEnum.FUKU_REG_R11,
    FukuRegisterEnum.FUKU_REG_R12,
    FukuRegisterEnum.FUKU_REG_R13,
    FukuRegisterEnum.FUKU_REG_R14,
    FukuRegisterEnum.FUKU_REG_R15
]
