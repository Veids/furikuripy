from __future__ import annotations

from typing import List
from enum import Enum
from pydantic import BaseModel
from capstone.x86 import X86Op
from iced_x86 import Register

from furikuripy.x86.misc import FukuOperandSize
from furikuripy.x86.fuku_register_math import bit_scan_forward, get_random_bit_by_mask
from furikuripy.x86.fuku_register_math_metadata import FlagRegisterIndex
from furikuripy.x86.fuku_register_math_tables import (
    FULL_INCLUDE_FLAGS_TABLE,
    SIZE_TO_INDEXSZ,
    CONVERT_FUKU_REGISTER_TO_FLAG,
)


class FukuRegisterEnum(Enum):
    REG_NONE = 0
    REG_RAX = 1
    REG_EAX = 2
    REG_AX = 3
    REG_AH = 4
    REG_AL = 5
    REG_RCX = 6
    REG_ECX = 7
    REG_CX = 8
    REG_CH = 9
    REG_CL = 10
    REG_RDX = 11
    REG_EDX = 12
    REG_DX = 13
    REG_DH = 14
    REG_DL = 15
    REG_RBX = 16
    REG_EBX = 17
    REG_BX = 18
    REG_BH = 19
    REG_BL = 20
    REG_RSP = 21
    REG_ESP = 22
    REG_SP = 23
    REG_SPL = 24
    REG_RBP = 25
    REG_EBP = 26
    REG_BP = 27
    REG_BPL = 28
    REG_RSI = 29
    REG_ESI = 30
    REG_SI = 31
    REG_SIL = 32
    REG_RDI = 33
    REG_EDI = 34
    REG_DI = 35
    REG_DIL = 36
    REG_R8 = 37
    REG_R8D = 38
    REG_R8W = 39
    REG_R8B = 40
    REG_R9 = 41
    REG_R9D = 42
    REG_R9W = 43
    REG_R9B = 44
    REG_R10 = 45
    REG_R10D = 46
    REG_R10W = 47
    REG_R10B = 48
    REG_R11 = 49
    REG_R11D = 50
    REG_R11W = 51
    REG_R11B = 52
    REG_R12 = 53
    REG_R12D = 54
    REG_R12W = 55
    REG_R12B = 56
    REG_R13 = 57
    REG_R13D = 58
    REG_R13W = 59
    REG_R13B = 60
    REG_R14 = 61
    REG_R14D = 62
    REG_R14W = 63
    REG_R14B = 64
    REG_R15 = 65
    REG_R15D = 66
    REG_R15W = 67
    REG_R15B = 68
    REG_MAX = 69

    @property
    def size(self) -> FukuOperandSize:
        if self in [FukuRegisterEnum.REG_NONE, FukuRegisterEnum.REG_MAX]:
            return FukuOperandSize.SIZE_0

        return FUKU_EXT_REGISTER_INFO[self.value].register_size

    @property
    def index(self) -> FukuRegisterIndex:
        if self in [FukuRegisterEnum.REG_NONE, FukuRegisterEnum.REG_MAX]:
            return FukuRegisterIndex.INDEX_INVALID

        return FUKU_EXT_REGISTER_INFO[self.value].register_index

    @property
    def is_x64_arch(self) -> bool:
        if self in [FukuRegisterEnum.REG_NONE, FukuRegisterEnum.REG_MAX]:
            return False

        return FUKU_EXT_REGISTER_INFO[self.value].is_x64_arch

    @property
    def is_x32_arch(self) -> bool:
        return not self.is_x64_arch

    @property
    def is_x64_arch_ext(self) -> bool:
        if self in [FukuRegisterEnum.REG_NONE, FukuRegisterEnum.REG_MAX]:
            return False

        return FUKU_EXT_REGISTER_INFO[self.value].is_x64_arch_ext

    def set_grade(self, target_size: FukuOperandSize) -> FukuRegisterEnum:
        reg = 1 << (
            SIZE_TO_INDEXSZ[target_size.value] * 16
            + CONVERT_FUKU_REGISTER_TO_FLAG[self.value] % 16
        )
        index = bit_scan_forward(0, reg)
        if index:
            return CONVERT_FLAG_REGISTER_TO_FUKU[index]

        return FukuRegisterEnum.REG_NONE

    @staticmethod
    def get_rand_free_register_index(inst_regs: int, min_idx: int, max_idx: int):
        if not (index := bit_scan_forward(min_idx, inst_regs)):
            return -1

        if index > max_idx:
            if max_idx + 16 >= 63:
                return -1

            index = FukuRegisterEnum.get_rand_free_register_index(
                inst_regs, min_idx + 16, max_idx + 16
            )

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
        exclude_regs: int = 0,  # FukuRegisterEnum.REG_NONE
    ) -> FukuRegisterEnum:
        reg_flags &= ~(exclude_regs)

        returned_idx = -1
        if not reg_flags:
            return FukuRegisterEnum.REG_NONE

        match reg_size:
            case FukuOperandSize.SIZE_8:
                if x86_only:
                    returned_idx = FukuRegisterEnum.get_rand_free_register_index(
                        reg_flags,
                        FlagRegisterIndex.AL.value,
                        FlagRegisterIndex.BL.value,
                    )
                else:
                    returned_idx = FukuRegisterEnum.get_rand_free_register_index(
                        reg_flags,
                        FlagRegisterIndex.AL.value,
                        FlagRegisterIndex.R15B.value,
                    )

            case FukuOperandSize.SIZE_16:
                if x86_only:
                    returned_idx = FukuRegisterEnum.get_rand_free_register_index(
                        reg_flags,
                        FlagRegisterIndex.AX.value,
                        FlagRegisterIndex.DI.value,
                    )
                else:
                    returned_idx = FukuRegisterEnum.get_rand_free_register_index(
                        reg_flags,
                        FlagRegisterIndex.AX.value,
                        FlagRegisterIndex.R15W.value,
                    )

            case FukuOperandSize.SIZE_32:
                if x86_only:
                    returned_idx = FukuRegisterEnum.get_rand_free_register_index(
                        reg_flags,
                        FlagRegisterIndex.EAX.value,
                        FlagRegisterIndex.EDI.value,
                    )
                else:
                    returned_idx = FukuRegisterEnum.get_rand_free_register_index(
                        reg_flags,
                        FlagRegisterIndex.EAX.value,
                        FlagRegisterIndex.R15D.value,
                    )

            case FukuOperandSize.SIZE_64:
                if x86_only:
                    returned_idx = FukuRegisterEnum.get_rand_free_register_index(
                        reg_flags,
                        FlagRegisterIndex.RAX.value,
                        FlagRegisterIndex.RDI.value,
                    )
                else:
                    returned_idx = FukuRegisterEnum.get_rand_free_register_index(
                        reg_flags,
                        FlagRegisterIndex.RAX.value,
                        FlagRegisterIndex.R15.value,
                    )

        if returned_idx == -1:
            return FukuRegisterEnum.REG_NONE

        return FukuRegisterEnum(CONVERT_FLAG_REGISTER_TO_FUKU[returned_idx])

    @staticmethod
    def get_random_free_register_x64(
        reg_flags: int,
        reg_size: FukuOperandSize,
        exclude_regs: int = 0,  # FukuRegisterEnum.REG_NONE
    ) -> FukuRegisterEnum:
        reg: FukuRegisterEnum = FukuRegisterEnum.get_random_free_register(
            reg_flags,
            FukuOperandSize.SIZE_64
            if reg_size == FukuOperandSize.SIZE_32
            else reg_size,
            False,
            exclude_regs,
        )

        if reg != FukuRegisterEnum.REG_NONE and reg_size == FukuOperandSize.SIZE_32:
            return reg.set_grade(FukuOperandSize.SIZE_32)

        return reg

    @staticmethod
    def get_random_register(
        reg_size: FukuOperandSize, x86_only: bool, exclude_regs: int
    ) -> FukuRegisterEnum:
        match reg_size:
            case FukuOperandSize.SIZE_8:
                return FukuRegisterEnum.get_random_free_register(
                    0xFFFFFFFFFFFFFFFF, FukuOperandSize.SIZE_8, x86_only, exclude_regs
                )

            case FukuOperandSize.SIZE_16:
                return FukuRegisterEnum.get_random_free_register(
                    0xFFFFFFFFFFFF0000, FukuOperandSize.SIZE_16, x86_only, exclude_regs
                )

            case FukuOperandSize.SIZE_32:
                return FukuRegisterEnum.get_random_free_register(
                    0xFFFFFFFF00000000, FukuOperandSize.SIZE_32, x86_only, exclude_regs
                )

            case FukuOperandSize.SIZE_64:
                return FukuRegisterEnum.get_random_free_register(
                    0xFFFF000000000000, FukuOperandSize.SIZE_64, x86_only, exclude_regs
                )

        return FukuRegisterEnum.REG_NONE

    @staticmethod
    def from_capstone(op: X86Op) -> FukuRegisterEnum:
        return CAP_TO_FUKU_TABLE[op.reg]


class FukuRegisterIndex(Enum):
    INDEX_AX = 0
    INDEX_R8 = 0
    INDEX_CX = 1
    INDEX_R9 = 1
    INDEX_DX = 2
    INDEX_R10 = 2
    INDEX_BX = 3
    INDEX_R11 = 3
    INDEX_SP = 4
    INDEX_R12 = 4
    INDEX_BP = 5
    INDEX_R13 = 5
    INDEX_SI = 6
    INDEX_R14 = 6
    INDEX_DI = 7
    INDEX_R15 = 7

    INDEX_INVALID = -1


class FukuRegister(BaseModel):
    reg: FukuRegisterEnum = FukuRegisterEnum.REG_NONE
    index: FukuRegisterIndex = FukuRegisterIndex.INDEX_INVALID
    size: FukuOperandSize = FukuOperandSize.SIZE_0

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
            case FukuOperandSize.SIZE_8:
                return (
                    FULL_INCLUDE_FLAGS_TABLE[
                        self.index.value
                        + (
                            FukuOperandSize.SIZE_64.value
                            if self.is_ext64
                            else FukuOperandSize.SIZE_0.value
                        )
                    ]
                    & 0xFFFF
                )

            case FukuOperandSize.SIZE_16:
                return (
                    FULL_INCLUDE_FLAGS_TABLE[
                        self.index.value
                        + (
                            FukuOperandSize.SIZE_64.value
                            if self.is_ext64
                            else FukuOperandSize.SIZE_0.value
                        )
                    ]
                    & 0xFFFFFFFF
                )

            case FukuOperandSize.SIZE_32:
                return (
                    FULL_INCLUDE_FLAGS_TABLE[
                        self.index.value
                        + (
                            FukuOperandSize.SIZE_64.value
                            if self.is_ext64
                            else FukuOperandSize.SIZE_0.value
                        )
                    ]
                    & 0xFFFFFFFFFFFF
                )

            case FukuOperandSize.SIZE_64:
                return FULL_INCLUDE_FLAGS_TABLE[
                    self.index.value
                    + (
                        FukuOperandSize.SIZE_64.value
                        if self.is_ext64
                        else FukuOperandSize.SIZE_0.value
                    )
                ]

    @staticmethod
    def from_capstone(op: X86Op) -> FukuRegister:
        return FukuRegister(FukuRegisterEnum.from_capstone(op))

    def to_iced(self):
        name = self.reg.name.removeprefix("REG_")
        if name[-1] == "B":
            name = name.replace("B", "L")
        return getattr(Register, name)

    def to_iced_name(self):
        return "reg"


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
        **kwargs,
    ):
        super().__init__(
            register_=a,
            register_index=b,
            register_size=c,
            is_x64_arch=d,
            is_x64_arch_ext=e,
            **kwargs,
        )


FUKU_EXT_REGISTER_INFO = [
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_NONE,
        FukuRegisterIndex(-1),
        FukuOperandSize.SIZE_0,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_RAX,
        FukuRegisterIndex.INDEX_AX,
        FukuOperandSize.SIZE_64,
        True,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_EAX,
        FukuRegisterIndex.INDEX_AX,
        FukuOperandSize.SIZE_32,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_AX,
        FukuRegisterIndex.INDEX_AX,
        FukuOperandSize.SIZE_16,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_AH,
        FukuRegisterIndex.INDEX_AX,
        FukuOperandSize.SIZE_8,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_AL,
        FukuRegisterIndex.INDEX_AX,
        FukuOperandSize.SIZE_8,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_RCX,
        FukuRegisterIndex.INDEX_CX,
        FukuOperandSize.SIZE_64,
        True,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_ECX,
        FukuRegisterIndex.INDEX_CX,
        FukuOperandSize.SIZE_32,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_CX,
        FukuRegisterIndex.INDEX_CX,
        FukuOperandSize.SIZE_16,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_CH,
        FukuRegisterIndex.INDEX_CX,
        FukuOperandSize.SIZE_8,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_CL,
        FukuRegisterIndex.INDEX_CX,
        FukuOperandSize.SIZE_8,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_RDX,
        FukuRegisterIndex.INDEX_DX,
        FukuOperandSize.SIZE_64,
        True,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_EDX,
        FukuRegisterIndex.INDEX_DX,
        FukuOperandSize.SIZE_32,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_DX,
        FukuRegisterIndex.INDEX_DX,
        FukuOperandSize.SIZE_16,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_DH,
        FukuRegisterIndex.INDEX_DX,
        FukuOperandSize.SIZE_8,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_DL,
        FukuRegisterIndex.INDEX_DX,
        FukuOperandSize.SIZE_8,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_RBX,
        FukuRegisterIndex.INDEX_BX,
        FukuOperandSize.SIZE_64,
        True,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_EBX,
        FukuRegisterIndex.INDEX_BX,
        FukuOperandSize.SIZE_32,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_BX,
        FukuRegisterIndex.INDEX_BX,
        FukuOperandSize.SIZE_16,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_BH,
        FukuRegisterIndex.INDEX_BX,
        FukuOperandSize.SIZE_8,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_BL,
        FukuRegisterIndex.INDEX_BX,
        FukuOperandSize.SIZE_8,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_RSP,
        FukuRegisterIndex.INDEX_SP,
        FukuOperandSize.SIZE_64,
        True,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_ESP,
        FukuRegisterIndex.INDEX_SP,
        FukuOperandSize.SIZE_32,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_SP,
        FukuRegisterIndex.INDEX_SP,
        FukuOperandSize.SIZE_16,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_SPL,
        FukuRegisterIndex.INDEX_SP,
        FukuOperandSize.SIZE_8,
        True,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_RBP,
        FukuRegisterIndex.INDEX_BP,
        FukuOperandSize.SIZE_64,
        True,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_EBP,
        FukuRegisterIndex.INDEX_BP,
        FukuOperandSize.SIZE_32,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_BP,
        FukuRegisterIndex.INDEX_BP,
        FukuOperandSize.SIZE_16,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_BPL,
        FukuRegisterIndex.INDEX_BP,
        FukuOperandSize.SIZE_8,
        True,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_RSI,
        FukuRegisterIndex.INDEX_SI,
        FukuOperandSize.SIZE_64,
        True,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_ESI,
        FukuRegisterIndex.INDEX_SI,
        FukuOperandSize.SIZE_32,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_SI,
        FukuRegisterIndex.INDEX_SI,
        FukuOperandSize.SIZE_16,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_SIL,
        FukuRegisterIndex.INDEX_SI,
        FukuOperandSize.SIZE_8,
        True,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_RDI,
        FukuRegisterIndex.INDEX_DI,
        FukuOperandSize.SIZE_64,
        True,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_EDI,
        FukuRegisterIndex.INDEX_DI,
        FukuOperandSize.SIZE_32,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_DI,
        FukuRegisterIndex.INDEX_DI,
        FukuOperandSize.SIZE_16,
        False,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_DIL,
        FukuRegisterIndex.INDEX_DI,
        FukuOperandSize.SIZE_8,
        True,
        False,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R8,
        FukuRegisterIndex.INDEX_R8,
        FukuOperandSize.SIZE_64,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R8D,
        FukuRegisterIndex.INDEX_R8,
        FukuOperandSize.SIZE_32,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R8W,
        FukuRegisterIndex.INDEX_R8,
        FukuOperandSize.SIZE_16,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R8B,
        FukuRegisterIndex.INDEX_R8,
        FukuOperandSize.SIZE_8,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R9,
        FukuRegisterIndex.INDEX_R9,
        FukuOperandSize.SIZE_64,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R9D,
        FukuRegisterIndex.INDEX_R9,
        FukuOperandSize.SIZE_32,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R9W,
        FukuRegisterIndex.INDEX_R9,
        FukuOperandSize.SIZE_16,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R9B,
        FukuRegisterIndex.INDEX_R9,
        FukuOperandSize.SIZE_8,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R10,
        FukuRegisterIndex.INDEX_R10,
        FukuOperandSize.SIZE_64,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R10D,
        FukuRegisterIndex.INDEX_R10,
        FukuOperandSize.SIZE_32,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R10W,
        FukuRegisterIndex.INDEX_R10,
        FukuOperandSize.SIZE_16,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R10B,
        FukuRegisterIndex.INDEX_R10,
        FukuOperandSize.SIZE_8,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R11,
        FukuRegisterIndex.INDEX_R11,
        FukuOperandSize.SIZE_64,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R11D,
        FukuRegisterIndex.INDEX_R11,
        FukuOperandSize.SIZE_32,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R11W,
        FukuRegisterIndex.INDEX_R11,
        FukuOperandSize.SIZE_16,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R11B,
        FukuRegisterIndex.INDEX_R11,
        FukuOperandSize.SIZE_8,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R12,
        FukuRegisterIndex.INDEX_R12,
        FukuOperandSize.SIZE_64,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R12D,
        FukuRegisterIndex.INDEX_R12,
        FukuOperandSize.SIZE_32,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R12W,
        FukuRegisterIndex.INDEX_R12,
        FukuOperandSize.SIZE_16,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R12B,
        FukuRegisterIndex.INDEX_R12,
        FukuOperandSize.SIZE_8,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R13,
        FukuRegisterIndex.INDEX_R13,
        FukuOperandSize.SIZE_64,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R13D,
        FukuRegisterIndex.INDEX_R13,
        FukuOperandSize.SIZE_32,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R13W,
        FukuRegisterIndex.INDEX_R13,
        FukuOperandSize.SIZE_16,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R13B,
        FukuRegisterIndex.INDEX_R13,
        FukuOperandSize.SIZE_8,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R14,
        FukuRegisterIndex.INDEX_R14,
        FukuOperandSize.SIZE_64,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R14D,
        FukuRegisterIndex.INDEX_R14,
        FukuOperandSize.SIZE_32,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R14W,
        FukuRegisterIndex.INDEX_R14,
        FukuOperandSize.SIZE_16,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R14B,
        FukuRegisterIndex.INDEX_R14,
        FukuOperandSize.SIZE_8,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R15,
        FukuRegisterIndex.INDEX_R15,
        FukuOperandSize.SIZE_64,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R15D,
        FukuRegisterIndex.INDEX_R15,
        FukuOperandSize.SIZE_32,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R15W,
        FukuRegisterIndex.INDEX_R15,
        FukuOperandSize.SIZE_16,
        True,
        True,
    ),
    FukuExtRegisterInfo(
        FukuRegisterEnum.REG_R15B,
        FukuRegisterIndex.INDEX_R15,
        FukuOperandSize.SIZE_8,
        True,
        True,
    ),
]

CAP_TO_FUKU_TABLE = [
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_AH,
    FukuRegisterEnum.REG_AL,
    FukuRegisterEnum.REG_AX,
    FukuRegisterEnum.REG_BH,
    FukuRegisterEnum.REG_BL,
    FukuRegisterEnum.REG_BP,
    FukuRegisterEnum.REG_BPL,
    FukuRegisterEnum.REG_BX,
    FukuRegisterEnum.REG_CH,
    FukuRegisterEnum.REG_CL,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_CX,
    FukuRegisterEnum.REG_DH,
    FukuRegisterEnum.REG_DI,
    FukuRegisterEnum.REG_DIL,
    FukuRegisterEnum.REG_DL,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_DX,
    FukuRegisterEnum.REG_EAX,
    FukuRegisterEnum.REG_EBP,
    FukuRegisterEnum.REG_EBX,
    FukuRegisterEnum.REG_ECX,
    FukuRegisterEnum.REG_EDI,
    FukuRegisterEnum.REG_EDX,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_ESI,
    FukuRegisterEnum.REG_ESP,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_RAX,
    FukuRegisterEnum.REG_RBP,
    FukuRegisterEnum.REG_RBX,
    FukuRegisterEnum.REG_RCX,
    FukuRegisterEnum.REG_RDI,
    FukuRegisterEnum.REG_RDX,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_RSI,
    FukuRegisterEnum.REG_RSP,
    FukuRegisterEnum.REG_SI,
    FukuRegisterEnum.REG_SIL,
    FukuRegisterEnum.REG_SP,
    FukuRegisterEnum.REG_SPL,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_R8,
    FukuRegisterEnum.REG_R9,
    FukuRegisterEnum.REG_R10,
    FukuRegisterEnum.REG_R11,
    FukuRegisterEnum.REG_R12,
    FukuRegisterEnum.REG_R13,
    FukuRegisterEnum.REG_R14,
    FukuRegisterEnum.REG_R15,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_NONE,
    FukuRegisterEnum.REG_R8B,
    FukuRegisterEnum.REG_R9B,
    FukuRegisterEnum.REG_R10B,
    FukuRegisterEnum.REG_R11B,
    FukuRegisterEnum.REG_R12B,
    FukuRegisterEnum.REG_R13B,
    FukuRegisterEnum.REG_R14B,
    FukuRegisterEnum.REG_R15B,
    FukuRegisterEnum.REG_R8D,
    FukuRegisterEnum.REG_R9D,
    FukuRegisterEnum.REG_R10D,
    FukuRegisterEnum.REG_R11D,
    FukuRegisterEnum.REG_R12D,
    FukuRegisterEnum.REG_R13D,
    FukuRegisterEnum.REG_R14D,
    FukuRegisterEnum.REG_R15D,
    FukuRegisterEnum.REG_R8W,
    FukuRegisterEnum.REG_R9W,
    FukuRegisterEnum.REG_R10W,
    FukuRegisterEnum.REG_R11W,
    FukuRegisterEnum.REG_R12W,
    FukuRegisterEnum.REG_R13W,
    FukuRegisterEnum.REG_R14W,
    FukuRegisterEnum.REG_R15W,
    FukuRegisterEnum.REG_MAX,
]


CONVERT_FLAG_REGISTER_TO_FUKU = [
    FukuRegisterEnum.REG_AL,
    FukuRegisterEnum.REG_CL,
    FukuRegisterEnum.REG_DL,
    FukuRegisterEnum.REG_BL,
    FukuRegisterEnum.REG_SPL,
    FukuRegisterEnum.REG_BPL,
    FukuRegisterEnum.REG_SIL,
    FukuRegisterEnum.REG_DIL,
    FukuRegisterEnum.REG_R8B,
    FukuRegisterEnum.REG_R9B,
    FukuRegisterEnum.REG_R10B,
    FukuRegisterEnum.REG_R11B,
    FukuRegisterEnum.REG_R12B,
    FukuRegisterEnum.REG_R13B,
    FukuRegisterEnum.REG_R14B,
    FukuRegisterEnum.REG_R15B,
    # word
    FukuRegisterEnum.REG_AX,
    FukuRegisterEnum.REG_CX,
    FukuRegisterEnum.REG_DX,
    FukuRegisterEnum.REG_BX,
    FukuRegisterEnum.REG_SP,
    FukuRegisterEnum.REG_BP,
    FukuRegisterEnum.REG_SI,
    FukuRegisterEnum.REG_DI,
    FukuRegisterEnum.REG_R8W,
    FukuRegisterEnum.REG_R9W,
    FukuRegisterEnum.REG_R10W,
    FukuRegisterEnum.REG_R11W,
    FukuRegisterEnum.REG_R12W,
    FukuRegisterEnum.REG_R13W,
    FukuRegisterEnum.REG_R14W,
    FukuRegisterEnum.REG_R15W,
    # dword
    FukuRegisterEnum.REG_EAX,
    FukuRegisterEnum.REG_ECX,
    FukuRegisterEnum.REG_EDX,
    FukuRegisterEnum.REG_EBX,
    FukuRegisterEnum.REG_ESP,
    FukuRegisterEnum.REG_EBP,
    FukuRegisterEnum.REG_ESI,
    FukuRegisterEnum.REG_EDI,
    FukuRegisterEnum.REG_R8D,
    FukuRegisterEnum.REG_R9D,
    FukuRegisterEnum.REG_R10D,
    FukuRegisterEnum.REG_R11D,
    FukuRegisterEnum.REG_R12D,
    FukuRegisterEnum.REG_R13D,
    FukuRegisterEnum.REG_R14D,
    FukuRegisterEnum.REG_R15D,
    # qword
    FukuRegisterEnum.REG_RAX,
    FukuRegisterEnum.REG_RCX,
    FukuRegisterEnum.REG_RDX,
    FukuRegisterEnum.REG_RBX,
    FukuRegisterEnum.REG_RSP,
    FukuRegisterEnum.REG_RBP,
    FukuRegisterEnum.REG_RSI,
    FukuRegisterEnum.REG_RDI,
    FukuRegisterEnum.REG_R8,
    FukuRegisterEnum.REG_R9,
    FukuRegisterEnum.REG_R10,
    FukuRegisterEnum.REG_R11,
    FukuRegisterEnum.REG_R12,
    FukuRegisterEnum.REG_R13,
    FukuRegisterEnum.REG_R14,
    FukuRegisterEnum.REG_R15,
]


def cpu_registers_to_names(cpu_registers: int) -> List:
    bits = []

    for i, c in enumerate(bin(cpu_registers)[:1:-1], 1):
        if c == "1":
            bits.append(i - 1)

    return [CONVERT_FLAG_REGISTER_TO_FUKU[index] for index in bits]
