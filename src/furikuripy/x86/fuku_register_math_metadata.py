from enum import Enum, Flag
from capstone import x86_const


class EflagsGroup(Enum):
    TEST = (
        x86_const.X86_EFLAGS_TEST_OF
        | x86_const.X86_EFLAGS_TEST_SF
        | x86_const.X86_EFLAGS_TEST_ZF
        | x86_const.X86_EFLAGS_TEST_PF
        | x86_const.X86_EFLAGS_TEST_CF
        | x86_const.X86_EFLAGS_TEST_DF
        | x86_const.X86_EFLAGS_TEST_AF
    )
    MODIFY = (
        x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF
        | x86_const.X86_EFLAGS_MODIFY_DF
        | x86_const.X86_EFLAGS_MODIFY_AF
    )
    SET = (
        x86_const.X86_EFLAGS_SET_CF
        | x86_const.X86_EFLAGS_SET_DF
        | x86_const.X86_EFLAGS_SET_OF
        | x86_const.X86_EFLAGS_SET_SF
        | x86_const.X86_EFLAGS_SET_ZF
        | x86_const.X86_EFLAGS_SET_AF
        | x86_const.X86_EFLAGS_SET_PF
    )
    RESET = (
        x86_const.X86_EFLAGS_RESET_OF
        | x86_const.X86_EFLAGS_RESET_CF
        | x86_const.X86_EFLAGS_RESET_DF
        | x86_const.X86_EFLAGS_RESET_SF
        | x86_const.X86_EFLAGS_RESET_AF
        | x86_const.X86_EFLAGS_RESET_ZF
    )
    UNDEFINED = (
        x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_UNDEFINED_SF
        | x86_const.X86_EFLAGS_UNDEFINED_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_PF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_UNDEFINED_CF
    )


class EflagsMod(Enum):
    CF = (
        x86_const.X86_EFLAGS_SET_CF
        | x86_const.X86_EFLAGS_UNDEFINED_CF
        | x86_const.X86_EFLAGS_RESET_OF
        | x86_const.X86_EFLAGS_MODIFY_CF
    )
    OF = (
        x86_const.X86_EFLAGS_SET_OF
        | x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_RESET_OF
        | x86_const.X86_EFLAGS_MODIFY_OF
    )
    ZF = (
        x86_const.X86_EFLAGS_SET_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_ZF
        | x86_const.X86_EFLAGS_RESET_ZF
        | x86_const.X86_EFLAGS_MODIFY_ZF
    )
    DF = (
        x86_const.X86_EFLAGS_SET_DF
        | x86_const.X86_EFLAGS_RESET_DF
        | x86_const.X86_EFLAGS_MODIFY_DF
    )
    SF = (
        x86_const.X86_EFLAGS_SET_SF
        | x86_const.X86_EFLAGS_UNDEFINED_SF
        | x86_const.X86_EFLAGS_RESET_SF
        | x86_const.X86_EFLAGS_MODIFY_SF
    )
    PF = (
        x86_const.X86_EFLAGS_SET_PF
        | x86_const.X86_EFLAGS_UNDEFINED_PF
        | x86_const.X86_EFLAGS_RESET_PF
        | x86_const.X86_EFLAGS_MODIFY_PF
    )
    AF = (
        x86_const.X86_EFLAGS_SET_AF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_RESET_AF
        | x86_const.X86_EFLAGS_MODIFY_AF
    )


FlagRegisterIndex = Enum(
    "FlagRegisterIndex",
    [
        # byte
        "AL",
        "CL",
        "DL",
        "BL",
        "SPL",
        "BPL",
        "SIL",
        "DIL",
        "R8B",
        "R9B",
        "R10B",
        "R11B",
        "R12B",
        "R13B",
        "R14B",
        "R15B",
        # word
        "AX",
        "CX",
        "DX",
        "BX",
        "SP",
        "BP",
        "SI",
        "DI",
        "R8W",
        "R9W",
        "R10W",
        "R11W",
        "R12W",
        "R13W",
        "R14W",
        "R15W",
        # dword
        "EAX",
        "ECX",
        "EDX",
        "EBX",
        "ESP",
        "EBP",
        "ESI",
        "EDI",
        "R8D",
        "R9D",
        "R10D",
        "R11D",
        "R12D",
        "R13D",
        "R14D",
        "R15D",
        # qword
        "RAX",
        "RCX",
        "RDX",
        "RBX",
        "RSP",
        "RBP",
        "RSI",
        "RDI",
        "R8",
        "R9",
        "R10",
        "R11",
        "R12",
        "R13",
        "R14",
        "R15",
    ],
    start=0,
)


class FlagRegister(Flag):
    # byte
    AL = 1 << FlagRegisterIndex.AL.value
    CL = 1 << FlagRegisterIndex.CL.value
    DL = 1 << FlagRegisterIndex.DL.value
    BL = 1 << FlagRegisterIndex.BL.value
    SPL = 1 << FlagRegisterIndex.SPL.value
    BPL = 1 << FlagRegisterIndex.BPL.value
    SIL = 1 << FlagRegisterIndex.SIL.value
    DIL = 1 << FlagRegisterIndex.DIL.value
    R8B = 1 << FlagRegisterIndex.R8B.value
    R9B = 1 << FlagRegisterIndex.R9B.value
    R10B = 1 << FlagRegisterIndex.R10B.value
    R11B = 1 << FlagRegisterIndex.R11B.value
    R12B = 1 << FlagRegisterIndex.R12B.value
    R13B = 1 << FlagRegisterIndex.R13B.value
    R14B = 1 << FlagRegisterIndex.R14B.value
    R15B = 1 << FlagRegisterIndex.R15B.value
    # word
    AX = 1 << FlagRegisterIndex.AX.value
    CX = 1 << FlagRegisterIndex.CX.value
    DX = 1 << FlagRegisterIndex.DX.value
    BX = 1 << FlagRegisterIndex.BX.value
    SP = 1 << FlagRegisterIndex.SP.value
    BP = 1 << FlagRegisterIndex.BP.value
    SI = 1 << FlagRegisterIndex.SI.value
    DI = 1 << FlagRegisterIndex.DI.value
    R8W = 1 << FlagRegisterIndex.R8W.value
    R9W = 1 << FlagRegisterIndex.R9W.value
    R10W = 1 << FlagRegisterIndex.R10W.value
    R11W = 1 << FlagRegisterIndex.R11W.value
    R12W = 1 << FlagRegisterIndex.R12W.value
    R13W = 1 << FlagRegisterIndex.R13W.value
    R14W = 1 << FlagRegisterIndex.R14W.value
    R15W = 1 << FlagRegisterIndex.R15W.value
    # dword
    EAX = 1 << FlagRegisterIndex.EAX.value
    ECX = 1 << FlagRegisterIndex.ECX.value
    EDX = 1 << FlagRegisterIndex.EDX.value
    EBX = 1 << FlagRegisterIndex.EBX.value
    ESP = 1 << FlagRegisterIndex.ESP.value
    EBP = 1 << FlagRegisterIndex.EBP.value
    ESI = 1 << FlagRegisterIndex.ESI.value
    EDI = 1 << FlagRegisterIndex.EDI.value
    R8D = 1 << FlagRegisterIndex.R8D.value
    R9D = 1 << FlagRegisterIndex.R9D.value
    R10D = 1 << FlagRegisterIndex.R10D.value
    R11D = 1 << FlagRegisterIndex.R11D.value
    R12D = 1 << FlagRegisterIndex.R12D.value
    R13D = 1 << FlagRegisterIndex.R13D.value
    R14D = 1 << FlagRegisterIndex.R14D.value
    R15D = 1 << FlagRegisterIndex.R15D.value
    # qword
    RAX = 1 << FlagRegisterIndex.RAX.value
    RCX = 1 << FlagRegisterIndex.RCX.value
    RDX = 1 << FlagRegisterIndex.RDX.value
    RBX = 1 << FlagRegisterIndex.RBX.value
    RSP = 1 << FlagRegisterIndex.RSP.value
    RBP = 1 << FlagRegisterIndex.RBP.value
    RSI = 1 << FlagRegisterIndex.RSI.value
    RDI = 1 << FlagRegisterIndex.RDI.value
    R8 = 1 << FlagRegisterIndex.R8.value
    R9 = 1 << FlagRegisterIndex.R9.value
    R10 = 1 << FlagRegisterIndex.R10.value
    R11 = 1 << FlagRegisterIndex.R11.value
    R12 = 1 << FlagRegisterIndex.R12.value
    R13 = 1 << FlagRegisterIndex.R13.value
    R14 = 1 << FlagRegisterIndex.R14.value
    R15 = 1 << FlagRegisterIndex.R15.value


class RegisterAccess(Flag):
    READ = 1 << 0
    WRITE = 1 << 1


class AllowInstruction(Enum):
    REGISTER = 1 << 0
    OPERAND = 1 << 1
    IMMEDIATE = 1 << 2


TESTED_FLAGS_TABLE = [
    x86_const.X86_EFLAGS_TEST_OF,
    x86_const.X86_EFLAGS_TEST_SF,
    x86_const.X86_EFLAGS_TEST_ZF,
    x86_const.X86_EFLAGS_TEST_PF,
    x86_const.X86_EFLAGS_TEST_CF,
    x86_const.X86_EFLAGS_TEST_DF,
    x86_const.X86_EFLAGS_TEST_AF,
]

EXCLUDED_FLAGS_TABLE = [
    EflagsMod.OF.value,
    EflagsMod.SF.value,
    EflagsMod.ZF.value,
    EflagsMod.PF.value,
    EflagsMod.CF.value,
    EflagsMod.DF.value,
    EflagsMod.AF.value,
]

ODI_FL_JCC = [
    EflagsMod.OF.value,
    EflagsMod.OF.value,  # jo / jno
    EflagsMod.CF.value,
    EflagsMod.CF.value,  # jb / jae
    EflagsMod.ZF.value,
    EflagsMod.ZF.value,  # je / jne
    EflagsMod.ZF.value | EflagsMod.CF.value,
    EflagsMod.ZF.value | EflagsMod.CF.value,  # jbe / jnbe
    EflagsMod.SF.value,
    EflagsMod.SF.value,  # js / jns
    EflagsMod.PF.value,
    EflagsMod.PF.value,  # jp / jnp
    EflagsMod.OF.value | EflagsMod.SF.value,
    EflagsMod.OF.value | EflagsMod.SF.value,  # jnge / jge
    EflagsMod.OF.value | EflagsMod.SF.value | EflagsMod.ZF.value,
    EflagsMod.OF.value | EflagsMod.SF.value | EflagsMod.ZF.value,  # jng / jnle
]
