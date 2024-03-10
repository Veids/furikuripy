from capstone import x86_const
from x86.fuku_register_math_metadata import FlagRegister, FlagRegisterIndex


CAPSTONE_JCC = [
    x86_const.X86_INS_JO, x86_const.X86_INS_JNO,
    x86_const.X86_INS_JB, x86_const.X86_INS_JAE,
    x86_const.X86_INS_JE, x86_const.X86_INS_JNE,
    x86_const.X86_INS_JBE, x86_const.X86_INS_JA,
    x86_const.X86_INS_JS, x86_const.X86_INS_JNS,
    x86_const.X86_INS_JP, x86_const.X86_INS_JNP,
    x86_const.X86_INS_JL, x86_const.X86_INS_JGE,
    x86_const.X86_INS_JLE, x86_const.X86_INS_JG,
]

CAPSTONE_SETCC = [
    x86_const.X86_INS_SETO, x86_const.X86_INS_SETNO,
    x86_const.X86_INS_SETB, x86_const.X86_INS_SETAE,
    x86_const.X86_INS_SETE, x86_const.X86_INS_SETNE,
    x86_const.X86_INS_SETBE, x86_const.X86_INS_SETA,
    x86_const.X86_INS_SETS, x86_const.X86_INS_SETNS,
    x86_const.X86_INS_SETP, x86_const.X86_INS_SETNP,
    x86_const.X86_INS_SETL, x86_const.X86_INS_SETGE,
    x86_const.X86_INS_SETLE, x86_const.X86_INS_SETG,
]

CAPSTONE_MOVCC = [
    x86_const.X86_INS_CMOVO, x86_const.X86_INS_CMOVNO,
    x86_const.X86_INS_CMOVB, x86_const.X86_INS_CMOVAE,
    x86_const.X86_INS_CMOVE, x86_const.X86_INS_CMOVNE,
    x86_const.X86_INS_CMOVBE, x86_const.X86_INS_CMOVA,
    x86_const.X86_INS_CMOVS, x86_const.X86_INS_CMOVNS,
    x86_const.X86_INS_CMOVP, x86_const.X86_INS_CMOVNP,
    x86_const.X86_INS_CMOVL, x86_const.X86_INS_CMOVGE,
    x86_const.X86_INS_CMOVLE, x86_const.X86_INS_CMOVG,
]

CAPSTONE_REGISTER_FLAGS = [
    -2,
    FlagRegister.AX.value, FlagRegister.AL.value, FlagRegister.AX.value, FlagRegister.BX.value, FlagRegister.BL.value,
    FlagRegister.BP.value, FlagRegister.BPL.value, FlagRegister.BX.value, FlagRegister.CX.value, FlagRegister.CL.value,
    -2, FlagRegister.CX.value, FlagRegister.DX.value, FlagRegister.DI.value, FlagRegister.DIL.value,
    FlagRegister.DL.value, -2, FlagRegister.DX.value, FlagRegister.EAX.value, FlagRegister.EBP.value,
    FlagRegister.EBX.value, FlagRegister.ECX.value, FlagRegister.EDI.value, FlagRegister.EDX.value, 0,
    -2, -2, -2, FlagRegister.ESI.value, FlagRegister.ESP.value,
    -2, -2, -2, -2, FlagRegister.RAX.value,
    FlagRegister.RBP.value, FlagRegister.RBX.value, FlagRegister.RCX.value, FlagRegister.RDI.value, FlagRegister.RDX.value,
    -2, -2, FlagRegister.RSI.value, FlagRegister.RSP.value, FlagRegister.SI.value,
    FlagRegister.SIL.value, FlagRegister.SP.value, FlagRegister.SPL.value, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, FlagRegister.R8.value, FlagRegister.R9.value, FlagRegister.R10.value, FlagRegister.R11.value,
    FlagRegister.R12.value, FlagRegister.R13.value, FlagRegister.R14.value, FlagRegister.R15.value,
    -2, -2, -2, -2,
    -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, FlagRegister.R8B.value, FlagRegister.R9B.value, FlagRegister.R10B.value, FlagRegister.R11B.value,
    FlagRegister.R12B.value, FlagRegister.R13B.value, FlagRegister.R14B.value, FlagRegister.R15B.value, FlagRegister.R8D.value,
    FlagRegister.R9D.value, FlagRegister.R10D.value, FlagRegister.R11D.value, FlagRegister.R12D.value, FlagRegister.R13D.value,
    FlagRegister.R14D.value, FlagRegister.R15D.value, FlagRegister.R8W.value, FlagRegister.R9W.value, FlagRegister.R10W.value,
    FlagRegister.R11W.value, FlagRegister.R12W.value, FlagRegister.R13W.value, FlagRegister.R14W.value, FlagRegister.R15W.value,
    -2
]

FULL_INCLUDE_FLAGS_TABLE = [
    FlagRegister.RAX.value | FlagRegister.EAX.value | FlagRegister.AX.value | FlagRegister.AL.value,
    FlagRegister.RCX.value | FlagRegister.ECX.value | FlagRegister.CX.value | FlagRegister.CL.value,
    FlagRegister.RDX.value | FlagRegister.EDX.value | FlagRegister.DX.value | FlagRegister.DL.value,
    FlagRegister.RBX.value | FlagRegister.EBX.value | FlagRegister.BX.value | FlagRegister.BL.value,
    FlagRegister.RSP.value | FlagRegister.ESP.value | FlagRegister.SP.value | FlagRegister.SPL.value,
    FlagRegister.RBP.value | FlagRegister.EBP.value | FlagRegister.BP.value | FlagRegister.BPL.value,
    FlagRegister.RSI.value | FlagRegister.ESI.value | FlagRegister.SI.value | FlagRegister.SIL.value,
    FlagRegister.RDI.value | FlagRegister.EDI.value | FlagRegister.DI.value | FlagRegister.DIL.value,
    FlagRegister.R8.value | FlagRegister.R8D.value | FlagRegister.R8W.value | FlagRegister.R8B.value,
    FlagRegister.R9.value | FlagRegister.R9D.value | FlagRegister.R9W.value | FlagRegister.R9B.value,
    FlagRegister.R10.value | FlagRegister.R10D.value | FlagRegister.R10W.value | FlagRegister.R10B.value,
    FlagRegister.R11.value | FlagRegister.R11D.value | FlagRegister.R11W.value | FlagRegister.R11B.value,
    FlagRegister.R12.value | FlagRegister.R12D.value | FlagRegister.R12W.value | FlagRegister.R12B.value,
    FlagRegister.R13.value | FlagRegister.R13D.value | FlagRegister.R13W.value | FlagRegister.R13B.value,
    FlagRegister.R14.value | FlagRegister.R14D.value | FlagRegister.R14W.value | FlagRegister.R14B.value,
    FlagRegister.R15.value | FlagRegister.R15D.value | FlagRegister.R15W.value | FlagRegister.R15B.value,
]


SIZE_TO_INDEXSZ = [
    0,
    0,
    1,
    0,2,
    0,0,0,3
]

CONVERT_FUKU_REGISTER_TO_FLAG = [
    0,

    # x86-x32 registers
    FlagRegisterIndex.RAX.value,
    FlagRegisterIndex.EAX.value,
    FlagRegisterIndex.AX.value,
    FlagRegisterIndex.AX.value,
    FlagRegisterIndex.AL.value,

    FlagRegisterIndex.RCX.value,
    FlagRegisterIndex.ECX.value,
    FlagRegisterIndex.CX.value,
    FlagRegisterIndex.CX.value,
    FlagRegisterIndex.CL.value,

    FlagRegisterIndex.RDX.value,
    FlagRegisterIndex.EDX.value,
    FlagRegisterIndex.DX.value,
    FlagRegisterIndex.DX.value,
    FlagRegisterIndex.DL.value,

    FlagRegisterIndex.RBX.value,
    FlagRegisterIndex.EBX.value,
    FlagRegisterIndex.BX.value,
    FlagRegisterIndex.BX.value,
    FlagRegisterIndex.BL.value,

    FlagRegisterIndex.RSP.value,
    FlagRegisterIndex.ESP.value,
    FlagRegisterIndex.SP.value,
    FlagRegisterIndex.SPL.value,

    FlagRegisterIndex.RBP.value,
    FlagRegisterIndex.EBP.value,
    FlagRegisterIndex.BP.value,
    FlagRegisterIndex.BPL.value,

    FlagRegisterIndex.RSI.value,
    FlagRegisterIndex.ESI.value,
    FlagRegisterIndex.SI.value,
    FlagRegisterIndex.SIL.value,

    FlagRegisterIndex.RDI.value,
    FlagRegisterIndex.EDI.value,
    FlagRegisterIndex.DI.value,
    FlagRegisterIndex.DIL.value,

    # x86-x64 registers
    FlagRegisterIndex.R8.value,
    FlagRegisterIndex.R8D.value,
    FlagRegisterIndex.R8W.value,
    FlagRegisterIndex.R8B.value,
    FlagRegisterIndex.R9.value,
    FlagRegisterIndex.R9D.value,
    FlagRegisterIndex.R9W.value,
    FlagRegisterIndex.R9B.value,

    FlagRegisterIndex.R10.value,
    FlagRegisterIndex.R10D.value,
    FlagRegisterIndex.R10W.value,
    FlagRegisterIndex.R10B.value,

    FlagRegisterIndex.R11.value,
    FlagRegisterIndex.R11D.value,
    FlagRegisterIndex.R11W.value,
    FlagRegisterIndex.R11B.value,

    FlagRegisterIndex.R12.value,
    FlagRegisterIndex.R12D.value,
    FlagRegisterIndex.R12W.value,
    FlagRegisterIndex.R12B.value,

    FlagRegisterIndex.R13.value,
    FlagRegisterIndex.R13D.value,
    FlagRegisterIndex.R13W.value,
    FlagRegisterIndex.R13B.value,

    FlagRegisterIndex.R14.value,
    FlagRegisterIndex.R14D.value,
    FlagRegisterIndex.R14W.value,
    FlagRegisterIndex.R14B.value,

    FlagRegisterIndex.R15.value,
    FlagRegisterIndex.R15D.value,
    FlagRegisterIndex.R15W.value,
    FlagRegisterIndex.R15B.value
]
