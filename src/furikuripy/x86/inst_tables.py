from capstone import x86_const
from pydantic import BaseModel

from furikuripy.x86.fuku_immediate import FukuImmediate
from furikuripy.x86.fuku_operand import FukuOperand
from furikuripy.x86.fuku_register import FukuRegister


class InstProp(BaseModel):
    capstone_code: int
    cap_eflags: int
    ops: dict = dict()


INST_PROPS = {
    # Binary Arithmetic Instructions
    "adcx": InstProp(
        capstone_code=x86_const.X86_INS_ADCX,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister, "op2": FukuRegister | FukuOperand},
    ),
    "adox": InstProp(
        capstone_code=x86_const.X86_INS_ADOX,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF,
        ops={"op1": FukuRegister, "op2": FukuRegister | FukuOperand},
    ),
    "add": InstProp(
        capstone_code=x86_const.X86_INS_ADD,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF,
        ops={
            "op1": FukuRegister | FukuOperand | FukuImmediate,
            "op2": FukuRegister | FukuOperand | FukuImmediate,
        },
    ),
    "adc": InstProp(
        capstone_code=x86_const.X86_INS_ADC,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={
            "op1": FukuRegister | FukuOperand | FukuImmediate,
            "op2": FukuRegister | FukuOperand | FukuImmediate,
        },
    ),
    "sub": InstProp(
        capstone_code=x86_const.X86_INS_SUB,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={
            "op1": FukuRegister | FukuOperand | FukuImmediate,
            "op2": FukuRegister | FukuOperand | FukuImmediate,
        },
    ),
    "sbb": InstProp(
        capstone_code=x86_const.X86_INS_SBB,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={
            "op1": FukuRegister | FukuOperand | FukuImmediate,
            "op2": FukuRegister | FukuOperand | FukuImmediate,
        },
    ),
    "imul": InstProp(
        capstone_code=x86_const.X86_INS_IMUL,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_CF
        | x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_UNDEFINED_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_UNDEFINED_PF,
        ops={
            "op1": FukuRegister | FukuOperand,
        },
    ),
    "mul": InstProp(
        capstone_code=x86_const.X86_INS_MUL,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_UNDEFINED_SF
        | x86_const.X86_EFLAGS_UNDEFINED_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_UNDEFINED_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={
            "op1": FukuRegister | FukuOperand,
        },
    ),
    "idiv": InstProp(
        capstone_code=x86_const.X86_INS_IDIV,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_UNDEFINED_SF
        | x86_const.X86_EFLAGS_UNDEFINED_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_UNDEFINED_PF
        | x86_const.X86_EFLAGS_UNDEFINED_CF,
        ops={
            "op1": FukuRegister | FukuOperand,
        },
    ),
    "div": InstProp(
        capstone_code=x86_const.X86_INS_DIV,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_UNDEFINED_SF
        | x86_const.X86_EFLAGS_UNDEFINED_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_UNDEFINED_PF
        | x86_const.X86_EFLAGS_UNDEFINED_CF,
        ops={"op1": FukuRegister | FukuOperand},
    ),
    "inc": InstProp(
        capstone_code=x86_const.X86_INS_INC,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_PF,
        ops={
            "op1": FukuRegister | FukuOperand,
        },
    ),
    "dec": InstProp(
        capstone_code=x86_const.X86_INS_DEC,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_PF,
        ops={
            "op1": FukuRegister | FukuOperand,
        },
    ),
    "neg": InstProp(
        capstone_code=x86_const.X86_INS_NEG,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={
            "op1": FukuRegister | FukuOperand,
        },
    ),
    "cmp": InstProp(
        capstone_code=x86_const.X86_INS_CMP,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={
            "op1": FukuRegister | FukuOperand | FukuImmediate,
            "op2": FukuRegister | FukuOperand | FukuImmediate,
        },
    ),
    # Decimal Arithmetic Instructions
    "daa": InstProp(
        capstone_code=x86_const.X86_INS_DAA,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
    ),
    "das": InstProp(
        capstone_code=x86_const.X86_INS_DAS,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
    ),
    "aaa": InstProp(
        capstone_code=x86_const.X86_INS_AAA,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_UNDEFINED_SF
        | x86_const.X86_EFLAGS_UNDEFINED_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_UNDEFINED_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
    ),
    "aas": InstProp(
        capstone_code=x86_const.X86_INS_AAS,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_UNDEFINED_SF
        | x86_const.X86_EFLAGS_UNDEFINED_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_UNDEFINED_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
    ),
    # Logical Instructions Instructions
    "and": InstProp(
        capstone_code=x86_const.X86_INS_AND,
        cap_eflags=x86_const.X86_EFLAGS_RESET_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_RESET_CF,
        ops={
            "op1": FukuRegister | FukuOperand | FukuImmediate,
            "op2": FukuRegister | FukuOperand | FukuImmediate,
        },
    ),
    "or": InstProp(
        capstone_code=x86_const.X86_INS_OR,
        cap_eflags=x86_const.X86_EFLAGS_RESET_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_RESET_CF,
        ops={
            "op1": FukuRegister | FukuOperand | FukuImmediate,
            "op2": FukuRegister | FukuOperand | FukuImmediate,
        },
    ),
    "xor": InstProp(
        capstone_code=x86_const.X86_INS_XOR,
        cap_eflags=x86_const.X86_EFLAGS_RESET_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_RESET_CF,
        ops={
            "op1": FukuRegister | FukuOperand | FukuImmediate,
            "op2": FukuRegister | FukuOperand | FukuImmediate,
        },
    ),
    "not": InstProp(
        capstone_code=x86_const.X86_INS_NOT,
        cap_eflags=0,
        ops={"op1": FukuRegister | FukuOperand},
    ),
    # Shift and Rotate Instructions
    "sar": InstProp(
        capstone_code=x86_const.X86_INS_SAR,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand, "op2": FukuImmediate},
    ),
    "sar_cl": InstProp(
        capstone_code=x86_const.X86_INS_SAR,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand},
    ),
    "shr": InstProp(
        capstone_code=x86_const.X86_INS_SHR,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand, "op2": FukuImmediate},
    ),
    "shr_cl": InstProp(
        capstone_code=x86_const.X86_INS_SHR,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand},
    ),
    "shl": InstProp(
        capstone_code=x86_const.X86_INS_SHL,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand, "op2": FukuImmediate},
    ),
    "shl_cl": InstProp(
        capstone_code=x86_const.X86_INS_SHL,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand},
    ),
    "shrd": InstProp(
        capstone_code=x86_const.X86_INS_SHRD,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={
            "op1": FukuRegister | FukuOperand,
            "op2": FukuRegister,
            "op3": FukuImmediate,
        },
    ),
    "shrd_cl": InstProp(
        capstone_code=x86_const.X86_INS_SHRD,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand, "op2": FukuRegister},
    ),
    "shld": InstProp(
        capstone_code=x86_const.X86_INS_SHLD,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={
            "op1": FukuRegister | FukuOperand,
            "op2": FukuRegister,
            "op3": FukuImmediate,
        },
    ),
    "shld_cl": InstProp(
        capstone_code=x86_const.X86_INS_SHLD,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand, "op2": FukuRegister},
    ),
    "ror": InstProp(
        capstone_code=x86_const.X86_INS_ROR,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand, "op2": FukuImmediate},
    ),
    "ror_cl": InstProp(
        capstone_code=x86_const.X86_INS_ROR,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand},
    ),
    "rol": InstProp(
        capstone_code=x86_const.X86_INS_ROL,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand, "op2": FukuImmediate},
    ),
    "rol_cl": InstProp(
        capstone_code=x86_const.X86_INS_ROL,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand},
    ),
    "rcr": InstProp(
        capstone_code=x86_const.X86_INS_RCR,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand, "op2": FukuImmediate},
    ),
    "rcr_cl": InstProp(
        capstone_code=x86_const.X86_INS_RCR,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand},
    ),
    "rcl": InstProp(
        capstone_code=x86_const.X86_INS_RCL,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand, "op2": FukuImmediate},
    ),
    "rcl_cl": InstProp(
        capstone_code=x86_const.X86_INS_RCL,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister | FukuOperand},
    ),
    # Data Transfer Instructions
    "mov": InstProp(
        capstone_code=x86_const.X86_INS_MOV,
        cap_eflags=0,
        ops={
            "op1": FukuRegister | FukuOperand,
            "op2": FukuRegister | FukuOperand | FukuImmediate,
        },
    ),
    "xchg": InstProp(
        capstone_code=x86_const.X86_INS_XCHG,
        cap_eflags=0,
        ops={
            "op1": FukuOperand | FukuRegister,
            "op2": FukuRegister,
        },
    ),
    "bswap": InstProp(
        capstone_code=x86_const.X86_INS_BSWAP, cap_eflags=0, ops={"op1": FukuRegister}
    ),
    "xadd": InstProp(
        capstone_code=x86_const.X86_INS_XADD,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={
            "op1": FukuOperand | FukuRegister,
            "op2": FukuRegister,
        },
    ),
    "cmpxchg": InstProp(
        capstone_code=x86_const.X86_INS_CMPXCHG,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={
            "op1": FukuOperand | FukuRegister,
            "op2": FukuRegister,
        },
    ),
    "cmpxchg8b": InstProp(
        capstone_code=x86_const.X86_INS_CMPXCHG8B,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_ZF,
        ops={"op1": FukuOperand},
    ),
    "cmpxchg16b": InstProp(
        capstone_code=x86_const.X86_INS_CMPXCHG16B,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_ZF,
        ops={"op1": FukuOperand},
    ),
    "push": InstProp(
        capstone_code=x86_const.X86_INS_PUSH,
        cap_eflags=0,
        ops={
            "op1": FukuRegister | FukuOperand,
        },
    ),
    "pop": InstProp(
        capstone_code=x86_const.X86_INS_POP,
        cap_eflags=0,
        ops={"op1": FukuRegister | FukuOperand},
    ),
    "cwd": InstProp(
        capstone_code=x86_const.X86_INS_CWD,
        cap_eflags=0,
    ),
    "cdq": InstProp(
        capstone_code=x86_const.X86_INS_CDQ,
        cap_eflags=0,
    ),
    "cqo": InstProp(capstone_code=x86_const.X86_INS_CQO, cap_eflags=0),
    "cbw": InstProp(
        capstone_code=x86_const.X86_INS_CBW,
        cap_eflags=0,
    ),
    "cwde": InstProp(capstone_code=x86_const.X86_INS_CWDE, cap_eflags=0),
    "cdqe": InstProp(capstone_code=x86_const.X86_INS_CDQE, cap_eflags=0),
    "movzx": InstProp(
        capstone_code=x86_const.X86_INS_MOVZX,
        cap_eflags=0,
        ops={
            "op1": FukuRegister,
            "op2": FukuRegister | FukuOperand,
        },
    ),
    "movsx": InstProp(
        capstone_code=x86_const.X86_INS_MOVSX,
        cap_eflags=0,
        ops={
            "op1": FukuRegister,
            "op2": FukuRegister | FukuOperand,
        },
    ),
    "movsxd": InstProp(
        capstone_code=x86_const.X86_INS_MOVSXD,
        cap_eflags=0,
        ops={
            "op1": FukuRegister,
            "op2": FukuRegister | FukuOperand,
        },
    ),
    # Bit and Byte Instructions
    "bt": InstProp(
        capstone_code=x86_const.X86_INS_BT,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_UNDEFINED_SF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_UNDEFINED_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={
            "op1": FukuRegister,
            "op2": FukuRegister | FukuImmediate,
        },
    ),
    "bts": InstProp(
        capstone_code=x86_const.X86_INS_BTS,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_UNDEFINED_SF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_UNDEFINED_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister, "op2": FukuRegister | FukuImmediate},
    ),
    "btr": InstProp(
        capstone_code=x86_const.X86_INS_BTR,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_UNDEFINED_SF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_UNDEFINED_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister, "op2": FukuRegister | FukuImmediate},
    ),
    "btc": InstProp(
        capstone_code=x86_const.X86_INS_BTC,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_UNDEFINED_SF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_UNDEFINED_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
        ops={"op1": FukuRegister, "op2": FukuRegister | FukuImmediate},
    ),
    "popcnt": InstProp(
        capstone_code=x86_const.X86_INS_POPCNT,
        cap_eflags=x86_const.X86_EFLAGS_RESET_OF
        | x86_const.X86_EFLAGS_RESET_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_RESET_AF
        | x86_const.X86_EFLAGS_RESET_PF
        | x86_const.X86_EFLAGS_RESET_CF,
        ops={
            "op1": FukuRegister,
            "op2": FukuRegister | FukuOperand,
        },
    ),
    "test": InstProp(
        capstone_code=x86_const.X86_INS_TEST,
        cap_eflags=x86_const.X86_EFLAGS_RESET_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_RESET_CF,
        ops={"op1": FukuRegister | FukuOperand, "op2": FukuRegister | FukuImmediate},
    ),
    "bsf": InstProp(
        capstone_code=x86_const.X86_INS_BSF,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_UNDEFINED_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_UNDEFINED_PF
        | x86_const.X86_EFLAGS_UNDEFINED_CF,
        ops={"op1": FukuRegister, "op2": FukuRegister | FukuImmediate},
    ),
    "bsr": InstProp(
        capstone_code=x86_const.X86_INS_BSR,
        cap_eflags=x86_const.X86_EFLAGS_UNDEFINED_OF
        | x86_const.X86_EFLAGS_UNDEFINED_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_UNDEFINED_AF
        | x86_const.X86_EFLAGS_UNDEFINED_PF
        | x86_const.X86_EFLAGS_UNDEFINED_CF,
        ops={"op1": FukuRegister, "op2": FukuRegister | FukuImmediate},
    ),
    # Control Transfer Instructions
    "int3": InstProp(
        capstone_code=x86_const.X86_INS_INT3,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_IF
        | x86_const.X86_EFLAGS_MODIFY_TF
        | x86_const.X86_EFLAGS_MODIFY_NT
        | x86_const.X86_EFLAGS_MODIFY_RF,
    ),
    "leave": InstProp(capstone_code=x86_const.X86_INS_LEAVE, cap_eflags=0),
    # String Instructions
    "outs": InstProp(
        capstone_code=x86_const.X86_INS_OUTSB,
        cap_eflags=x86_const.X86_EFLAGS_TEST_DF,
    ),
    "movs": InstProp(
        capstone_code=x86_const.X86_INS_MOVSB,
        cap_eflags=x86_const.X86_EFLAGS_TEST_DF,
    ),
    "cmps": InstProp(
        capstone_code=x86_const.X86_INS_CMPSB,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
    ),
    "stos": InstProp(
        capstone_code=x86_const.X86_INS_STOSB,
        cap_eflags=x86_const.X86_EFLAGS_TEST_DF,
    ),
    "lods": InstProp(
        capstone_code=x86_const.X86_INS_LODSB,
        cap_eflags=x86_const.X86_EFLAGS_TEST_DF,
    ),
    "scas": InstProp(
        capstone_code=x86_const.X86_INS_SCASB,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
    ),
    # Flag Control (EFLAG) Instructions
    "stc": InstProp(
        capstone_code=x86_const.X86_INS_STC, cap_eflags=x86_const.X86_EFLAGS_SET_CF
    ),
    "clc": InstProp(
        capstone_code=x86_const.X86_INS_CLC, cap_eflags=x86_const.X86_EFLAGS_RESET_CF
    ),
    "cmc": InstProp(
        capstone_code=x86_const.X86_INS_CMC, cap_eflags=x86_const.X86_EFLAGS_MODIFY_CF
    ),
    "cld": InstProp(
        capstone_code=x86_const.X86_INS_CLD, cap_eflags=x86_const.X86_EFLAGS_RESET_DF
    ),
    "std": InstProp(
        capstone_code=x86_const.X86_INS_STD, cap_eflags=x86_const.X86_EFLAGS_SET_DF
    ),
    "lahf": InstProp(capstone_code=x86_const.X86_INS_LAHF, cap_eflags=0),
    "sahf": InstProp(
        capstone_code=x86_const.X86_INS_SAHF,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_CF,
    ),
    "pusha": InstProp(
        capstone_code=x86_const.X86_INS_PUSHAW,
        cap_eflags=0,
    ),
    "pushad": InstProp(capstone_code=x86_const.X86_INS_PUSHAL, cap_eflags=0),
    "popa": InstProp(
        capstone_code=x86_const.X86_INS_POPAW,
        cap_eflags=0,
    ),
    "popad": InstProp(
        capstone_code=x86_const.X86_INS_POPAL,
        cap_eflags=0,
    ),
    "pushf": InstProp(
        capstone_code=x86_const.X86_INS_PUSHF,
        cap_eflags=0,
    ),
    "pushfd": InstProp(
        capstone_code=x86_const.X86_INS_PUSHFD,
        cap_eflags=0,
    ),
    "pushfq": InstProp(
        capstone_code=x86_const.X86_INS_PUSHFQ,
        cap_eflags=0,
    ),
    "popf": InstProp(
        capstone_code=x86_const.X86_INS_POPF,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_CF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_TF
        | x86_const.X86_EFLAGS_MODIFY_IF
        | x86_const.X86_EFLAGS_MODIFY_DF
        | x86_const.X86_EFLAGS_MODIFY_NT
        | x86_const.X86_EFLAGS_MODIFY_RF,
    ),
    "popfd": InstProp(
        capstone_code=x86_const.X86_INS_POPFD,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_CF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_TF
        | x86_const.X86_EFLAGS_MODIFY_IF
        | x86_const.X86_EFLAGS_MODIFY_DF
        | x86_const.X86_EFLAGS_MODIFY_NT
        | x86_const.X86_EFLAGS_MODIFY_RF,
    ),
    "popfq": InstProp(
        capstone_code=x86_const.X86_INS_POPFQ,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_CF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_TF
        | x86_const.X86_EFLAGS_MODIFY_IF
        | x86_const.X86_EFLAGS_MODIFY_DF
        | x86_const.X86_EFLAGS_MODIFY_NT
        | x86_const.X86_EFLAGS_MODIFY_RF,
    ),
    # Miscellaneous Instructions
    "lea": InstProp(
        capstone_code=x86_const.X86_INS_LEA,
        cap_eflags=0,
        ops={
            "op1": FukuRegister,
            "op2": FukuOperand,
        },
    ),
    "ud2": InstProp(
        capstone_code=x86_const.X86_INS_UD2,
        cap_eflags=0,
    ),
    "cpuid": InstProp(
        capstone_code=x86_const.X86_INS_CPUID,
        cap_eflags=0,
    ),
    # Random Number Generator Instructions
    "rdrand": InstProp(
        capstone_code=x86_const.X86_INS_RDRAND,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_CF
        | x86_const.X86_EFLAGS_RESET_OF
        | x86_const.X86_EFLAGS_RESET_SF
        | x86_const.X86_EFLAGS_RESET_ZF
        | x86_const.X86_EFLAGS_RESET_AF
        | x86_const.X86_EFLAGS_RESET_PF,
        ops={
            "op1": FukuRegister,
        },
    ),
    "rdseed": InstProp(
        capstone_code=x86_const.X86_INS_RDSEED,
        cap_eflags=x86_const.X86_EFLAGS_MODIFY_CF
        | x86_const.X86_EFLAGS_RESET_OF
        | x86_const.X86_EFLAGS_RESET_SF
        | x86_const.X86_EFLAGS_RESET_ZF
        | x86_const.X86_EFLAGS_RESET_AF
        | x86_const.X86_EFLAGS_RESET_PF,
        ops={
            "op1": FukuRegister,
        },
    ),
    # SYSTEM INSTRUCTIONS
    "hlt": InstProp(
        capstone_code=x86_const.X86_INS_HLT,
        cap_eflags=0,
    ),
    "rdtsc": InstProp(
        capstone_code=x86_const.X86_INS_RDTSC,
        cap_eflags=0,
    ),
    "lfence": InstProp(
        capstone_code=x86_const.X86_INS_LFENCE,
        cap_eflags=0,
    ),
    "cmovcc": InstProp(
        capstone_code=-1,
        cap_eflags=-1,
        ops={
            "op1": FukuRegister,
            "op2": FukuOperand | FukuRegister,
        },
    ),
    "setcc": InstProp(
        capstone_code=-1,
        cap_eflags=-1,
        ops={
            "op1": FukuRegister | FukuOperand,
        },
    ),
}
