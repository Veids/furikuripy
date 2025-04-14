from enum import Enum
from typing import Callable, Optional
from capstone import x86_const, Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from iced_x86 import Code, Instruction, BlockEncoder, Register
from pydantic import BaseModel

from furikuripy.common import rng
from furikuripy.x86.misc import FukuCondition, FukuToCapConvertType
from furikuripy.x86.fuku_asm_ctx import FukuAsmCtx
from furikuripy.x86.fuku_immediate import FukuImmediate
from furikuripy.x86.fuku_register import FukuRegister, FukuRegisterEnum
from furikuripy.x86.fuku_operand import FukuOperand, FukuMemOperandType, FukuPrefix

cs = Cs(CS_ARCH_X86, CS_MODE_64)
cs.detail = True

ADI_FL_JCC = [
    x86_const.X86_EFLAGS_TEST_OF , x86_const.X86_EFLAGS_TEST_OF, # jo   / jno
    x86_const.X86_EFLAGS_TEST_CF , x86_const.X86_EFLAGS_TEST_CF, # jb   / jae
    x86_const.X86_EFLAGS_TEST_ZF , x86_const.X86_EFLAGS_TEST_ZF, # je   / jne
    x86_const.X86_EFLAGS_TEST_ZF | x86_const.X86_EFLAGS_TEST_CF, x86_const.X86_EFLAGS_TEST_ZF | x86_const.X86_EFLAGS_TEST_CF, # jbe / jnbe
    x86_const.X86_EFLAGS_TEST_SF , x86_const.X86_EFLAGS_TEST_SF, # js   / jns
    x86_const.X86_EFLAGS_TEST_PF , x86_const.X86_EFLAGS_TEST_PF, # jp   / jnp
    x86_const.X86_EFLAGS_TEST_OF | x86_const.X86_EFLAGS_TEST_SF, x86_const.X86_EFLAGS_TEST_OF | x86_const.X86_EFLAGS_TEST_SF, # jnge / jge
    x86_const.X86_EFLAGS_TEST_OF | x86_const.X86_EFLAGS_TEST_SF | x86_const.X86_EFLAGS_TEST_ZF, x86_const.X86_EFLAGS_TEST_OF | x86_const.X86_EFLAGS_TEST_SF | x86_const.X86_EFLAGS_TEST_ZF # jng / jnle
]  # fmt: skip


class PostfixEnum(Enum):
    b = 8
    w = 16
    dw = 32
    qw = 64


class PostfixedWrapper(BaseModel):
    postfix: str
    wrapper: Callable


def gen_default_postfix(
    wrapper: Callable, modifier: str = "", exclude: list[str] = []
) -> list[PostfixedWrapper]:
    return [
        PostfixedWrapper(postfix=f"{modifier}{p.name}", wrapper=wrapper(p.value))
        for p in PostfixEnum
        if p.name not in exclude
    ]


def build_code_left_part(t, size: int) -> str:
    if isinstance(t, FukuRegister):
        return f"R{size}"
    elif isinstance(t, FukuOperand):
        return f"RM{size}"
    else:
        raise Exception("Unknown")


def build_code_right_part(ctx, t, size: int) -> str:
    if isinstance(t, FukuRegister):
        return f"RM{size}"
    elif isinstance(t, FukuOperand):
        return f"RM{size}"
    elif isinstance(t, FukuImmediate):
        return t.to_iced_code(ctx.is_used_short_disp, size)
    else:
        raise Exception("Unimplemented")


def get_iced_code(ctx, name: str, dst, src, size, max_imm_size=64):
    name = name.upper()
    l = r = ""
    if isinstance(src, FukuImmediate):
        l = f"RM{size}"
        r = build_code_right_part(ctx, src, min(size, max_imm_size))
    else:
        l = build_code_left_part(dst, size)
        r = build_code_right_part(ctx, src, size)

    return getattr(Code, f"{name}_{l}_{r}")


def get_iced_code_one_op(ctx, name: str, src, size: int, postfix: str = ""):
    name = name.upper()
    l = build_code_right_part(ctx, src, size)
    return getattr(Code, f"{name}_{l}{postfix}")


def get_iced_code_three_op(ctx, name: str, dst, src, imm, size: int, postfix: str = ""):
    name = name.upper()
    l = build_code_left_part(dst, size)
    r = build_code_right_part(ctx, src, size)
    i = build_code_right_part(ctx, imm, size)
    return getattr(Code, f"{name}_{l}_{r}_{i}{postfix}")


def gen_iced_ins(ctx, ins):
    encoder = BlockEncoder(64)
    encoder.add(ins)
    opcode = encoder.encode(0x0)

    ins = next(cs.disasm(opcode, 0))
    ctx.displacment_offset = ins.disp_offset
    ctx.bytecode = bytearray(opcode)


class FukuAsmBody:
    def __init__(self):
        # Data Transfer Instructions
        self._gen_func_body_byte_no_arg_iced(
            "cwd",
            x86_const.X86_INS_CWD,
            0,
        )
        self._gen_func_body_byte_no_arg_iced("cdq", x86_const.X86_INS_CDQ, 0)
        self._gen_func_body_byte_no_arg_iced("cqo", x86_const.X86_INS_CQO, 0)

        self._gen_func_body_byte_no_arg_iced(
            "cbw",
            x86_const.X86_INS_CBW,
            0,
        )
        self._gen_func_body_byte_no_arg_iced("cwde", x86_const.X86_INS_CWDE, 0)
        self._gen_func_body_byte_no_arg_iced("cdqe", x86_const.X86_INS_CDQE, 0)

        self._gen_func_body_movxx("movzx", 0xB6, x86_const.X86_INS_MOVZX)
        self._gen_func_body_movxx("movsx", 0xBE, x86_const.X86_INS_MOVSX)

        # Binary Arithmetic Instructions
        self._gen_func_body_arith_iced(
            "add",
            x86_const.X86_INS_ADD,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_arith_iced(
            "adc",
            x86_const.X86_INS_ADC,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_arith_iced(
            "sub",
            x86_const.X86_INS_SUB,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_arith_iced(
            "sbb",
            x86_const.X86_INS_SBB,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_arith_ex_one_op_iced(
            "imul",
            x86_const.X86_INS_IMUL,
            x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_CF
            | x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_UNDEFINED_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_UNDEFINED_PF,
        )
        self._gen_func_body_arith_ex_one_op_iced(
            "mul",
            x86_const.X86_INS_MUL,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_UNDEFINED_SF
            | x86_const.X86_EFLAGS_UNDEFINED_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_UNDEFINED_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_arith_ex_one_op_iced(
            "idiv",
            x86_const.X86_INS_IDIV,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_UNDEFINED_SF
            | x86_const.X86_EFLAGS_UNDEFINED_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_UNDEFINED_PF
            | x86_const.X86_EFLAGS_UNDEFINED_CF,
        )
        self._gen_func_body_arith_ex_one_op_iced(
            "div",
            x86_const.X86_INS_DIV,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_UNDEFINED_SF
            | x86_const.X86_EFLAGS_UNDEFINED_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_UNDEFINED_PF
            | x86_const.X86_EFLAGS_UNDEFINED_CF,
        )
        self._gen_func_body_arith_ex_one_op_iced(
            "inc",
            x86_const.X86_INS_INC,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF,
        )
        self._gen_func_body_arith_ex_one_op_iced(
            "dec",
            x86_const.X86_INS_DEC,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF,
        )
        self._gen_func_body_arith_ex_one_op_iced(
            "neg",
            x86_const.X86_INS_NEG,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_arith_iced(
            "cmp",
            x86_const.X86_INS_CMP,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )

        # Decimal Arithmetic Instructions
        self._gen_func_body_byte_no_arg_iced(
            "daa",
            x86_const.X86_INS_DAA,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_byte_no_arg_iced(
            "das",
            x86_const.X86_INS_DAS,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_byte_no_arg_iced(
            "aaa",
            x86_const.X86_INS_AAA,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_UNDEFINED_SF
            | x86_const.X86_EFLAGS_UNDEFINED_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_UNDEFINED_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_byte_no_arg_iced(
            "aas",
            x86_const.X86_INS_AAS,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_UNDEFINED_SF
            | x86_const.X86_EFLAGS_UNDEFINED_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_UNDEFINED_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )

        # Logical Instructions Instructions
        self._gen_func_body_arith_iced(
            "and",
            x86_const.X86_INS_AND,
            x86_const.X86_EFLAGS_RESET_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_RESET_CF,
        )
        self._gen_func_body_arith_iced(
            "or",
            x86_const.X86_INS_OR,
            x86_const.X86_EFLAGS_RESET_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_RESET_CF,
        )
        self._gen_func_body_arith_iced(
            "xor",
            x86_const.X86_INS_XOR,
            x86_const.X86_EFLAGS_RESET_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_RESET_CF,
        )
        self._gen_func_body_arith_ex_one_op_iced("not", x86_const.X86_INS_NOT, 0)

        # TODO: Make sure pop_b and push_b don't exist
        self._gen_func_body_arith_ex_one_op_iced("pop", x86_const.X86_INS_POP, 0)
        self._gen_func_body_arith_ex_one_op_iced("push", x86_const.X86_INS_PUSH, 0)

        # Shift and Rotate Instructions
        self._gen_func_body_shift_iced(
            "sar",
            x86_const.X86_INS_SAR,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_shift_iced(
            "shr",
            x86_const.X86_INS_SHR,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_shift_iced(
            "shl",
            x86_const.X86_INS_SHL,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )

        self._gen_func_body_shxd_iced(
            "shrd",
            x86_const.X86_INS_SHRD,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_shxd_iced(
            "shld",
            x86_const.X86_INS_SHLD,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )

        self._gen_func_body_shift_iced(
            "ror",
            x86_const.X86_INS_ROR,
            x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_shift_iced(
            "rol",
            x86_const.X86_INS_ROL,
            x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_shift_iced(
            "rcr",
            x86_const.X86_INS_RCR,
            x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_shift_iced(
            "rcl",
            x86_const.X86_INS_RCL,
            x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF,
        )

        # Bit and Byte Instructions
        self._gen_func_body_bit_iced(
            "bt",
            x86_const.X86_INS_BT,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_UNDEFINED_SF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_UNDEFINED_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_bit_iced(
            "bts",
            x86_const.X86_INS_BTS,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_UNDEFINED_SF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_UNDEFINED_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_bit_iced(
            "btr",
            x86_const.X86_INS_BTR,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_UNDEFINED_SF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_UNDEFINED_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_bit_iced(
            "btc",
            x86_const.X86_INS_BTC,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_UNDEFINED_SF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_UNDEFINED_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_bit_iced(
            "bsf",
            x86_const.X86_INS_BSF,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_UNDEFINED_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_UNDEFINED_PF
            | x86_const.X86_EFLAGS_UNDEFINED_CF,
        )
        self._gen_func_body_bit_iced(
            "bsr",
            x86_const.X86_INS_BSR,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_UNDEFINED_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_UNDEFINED_PF
            | x86_const.X86_EFLAGS_UNDEFINED_CF,
        )

        # Control Transfer Instructions
        self._gen_func_body_byte_no_arg_iced(
            "int3",
            x86_const.X86_INS_INT3,
            x86_const.X86_EFLAGS_MODIFY_IF
            | x86_const.X86_EFLAGS_MODIFY_TF
            | x86_const.X86_EFLAGS_MODIFY_NT
            | x86_const.X86_EFLAGS_MODIFY_RF,
        )
        self._gen_func_body_byte_no_arg_iced("leave", x86_const.X86_INS_LEAVE, 0)

        # String Instructions
        self._gen_func_body_string_inst_iced(
            "outs",
            x86_const.X86_EFLAGS_TEST_DF,
            mapping={
                8: "B_DX_M8",
                16: "W_DX_M16",
                32: "D_DX_M32",
            },
            exclude=["qw"],
        )
        self._gen_func_body_string_inst_iced(
            "movs",
            x86_const.X86_EFLAGS_TEST_DF,
            mapping={
                8: "B_M8_M8",
                16: "W_M16_M16",
                32: "D_M32_M32",
                64: "Q_M64_M64",
            },
        )
        self._gen_func_body_string_inst_iced(
            "cmps",
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
            mapping={
                8: "B_M8_M8",
                16: "W_M16_M16",
                32: "D_M32_M32",
                64: "Q_M64_M64",
            },
        )
        self._gen_func_body_string_inst_iced(
            "stos",
            x86_const.X86_EFLAGS_TEST_DF,
            mapping={
                8: "B_M8_AL",
                16: "W_M16_AX",
                32: "D_M32_EAX",
                64: "Q_M64_RAX",
            },
        )
        self._gen_func_body_string_inst_iced(
            "lods",
            x86_const.X86_EFLAGS_TEST_DF,
            mapping={
                8: "B_AL_M8",
                16: "W_AX_M16",
                32: "D_EAX_M32",
                64: "Q_RAX_M64",
            },
        )
        self._gen_func_body_string_inst_iced(
            "scas",
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
            mapping={
                8: "B_AL_M8",
                16: "W_AX_M16",
                32: "D_EAX_M32",
                64: "Q_RAX_M64",
            },
        )

        # Flag Control (EFLAG) Instructions
        self._gen_func_body_byte_no_arg_iced(
            "stc", x86_const.X86_INS_STC, x86_const.X86_EFLAGS_SET_CF
        )
        self._gen_func_body_byte_no_arg_iced(
            "clc", x86_const.X86_INS_CLC, x86_const.X86_EFLAGS_RESET_CF
        )
        self._gen_func_body_byte_no_arg_iced(
            "cmc", x86_const.X86_INS_CMC, x86_const.X86_EFLAGS_MODIFY_CF
        )
        self._gen_func_body_byte_no_arg_iced(
            "cld", x86_const.X86_INS_CLD, x86_const.X86_EFLAGS_RESET_DF
        )
        self._gen_func_body_byte_no_arg_iced(
            "std", x86_const.X86_INS_STD, x86_const.X86_EFLAGS_SET_DF
        )
        self._gen_func_body_byte_no_arg_iced("lahf", x86_const.X86_INS_LAHF, 0)
        self._gen_func_body_byte_no_arg_iced(
            "sahf",
            x86_const.X86_INS_SAHF,
            x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )
        self._gen_func_body_byte_no_arg_iced(
            "pusha",
            x86_const.X86_INS_PUSHAW,
            0,
        )
        self._gen_func_body_byte_no_arg_iced("pushad", x86_const.X86_INS_PUSHAL, 0)
        self._gen_func_body_byte_no_arg_iced(
            "popa",
            x86_const.X86_INS_POPAW,
            0,
        )
        self._gen_func_body_byte_no_arg_iced("popad", x86_const.X86_INS_POPAL, 0)
        self._gen_func_body_byte_no_arg_iced(
            "pushf",
            x86_const.X86_INS_PUSHF,
            0,
        )
        self._gen_func_body_byte_no_arg_iced("pushfd", x86_const.X86_INS_PUSHFD, 0)
        self._gen_func_body_byte_no_arg_iced("pushfq", x86_const.X86_INS_PUSHFQ, 0)
        self._gen_func_body_byte_no_arg_iced(
            "popf",
            x86_const.X86_INS_POPF,
            x86_const.X86_EFLAGS_MODIFY_AF
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
        )
        self._gen_func_body_byte_no_arg_iced(
            "popfd",
            x86_const.X86_INS_POPFD,
            x86_const.X86_EFLAGS_MODIFY_AF
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
        )
        self._gen_func_body_byte_no_arg_iced(
            "popfq",
            x86_const.X86_INS_POPFQ,
            x86_const.X86_EFLAGS_MODIFY_AF
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
        )

        # Miscellaneous Instructions
        self._gen_func_body_byte_no_arg_iced("ud2", x86_const.X86_INS_UD2, 0)
        self._gen_func_body_byte_no_arg_iced("cpuid", x86_const.X86_INS_CPUID, 0)

        # BMI1, BMI2 Instructions
        # ANDN
        # BEXTR
        # BLSI
        # BLSMSK
        # BLSR
        # BZHI
        # LZCNT
        # MULX
        # PDEP
        # PEXT
        # RORX
        # SARX
        # SHLX
        # SHRX
        # SYSTEM INSTRUCTIONS
        self._gen_func_body_byte_no_arg_iced("hlt", x86_const.X86_INS_HLT, 0)
        self._gen_func_body_byte_no_arg_iced("rdtsc", x86_const.X86_INS_RDTSC, 0)
        self._gen_func_body_byte_no_arg_iced("lfence", x86_const.X86_INS_LFENCE, 0)

        self._gen_func_body_mov_iced("mov")
        self._gen_func_body_rdxxxx_iced(
            "rdrand",
            x86_const.X86_INS_RDRAND,
            x86_const.X86_EFLAGS_MODIFY_CF
            | x86_const.X86_EFLAGS_RESET_OF
            | x86_const.X86_EFLAGS_RESET_SF
            | x86_const.X86_EFLAGS_RESET_ZF
            | x86_const.X86_EFLAGS_RESET_AF
            | x86_const.X86_EFLAGS_RESET_PF,
        )
        self._gen_func_body_rdxxxx_iced(
            "rdseed",
            x86_const.X86_INS_RDSEED,
            x86_const.X86_EFLAGS_MODIFY_CF
            | x86_const.X86_EFLAGS_RESET_OF
            | x86_const.X86_EFLAGS_RESET_SF
            | x86_const.X86_EFLAGS_RESET_ZF
            | x86_const.X86_EFLAGS_RESET_AF
            | x86_const.X86_EFLAGS_RESET_PF,
        )

    def _gen_fn(self, name: str, wrappers: list[PostfixedWrapper]):
        for wrapper in wrappers:
            setattr(self.__class__, f"{name}_{wrapper.postfix}", wrapper.wrapper)

    # Data Transfer Instructions
    # MOV
    def _gen_func_body_mov_iced(self, name):
        eax_mapping = {
            8: {
                "reg": FukuRegisterEnum.REG_AL,
                "code_reg_op": Code.MOV_AL_MOFFS8,
                "code_op_reg": Code.MOV_MOFFS8_AL,
                "op_imm_size": 8,
            },
            16: {
                "reg": FukuRegisterEnum.REG_AX,
                "code_reg_op": Code.MOV_AX_MOFFS16,
                "code_op_reg": Code.MOV_MOFFS16_AX,
                "op_imm_size": 16,
            },
            32: {
                "reg": FukuRegisterEnum.REG_EAX,
                "code_reg_op": Code.MOV_EAX_MOFFS32,
                "code_op_reg": Code.MOV_MOFFS32_EAX,
                "op_imm_size": 32,
            },
            64: {
                "reg": FukuRegisterEnum.REG_RAX,
                "code_reg_op": Code.MOV_RAX_MOFFS64,
                "code_op_reg": Code.MOV_MOFFS64_RAX,
                "op_imm_size": 32,
            },
        }

        def wrapper(size: int):
            def fn(self, ctx: FukuAsmCtx, dst, src):
                ctx.clear()

                if (
                    (
                        (isinstance(dst, FukuRegister) and isinstance(src, FukuOperand))
                        or (
                            isinstance(dst, FukuOperand)
                            and isinstance(src, FukuRegister)
                        )
                    )
                    and ctx.is_used_short_eax
                    and (
                        (
                            isinstance(dst, FukuRegister)
                            and dst.reg == eax_mapping[size]["reg"]
                            and src.type
                            == FukuMemOperandType.FUKU_MEM_OPERAND_DISP_ONLY
                        )
                        or (
                            isinstance(src, FukuRegister)
                            and src.reg == eax_mapping[size]["reg"]
                            and dst.type
                            == FukuMemOperandType.FUKU_MEM_OPERAND_DISP_ONLY
                        )
                    )
                ):
                    if (
                        isinstance(dst, FukuRegister)
                        and dst.reg == eax_mapping[size]["reg"]
                    ) or (
                        isinstance(src, FukuRegister)
                        and src.reg == eax_mapping[size]["reg"]
                    ):
                        code = eax_mapping[size]["code_reg_op"]
                    else:
                        code = eax_mapping[size]["code_op_reg"]
                else:
                    if isinstance(dst, FukuOperand) and isinstance(src, FukuRegister):
                        code = getattr(Code, f"{name.upper()}_RM{size}_R{size}")
                    elif isinstance(dst, FukuOperand) and isinstance(
                        src, FukuImmediate
                    ):
                        code_str = f"{name.upper()}_RM{size}_IMM{eax_mapping[size]['op_imm_size']}"
                        code = getattr(Code, code_str)
                    else:
                        code = get_iced_code(ctx, "mov", dst, src, size)

                arg1 = dst.to_iced_name()
                arg2 = src.to_iced_name()
                ins = getattr(Instruction, f"create_{arg1}_{arg2}")(
                    code, dst.to_iced(), src.to_iced()
                )
                gen_iced_ins(ctx, ins)

                if isinstance(dst, FukuRegister) and isinstance(src, FukuImmediate):
                    ctx.gen_func_return(x86_const.X86_INS_MOVABS, 0)
                else:
                    ctx.gen_func_return(x86_const.X86_INS_MOV, 0)

            return fn

        self._gen_fn(name, gen_default_postfix(wrapper))

    def cmovcc_w(
        self,
        ctx: FukuAsmCtx,
        cond: FukuCondition,
        dst: FukuRegister,
        src: FukuOperand | FukuRegister,
    ):
        ctx.clear()

        if isinstance(src, FukuOperand):
            ctx.gen_pattern32_2em_op_r_word(0x0F, 0x40 | cond.value, src, dst)
        else:
            ctx.gen_pattern32_2em_rm_r_word(0x0F, 0x40 | cond.value, src, dst)

        ctx.gen_func_return(
            cond.to_capstone_cc(FukuToCapConvertType.CMOVCC), ADI_FL_JCC[cond.value]
        )

    def cmovcc_dw(
        self,
        ctx: FukuAsmCtx,
        cond: FukuCondition,
        dst: FukuRegister,
        src: FukuOperand | FukuRegister,
    ):
        ctx.clear()

        if isinstance(src, FukuOperand):
            ctx.gen_pattern32_2em_op_r(0x0F, 0x40 | cond.value, src, dst)
        else:
            ctx.gen_pattern32_2em_rm_r(0x0F, 0x40 | cond.value, src, dst)

        ctx.gen_func_return(
            cond.to_capstone_cc(FukuToCapConvertType.CMOVCC), ADI_FL_JCC[cond.value]
        )

    def cmovcc_qw(
        self,
        ctx: FukuAsmCtx,
        cond: FukuCondition,
        dst: FukuRegister,
        src: FukuOperand | FukuRegister,
    ):
        ctx.clear()

        if isinstance(src, FukuOperand):
            ctx.gen_pattern64_2em_op_r(0x0F, 0x40 | cond.value, src, dst)
        else:
            ctx.gen_pattern64_2em_rm_r(0x0F, 0x40 | cond.value, src, dst)

        ctx.gen_func_return(
            cond.to_capstone_cc(FukuToCapConvertType.CMOVCC), ADI_FL_JCC[cond.value]
        )

    def xchg_b(
        self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister
    ):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_1em_op_r(0x86, dst, src)
        else:
            ctx.gen_pattern32_1em_rm_r(0x86, dst, src)

        ctx.gen_func_return(x86_const.X86_INS_XCHG, 0)

    def xchg_w(
        self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister
    ):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_1em_op_r_word(0x87, dst, src)
        else:
            ctx.gen_pattern32_1em_rm_r_word(0x87, dst, src)

        ctx.gen_func_return(x86_const.X86_INS_XCHG, 0)

    def xchg_dw(
        self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister
    ):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_1em_op_r(0x87, dst, src)
        else:
            ctx.gen_pattern32_1em_rm_r(0x87, dst, src)

        ctx.gen_func_return(x86_const.X86_INS_XCHG, 0)

    def xchg_qw(
        self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister
    ):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern64_1em_op_r(0x87, dst, src)
        else:
            ctx.gen_pattern64_1em_rm_r(0x87, dst, src)

        ctx.gen_func_return(x86_const.X86_INS_XCHG, 0)

    def bswap_w(self, ctx: FukuAsmCtx, dst: FukuRegister):
        ctx.clear()
        ctx.gen_pattern32_1em_rm_idx_word(0x0F, dst, 1)
        ctx.gen_func_return(x86_const.X86_INS_BSWAP, 0)

    def bswap_dw(self, ctx: FukuAsmCtx, dst: FukuRegister):
        ctx.clear()
        ctx.gen_pattern32_1em_rm_idx(0x0F, dst, 1)
        ctx.gen_func_return(x86_const.X86_INS_BSWAP, 0)

    def bswap_qw(self, ctx: FukuAsmCtx, dst: FukuRegister):
        ctx.clear()
        ctx.gen_pattern64_1em_rm_idx(0x0F, dst, 1)
        ctx.gen_func_return(x86_const.X86_INS_BSWAP, 0)

    def xadd_b(
        self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister
    ):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_2em_op_r(0x0F, 0xC0, dst, src)
        else:
            ctx.gen_pattern32_2em_rm_r(0x0F, 0xC0, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_XADD,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )

    def xadd_w(
        self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister
    ):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_2em_op_r_word(0x0F, 0xC1, dst, src)
        else:
            ctx.gen_pattern32_2em_rm_r_word(0x0F, 0xC1, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_XADD,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )

    def xadd_dw(
        self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister
    ):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_2em_op_r(0x0F, 0xC1, dst, src)
        else:
            ctx.gen_pattern32_2em_rm_r(0x0F, 0xC1, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_XADD,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )

    def xadd_qw(
        self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister
    ):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern64_2em_op_r(0x0F, 0xC1, dst, src)
        else:
            ctx.gen_pattern64_2em_rm_r(0x0F, 0xC1, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_XADD,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )

    def cmpxchg_b(
        self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister
    ):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_2em_op_r(0x0F, 0xB0, dst, src)
        else:
            ctx.gen_pattern32_2em_rm_r(0x0F, 0xB0, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_CMPXCHG,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )

    def cmpxchg_w(
        self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister
    ):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_2em_op_r_word(0x0F, 0xB1, dst, src)
        else:
            ctx.gen_pattern32_2em_rm_r_word(0x0F, 0xB1, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_CMPXCHG,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )

    def cmpxchg_dw(
        self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister
    ):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_2em_op_r(0x0F, 0xB1, dst, src)
        else:
            ctx.gen_pattern32_2em_rm_r(0x0F, 0xB1, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_CMPXCHG,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )

    def cmpxchg_qw(
        self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister
    ):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern64_2em_op_r(0x0F, 0xB1, dst, src)
        else:
            ctx.gen_pattern64_2em_rm_r(0x0F, 0xB1, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_CMPXCHG,
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
        )

    def cmpxchg8b(self, ctx: FukuAsmCtx, dst: FukuOperand):
        ctx.clear()
        ctx.gen_pattern32_2em_op_idx(0x0F, 0xC7, dst, 1)
        ctx.gen_func_return(x86_const.X86_INS_CMPXCHG8B, x86_const.X86_EFLAGS_MODIFY_ZF)

    def cmpxchg16b(self, ctx: FukuAsmCtx, dst: FukuOperand):
        ctx.clear()
        ctx.gen_pattern64_2em_op_idx(0x0F, 0xC7, dst, 1)
        ctx.gen_func_return(
            x86_const.X86_INS_CMPXCHG16B, x86_const.X86_EFLAGS_MODIFY_ZF
        )

    def movsxd_word_w(
        self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand
    ):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_r_word(0x63, src, dst)
        else:
            ctx.gen_pattern32_1em_op_r_word(0x63, dst, src)

        ctx.gen_func_return(x86_const.X86_INS_MOVSXD, 0)

    def movsxd_dword_dw(
        self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand
    ):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_r(0x63, src, dst)
        else:
            ctx.gen_pattern32_1em_op_r(0x63, dst, src)

        ctx.gen_func_return(x86_const.X86_INS_MOVSXD, 0)

    def movsxd_dword_qw(
        self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand
    ):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.gen_pattern64_1em_rm_r(0x63, src, dst)
        else:
            ctx.gen_pattern64_1em_op_r(0x63, dst, src)

        ctx.gen_func_return(x86_const.X86_INS_MOVSXD, 0)

    # Binary Arithmetic Instructions
    def adcx_dw(
        self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand
    ):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
            ctx.emit_optional_rex_32(dst, src)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_modrm(src, dst)
        else:
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
            ctx.emit_optional_rex_32(src, dst)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_operand(src, dst)

        ctx.gen_func_return(x86_const.X86_INS_ADCX, x86_const.X86_EFLAGS_MODIFY_CF)

    def adcx_qw(
        self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand
    ):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
            ctx.emit_rex_64(dst, src)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_modrm(src, dst)
        else:
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
            ctx.emit_rex_64(src, dst)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_operand(src, dst)

        ctx.gen_func_return(x86_const.X86_INS_ADCX, x86_const.X86_EFLAGS_MODIFY_CF)

    def adox_dw(
        self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand
    ):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.emit_b(0xF3)
            ctx.emit_optional_rex_32(dst, src)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_modrm(src, dst)
        else:
            ctx.emit_b(0xF3)
            ctx.emit_optional_rex_32(src, dst)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_operand(src, dst)

        ctx.gen_func_return(x86_const.X86_INS_ADOX, x86_const.X86_EFLAGS_MODIFY_OF)

    def adox_qw(
        self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand
    ):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.emit_b(0xF3)
            ctx.emit_rex_64(dst, src)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_modrm(src, dst)
        else:
            ctx.emit_b(0xF3)
            ctx.emit_rex_64(src, dst)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_operand(src, dst)

        ctx.gen_func_return(x86_const.X86_INS_ADOX, x86_const.X86_EFLAGS_MODIFY_OF)

    # Decimal Arithmetic Instructions
    def aam(self, ctx: FukuAsmCtx, imm: FukuImmediate):
        ctx.clear()
        ctx.gen_pattern32_1em_immb(0xD4, FukuRegister(FukuRegisterEnum.REG_NONE), imm)
        ctx.gen_func_return(
            x86_const.X86_INS_AAM,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_UNDEFINED_CF,
        )

    def aad(self, ctx: FukuAsmCtx, imm: FukuImmediate):
        ctx.clear()
        ctx.gen_pattern32_1em_immb(0xD5, FukuRegister(FukuRegisterEnum.REG_NONE), imm)
        ctx.gen_func_return(
            x86_const.X86_INS_AAD,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_UNDEFINED_CF,
        )

    # Bit and Byte Instructions
    def setcc(
        self, ctx: FukuAsmCtx, cond: FukuCondition, dst: FukuRegister | FukuOperand
    ):
        ctx.clear()

        assert cond not in [FukuCondition.NO_CONDITION, FukuCondition.CONDITION_MAX]

        if isinstance(dst, FukuRegister):
            ctx.gen_pattern32_2em_rm_idx(0x0F, 0x90 | cond.value, dst, 0)
        else:
            ctx.gen_pattern32_2em_op_idx(0x0F, 0x90 | cond.value, dst, 0)

        ctx.gen_func_return(
            cond.to_capstone_cc(FukuToCapConvertType.SETCC), ADI_FL_JCC[cond.value]
        )

    def test_b(
        self,
        ctx: FukuAsmCtx,
        dst: FukuRegister | FukuOperand,
        src: FukuRegister | FukuImmediate,
    ):
        ctx.clear()

        if isinstance(dst, FukuRegister) and isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_r(0x84, dst, src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuImmediate):
            if ctx.is_used_short_eax and dst.reg == FukuRegisterEnum.REG_AL:
                ctx.gen_pattern32_1em_immb(0xA8, dst, src)
            else:
                ctx.gen_pattern32_1em_rm_idx_immb(0xF6, dst, 0, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_op_r(0x84, dst, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuImmediate):
            ctx.gen_pattern32_1em_op_idx_immb(0xF6, dst, 0, src)

        ctx.gen_func_return(
            x86_const.X86_INS_TEST,
            x86_const.X86_EFLAGS_RESET_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_RESET_CF,
        )

    def test_w(
        self,
        ctx: FukuAsmCtx,
        dst: FukuRegister | FukuOperand,
        src: FukuRegister | FukuImmediate,
    ):
        ctx.clear()

        if isinstance(dst, FukuRegister) and isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_r_word(0x85, dst, src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuImmediate):
            if ctx.is_used_short_eax and dst.reg == FukuRegisterEnum.REG_AX:
                ctx.gen_pattern32_1em_immw_word(0xA9, dst, src)
            else:
                ctx.gen_pattern32_1em_rm_idx_immw_word(0xF7, dst, 0, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_op_r_word(0x85, dst, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuImmediate):
            ctx.gen_pattern32_1em_op_idx_immw_word(0xF7, dst, 0, src)

        ctx.gen_func_return(
            x86_const.X86_INS_TEST,
            x86_const.X86_EFLAGS_RESET_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_RESET_CF,
        )

    def test_dw(
        self,
        ctx: FukuAsmCtx,
        dst: FukuRegister | FukuOperand,
        src: FukuRegister | FukuImmediate,
    ):
        ctx.clear()

        if isinstance(dst, FukuRegister) and isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_r(0x85, dst, src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuImmediate):
            if ctx.is_used_short_eax and dst.reg == FukuRegisterEnum.REG_EAX:
                ctx.gen_pattern32_1em_immdw(0xA9, dst, src)
            else:
                ctx.gen_pattern32_1em_rm_idx_immdw(0xF7, dst, 0, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_op_r(0x85, dst, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuImmediate):
            ctx.gen_pattern32_1em_op_idx_immdw(0xF7, dst, 0, src)

        ctx.gen_func_return(
            x86_const.X86_INS_TEST,
            x86_const.X86_EFLAGS_RESET_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_RESET_CF,
        )

    def test_qw(
        self,
        ctx: FukuAsmCtx,
        dst: FukuRegister | FukuOperand,
        src: FukuRegister | FukuImmediate,
    ):
        ctx.clear()

        if isinstance(dst, FukuRegister) and isinstance(src, FukuRegister):
            ctx.gen_pattern64_1em_rm_r(0x85, dst, src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuImmediate):
            if ctx.is_used_short_eax and dst.reg == FukuRegisterEnum.REG_RAX:
                ctx.emit_rex_64(dst)
                ctx.gen_pattern64_1em_immdw(0xA9, dst, src)
            else:
                ctx.gen_pattern64_1em_rm_idx_immdw(0xF7, dst, 0, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuRegister):
            ctx.gen_pattern64_1em_op_r(0x85, dst, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuImmediate):
            ctx.gen_pattern64_1em_op_idx_immdw(0xF7, dst, 0, src)

        ctx.gen_func_return(
            x86_const.X86_INS_TEST,
            x86_const.X86_EFLAGS_RESET_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_RESET_CF,
        )

    def popcnt_w(
        self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand
    ):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
            ctx.emit_b(0xF3)
            ctx.emit_optional_rex_32(dst, src)
            ctx.emit_b(0x0F)
            ctx.emit_b(0xB8)
            ctx.emit_modrm(src, dst)
        else:
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
            ctx.emit_b(0xF3)
            ctx.emit_optional_rex_32(src, dst)
            ctx.emit_b(0x0F)
            ctx.emit_b(0xB8)
            ctx.emit_operand(src, dst)

        ctx.gen_func_return(
            x86_const.X86_INS_POPCNT,
            x86_const.X86_EFLAGS_RESET_OF
            | x86_const.X86_EFLAGS_RESET_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_RESET_AF
            | x86_const.X86_EFLAGS_RESET_PF
            | x86_const.X86_EFLAGS_RESET_CF,
        )

    def popcnt_dw(
        self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand
    ):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.emit_b(0xF3)
            ctx.emit_optional_rex_32(dst, src)
            ctx.emit_b(0x0F)
            ctx.emit_b(0xB8)
            ctx.emit_modrm(src, dst)
        else:
            ctx.emit_b(0xF3)
            ctx.emit_optional_rex_32(src, dst)
            ctx.emit_b(0x0F)
            ctx.emit_b(0xB8)
            ctx.emit_operand(src, dst)

        ctx.gen_func_return(
            x86_const.X86_INS_POPCNT,
            x86_const.X86_EFLAGS_RESET_OF
            | x86_const.X86_EFLAGS_RESET_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_RESET_AF
            | x86_const.X86_EFLAGS_RESET_PF
            | x86_const.X86_EFLAGS_RESET_CF,
        )

    def popcnt_qw(
        self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand
    ):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.emit_b(0xF3)
            ctx.emit_rex_64(dst, src)
            ctx.emit_b(0x0F)
            ctx.emit_b(0xB8)
            ctx.emit_modrm(src, dst)
        else:
            ctx.emit_b(0xF3)
            ctx.emit_rex_64(src, dst)
            ctx.emit_b(0x0F)
            ctx.emit_b(0xB8)
            ctx.emit_operand(src, dst)

        ctx.gen_func_return(
            x86_const.X86_INS_POPCNT,
            x86_const.X86_EFLAGS_RESET_OF
            | x86_const.X86_EFLAGS_RESET_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_RESET_AF
            | x86_const.X86_EFLAGS_RESET_PF
            | x86_const.X86_EFLAGS_RESET_CF,
        )

    # Control Transfer Instructions
    def jmp(self, ctx: FukuAsmCtx, src: FukuRegister | FukuOperand | FukuImmediate):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_idx(0xFF, src, 4)
        elif isinstance(src, FukuOperand):
            ctx.gen_pattern32_1em_op_idx(0xFF, src, 4)
        else:
            ctx.gen_pattern32_1em_immdw(
                0xE9, FukuRegister(FukuRegisterEnum.REG_NONE), src
            )

        ctx.gen_func_return(x86_const.X86_INS_JMP, 0)

    def jcc(self, ctx: FukuAsmCtx, cond: FukuCondition, imm: FukuImmediate):
        ctx.clear()

        assert cond not in [FukuCondition.NO_CONDITION, FukuCondition.CONDITION_MAX]

        ctx.gen_pattern32_2em_immdw(
            0x0F, 0x80 | cond.value, FukuRegister(FukuRegisterEnum.REG_NONE), imm
        )

        ctx.gen_func_return(
            cond.to_capstone_cc(FukuToCapConvertType.JCC), ADI_FL_JCC[cond.value]
        )

    def call(self, ctx: FukuAsmCtx, src: FukuRegister | FukuOperand | FukuImmediate):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_idx(0xFF, src, 2)
        elif isinstance(src, FukuOperand):
            ctx.gen_pattern32_1em_op_idx(0xFF, src, 2)
        else:
            ctx.gen_pattern32_1em_immdw(
                0xE8, FukuRegister(FukuRegisterEnum.REG_NONE), src
            )

        ctx.gen_func_return(x86_const.X86_INS_CALL, 0)

    def ret(self, ctx: FukuAsmCtx, imm: Optional[FukuImmediate] = None):
        ctx.clear()

        if imm is not None:
            ins = Instruction.create_u32(Code.RETNQ_IMM16, imm.to_iced())
        else:
            ins = Instruction.create(Code.RETNQ)
        gen_iced_ins(ctx, ins)

        ctx.gen_func_return(x86_const.X86_INS_RET, 0)

    def enter(self, ctx: FukuAsmCtx, size: FukuImmediate, nesting_level: int):
        ctx.clear()

        ins = Instruction.create_u32_u32(
            Code.ENTERQ_IMM16_IMM8, size.to_iced(), nesting_level
        )
        gen_iced_ins(ctx, ins)

        ctx.gen_func_return(x86_const.X86_INS_ENTER, 0)

    # Miscellaneous Instructions
    def lea_w(self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuOperand):
        ctx.clear()
        ctx.gen_pattern32_1em_op_r_word(0x8D, src, dst)
        ctx.gen_func_return(x86_const.X86_INS_LEA, 0)

    def lea_dw(self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuOperand):
        ctx.clear()
        ctx.gen_pattern32_1em_op_r(0x8D, src, dst)
        ctx.gen_func_return(x86_const.X86_INS_LEA, 0)

    def lea_qw(self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuOperand):
        ctx.clear()
        ctx.gen_pattern64_1em_op_r(0x8D, src, dst)
        ctx.gen_func_return(x86_const.X86_INS_LEA, 0)

    # Random Number Generator Instructions
    def _gen_func_body_rdxxxx_iced(self, name, id, cap_eflags):
        def wrapper(size: int):
            def fn(self, ctx: FukuAsmCtx, dst: FukuRegister):
                ctx.clear()

                code = getattr(Code, f"{name}_R{size}")
                arg1 = dst.to_iced_name()
                ins = getattr(Instruction, f"create_{arg1}")(code, dst.to_iced())
                gen_iced_ins(ctx, ins)

                ctx.gen_func_return(id, cap_eflags)

            return fn

        self._gen_fn(name, gen_default_postfix(wrapper, exclude=["b"]))

    # SYSTEM INSTRUCTIONS
    def nop(self, ctx: FukuAsmCtx, n: int = None):
        ctx.clear()

        if not n:
            n = rng.randint(1, 11)

        match n:
            case 2:
                ctx.emit_b(0x66)

            case 3:
                ctx.emit_b(0x0F)
                ctx.emit_b(0x1F)
                ctx.emit_b(0x00)

            case 4:
                ctx.emit_b(0x0F)
                ctx.emit_b(0x1F)
                ctx.emit_b(0x40)
                ctx.emit_b(0x00)

            case 5 | 6:
                if n == 6:
                    ctx.emit_b(0x66)

                ctx.emit_b(0x0F)
                ctx.emit_b(0x1F)
                ctx.emit_b(0x44)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)

            case 7:
                ctx.emit_b(0x0F)
                ctx.emit_b(0x1F)
                ctx.emit_b(0x80)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)

            case 8 | 9 | 10 | 11:
                if n >= 9:
                    if n >= 10:
                        if n == 11:
                            ctx.emit_b(0x66)
                        ctx.emit_b(0x66)
                    ctx.emit_b(0x66)

                ctx.emit_b(0x0F)
                ctx.emit_b(0x1F)
                ctx.emit_b(0x84)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)

            case _:
                ctx.emit_b(0x90)

        ctx.gen_func_return(x86_const.X86_INS_NOP, 0)

    def _gen_name(self, name, postfix):
        return name + postfix

    def _gen_func_body_byte_no_arg_iced(self, name, id, cap_eflags):
        def func_body_byte_no_arg(self, ctx: FukuAsmCtx):
            ctx.clear()

            code = getattr(Code, name.upper())
            ins = Instruction.create(code)
            gen_iced_ins(ctx, ins)

            ctx.gen_func_return(id, cap_eflags)

        setattr(self.__class__, name, func_body_byte_no_arg)

    def _gen_func_body_arith_iced(self, name, id, cap_eflags):
        def wrapper(size: int):
            def fn(self, ctx: FukuAsmCtx, dst, src):
                ctx.clear()

                code = get_iced_code(ctx, name, dst, src, size)
                arg1 = dst.to_iced_name()
                arg2 = src.to_iced_name()
                ins = getattr(Instruction, f"create_{arg1}_{arg2}")(
                    code, dst.to_iced(), src.to_iced()
                )
                gen_iced_ins(ctx, ins)

                ctx.gen_func_return(id, cap_eflags)

            return fn

        self._gen_fn(name, gen_default_postfix(wrapper))

    def _gen_func_body_arith_ex_one_op_iced(self, name, id, cap_eflags):
        def wrapper(size: int):
            def fn(self, ctx: FukuAsmCtx, src: FukuRegister | FukuOperand):
                ctx.clear()

                code = get_iced_code_one_op(ctx, name, src, size)
                arg1 = src.to_iced_name()
                ins = getattr(Instruction, f"create_{arg1}")(code, src.to_iced())
                gen_iced_ins(ctx, ins)

                ctx.gen_func_return(id, cap_eflags)

            return fn

        self._gen_fn(name, gen_default_postfix(wrapper))

    def _gen_func_body_shift_iced(self, name, id, cap_eflags):
        def wrapper_cl(size: int):
            def fn(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand):
                ctx.clear()

                code = get_iced_code_one_op(ctx, name, dst, size, "_CL")
                arg1 = dst.to_iced_name()
                ins = getattr(Instruction, f"create_{arg1}_reg")(
                    code, dst.to_iced(), Register.CL
                )
                gen_iced_ins(ctx, ins)

                ctx.gen_func_return(id, cap_eflags)

            return fn

        def wrapper(size: int):
            def fn(
                self,
                ctx: FukuAsmCtx,
                dst: FukuRegister | FukuOperand,
                src: FukuImmediate,
            ):
                ctx.clear()

                code = get_iced_code(ctx, name, dst, src, size)
                arg1 = dst.to_iced_name()
                arg2 = src.to_iced_name()
                ins = getattr(Instruction, f"create_{arg1}_{arg2}")(
                    code, dst.to_iced(), src.to_iced()
                )
                gen_iced_ins(ctx, ins)

                ctx.gen_func_return(id, cap_eflags)

            return fn

        self._gen_fn(name, gen_default_postfix(wrapper_cl, "cl_"))
        self._gen_fn(name, gen_default_postfix(wrapper))

    def _gen_func_body_bit_iced(self, name, id, cap_eflags):
        def wrapper(size: int):
            def fn(
                self,
                ctx: FukuAsmCtx,
                dst: FukuRegister | FukuOperand,
                src: FukuRegister | FukuImmediate,
            ):
                ctx.clear()

                code = get_iced_code(ctx, name, dst, src, size, max_imm_size=8)
                arg1 = dst.to_iced_name()
                arg2 = src.to_iced_name()
                ins = getattr(Instruction, f"create_{arg1}_{arg2}")(
                    code, dst.to_iced(), src.to_iced()
                )
                gen_iced_ins(ctx, ins)

                ctx.gen_func_return(id, cap_eflags)

            return fn

        self._gen_fn(name, gen_default_postfix(wrapper, exclude=["b"]))

    def _gen_func_body_string_inst_iced(
        self, name, cap_eflags, mapping: dict[int, str], exclude: list[str] = []
    ):
        def wrapper(size: int):
            def fn(self, ctx: FukuAsmCtx):
                ctx.clear()

                code = getattr(Code, f"{name.upper()}{mapping[size]}")
                ins = Instruction.create(code)
                gen_iced_ins(ctx, ins)

                ctx.gen_func_return(id, cap_eflags)

            return fn

        self._gen_fn(name, gen_default_postfix(wrapper, exclude=exclude))

    def _gen_func_body_movxx(self, name, type: int, id):
        def wrapper_byte_w(
            self, ctx: FukuAsmCtx, src: FukuRegister, dst: FukuRegister | FukuOperand
        ):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern32_2em_rm_r_word(0x0F, type, dst, src)
            else:
                ctx.gen_pattern32_2em_op_r_word(0x0F, type, dst, src)

            ctx.gen_func_return(id, 0)

        def wrapper_byte_dw(
            self, ctx: FukuAsmCtx, src: FukuRegister, dst: FukuRegister | FukuOperand
        ):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern32_2em_rm_r(0x0F, type, dst, src)
            else:
                ctx.gen_pattern32_2em_op_r(0x0F, type, dst, src)

            ctx.gen_func_return(id, 0)

        def wrapper_byte_qw(
            self, ctx: FukuAsmCtx, src: FukuRegister, dst: FukuRegister | FukuOperand
        ):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern64_2em_rm_r(0x0F, type, dst, src)
            else:
                ctx.gen_pattern64_2em_op_r(0x0F, type, dst, src)

            ctx.gen_func_return(id, 0)

        def wrapper_word_dw(
            self, ctx: FukuAsmCtx, src: FukuRegister, dst: FukuRegister | FukuOperand
        ):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern32_2em_rm_r(0x0F, type + 1, dst, src)
            else:
                ctx.gen_pattern32_2em_op_r(0x0F, type + 1, dst, src)

            ctx.gen_func_return(id, 0)

        def wrapper_word_qw(
            self, ctx: FukuAsmCtx, src: FukuRegister, dst: FukuRegister | FukuOperand
        ):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern64_2em_rm_r(0x0F, type + 1, dst, src)
            else:
                ctx.gen_pattern64_2em_op_r(0x0F, type + 1, dst, src)

            ctx.gen_func_return(id, 0)

        setattr(self.__class__, self._gen_name(name, "_byte_w"), wrapper_byte_w)
        setattr(self.__class__, self._gen_name(name, "_byte_dw"), wrapper_byte_dw)
        setattr(self.__class__, self._gen_name(name, "_byte_qw"), wrapper_byte_qw)
        setattr(self.__class__, self._gen_name(name, "_word_dw"), wrapper_word_dw)
        setattr(self.__class__, self._gen_name(name, "_word_qw"), wrapper_word_qw)

    def _gen_func_body_shxd_iced(self, name, id, cap_eflags):
        def wrapper(size: int):
            def fn(
                self,
                ctx: FukuAsmCtx,
                dst: FukuRegister | FukuOperand,
                src: FukuRegister,
                imm: FukuImmediate,
            ):
                ctx.clear()

                code = get_iced_code_three_op(ctx, name, dst, src, imm, size)
                arg1 = dst.to_iced_name()
                arg2 = src.to_iced_name()
                arg3 = imm.to_iced_name()
                ins = getattr(Instruction, f"create_{arg1}_{arg2}_{arg3}")(
                    code, dst.to_iced(), src.to_iced(), imm.to_iced()
                )
                gen_iced_ins(ctx, ins)

                ctx.gen_func_return(id, cap_eflags)

            return fn

        def wrapper_cl(size: int):
            def fn(
                self,
                ctx: FukuAsmCtx,
                dst: FukuRegister | FukuOperand,
                src: FukuRegister,
            ):
                ctx.clear()

                code = get_iced_code(ctx, name, dst, src, size)
                arg1 = dst.to_iced_name()
                arg2 = src.to_iced_name()
                ins = getattr(Instruction, f"create_{arg1}_{arg2}")(
                    code, dst.to_iced(), src.to_iced()
                )
                gen_iced_ins(ctx, ins)

                ctx.gen_func_return(id, cap_eflags)

            return fn

        self._gen_fn(name, gen_default_postfix(wrapper, exclude=["b"]))
        self._gen_fn(
            name, gen_default_postfix(wrapper_cl, modifier="cl_", exclude=["b"])
        )
