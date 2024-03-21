from common import rng
from typing import Tuple, Optional
from capstone import x86_const

from x86.misc import FukuCondition, FukuToCapConvertType
from x86.fuku_asm_ctx import FukuAsmCtx
from x86.fuku_immediate import FukuImmediate
from x86.fuku_register import FukuRegister, FukuRegisterEnum
from x86.fuku_operand import FukuOperand, FukuMemOperandType, FukuPrefix

FUKU_INTERNAL_ASSEMBLER_ARITH_ADD = 0
FUKU_INTERNAL_ASSEMBLER_ARITH_OR = 1
FUKU_INTERNAL_ASSEMBLER_ARITH_ADC = 2
FUKU_INTERNAL_ASSEMBLER_ARITH_SBB = 3
FUKU_INTERNAL_ASSEMBLER_ARITH_AND = 4
FUKU_INTERNAL_ASSEMBLER_ARITH_SUB = 5
FUKU_INTERNAL_ASSEMBLER_ARITH_XOR = 6
FUKU_INTERNAL_ASSEMBLER_ARITH_CMP = 7

FUKU_INTERNAL_ASSEMBLER_ARITH_EX_NOT = 2
FUKU_INTERNAL_ASSEMBLER_ARITH_EX_NEG = 3
FUKU_INTERNAL_ASSEMBLER_ARITH_EX_MUL = 4
FUKU_INTERNAL_ASSEMBLER_ARITH_EX_IMUL = 5
FUKU_INTERNAL_ASSEMBLER_ARITH_EX_DIV = 6
FUKU_INTERNAL_ASSEMBLER_ARITH_EX_IDIV = 7

FUKU_INTERNAL_ASSEMBLER_ARITH_INC = 0
FUKU_INTERNAL_ASSEMBLER_ARITH_DEC = 1

FUKU_INTERNAL_ASSEMBLER_SHIFT_ROL = 0
FUKU_INTERNAL_ASSEMBLER_SHIFT_ROR = 1
FUKU_INTERNAL_ASSEMBLER_SHIFT_RCL = 2
FUKU_INTERNAL_ASSEMBLER_SHIFT_RCR = 3
FUKU_INTERNAL_ASSEMBLER_SHIFT_SHL = 4
FUKU_INTERNAL_ASSEMBLER_SHIFT_SHR = 5
FUKU_INTERNAL_ASSEMBLER_SHIFT_SAR = 7

FUKU_INTERNAL_ASSEMBLER_SHIFT_SHLD = 0
FUKU_INTERNAL_ASSEMBLER_SHIFT_SHRD = 1

FUKU_INTERNAL_ASSEMBLER_BITTEST_BT = 4
FUKU_INTERNAL_ASSEMBLER_BITTEST_BTS = 5
FUKU_INTERNAL_ASSEMBLER_BITTEST_BTR = 6
FUKU_INTERNAL_ASSEMBLER_BITTEST_BTC = 7

FUKU_INTERNAL_ASSEMBLER_BITTEST_BSF = 0
FUKU_INTERNAL_ASSEMBLER_BITTEST_BSR = 1

FUKU_INTERNAL_ASSEMBLER_STRING_OUT = 55
FUKU_INTERNAL_ASSEMBLER_STRING_MOV = 82
FUKU_INTERNAL_ASSEMBLER_STRING_CMP = 83
FUKU_INTERNAL_ASSEMBLER_STRING_STO = 85
FUKU_INTERNAL_ASSEMBLER_STRING_LOD = 86
FUKU_INTERNAL_ASSEMBLER_STRING_SCA = 87

FUKU_INTERNAL_ASSEMBLER_POP = 0
FUKU_INTERNAL_ASSEMBLER_PUSH = 6

ADI_FL_JCC = [
    x86_const.X86_EFLAGS_TEST_OF , x86_const.X86_EFLAGS_TEST_OF, # jo   / jno
    x86_const.X86_EFLAGS_TEST_CF , x86_const.X86_EFLAGS_TEST_CF, # jb   / jae
    x86_const.X86_EFLAGS_TEST_ZF , x86_const.X86_EFLAGS_TEST_ZF, # je   / jne
    x86_const.X86_EFLAGS_TEST_ZF | x86_const.X86_EFLAGS_TEST_CF, x86_const.X86_EFLAGS_TEST_ZF | x86_const.X86_EFLAGS_TEST_CF, # jbe / jnbe
    x86_const.X86_EFLAGS_TEST_SF , x86_const.X86_EFLAGS_TEST_SF, # js   / jns
    x86_const.X86_EFLAGS_TEST_PF , x86_const.X86_EFLAGS_TEST_PF, # jp   / jnp
    x86_const.X86_EFLAGS_TEST_OF | x86_const.X86_EFLAGS_TEST_SF, x86_const.X86_EFLAGS_TEST_OF | x86_const.X86_EFLAGS_TEST_SF, # jnge / jge
    x86_const.X86_EFLAGS_TEST_OF | x86_const.X86_EFLAGS_TEST_SF | x86_const.X86_EFLAGS_TEST_ZF, x86_const.X86_EFLAGS_TEST_OF | x86_const.X86_EFLAGS_TEST_SF | x86_const.X86_EFLAGS_TEST_ZF # jng / jnle
]


class FukuAsmBody:
    def __init__(self):
        # Data Transfer Instructions
        self._gen_func_body_byte_no_arg("cwd", (FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value, 0x99), x86_const.X86_INS_CWD, 0)
        self._gen_func_body_byte_no_arg("cdq", (0x99,), x86_const.X86_INS_CDQ, 0)
        self._gen_func_body_byte_no_arg("cqo", (0x48, 0x99), x86_const.X86_INS_CQO, 0)

        self._gen_func_body_byte_no_arg("cbw", (FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value, 0x98), x86_const.X86_INS_CBW, 0)
        self._gen_func_body_byte_no_arg("cwde", (0x98, ), x86_const.X86_INS_CWDE, 0)
        self._gen_func_body_byte_no_arg("cdqe", (0x48, 0x98), x86_const.X86_INS_CDQE, 0)

        self._gen_func_body_movxx("movzx", 0xB6, x86_const.X86_INS_MOVZX)
        self._gen_func_body_movxx("movsx", 0xBE, x86_const.X86_INS_MOVSX)

        # Binary Arithmetic Instructions
        self._gen_func_body_arith("add", FUKU_INTERNAL_ASSEMBLER_ARITH_ADD, x86_const.X86_INS_ADD, x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_arith("adc", FUKU_INTERNAL_ASSEMBLER_ARITH_ADC, x86_const.X86_INS_ADC, x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_arith("sub", FUKU_INTERNAL_ASSEMBLER_ARITH_SUB, x86_const.X86_INS_SUB, x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_arith("sbb", FUKU_INTERNAL_ASSEMBLER_ARITH_SBB, x86_const.X86_INS_SBB, x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_arith_ex_one_op("imul", FUKU_INTERNAL_ASSEMBLER_ARITH_EX_IMUL, x86_const.X86_INS_IMUL, x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_UNDEFINED_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_UNDEFINED_PF)
        self._gen_func_body_arith_ex_one_op("mul", FUKU_INTERNAL_ASSEMBLER_ARITH_EX_MUL, x86_const.X86_INS_MUL, x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_UNDEFINED_SF | x86_const.X86_EFLAGS_UNDEFINED_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_UNDEFINED_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_arith_ex_one_op("idiv", FUKU_INTERNAL_ASSEMBLER_ARITH_EX_IDIV, x86_const.X86_INS_IDIV, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_UNDEFINED_SF | x86_const.X86_EFLAGS_UNDEFINED_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_UNDEFINED_PF | x86_const.X86_EFLAGS_UNDEFINED_CF)
        self._gen_func_body_arith_ex_one_op("div", FUKU_INTERNAL_ASSEMBLER_ARITH_EX_DIV, x86_const.X86_INS_DIV, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_UNDEFINED_SF | x86_const.X86_EFLAGS_UNDEFINED_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_UNDEFINED_PF | x86_const.X86_EFLAGS_UNDEFINED_CF)
        self._gen_func_body_arith_incdec("inc", FUKU_INTERNAL_ASSEMBLER_ARITH_INC, x86_const.X86_INS_INC, x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_PF)
        self._gen_func_body_arith_incdec("dec", FUKU_INTERNAL_ASSEMBLER_ARITH_DEC, x86_const.X86_INS_DEC, x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_PF)
        self._gen_func_body_arith_ex_one_op("neg", FUKU_INTERNAL_ASSEMBLER_ARITH_EX_NEG, x86_const.X86_INS_NEG, x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_arith("cmp", FUKU_INTERNAL_ASSEMBLER_ARITH_CMP, x86_const.X86_INS_CMP, x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)

        # Decimal Arithmetic Instructions
        self._gen_func_body_byte_no_arg("daa", (0x27,), x86_const.X86_INS_DAA, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_byte_no_arg("das", (0x2F,), x86_const.X86_INS_DAS, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_byte_no_arg("aaa", (0x37,), x86_const.X86_INS_AAA, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_UNDEFINED_SF | x86_const.X86_EFLAGS_UNDEFINED_ZF | x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_UNDEFINED_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_byte_no_arg("aas", (0x3F,), x86_const.X86_INS_AAS, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_UNDEFINED_SF | x86_const.X86_EFLAGS_UNDEFINED_ZF | x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_UNDEFINED_PF | x86_const.X86_EFLAGS_MODIFY_CF)

        # Logical Instructions Instructions
        self._gen_func_body_arith("and", FUKU_INTERNAL_ASSEMBLER_ARITH_AND, x86_const.X86_INS_AND, x86_const.X86_EFLAGS_RESET_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_RESET_CF)
        self._gen_func_body_arith("or", FUKU_INTERNAL_ASSEMBLER_ARITH_OR, x86_const.X86_INS_OR, x86_const.X86_EFLAGS_RESET_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_RESET_CF)
        self._gen_func_body_arith("xor", FUKU_INTERNAL_ASSEMBLER_ARITH_XOR, x86_const.X86_INS_XOR, x86_const.X86_EFLAGS_RESET_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_RESET_CF)
        self._gen_func_body_arith_ex_one_op("not", FUKU_INTERNAL_ASSEMBLER_ARITH_EX_NOT, x86_const.X86_INS_NOT, 0)

        # Shift and Rotate Instructions
        self._gen_func_body_shift("sar", FUKU_INTERNAL_ASSEMBLER_SHIFT_SAR, x86_const.X86_INS_SAR, x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_shift("shr", FUKU_INTERNAL_ASSEMBLER_SHIFT_SHR, x86_const.X86_INS_SHR, x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_shift("shl", FUKU_INTERNAL_ASSEMBLER_SHIFT_SHL, x86_const.X86_INS_SHL, x86_const.X86_EFLAGS_MODIFY_OF    | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)

        self._gen_func_body_shxd("shrd", FUKU_INTERNAL_ASSEMBLER_SHIFT_SHRD, x86_const.X86_INS_SHRD, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_shxd("shld", FUKU_INTERNAL_ASSEMBLER_SHIFT_SHLD, x86_const.X86_INS_SHLD, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)

        self._gen_func_body_shift("ror", FUKU_INTERNAL_ASSEMBLER_SHIFT_ROR, x86_const.X86_INS_ROR, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_shift("rol", FUKU_INTERNAL_ASSEMBLER_SHIFT_ROL, x86_const.X86_INS_ROL, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_shift("rcr", FUKU_INTERNAL_ASSEMBLER_SHIFT_RCR, x86_const.X86_INS_RCR, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_shift("rcl", FUKU_INTERNAL_ASSEMBLER_SHIFT_RCL, x86_const.X86_INS_RCL, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_CF)

        # Bit and Byte Instructions
        self._gen_func_body_bit("bt", FUKU_INTERNAL_ASSEMBLER_BITTEST_BT, x86_const.X86_INS_BT, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_UNDEFINED_SF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_UNDEFINED_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_bit("bts", FUKU_INTERNAL_ASSEMBLER_BITTEST_BTS, x86_const.X86_INS_BTS, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_UNDEFINED_SF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_UNDEFINED_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_bit("btr", FUKU_INTERNAL_ASSEMBLER_BITTEST_BTR, x86_const.X86_INS_BTR, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_UNDEFINED_SF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_UNDEFINED_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_bit("btc", FUKU_INTERNAL_ASSEMBLER_BITTEST_BTC, x86_const.X86_INS_BTC, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_UNDEFINED_SF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_UNDEFINED_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_bit_ex("bsf", FUKU_INTERNAL_ASSEMBLER_BITTEST_BSF, x86_const.X86_INS_BSF, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_UNDEFINED_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_UNDEFINED_PF | x86_const.X86_EFLAGS_UNDEFINED_CF)
        self._gen_func_body_bit_ex("bsr", FUKU_INTERNAL_ASSEMBLER_BITTEST_BSR, x86_const.X86_INS_BSR, x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_UNDEFINED_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_UNDEFINED_PF | x86_const.X86_EFLAGS_UNDEFINED_CF)

        # Control Transfer Instructions
        self._gen_func_body_byte_no_arg("int3", (0xCC,), x86_const.X86_INS_INT3, x86_const.X86_EFLAGS_MODIFY_IF | x86_const.X86_EFLAGS_MODIFY_TF | x86_const.X86_EFLAGS_MODIFY_NT | x86_const.X86_EFLAGS_MODIFY_RF)
        self._gen_func_body_byte_no_arg("leave", (0xC9,), x86_const.X86_INS_LEAVE, 0)

        # String Instructions
        self._gen_func_body_string_inst("outs", FUKU_INTERNAL_ASSEMBLER_STRING_OUT, "X86_INS_OUTS", x86_const.X86_EFLAGS_TEST_DF, q = False)
        self._gen_func_body_string_inst("movs", FUKU_INTERNAL_ASSEMBLER_STRING_MOV, "X86_INS_MOVS", x86_const.X86_EFLAGS_TEST_DF)
        self._gen_func_body_string_inst("cmps", FUKU_INTERNAL_ASSEMBLER_STRING_CMP, "X86_INS_CMPS", x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_string_inst("stos", FUKU_INTERNAL_ASSEMBLER_STRING_STO, "X86_INS_STOS", x86_const.X86_EFLAGS_TEST_DF)
        self._gen_func_body_string_inst("lods", FUKU_INTERNAL_ASSEMBLER_STRING_LOD, "X86_INS_LODS", x86_const.X86_EFLAGS_TEST_DF)
        self._gen_func_body_string_inst("scas", FUKU_INTERNAL_ASSEMBLER_STRING_SCA, "X86_INS_SCAS", x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)

        # Flag Control (EFLAG) Instructions
        self._gen_func_body_byte_no_arg("stc", (0xF9,), x86_const.X86_INS_STC, x86_const.X86_EFLAGS_SET_CF)
        self._gen_func_body_byte_no_arg("clc", (0xF8,), x86_const.X86_INS_CLC, x86_const.X86_EFLAGS_RESET_CF)
        self._gen_func_body_byte_no_arg("cmc", (0xF5,), x86_const.X86_INS_CMC, x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_byte_no_arg("cld", (0xFC,), x86_const.X86_INS_CLD, x86_const.X86_EFLAGS_RESET_DF)
        self._gen_func_body_byte_no_arg("std", (0xFD,), x86_const.X86_INS_STD, x86_const.X86_EFLAGS_SET_DF)
        self._gen_func_body_byte_no_arg("lahf", (0x9F,), x86_const.X86_INS_LAHF, 0)
        self._gen_func_body_byte_no_arg("sahf", (0x9E,), x86_const.X86_INS_SAHF, x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF)
        self._gen_func_body_byte_no_arg("pusha", (FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value, 0x60), x86_const.X86_INS_PUSHAW, 0)
        self._gen_func_body_byte_no_arg("pushad", (0x60,), x86_const.X86_INS_PUSHAL, 0)
        self._gen_func_body_byte_no_arg("popa", (FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value, 0x61), x86_const.X86_INS_POPAW, 0)
        self._gen_func_body_byte_no_arg("popad", 0x61, x86_const.X86_INS_POPAL, 0)
        self._gen_func_body_byte_no_arg("pushf", (FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value, 0x9C), x86_const.X86_INS_PUSHF, 0)
        self._gen_func_body_byte_no_arg("pushfd", 0x9C, x86_const.X86_INS_PUSHFD, 0)
        self._gen_func_body_byte_no_arg("pushfq", 0x9C, x86_const.X86_INS_PUSHFQ, 0)
        self._gen_func_body_byte_no_arg("popf", (FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value, 0x9D), x86_const.X86_INS_POPF, x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_TF | x86_const.X86_EFLAGS_MODIFY_IF | x86_const.X86_EFLAGS_MODIFY_DF | x86_const.X86_EFLAGS_MODIFY_NT | x86_const.X86_EFLAGS_MODIFY_RF)
        self._gen_func_body_byte_no_arg("popfd", (0x9D,), x86_const.X86_INS_POPFD, x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_TF | x86_const.X86_EFLAGS_MODIFY_IF | x86_const.X86_EFLAGS_MODIFY_DF | x86_const.X86_EFLAGS_MODIFY_NT | x86_const.X86_EFLAGS_MODIFY_RF)
        self._gen_func_body_byte_no_arg("popfq", (0x9D,), x86_const.X86_INS_POPFQ, x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_TF | x86_const.X86_EFLAGS_MODIFY_IF | x86_const.X86_EFLAGS_MODIFY_DF | x86_const.X86_EFLAGS_MODIFY_NT | x86_const.X86_EFLAGS_MODIFY_RF)

        # Miscellaneous Instructions
        self._gen_func_body_byte_no_arg("ud2", (0x0F, 0x0B), x86_const.X86_INS_UD2, 0)
        self._gen_func_body_byte_no_arg("cpuid", (0x0F, 0xA2), x86_const.X86_INS_CPUID, 0)

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
        self._gen_func_body_byte_no_arg("hlt", (0xF4,), x86_const.X86_INS_HLT, 0)
        self._gen_func_body_byte_no_arg("rdtsc", (0x0F, 0x31), x86_const.X86_INS_RDTSC, 0)
        self._gen_func_body_byte_no_arg("lfence", (0x0F, 0xAE, 0xE8), x86_const.X86_INS_LFENCE, 0)

    # Data Transfer Instructions
    # MOV
    def mov_b(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister | FukuImmediate | FukuOperand):
        ctx.clear()

        if isinstance(dst, FukuRegister) and isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_r(0x88, dst, src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuImmediate):
            ctx.gen_pattern32_1em_immb(0xB0 | dst.index.value, dst, src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuOperand):
            if (
                ctx.is_used_short_eax and
                dst.reg == FukuRegisterEnum.FUKU_REG_AL and
                src.type == FukuMemOperandType.FUKU_MEM_OPERAND_DISP_ONLY
            ):
                ctx.emit_optional_rex_32(src, dst)
                ctx.emit_b(0xA0)
                ctx.emit_dw(src.disp.immediate32)
                ctx.displacment_offset = len(ctx.bytecode) # todo
            else:
                ctx.gen_pattern32_1em_op_r(0x8A, src, dst)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuImmediate):
            ctx.gen_pattern32_1em_op_idx_immb(0xC6, dst, 0, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuRegister):
            if (
                ctx.is_used_short_eax and
                src.reg == FukuRegisterEnum.FUKU_REG_AL and
                dst.type == FukuMemOperandType.FUKU_MEM_OPERAND_DISP_ONLY
            ):
                ctx.emit_optional_rex_32(dst, src)
                ctx.emit_b(0xA2)
                ctx.emit_dw(dst.disp.immediate32)
                ctx.displacment_offset = len(ctx.bytecode) # todo
            else:
                ctx.gen_pattern32_1em_op_r(0x88, dst, src)
        else:
            raise AttributeError("Unhandled case")

        ctx.gen_func_return(x86_const.X86_INS_MOV, 0)

    def mov_w(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister | FukuImmediate | FukuOperand):
        ctx.clear()

        if isinstance(dst, FukuRegister) and isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_r_word(0x89, dst, src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuImmediate):
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
            ctx.emit_optional_rex_32(dst)
            ctx.emit_b(0xB8 | dst.index.value)
            ctx.emit_immediate_w(src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuOperand):
            if (
                ctx.is_used_short_eax and
                dst.reg == FukuRegisterEnum.FUKU_REG_AX and
                src.type == FukuMemOperandType.FUKU_MEM_OPERAND_DISP_ONLY
            ):
                ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
                ctx.emit_optional_rex_32(src, dst)
                ctx.emit_b(0xA1)
                ctx.emit_dw(src.disp.immediate32)
                ctx.displacment_offset = len(ctx.bytecode) # todo
            else:
                ctx.gen_pattern32_1em_op_r_word(0x8B, src, dst)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuImmediate):
            ctx.gen_pattern32_1em_op_idx_immw_word(0xC7, dst, 0, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuRegister):
            if (
                ctx.is_used_short_eax and
                src.reg == FukuRegisterEnum.FUKU_REG_AX and
                dst.type == FukuMemOperandType.FUKU_MEM_OPERAND_DISP_ONLY
            ):
                ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
                ctx.emit_optional_rex_32(dst, src)
                ctx.emit_b(0xA3)
                ctx.emit_dw(dst.disp.immediate32)
                ctx.displacment_offset = len(ctx.bytecode) # todo
            else:
                ctx.gen_pattern32_1em_op_r_word(0x89, dst, src)
        else:
            raise AttributeError("Unhandled case")

        ctx.gen_func_return(x86_const.X86_INS_MOV, 0)

    def mov_dw(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister | FukuImmediate | FukuOperand):
        ctx.clear()

        if isinstance(dst, FukuRegister) and isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_r(0x89, dst, src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuImmediate):
            ctx.emit_optional_rex_32(dst)
            ctx.emit_b(0xB8 | dst.index.value)
            ctx.emit_immediate_dw(src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuOperand):
            if (
                ctx.is_used_short_eax and
                dst.reg == FukuRegisterEnum.FUKU_REG_EAX and
                src.type == FukuMemOperandType.FUKU_MEM_OPERAND_DISP_ONLY
            ):
                ctx.emit_optional_rex_32(dst)
                ctx.emit_b(0xA1)
                ctx.emit_dw(src.disp.immediate32)
                ctx.displacment_offset = len(ctx.bytecode) # todo
            else:
                ctx.gen_pattern32_1em_op_r(0x8B, src, dst)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuImmediate):
            ctx.gen_pattern32_1em_op_idx_immdw(0xC7, dst, 0, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuRegister):
            if (
                ctx.is_used_short_eax and
                src.reg == FukuRegisterEnum.FUKU_REG_EAX and
                dst.type == FukuMemOperandType.FUKU_MEM_OPERAND_DISP_ONLY
            ):
                ctx.emit_optional_rex_32(dst, src)
                ctx.emit_b(0xA3)
                ctx.emit_dw(dst.disp.immediate32)
                ctx.displacment_offset = len(ctx.bytecode) # todo
            else:
                ctx.gen_pattern32_1em_op_r(0x89, dst, src)
        else:
            raise AttributeError("Unhandled case")

        ctx.gen_func_return(x86_const.X86_INS_MOV, 0)

    def mov_qw(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister | FukuImmediate | FukuOperand):
        ctx.clear()

        if isinstance(dst, FukuRegister) and isinstance(src, FukuRegister):
          ctx.gen_pattern64_1em_rm_r(0x89, dst, src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuImmediate):
            ctx.emit_rex_64(dst)
            ctx.emit_b(0xB8 | dst.index.value)
            ctx.emit_immediate_qw(src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuOperand):
            if (
                ctx.is_used_short_eax and
                dst.reg == FukuRegisterEnum.FUKU_REG_RAX and
                src.type == FukuMemOperandType.FUKU_MEM_OPERAND_DISP_ONLY
            ):
                ctx.emit_rex_64(dst)
                ctx.emit_b(0xA1)
                ctx.emit_dw(src.disp.immediate32)
                ctx.displacment_offset = len(ctx.bytecode) # todo
            else:
                ctx.gen_pattern64_1em_op_r(0x8B, src, dst)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuImmediate):
            ctx.gen_pattern64_1em_op_idx_immdw(0xC7, dst, 0, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuRegister):
            if (
                ctx.is_used_short_eax and
                src.reg == FukuRegisterEnum.FUKU_REG_RAX and
                dst.type == FukuMemOperandType.FUKU_MEM_OPERAND_DISP_ONLY
            ):
                ctx.emit_rex_64(dst, src)
                ctx.emit_b(0xA3)
                ctx.emit_dw(dst.disp.immediate32)
                ctx.displacment_offset = len(ctx.bytecode) # todo
            else:
                ctx.gen_pattern64_1em_op_r(0x89, dst, src)
        else:
            raise AttributeError("Unhandled case")

        if isinstance(dst, FukuRegister) and isinstance(src, FukuImmediate):
            ctx.gen_func_return(x86_const.X86_INS_MOVABS, 0)
        else:
            ctx.gen_func_return(x86_const.X86_INS_MOV, 0)

    def cmovcc_w(self, ctx: FukuAsmCtx, cond: FukuCondition, dst: FukuRegister, src: FukuOperand | FukuRegister):
        ctx.clear()

        if isinstance(src, FukuOperand):
            ctx.gen_pattern32_2em_op_r_word(0x0F, 0x40 | cond.value, src, dst)
        else:
            ctx.gen_pattern32_2em_rm_r_word(0x0F, 0x40 | cond.value, src, dst)

        ctx.gen_func_return(cond.to_capstone_cc(FukuToCapConvertType.CONVERT_TYPE_CMOVCC), ADI_FL_JCC[cond.value])

    def cmovcc_dw(self, ctx: FukuAsmCtx, cond: FukuCondition, dst: FukuRegister, src: FukuOperand | FukuRegister):
        ctx.clear()

        if isinstance(src, FukuOperand):
            ctx.gen_pattern32_2em_op_r(0x0F, 0x40 | cond.value, src, dst)
        else:
            ctx.gen_pattern32_2em_rm_r(0x0F, 0x40 | cond.value, src, dst)

        ctx.gen_func_return(cond.to_capstone_cc(FukuToCapConvertType.CONVERT_TYPE_CMOVCC), ADI_FL_JCC[cond.value])

    def cmovcc_qw(self, ctx: FukuAsmCtx, cond: FukuCondition, dst: FukuRegister, src: FukuOperand | FukuRegister):
        ctx.clear()

        if isinstance(src, FukuOperand):
            ctx.gen_pattern64_2em_op_r(0x0F, 0x40 | cond.value, src, dst)
        else:
            ctx.gen_pattern64_2em_rm_r(0x0F, 0x40 | cond.value, src, dst)

        ctx.gen_func_return(cond.to_capstone_cc(FukuToCapConvertType.CONVERT_TYPE_CMOVCC), ADI_FL_JCC[cond.value])

    def xchg_b(self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_1em_op_r(0x86, dst, src)
        else:
            ctx.gen_pattern32_1em_rm_r(0x86, dst, src)

        ctx.gen_func_return(x86_const.X86_INS_XCHG, 0)

    def xchg_w(self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_1em_op_r_word(0x87, dst, src)
        else:
            ctx.gen_pattern32_1em_rm_r_word(0x87, dst, src)

        ctx.gen_func_return(x86_const.X86_INS_XCHG, 0)

    def xchg_dw(self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_1em_op_r(0x87, dst, src)
        else:
            ctx.gen_pattern32_1em_rm_r(0x87, dst, src)

        ctx.gen_func_return(x86_const.X86_INS_XCHG, 0)

    def xchg_qw(self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister):
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

    def xadd_b(self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_2em_op_r(0x0F, 0xC0, dst, src)
        else:
            ctx.gen_pattern32_2em_rm_r(0x0F, 0xC0, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_XADD,
            x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
            x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF
        )

    def xadd_w(self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_2em_op_r_word(0x0F, 0xC1, dst, src)
        else:
            ctx.gen_pattern32_2em_rm_r_word(0x0F, 0xC1, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_XADD,
            x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
            x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF
        )

    def xadd_dw(self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_2em_op_r(0x0F, 0xC1, dst, src)
        else:
            ctx.gen_pattern32_2em_rm_r(0x0F, 0xC1, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_XADD,
            x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
            x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF
        )

    def xadd_qw(self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern64_2em_op_r(0x0F, 0xC1, dst, src)
        else:
            ctx.gen_pattern64_2em_rm_r(0x0F, 0xC1, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_XADD,
            x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
            x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF
        )

    def cmpxchg_b(self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_2em_op_r(0x0F, 0xB0, dst, src)
        else:
            ctx.gen_pattern32_2em_rm_r(0x0F, 0xB0, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_CMPXCHG,
            x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
            x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF
        )

    def cmpxchg_w(self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_2em_op_r_word(0x0F, 0xB1, dst, src)
        else:
            ctx.gen_pattern32_2em_rm_r_word(0x0F, 0xB1, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_CMPXCHG,
            x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
            x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF
        )

    def cmpxchg_dw(self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern32_2em_op_r(0x0F, 0xB1, dst, src)
        else:
            ctx.gen_pattern32_2em_rm_r(0x0F, 0xB1, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_CMPXCHG,
            x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
            x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF
        )

    def cmpxchg_qw(self, ctx: FukuAsmCtx, dst: FukuOperand | FukuRegister, src: FukuRegister):
        ctx.clear()

        if isinstance(dst, FukuOperand):
            ctx.gen_pattern64_2em_op_r(0x0F, 0xB1, dst, src)
        else:
            ctx.gen_pattern64_2em_rm_r(0x0F, 0xB1, dst, src)

        ctx.gen_func_return(
            x86_const.X86_INS_CMPXCHG,
            x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
            x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_MODIFY_CF
        )

    def cmpxchg8b(self, ctx: FukuAsmCtx, dst: FukuOperand):
        ctx.clear()
        ctx.gen_pattern32_2em_op_idx(0x0F, 0xC7, dst, 1)
        ctx.gen_func_return(x86_const.X86_INS_CMPXCHG8B, x86_const.X86_EFLAGS_MODIFY_ZF)

    def cmpxchg16b(self, ctx: FukuAsmCtx, dst: FukuOperand):
        ctx.clear()
        ctx.gen_pattern64_2em_op_idx(0x0F, 0xC7, dst, 1)
        ctx.gen_func_return(x86_const.X86_INS_CMPXCHG16B, x86_const.X86_EFLAGS_MODIFY_ZF)

    def push_w(self, ctx: FukuAsmCtx, src: FukuImmediate | FukuRegister | FukuOperand):
        ctx.clear()

        if isinstance(src, FukuImmediate):
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
            if ctx.is_used_short_imm and src.is_8:
                ctx.emit_b(0x6A)
                ctx.emit_immediate_b(src)
            else:
                ctx.emit_b(0x68)
                ctx.emit_immediate_w(src)
        elif isinstance(src, FukuRegister):
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
            ctx.emit_optional_rex_32(src)
            ctx.emit_b(0x50 | src.index.value)
        elif isinstance(src, FukuOperand):
            ctx.gen_pattern32_1em_op_idx_word(0xFF, src, FUKU_INTERNAL_ASSEMBLER_PUSH)

        ctx.gen_func_return(x86_const.X86_INS_PUSH, 0)

    def push_dw(self, ctx: FukuAsmCtx, src: FukuImmediate | FukuRegister | FukuOperand):
        ctx.clear()

        if isinstance(src, FukuImmediate):
            if ctx.is_used_short_imm and src.is_8:
                ctx.gen_pattern32_1em_immb(0x6A, FukuRegister(FukuRegisterEnum.FUKU_REG_NONE), src)
            else:
                ctx.gen_pattern32_1em_immdw(0x68, FukuRegister(FukuRegisterEnum.FUKU_REG_NONE), src)
        elif isinstance(src, FukuRegister):
            ctx.emit_optional_rex_32(src)
            ctx.emit_b(0x50 | src.index.value)
        elif isinstance(src, FukuOperand):
            ctx.gen_pattern32_1em_op_idx(0xFF, src, FUKU_INTERNAL_ASSEMBLER_PUSH)

        ctx.gen_func_return(x86_const.X86_INS_PUSH, 0)

    def push_qw(self, ctx: FukuAsmCtx, src: FukuImmediate | FukuRegister | FukuOperand):
        self.push_dw(ctx, src)

    def pop_w(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand):
        ctx.clear()

        if isinstance(dst, FukuRegister):
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
            ctx.emit_optional_rex_32(dst)
            ctx.emit_b(0x58 | dst.index.value)
        elif isinstance(dst, FukuOperand):
            ctx.gen_pattern32_1em_op_idx_word(0x8F, dst, FUKU_INTERNAL_ASSEMBLER_POP)

        ctx.gen_func_return(x86_const.X86_INS_POP, 0)

    def pop_dw(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand):
        ctx.clear()

        if isinstance(dst, FukuRegister):
            ctx.emit_optional_rex_32(dst)
            ctx.emit_b(0x58 | dst.index.value)
        elif isinstance(dst, FukuOperand):
            ctx.gen_pattern32_1em_op_idx(0x8F, dst, FUKU_INTERNAL_ASSEMBLER_POP)

        ctx.gen_func_return(x86_const.X86_INS_POP, 0)

    def pop_qw(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand):
        self.pop_dw(ctx, dst)

    def movsxd_word_w(self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_r_word(0x63, src, dst)
        else:
            ctx.gen_pattern32_1em_op_r_word(0x63, dst, src)

        ctx.gen_func_return(x86_const.X86_INS_MOVSXD, 0)

    def movsxd_dword_dw(self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_r(0x63, src, dst)
        else:
            ctx.gen_pattern32_1em_op_r(0x63, dst, src)

        ctx.gen_func_return(x86_const.X86_INS_MOVSXD, 0)

    def movsxd_dword_qw(self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.gen_pattern64_1em_rm_r(0x63, src, dst)
        else:
            ctx.gen_pattern64_1em_op_r(0x63, dst, src)

        ctx.gen_func_return(x86_const.X86_INS_MOVSXD, 0)

    # Binary Arithmetic Instructions
    def adcx_dw(self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand):
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

    def adcx_qw(self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand):
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

    def adox_dw(self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand):
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

    def adox_qw(self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand):
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
        ctx.gen_pattern32_1em_immb(0xD4, FukuRegister(FukuRegisterEnum.FUKU_REG_NONE), imm)
        ctx.gen_func_return(
            x86_const.X86_INS_AAM,
            x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF |
            x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_UNDEFINED_CF
        )

    def aad(self, ctx: FukuAsmCtx, imm: FukuImmediate):
        ctx.clear()
        ctx.gen_pattern32_1em_immb(0xD5, FukuRegister(FukuRegisterEnum.FUKU_REG_NONE), imm)
        ctx.gen_func_return(
            x86_const.X86_INS_AAD,
            x86_const.X86_EFLAGS_UNDEFINED_OF | x86_const.X86_EFLAGS_MODIFY_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF |
            x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_UNDEFINED_CF
        )

    # Bit and Byte Instructions
    def setcc(self, ctx: FukuAsmCtx, cond: FukuCondition, dst: FukuRegister | FukuOperand):
        ctx.clear()

        assert cond not in [FukuCondition.FUKU_NO_CONDITION, FukuCondition.FUKU_CONDITION_MAX]

        if isinstance(dst, FukuRegister):
            ctx.gen_pattern32_2em_rm_idx(0x0F, 0x90 | cond.value, dst, 0)
        else:
            ctx.gen_pattern32_2em_op_idx(0x0F, 0x90 | cond.value, dst, 0)

        ctx.gen_func_return(
            cond.to_capstone_cc(FukuToCapConvertType.CONVERT_TYPE_SETCC),
            ADI_FL_JCC[cond.value]
        )

    def test_b(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister | FukuImmediate):
        ctx.clear()

        if isinstance(dst, FukuRegister) and isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_r(0x84, dst, src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuImmediate):
            if ctx.is_used_short_eax and dst.reg == FukuRegisterEnum.FUKU_REG_AL:
                ctx.gen_pattern32_1em_immb(0xA8, dst, src)
            else:
                ctx.gen_pattern32_1em_rm_idx_immb(0xF6, dst, 0, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_op_r(0x84, dst, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuImmediate):
            ctx.gen_pattern32_1em_op_idx_immb(0xF6, dst, 0, src)

        ctx.gen_func_return(
            x86_const.X86_INS_TEST,
            x86_const.X86_EFLAGS_RESET_OF | x86_const.X86_EFLAGS_MODIFY_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF |
            x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_RESET_CF
        )

    def test_w(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister | FukuImmediate):
        ctx.clear()

        if isinstance(dst, FukuRegister) and isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_r_word(0x85, dst, src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuImmediate):
            if ctx.is_used_short_eax and dst.reg == FukuRegisterEnum.FUKU_REG_AX:
                ctx.gen_pattern32_1em_immw_word(0xA9, dst, src)
            else:
                ctx.gen_pattern32_1em_rm_idx_immw_word(0xF7, dst, 0, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_op_r_word(0x85, dst, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuImmediate):
            ctx.gen_pattern32_1em_op_idx_immw_word(0xF7, dst, 0, src)

        ctx.gen_func_return(
            x86_const.X86_INS_TEST,
            x86_const.X86_EFLAGS_RESET_OF | x86_const.X86_EFLAGS_MODIFY_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF |
            x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_RESET_CF
        )

    def test_dw(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister | FukuImmediate):
        ctx.clear()

        if isinstance(dst, FukuRegister) and isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_r(0x85, dst, src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuImmediate):
            if ctx.is_used_short_eax and dst.reg == FukuRegisterEnum.FUKU_REG_EAX:
                ctx.gen_pattern32_1em_immdw(0xA9, dst, src)
            else:
                ctx.gen_pattern32_1em_rm_idx_immdw(0xF7, dst, 0, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_op_r(0x85, dst, src)
        elif isinstance(dst, FukuOperand) and isinstance(src, FukuImmediate):
            ctx.gen_pattern32_1em_op_idx_immdw(0xF7, dst, 0, src)

        ctx.gen_func_return(
            x86_const.X86_INS_TEST,
            x86_const.X86_EFLAGS_RESET_OF | x86_const.X86_EFLAGS_MODIFY_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF |
            x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_RESET_CF
        )

    def test_qw(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister | FukuImmediate):
        ctx.clear()

        if isinstance(dst, FukuRegister) and isinstance(src, FukuRegister):
            ctx.gen_pattern64_1em_rm_r(0x85, dst, src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuImmediate):
            if ctx.is_used_short_eax and dst.reg == FukuRegisterEnum.FUKU_REG_RAX:
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
            x86_const.X86_EFLAGS_RESET_OF | x86_const.X86_EFLAGS_MODIFY_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF |
            x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_RESET_CF
        )

    def popcnt_w(self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand):
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
            x86_const.X86_EFLAGS_RESET_OF | x86_const.X86_EFLAGS_RESET_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_RESET_AF |
            x86_const.X86_EFLAGS_RESET_PF | x86_const.X86_EFLAGS_RESET_CF
        )

    def popcnt_dw(self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand):
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
            x86_const.X86_EFLAGS_RESET_OF | x86_const.X86_EFLAGS_RESET_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_RESET_AF |
            x86_const.X86_EFLAGS_RESET_PF | x86_const.X86_EFLAGS_RESET_CF
        )

    def popcnt_qw(self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand):
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
            x86_const.X86_EFLAGS_RESET_OF | x86_const.X86_EFLAGS_RESET_SF |
            x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_RESET_AF |
            x86_const.X86_EFLAGS_RESET_PF | x86_const.X86_EFLAGS_RESET_CF
        )

    # Control Transfer Instructions
    def jmp(self, ctx: FukuAsmCtx, src: FukuRegister | FukuOperand | FukuImmediate):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_idx(0xFF, src, 4)
        elif isinstance(src, FukuOperand):
            ctx.gen_pattern32_1em_op_idx(0xFF, src, 4)
        else:
            ctx.gen_pattern32_1em_immdw(0xE9, FukuRegister(FukuRegisterEnum.FUKU_REG_NONE), src)

        ctx.gen_func_return(x86_const.X86_INS_JMP, 0)

    def jcc(self, ctx: FukuAsmCtx, cond: FukuCondition, imm: FukuImmediate):
        ctx.clear()

        assert cond not in [FukuCondition.FUKU_NO_CONDITION, FukuCondition.FUKU_CONDITION_MAX]

        ctx.gen_pattern32_2em_immdw(0x0F, 0x80 | cond.value, FukuRegister(FukuRegisterEnum.FUKU_REG_NONE), imm)

        ctx.gen_func_return(
            cond.to_capstone_cc(FukuToCapConvertType.CONVERT_TYPE_JCC),
            ADI_FL_JCC[cond.value]
        )

    def call(self, ctx: FukuAsmCtx, src: FukuRegister | FukuOperand | FukuImmediate):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_idx(0xFF, src, 2)
        elif isinstance(src, FukuOperand):
            ctx.gen_pattern32_1em_op_idx(0xFF, src, 2)
        else:
            ctx.gen_pattern32_1em_immdw(0xE8, FukuRegister(FukuRegisterEnum.FUKU_REG_NONE), src)

        ctx.gen_func_return(x86_const.X86_INS_CALL, 0)

    def ret(self, ctx: FukuAsmCtx, imm: Optional[FukuImmediate] = None):
        ctx.clear()

        if imm is not None:
            ctx.gen_pattern32_1em_immw(0xC2, FukuRegister(FukuRegisterEnum.FUKU_REG_NONE), imm)
        else:
            ctx.emit_b(0xC3)

        ctx.gen_func_return(x86_const.X86_INS_RET, 0)

    def enter(self, ctx: FukuAsmCtx, size: FukuImmediate, nesting_level: int):
        ctx.clear()
        ctx.gen_pattern32_1em_immw(0xC8, FukuRegister(FukuRegisterEnum.FUKU_REG_NONE), size)
        ctx.emit_b(nesting_level)
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
    def rdrand_w(self, ctx: FukuAsmCtx, dst: FukuRegister):
        ctx.clear()
        ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        ctx.emit_optional_rex_32(dst)
        ctx.emit_b(0x0F)
        ctx.emit_b(0xC7)
        ctx.emit_b(0xF0 | dst.index.value)
        ctx.gen_func_return(
            x86_const.X86_INS_RDRAND,
            x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_RESET_OF |
            x86_const.X86_EFLAGS_RESET_SF | x86_const.X86_EFLAGS_RESET_ZF |
            x86_const.X86_EFLAGS_RESET_AF | x86_const.X86_EFLAGS_RESET_PF
        )

    def rdrand_dw(self, ctx: FukuAsmCtx, dst: FukuRegister):
        ctx.clear()
        ctx.emit_optional_rex_32(dst)
        ctx.emit_b(0x0F)
        ctx.emit_b(0xC7)
        ctx.emit_b(0xF0 | dst.index.value)
        ctx.gen_func_return(
            x86_const.X86_INS_RDRAND,
            x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_RESET_OF |
            x86_const.X86_EFLAGS_RESET_SF | x86_const.X86_EFLAGS_RESET_ZF |
            x86_const.X86_EFLAGS_RESET_AF | x86_const.X86_EFLAGS_RESET_PF
        )

    def rdrand_qw(self, ctx: FukuAsmCtx, dst: FukuRegister):
        ctx.clear()
        ctx.emit_rex_64(dst)
        ctx.emit_b(0x0F)
        ctx.emit_b(0xC7)
        ctx.emit_b(0xF0 | dst.index.value)
        ctx.gen_func_return(
            x86_const.X86_INS_RDRAND,
            x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_RESET_OF |
            x86_const.X86_EFLAGS_RESET_SF | x86_const.X86_EFLAGS_RESET_ZF |
            x86_const.X86_EFLAGS_RESET_AF | x86_const.X86_EFLAGS_RESET_PF
        )

    def rdseed_w(self, ctx: FukuAsmCtx, dst: FukuRegister):
        ctx.clear()
        ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        ctx.emit_optional_rex_32(dst)
        ctx.emit_b(0x0F)
        ctx.emit_b(0xC7)
        ctx.emit_b(0xF8 | dst.index.value)
        ctx.gen_func_return(
            x86_const.X86_INS_RDSEED,
            x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_RESET_OF |
            x86_const.X86_EFLAGS_RESET_SF | x86_const.X86_EFLAGS_RESET_ZF |
            x86_const.X86_EFLAGS_RESET_AF | x86_const.X86_EFLAGS_RESET_PF
        )

    def rdseed_dw(self, ctx: FukuAsmCtx, dst: FukuRegister):
        ctx.clear()
        ctx.emit_optional_rex_32(dst)
        ctx.emit_b(0x0F)
        ctx.emit_b(0xC7)
        ctx.emit_b(0xF8 | dst.index.value)
        ctx.gen_func_return(
            x86_const.X86_INS_RDSEED,
            x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_RESET_OF |
            x86_const.X86_EFLAGS_RESET_SF | x86_const.X86_EFLAGS_RESET_ZF |
            x86_const.X86_EFLAGS_RESET_AF | x86_const.X86_EFLAGS_RESET_PF
        )

    def rdseed_qw(self, ctx: FukuAsmCtx, dst: FukuRegister):
        ctx.clear()
        ctx.emit_rex_64(dst)
        ctx.emit_b(0x0F)
        ctx.emit_b(0xC7)
        ctx.emit_b(0xF8 | dst.index.value)
        ctx.gen_func_return(
            x86_const.X86_INS_RDSEED,
            x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_RESET_OF |
            x86_const.X86_EFLAGS_RESET_SF | x86_const.X86_EFLAGS_RESET_ZF |
            x86_const.X86_EFLAGS_RESET_AF | x86_const.X86_EFLAGS_RESET_PF
        )

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

    def _gen_func_body_byte_no_arg(self, name, _bytes: Tuple, id, cap_eflags):
        def func_body_byte_no_arg(self, ctx: FukuAsmCtx):
            ctx.clear()
            for byte in _bytes:
                ctx.emit_b(byte)
            ctx.emit_b(byte)
            ctx.gen_func_return(id, cap_eflags)

        setattr(self.__class__, name, func_body_byte_no_arg)

    def _gen_func_body_ff_r(self, name, type: int, id, cap_eflags):
        def func_body_ff_r(self, ctx: FukuAsmCtx, src: FukuRegister):
            ctx.clear()
            ctx.gen_pattern32_1em_rm_idx(0xFF, src, type)
            ctx.gen_func_return(id, cap_eflags)

        setattr(self.__class__, name, func_body_ff_r)

    def _gen_func_body_ff_offset(self, name, type: int, id, cap_eflags):
        def func_body_ff_offset(self, ctx: FukuAsmCtx, src: FukuImmediate):
            ctx.clear()
            ctx.gen_pattern32_1em_immdw(type, FukuRegister(FukuRegisterEnum.FUKU_REG_NONE),  src)
            ctx.gen_func_return(id, cap_eflags)

        setattr(self.__class__, name, func_body_ff_offset)

    def _gen_func_body_ff_op(self, name, type: int, id, cap_eflags):
        def func_body_ff_op(self, ctx: FukuAsmCtx, src: FukuOperand):
            ctx.clear()
            ctx.gen_pattern32_1em_op_idx(0xFF, src, type)
            ctx.gen_func_return(id, cap_eflags)

        setattr(self.__class__, name, func_body_ff_op)

    def _gen_func_body_arith(self, name, type: int, id, cap_eflags):
        def wrapper_b(self, ctx: FukuAsmCtx, dst, src):
            ctx.clear() # gencleanerdata

            def ri():
                if ctx.is_used_short_eax and dst.reg == FukuRegisterEnum.FUKU_REG_AL:
                    ctx.gen_pattern32_1em_immb(0x04 + 8 * type, dst, src)
                else:
                    ctx.gen_pattern32_1em_rm_idx_immb(0x80, dst, type, src)

            handlers = {}
            handlers[(FukuRegister, FukuRegister)] = lambda: ctx.gen_pattern32_1em_rm_r(8 * type, dst, src)
            handlers[(FukuRegister, FukuImmediate)] = ri
            handlers[(FukuRegister, FukuOperand)] = lambda: ctx.gen_pattern32_1em_op_idx(0x02 + 8 * type, src, dst)
            handlers[(FukuOperand, FukuRegister)] = lambda: ctx.gen_pattern32_1em_op_r(0x00 + 8 * type, dst, src)
            handlers[(FukuOperand, FukuImmediate)] = lambda: ctx.gen_pattern32_1em_op_idx_immb(0x80, dst, type, src)
            handlers[(dst.__class__, src.__class__)]()

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_w(self, ctx: FukuAsmCtx, dst, src):
            ctx.clear() # gencleanerdata

            def ri():
                if ctx.is_used_short_eax and dst.reg == FukuRegisterEnum.FUKU_REG_AX:
                    ctx.gen_pattern32_1em_immw_word(0x05 + 8 * type, dst, src)
                else:
                    if ctx.is_used_short_imm and src.is_8:
                        ctx.gen_pattern32_1em_rm_idx_immb_word(0x83, dst, type, src)
                    else:
                        ctx.gen_pattern32_1em_rm_idx_immw_word(0x81, dst, type, src)

            def oi():
                if ctx.is_used_short_eax and src.is_8:
                    ctx.gen_pattern32_1em_op_idx_immb_word(0x83, dst, type, src)
                else:
                    ctx.gen_pattern32_1em_op_idx_immw_word(0x81, dst, type, src)

            handlers = {}
            handlers[(FukuRegister, FukuRegister)] = lambda: ctx.gen_pattern32_1em_rm_r_word(0x01 + 8 * type, dst, src)
            handlers[(FukuRegister, FukuImmediate)] = ri
            handlers[(FukuRegister, FukuOperand)] = lambda: ctx.gen_pattern32_1em_op_r_word(0x03 + 8 * type, src, dst)
            handlers[(FukuOperand, FukuRegister)] = lambda: ctx.gen_pattern32_1em_op_r_word(0x01 + 8 * type, dst, src)
            handlers[(FukuOperand, FukuImmediate)] = oi
            handlers[(dst.__class__, src.__class__)]()

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_dw(self, ctx: FukuAsmCtx, dst, src):
            ctx.clear()

            def ri():
                if ctx.is_used_short_eax and dst.reg == FukuRegisterEnum.FUKU_REG_EAX:
                    ctx.gen_pattern32_1em_immdw(0x05 + 8 * type, dst, src)
                else:
                    if ctx.is_used_short_imm and src.is_8:
                        ctx.gen_pattern32_1em_rm_idx_immb(0x83, dst, type, src)
                    else:
                        ctx.gen_pattern32_1em_rm_idx_immdw(0x81, dst, type, src)

            def oi():
                if ctx.is_used_short_imm and src.is_8:
                    ctx.gen_pattern32_1em_op_idx_immb(0x83, dst, type, src)
                else:
                    ctx.gen_pattern32_1em_op_idx_immdw(0x81, dst, type, src)

            handlers = {}
            handlers[(FukuRegister, FukuRegister)] = lambda: ctx.gen_pattern32_1em_rm_r(0x01 + 8 * type, dst, src)
            handlers[(FukuRegister, FukuImmediate)] = ri
            handlers[(FukuRegister, FukuOperand)] = lambda: ctx.gen_pattern32_1em_op_r(0x03 + 8 * type, src, dst)
            handlers[(FukuOperand, FukuRegister)] = lambda: ctx.gen_pattern32_1em_op_r(0x01 + 8 * type, dst, src)
            handlers[(FukuOperand, FukuImmediate)] = oi
            handlers[(dst.__class__, src.__class__)]()

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_qw(self, ctx: FukuAsmCtx, dst, src):
            ctx.clear()

            def ri():
                if ctx.is_used_short_eax and dst.reg == FukuRegisterEnum.FUKU_REG_EAX:
                    ctx.gen_pattern64_1em_immdw(0x05 + 8 * type, dst, src)
                else:
                    if ctx.is_used_short_imm and src.is_8:
                        ctx.gen_pattern64_1em_rm_idx_immb(0x83, dst, type, src)
                    else:
                        ctx.gen_pattern64_1em_rm_idx_immdw(0x81, dst, type, src)

            def oi():
                if ctx.is_used_short_imm and src.is_8:
                    ctx.gen_pattern64_1em_op_idx_immb(0x83, dst, type, src)
                else:
                    ctx.gen_pattern64_1em_op_idx_immdw(0x81, dst, type, src)

            handlers = {}
            handlers[(FukuRegister, FukuRegister)] = lambda: ctx.gen_pattern64_1em_rm_r(0x01 + 8 * type, dst, src)
            handlers[(FukuRegister, FukuImmediate)] = ri
            handlers[(FukuRegister, FukuOperand)] = lambda: ctx.gen_pattern64_1em_op_r(0x03 + 8 * type, src, dst)
            handlers[(FukuOperand, FukuRegister)] = lambda: ctx.gen_pattern64_1em_op_r(0x01 + 8 * type, dst, src)
            handlers[(FukuOperand, FukuImmediate)] = oi
            handlers[(dst.__class__, src.__class__)]()

            ctx.gen_func_return(id, cap_eflags)

        setattr(self.__class__, self._gen_name(name, "_b"), wrapper_b)
        setattr(self.__class__, self._gen_name(name, "_w"), wrapper_w)
        setattr(self.__class__, self._gen_name(name, "_dw"), wrapper_dw)
        setattr(self.__class__, self._gen_name(name, "_qw"), wrapper_qw)

    def _gen_func_body_arith_ex_one_op(self, name, type: int, id, cap_eflags):
        def wrapper_b(self, ctx: FukuAsmCtx, src: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(src, FukuRegister):
                ctx.gen_pattern32_1em_rm_idx(0xF6, src, type)
            else:
                ctx.gen_pattern32_1em_op_idx(0xF6, src, type)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_w(self, ctx: FukuAsmCtx, src: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(src, FukuRegister):
                ctx.gen_pattern32_1em_rm_idx_word(0xF7, src, type)
            else:
                ctx.gen_pattern32_1em_op_idx_word(0xF7, src, type)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_dw(self, ctx: FukuAsmCtx, src: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(src, FukuRegister):
                ctx.gen_pattern32_1em_rm_idx(0xF7, src, type)
            else:
                ctx.gen_pattern32_1em_op_idx(0xF7, src, type)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_qw(self, ctx: FukuAsmCtx, src: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(src, FukuRegister):
                ctx.gen_pattern64_1em_rm_idx(0xF7, src, type)
            else:
                ctx.gen_pattern64_1em_op_idx(0xF7, src, type)

            ctx.gen_func_return(id, cap_eflags)

        setattr(self.__class__, self._gen_name(name, "_b"), wrapper_b)
        setattr(self.__class__, self._gen_name(name, "_w"), wrapper_w)
        setattr(self.__class__, self._gen_name(name, "_dw"), wrapper_dw)
        setattr(self.__class__, self._gen_name(name, "_qw"), wrapper_qw)

    def _gen_func_body_arith_incdec(self, name, type: int, id, cap_eflags):
        def wrapper_b(self, ctx: FukuAsmCtx, src: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(src, FukuRegister):
                ctx.gen_pattern32_1em_rm_idx(0xFE, src, type)
            else:
                ctx.gen_pattern32_1em_op_idx(0xFE, src, type)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_w(self, ctx: FukuAsmCtx, src: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(src, FukuRegister):
                ctx.gen_pattern32_1em_rm_idx_word(0xFF, src, type)
            else:
                ctx.gen_pattern32_1em_op_idx_word(0xFF, src, type)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_dw(self, ctx: FukuAsmCtx, src: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(src, FukuRegister):
                ctx.gen_pattern32_1em_rm_idx(0xFF, src, type)
            else:
                ctx.gen_pattern32_1em_op_idx(0xFF, src, type)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_qw(self, ctx: FukuAsmCtx, src: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(src, FukuRegister):
                ctx.gen_pattern64_1em_rm_idx(0xFF, src, type)
            else:
                ctx.gen_pattern64_1em_op_idx(0xFF, src, type)

            ctx.gen_func_return(id, cap_eflags)

        setattr(self.__class__, self._gen_name(name, "_b"), wrapper_b)
        setattr(self.__class__, self._gen_name(name, "_w"), wrapper_w)
        setattr(self.__class__, self._gen_name(name, "_dw"), wrapper_dw)
        setattr(self.__class__, self._gen_name(name, "_qw"), wrapper_qw)

    def _gen_func_body_shift(self, name, type: int, id, cap_eflags):
        def wrapper_cl_b(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern32_1em_rm_idx(0xD2, dst, type)
            else:
                ctx.gen_pattern32_1em_op_idx(0xD2, dst, type)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_b(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuImmediate):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.emit_optional_rex_32(dst)
                if ctx.is_used_short_imm and src.immediate8 == 1:
                    ctx.gen_pattern32_1em_rm_idx(0xD0, dst, type)
                else:
                    ctx.gen_pattern32_1em_rm_idx_immb(0xC0, dst, type, src)
            else:
                if ctx.is_used_short_imm and src.immediate8 == 1:
                    ctx.gen_pattern32_1em_op_idx(0xD0, dst, type)
                else:
                    ctx.gen_pattern32_1em_op_idx_immb(0xC0, dst, type, src)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_cl_w(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern32_1em_rm_idx_word(0xD3, dst, type)
            else:
                ctx.gen_pattern32_1em_op_idx_word(0xD3, dst, type)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_w(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuImmediate):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                if ctx.is_used_short_imm and src.immediate8 == 1:
                    ctx.gen_pattern32_1em_rm_idx_word(0xD1, dst, type)
                else:
                    ctx.gen_pattern32_1em_rm_idx_immb_word(0xC1, dst, type, src)
            else:
                if ctx.is_used_short_imm and src.immediate8 == 1:
                    ctx.gen_pattern32_1em_op_idx_word(0xD1, dst, type)
                else:
                    ctx.gen_pattern32_1em_op_idx_immb_word(0xC1, dst, type, src)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_cl_dw(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern32_1em_rm_idx(0xD3, dst, type)
            else:
                ctx.gen_pattern32_1em_op_idx(0xD3, dst, type)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_dw(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuImmediate):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                if ctx.is_used_short_imm and src.immediate8 == 1:
                    ctx.gen_pattern32_1em_rm_idx(0xD1, dst, type)
                else:
                    ctx.gen_pattern32_1em_rm_idx_immb(0xC1, dst, type, src)
            else:
                if ctx.is_used_short_imm and src.immediate8 == 1:
                    ctx.gen_pattern32_1em_op_idx(0xD1, dst, type)
                else:
                    ctx.gen_pattern32_1em_op_idx_immb(0xC1, dst, type, src)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_cl_qw(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern64_1em_rm_idx(0xD3, dst, type)
            else:
                ctx.gen_pattern64_1em_op_idx(0xD3, dst, type)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_qw(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuImmediate):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                if ctx.is_used_short_imm and src.immediate8 == 1:
                    ctx.gen_pattern64_1em_rm_idx(0xD1, dst, type)
                else:
                    ctx.gen_pattern64_1em_rm_idx_immb(0xC1, dst, type, src)
            else:
                if ctx.is_used_short_imm and src.immediate8 == 1:
                    ctx.gen_pattern64_1em_op_idx(0xD1, dst, type)
                else:
                    ctx.gen_pattern64_1em_op_idx_immb(0xC1, dst, type, src)

            ctx.gen_func_return(id, cap_eflags)

        setattr(self.__class__, self._gen_name(name, "_cl_b"), wrapper_cl_b)
        setattr(self.__class__, self._gen_name(name, "_b"), wrapper_b)
        setattr(self.__class__, self._gen_name(name, "_cl_w"), wrapper_cl_w)
        setattr(self.__class__, self._gen_name(name, "_w"), wrapper_w)
        setattr(self.__class__, self._gen_name(name, "_cl_dw"), wrapper_cl_dw)
        setattr(self.__class__, self._gen_name(name, "_dw"), wrapper_dw)
        setattr(self.__class__, self._gen_name(name, "_cl_qw"), wrapper_cl_qw)
        setattr(self.__class__, self._gen_name(name, "_qw"), wrapper_qw)

    def _gen_func_body_bit(self, name, type: int, id, cap_eflags):
        def wrapper_w(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister | FukuImmediate):
            ctx.clear()

            handlers = {}
            handlers[(FukuRegister, FukuRegister)] = lambda: ctx.gen_pattern32_2em_rm_r_word(0x0F, 0x83 + 8 * type, dst, src)
            handlers[(FukuRegister, FukuImmediate)] = lambda: ctx.gen_pattern32_2em_rm_idx_immb_word(0x0F, 0xBA, dst, type, src)
            handlers[(FukuOperand, FukuRegister)] = lambda: ctx.gen_pattern32_2em_op_r_word(0x0F, 0x83 + 8 * type, dst, src)
            handlers[(FukuOperand, FukuImmediate)] = lambda: ctx.gen_pattern32_2em_op_idx_immb_word(0x0F, 0xBA, dst, type, src)
            handlers[(dst.__class__, src.__class__)]()

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_dw(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister | FukuImmediate):
            ctx.clear()

            handlers = {}
            handlers[(FukuRegister, FukuRegister)] = lambda: ctx.gen_pattern32_2em_rm_r(0x0F, 0x83 + 8 * type, dst, src)
            handlers[(FukuRegister, FukuImmediate)] = lambda: ctx.gen_pattern32_2em_rm_idx_immb(0x0F, 0xBA, dst, type, src)
            handlers[(FukuOperand, FukuRegister)] = lambda: ctx.gen_pattern32_2em_op_r(0x0F, 0x83 + 8 * type, dst, src)
            handlers[(FukuOperand, FukuImmediate)] = lambda: ctx.gen_pattern32_2em_op_idx_immb(0x0F, 0xBA, dst, type, src)
            handlers[(dst.__class__, src.__class__)]()

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_qw(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister | FukuImmediate):
            ctx.clear()

            handlers = {}
            handlers[(FukuRegister, FukuRegister)] = lambda: ctx.gen_pattern64_2em_rm_r(0x0F, 0x83 + 8 * type, dst, src)
            handlers[(FukuRegister, FukuImmediate)] = lambda: ctx.gen_pattern64_2em_rm_idx_immb(0x0F, 0xBA, dst, type, src)
            handlers[(FukuOperand, FukuRegister)] = lambda: ctx.gen_pattern64_2em_op_r(0x0F, 0x83 + 8*type, dst, src)
            handlers[(FukuOperand, FukuImmediate)] = lambda: ctx.gen_pattern64_2em_op_idx_immb(0x0F, 0xBA, dst, type, src)
            handlers[(dst.__class__, src.__class__)]()

            ctx.gen_func_return(id, cap_eflags)

        setattr(self.__class__, self._gen_name(name, "_w"), wrapper_w)
        setattr(self.__class__, self._gen_name(name, "_dw"), wrapper_dw)
        setattr(self.__class__, self._gen_name(name, "_qw"), wrapper_qw)

    def _gen_func_body_bit_ex(self, name, type: int, id, cap_eflags):
        def wrapper_w(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern32_2em_rm_r_word(0x0F, 0xBC + type, dst, src)
            else:
                ctx.gen_pattern32_2em_op_r_word(0x0F, 0xBC + type, dst, src)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_dw(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern32_2em_rm_r(0x0F, 0xBC + type, dst, src)
            else:
                ctx.gen_pattern32_2em_op_r(0x0F, 0xBC + type, dst, src)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_qw(self, ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern64_2em_rm_r(0x0F, 0xBC + type, dst, src)
            else:
                ctx.gen_pattern64_2em_op_r(0x0F, 0xBC + type, dst, src)

            ctx.gen_func_return(id, cap_eflags)

        setattr(self.__class__, self._gen_name(name, "_w"), wrapper_w)
        setattr(self.__class__, self._gen_name(name, "_dw"), wrapper_dw)
        setattr(self.__class__, self._gen_name(name, "_qw"), wrapper_qw)

    def _gen_func_body_string_inst(self, name, type: int, idMASK: str, cap_eflags, q = True):
        def wrapper_b(self, ctx: FukuAsmCtx):
            ctx.clear()
            ctx.emit_b(type * 2)
            ctx.gen_func_return(getattr(x86_const, idMASK + "B"), cap_eflags)

        def wrapper_w(self, ctx: FukuAsmCtx):
            ctx.clear()
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
            ctx.emit_b(type*2 + 1)
            ctx.gen_func_return(getattr(x86_const, idMASK + "W"), cap_eflags)

        def wrapper_d(self, ctx: FukuAsmCtx):
            ctx.clear()
            ctx.emit_b(type * 2 + 1)
            ctx.gen_func_return(getattr(x86_const, idMASK + "D"), cap_eflags)

        def wrapper_q(self, ctx: FukuAsmCtx):
            ctx.clear()
            ctx.emit_rex_64()
            ctx.emit_b(type * 2 + 1)
            ctx.gen_func_return(getattr(x86_const, idMASK + "Q"), cap_eflags)

        setattr(self.__class__, self._gen_name(name, "b"), wrapper_b)
        setattr(self.__class__, self._gen_name(name, "w"), wrapper_w)
        setattr(self.__class__, self._gen_name(name, "d"), wrapper_d)

        if q:
            setattr(self.__class__, self._gen_name(name, "q"), wrapper_q)

    def _gen_func_body_movxx(self, name, type: int, id):
        def wrapper_byte_w(self, ctx: FukuAsmCtx, src: FukuRegister, dst: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern32_2em_rm_r_word(0x0F, type, dst, src)
            else:
                ctx.gen_pattern32_2em_op_r_word(0x0F, type, dst, src)

            ctx.gen_func_return(id, 0)

        def wrapper_byte_dw(self, ctx: FukuAsmCtx, src: FukuRegister, dst: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern32_2em_rm_r(0x0F, type, dst, src)
            else:
                ctx.gen_pattern32_2em_op_r(0x0F, type, dst, src)

            ctx.gen_func_return(id, 0)

        def wrapper_byte_qw(self, ctx: FukuAsmCtx, src: FukuRegister, dst: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern64_2em_rm_r(0x0F, type, dst, src)
            else:
                ctx.gen_pattern64_2em_op_r(0x0F, type, dst, src)

            ctx.gen_func_return(id, 0)

        def wrapper_word_dw(self, ctx: FukuAsmCtx, src: FukuRegister, dst: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern32_2em_rm_r(0x0F, type + 1, dst, src)
            else:
                ctx.gen_pattern32_2em_op_r(0x0F, type + 1, dst, src)

            ctx.gen_func_return(id, 0)

        def wrapper_word_qw(self, ctx: FukuAsmCtx, src: FukuRegister, dst: FukuRegister | FukuOperand):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern64_2em_rm_r(0x0F,type + 1, dst, src)
            else:
                ctx.gen_pattern64_2em_op_r(0x0F,type + 1, dst, src)

            ctx.gen_func_return(id, 0)

        setattr(self.__class__, self._gen_name(name, "_byte_w"), wrapper_byte_w)
        setattr(self.__class__, self._gen_name(name, "_byte_dw"), wrapper_byte_dw)
        setattr(self.__class__, self._gen_name(name, "_byte_qw"), wrapper_byte_qw)
        setattr(self.__class__, self._gen_name(name, "_word_dw"), wrapper_word_dw)
        setattr(self.__class__, self._gen_name(name, "_word_qw"), wrapper_word_qw)

    def _gen_func_body_shxd(self, name, type: int, id, cap_eflags):
        def wrapper_w(ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister, imm: FukuImmediate):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern32_2em_rm_idx_immb_word(0x0F, 0xA4 + 8 * type, dst, src, imm)
            else:
                ctx.gen_pattern32_2em_op_idx_immb_word(0x0F, 0xA4 + 8 * type, dst, src, imm)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_cl_w(ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern32_2em_rm_idx_word(0x0F, 0xA5 + 8 * type, dst, src)
            else:
                ctx.gen_pattern32_2em_op_idx_word(0x0F, 0xA5 + 8 * type, dst, src)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_dw(ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister, imm: FukuImmediate):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern32_2em_rm_idx_immb(0x0F, 0xA4 + 8 * type, dst, src, imm)
            else:
                ctx.gen_pattern32_2em_op_idx_immb(0x0F, 0xA4 + 8 * type, dst, src, imm)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_cl_dw(ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern32_2em_rm_idx(0x0F, 0xA5 + 8 * type, dst, src)
            else:
                ctx.gen_pattern32_2em_op_idx(0x0F, 0xA5 + 8 * type, dst, src)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_qw(ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister, imm: FukuImmediate):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern64_2em_rm_idx_immb(0x0F, 0xA4 + 8 * type, dst, src, imm)
            else:
                ctx.gen_pattern64_2em_op_idx_immb(0x0F, 0xA4 + 8 * type, dst, src, imm)

            ctx.gen_func_return(id, cap_eflags)

        def wrapper_cl_qw(ctx: FukuAsmCtx, dst: FukuRegister | FukuOperand, src: FukuRegister):
            ctx.clear()

            if isinstance(dst, FukuRegister):
                ctx.gen_pattern64_2em_rm_idx(0x0F, 0xA5 + 8 * type, dst, src)
            else:
                ctx.gen_pattern64_2em_op_idx(0x0F, 0xA5 + 8 * type, dst, src)

            ctx.gen_func_return(id, cap_eflags)

        setattr(self.__class__, self._gen_name(name, "_w"), wrapper_w)
        setattr(self.__class__, self._gen_name(name, "_cl_w"), wrapper_cl_w)
        setattr(self.__class__, self._gen_name(name, "_dw"), wrapper_dw)
        setattr(self.__class__, self._gen_name(name, "_cl_dw"), wrapper_cl_dw)
        setattr(self.__class__, self._gen_name(name, "_qw"), wrapper_qw)
        setattr(self.__class__, self._gen_name(name, "_cl_qw"), wrapper_cl_qw)
