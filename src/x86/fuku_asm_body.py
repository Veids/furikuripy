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
        # Logical Instructions Instructions
        self.gen_func_body_arith("and", FUKU_INTERNAL_ASSEMBLER_ARITH_AND, x86_const.X86_INS_AND, x86_const.X86_EFLAGS_RESET_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_RESET_CF)
        self.gen_func_body_arith("or", FUKU_INTERNAL_ASSEMBLER_ARITH_OR, x86_const.X86_INS_OR, x86_const.X86_EFLAGS_RESET_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_RESET_CF)
        self.gen_func_body_arith("xor", FUKU_INTERNAL_ASSEMBLER_ARITH_XOR, x86_const.X86_INS_XOR, x86_const.X86_EFLAGS_RESET_OF | x86_const.X86_EFLAGS_MODIFY_SF | x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_UNDEFINED_AF | x86_const.X86_EFLAGS_MODIFY_PF | x86_const.X86_EFLAGS_RESET_CF)

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
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA)
            ctx.emit_optional_rex_32(dst)
            ctx.emit_b(0xB8 | dst.index.value)
            ctx.emit_immediate_w(src)
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuOperand):
            if (
                ctx.is_used_short_eax and
                dst.reg == FukuRegisterEnum.FUKU_REG_AX and
                src.type == FukuMemOperandType.FUKU_MEM_OPERAND_DISP_ONLY
            ):
                ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA)
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
                ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA)
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
                ctx.emit_optional_rex_32(dst, src);
                ctx.emit_b(0xA3);
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
            ctx.gen_pattern64_2em_rm_r(0x0F, 0x40 | cond, src, dst)

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

    def gen_name(self, name, postfix):
        return name + postfix

    def gen_func_body_arith(self, name, type, id, cap_eflags):
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

        self.__dict__[self.gen_name(name, "_b")] = wrapper_b
        self.__dict__[self.gen_name(name, "_w")] = wrapper_w
        self.__dict__[self.gen_name(name, "_dw")] = wrapper_dw
        self.__dict__[self.gen_name(name, "_qw")] = wrapper_qw
        return
