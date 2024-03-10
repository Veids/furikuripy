from common import trace
from random import randint
from capstone import x86_const

from fuku_misc import FukuInstFlags
from fuku_inst import FukuInst, FukuRipRelocation, FukuCodeLabel
from x86.misc import FukuOperandSize, FukuCondition
from x86.fuku_type import FukuType, FukuT0Types
from x86.fuku_operand import FukuOperand
from x86.fuku_register import FukuRegister, FukuRegisterEnum, FukuRegisterIndex
from x86.fuku_immediate import FukuImmediate
from x86.fuku_mutation_ctx import FukuMutationCtx
from x86.fuku_register_math import has_free_eflags
from x86.fuku_register_math_metadata import ODI_FL_JCC, AllowInstruction, FlagRegister

# mov somereg, src
# xchg dst, somereg
def _mov_64_multi_tmpl_1(ctx: FukuMutationCtx, dst: FukuType, src: FukuType, inst_size: int) -> bool:
    changes_regflags = ctx.cpu_registers & ~(dst.get_mask_register() | src.get_mask_register())

    somereg = FukuType.get_random_operand_dst_x64(
        AllowInstruction.REGISTER.value, inst_size, changes_regflags,
        FlagRegister.SP.value |
        FlagRegister.ESP.value |
        FlagRegister.RSP.value
    )

    if not somereg:
        return False

    inst: FukuInst = ctx.payload_inst_iter.peek()
    out_regflags = changes_regflags & ~(somereg.register.get_flag_complex(FukuOperandSize.FUKU_OPERAND_SIZE_64))

    ctx.f_asm.mov(somereg, src)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers

    ctx.restore_imm_or_disp(src, inst.disp_reloc, inst.flags.inst_used_disp, inst.imm_reloc, inst_size)

    ctx.f_asm.xchg(dst, somereg)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags

    ctx.restore_disp_relocate(src, inst.disp_reloc, inst.flags.inst_used_disp)

    trace.info("mov dst, src -> mov somereg, src; xchg dst, somereg")
    return True

# xor dst, dst
# add dst, src
def _mov_64_multi_tmpl_2(ctx: FukuMutationCtx, dst: FukuType, src: FukuType, inst_size: int) -> bool:
    if not has_free_eflags(
        ctx.cpu_flags,
        x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
        x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
        x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_MODIFY_PF
    ):
        return False

    out_regflags = ctx.cpu_registers & ~(dst.get_mask_register() | src.get_mask_register())

    ctx.f_asm.xor(dst, dst)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers

    ctx.f_asm.add(dst, src)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags

    trace.info("mov dst, src -> xor dst, dst; add dst, src")
    return True

# push src
# pop dst
def _mov_64_multi_tmpl_3(ctx: FukuMutationCtx, dst: FukuType, src: FukuType, inst_size: int) -> bool:
    if (
        not ctx.is_allowed_stack_operations or
        inst_size == FukuOperandSize.FUKU_OPERAND_SIZE_8.value or
        (src.type == FukuT0Types.FUKU_T0_IMMEDIATE and inst_size != FukuOperandSize.FUKU_OPERAND_SIZE_32.value)
    ):
        return False

    if (
         (dst.register.index == FukuRegisterIndex.FUKU_REG_INDEX_SP if dst.type == FukuT0Types.FUKU_T0_REGISTER else False) or
         (src.register.index == FukuRegisterIndex.FUKU_REG_INDEX_SP if src.type == FukuT0Types.FUKU_T0_REGISTER else False)
    ):
        return False

    inst: FukuInst = ctx.payload_inst_iter.peek()
    out_regflags = ctx.cpu_registers & ~(dst.get_mask_register() | src.get_mask_register())

    ctx.f_asm.push(src)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags

    ctx.restore_imm_or_disp(src, inst.disp_reloc, inst.flags.inst_used_disp, inst.imm_reloc, inst_size)

    ctx.f_asm.pop(dst)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags

    ctx.restore_disp_relocate(dst, inst.disp_reloc, inst.flags.inst_used_disp)

    trace.info("mov dst, src -> push src; pop dst")
    return True


def _mov_64_reg_reg_tmpl(ctx: FukuMutationCtx) -> bool:
    reg_dst = FukuRegister(FukuRegisterEnum.from_capstone(ctx.instruction.operands[0])).ftype
    reg_src = FukuRegister(FukuRegisterEnum.from_capstone(ctx.instruction.operands[1])).ftype

    match randint(0, 2):
        case 0:
            return _mov_64_multi_tmpl_1(ctx, reg_dst, reg_src, ctx.instruction.operands[0].size)

        case 1:
            return _mov_64_multi_tmpl_2(ctx, reg_dst, reg_src, ctx.instruction.operands[0].size)

        case 2:
            return _mov_64_multi_tmpl_3(ctx, reg_dst, reg_src, ctx.instruction.operands[0].size)


def _mov_64_reg_imm_tmpl(ctx: FukuMutationCtx) -> bool:
    reg_dst = FukuRegister(FukuRegisterEnum.from_capstone(ctx.instruction.operands[0])).ftype
    imm_src = FukuImmediate(immediate_value = ctx.instruction.operands[1].imm).ftype

    match randint(0, 2):
        case 0:
            return _mov_64_multi_tmpl_1(ctx, reg_dst, imm_src, ctx.instruction.operands[0].size)

        case 1:
            return _mov_64_multi_tmpl_2(ctx, reg_dst, imm_src, ctx.instruction.operands[0].size)

        case 2:
            return _mov_64_multi_tmpl_3(ctx, reg_dst, imm_src, ctx.instruction.operands[0].size)

def _mov_64_reg_op_tmpl(ctx: FukuMutationCtx) -> bool:
    reg_dst = FukuRegister(FukuRegisterEnum.from_capstone(ctx.instruction.operands[0])).ftype
    op_src = FukuOperand.from_capstone(ctx.instruction.operands[1]).ftype

    match randint(0, 2):
        case 0:
            return _mov_64_multi_tmpl_1(ctx, reg_dst, op_src, ctx.instruction.operands[0].size)

        case 1:
            return _mov_64_multi_tmpl_2(ctx, reg_dst, op_src, ctx.instruction.operands[0].size)

        case 2:
            return _mov_64_multi_tmpl_3(ctx, reg_dst, op_src, ctx.instruction.operands[0].size)


def _mov_64_op_reg_tmpl(ctx: FukuMutationCtx) -> bool:
    op_dst = FukuOperand.from_capstone(ctx.instruction.operands[0]).ftype
    reg_src = FukuRegister(FukuRegisterEnum.from_capstone(ctx.instruction.operands[1])).ftype

    match randint(0, 1):
        case 0:
            return _mov_64_multi_tmpl_1(ctx, op_dst, reg_src, ctx.instruction.operands[0].size)

        case 1:
            return _mov_64_multi_tmpl_3(ctx, op_dst, reg_src, ctx.instruction.operands[0].size);


def _mov_64_op_imm_tmpl(ctx: FukuMutationCtx) -> bool:
    op_dst = FukuOperand.from_capstone(ctx.instruction.operands[0]).ftype
    imm_src = FukuImmediate(immediate_value = ctx.instruction.operands[1].imm).ftype

    match randint(0, 1):
        case 0:
            return _mov_64_multi_tmpl_1(ctx, op_dst, imm_src, ctx.instruction.operands[0].size)

        case 1:
            return _mov_64_multi_tmpl_3(ctx, op_dst, imm_src, ctx.instruction.operands[0].size);

def fukutate_64_mov(ctx: FukuMutationCtx) -> bool:
    operands = ctx.instruction.operands
    if operands[0].type == x86_const.X86_OP_REG:
        if operands[1].type == x86_const.X86_OP_REG: # mov reg, reg
            return _mov_64_reg_reg_tmpl(ctx)
        elif operands[1].type == x86_const.X86_OP_IMM: # mov reg, imm
            return _mov_64_reg_imm_tmpl(ctx)
        elif operands[1].type == x86_const.X86_OP_MEM: # mov reg, [op]
            return _mov_64_reg_op_tmpl(ctx)
    elif operands[0].type == x86_const.X86_OP_MEM:
        if operands[1].type == x86_const.X86_OP_REG: # mov [op], reg
            return _mov_64_op_reg_tmpl(ctx)
        elif operands[1].type == x86_const.X86_OP_IMM: # mov [op], imm
            return _mov_64_op_imm_tmpl(ctx)

    return False
