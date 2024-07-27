from capstone import x86_const

from furikuripy.common import rng, trace_inst
from furikuripy.fuku_misc import FukuInstFlags
from furikuripy.x86.fuku_type import FukuType, FukuT0Types
from furikuripy.x86.fuku_operand import FukuOperand
from furikuripy.x86.fuku_register import FukuRegister, FukuRegisterIndex
from furikuripy.x86.fuku_mutation_ctx import FukuMutationCtx
from furikuripy.x86.fuku_register_math import has_free_eflags
from furikuripy.x86.fuku_register_math_metadata import AllowInstruction, FlagRegister

# xor dst_1, dst_2
# xor dst_2, dst_1
# xor dst_1, dst_2
def _xchg_64_multi_tmpl_1(ctx: FukuMutationCtx, dst_1: FukuType, dst_2: FukuType, inst_size: int) -> bool:
    if not has_free_eflags(
        ctx.cpu_flags,
        x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
        x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
        x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_MODIFY_PF
    ):
        return False

    opcodes = []
    changes_regflags = ctx.cpu_registers & ~(dst_1.get_mask_register() | dst_2.get_mask_register())

    ctx.f_asm.xor(dst_1, dst_2)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = changes_regflags
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.xor(dst_2, dst_1)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = changes_regflags
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.xor(dst_1, dst_2)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = changes_regflags
    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("xchg dst_1, dst_2 -> xor dst_1, dst_2; xor dst_2, dst_1, xor dst_1, dst_2", opcodes)
    return True

# mov somereg_1, dst_1
# mov somereg_2, dst_2
# mov dst_1, somereg_2
# mov dst_2, somereg_1
def _xchg_64_multi_tmpl_2(ctx: FukuMutationCtx, dst_1: FukuType, dst_2: FukuType, inst_size: int) -> bool:
    additation_inst_flag = 0

    if dst_1.type == FukuT0Types.FUKU_T0_OPERAND:
        if dst_1.operand.base.index == FukuRegisterIndex.INDEX_SP or dst_1.operand.index.index == FukuRegisterIndex.INDEX_SP:
            additation_inst_flag = FukuInstFlags.FUKU_INST_BAD_STACK
    else:
        if dst_1.register.index == FukuRegisterIndex.INDEX_SP:
            additation_inst_flag = FukuInstFlags.FUKU_INST_BAD_STACK

    if dst_2.operand.base.index == FukuRegisterIndex.INDEX_SP:
        additation_inst_flag = FukuInstFlags.FUKU_INST_BAD_STACK

    out_regflags = ctx.cpu_registers & ~(dst_1.get_mask_register() | dst_2.get_mask_register())

    somereg_1 = FukuType.get_random_operand_dst_x64(
        AllowInstruction.REGISTER.value, inst_size, out_regflags,
        FlagRegister.SP.value |
        FlagRegister.ESP.value
    )

    if not somereg_1:
        return False

    out_regflags &= ~(somereg_1.get_mask_register())

    somereg_2 = FukuType.get_random_operand_dst_x64(
        AllowInstruction.REGISTER.value, inst_size, out_regflags,
        FlagRegister.SP.value |
        FlagRegister.ESP.value
    )

    if not somereg_2:
        return False

    opcodes = []
    disp_reloc = ctx.payload_inst.disp_reloc
    out_regflags &= ~(somereg_2.get_mask_register())

    ctx.f_asm.mov(somereg_1, dst_1)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags
    ctx.f_asm.context.inst.flags = additation_inst_flag
    ctx.restore_disp_relocate(dst_1, disp_reloc)
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.mov(somereg_2, dst_2)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags
    ctx.f_asm.context.inst.flags = additation_inst_flag
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.mov(dst_1, somereg_2)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags
    ctx.f_asm.context.inst.flags = additation_inst_flag
    ctx.restore_disp_relocate(dst_1, disp_reloc)
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.mov(dst_2, somereg_1)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags
    ctx.f_asm.context.inst.flags = additation_inst_flag
    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("xchg dst_1, dst_2 -> mov reg_1, dst_1; mov reg_2, dst_2, mov dst_1, reg_2; mov dst_2, reg_1", opcodes)
    return True

def _xchg_64_reg_reg_tmpl(ctx: FukuMutationCtx) -> bool:
    reg_dst_1 = FukuRegister.from_capstone(ctx.instruction.operands[0]).ftype
    reg_dst_2 = FukuRegister.from_capstone(ctx.instruction.operands[1]).ftype

    match rng.randint(0, 1):
        case 0:
            return _xchg_64_multi_tmpl_1(ctx, reg_dst_1, reg_dst_2, ctx.instruction.operands[0].size)

        case 1:
            return _xchg_64_multi_tmpl_2(ctx, reg_dst_1, reg_dst_2, ctx.instruction.operands[0].size)

def _xchg_64_op_reg_tmpl(ctx: FukuMutationCtx) -> bool:
    op_dst = None
    reg_dst = None

    if ctx.instruction.operands[0].type == x86_const.X86_OP_MEM:
        op_dst = FukuOperand.from_capstone(ctx.instruction.operands[0])
        reg_dst = FukuRegister.from_capstone(ctx.instruction.operands[1])
    else:
        op_dst = FukuOperand.from_capstone(ctx.instruction.operands[1])
        reg_dst = FukuRegister.from_capstone(ctx.instruction.operands[0])

    return _xchg_64_multi_tmpl_2(ctx, op_dst.ftype, reg_dst.ftype, ctx.instruction.operand[0].size)


def fukutate_64_xchg(ctx: FukuMutationCtx) -> bool:
    if (
        ctx.instruction.operands[0].type == x86_const.X86_OP_MEM or
        ctx.instruction.operands[1].type == x86_const.X86_OP_MEM
    ):
        return _xchg_64_op_reg_tmpl(ctx)

    return _xchg_64_reg_reg_tmpl(ctx)
