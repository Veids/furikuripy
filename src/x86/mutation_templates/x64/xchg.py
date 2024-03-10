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

    changes_regflags = ctx.cpu_registers & ~(dst_1.get_mask_register() | dst_2.get_mask_register())

    ctx.f_asm.xor(dst_1, dst_2)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = changes_regflags

    ctx.f_asm.xor(dst_2, dst_1)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = changes_regflags

    ctx.f_asm.xor(dst_1, dst_2)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = changes_regflags

    trace.info("xchg dst_1, dst_2 -> xor dst_1, dst_2; xor dst_2, dst_1, xor dst_1, dst_2")
    return True

# mov somereg_1, dst_1
# mov somereg_2, dst_2
# mov dst_1, somereg_2
# mov dst_2, somereg_1
def _xchg_64_multi_tmpl_2(ctx: FukuMutationCtx, dst_1: FukuType, dst_2: FukuType, inst_size: int) -> bool:
    additation_inst_flag = 0

    if dst_1.type == FukuT0Types.FUKU_T0_OPERAND:
        if dst_1.operand.base.index == FukuRegisterIndex.SP or dst_1.operand.index.index == FukuRegisterIndex.SP:
            additation_inst_flag = FukuInstFlags.FUKU_INST_BAD_STACK
    else:
        if dst_1.register.index == FukuRegisterIndex.SP:
            additation_inst_flag = FukuInstFlags.FUKU_INST_BAD_STACK

    if dst_2.operand.base.index == FukuRegisterIndex.SP:
        additation_inst_flag = FukuInstFlags.FUKU_INST_BAD_STACK

    out_regflags = ctx.cpu_registers & ~(dst_1.get_mask_register() | dst_2.get_mask_register())

    somereg_1 = FukuType.get_random_operand_dst_x64(
        AllowInstruction.REGISTER.value, inst_size, changes_regflags,
        FlagRegister.SP.value |
        FlagRegister.ESP.value
    )

    if not somereg_1:
        return False

    out_regflags &= ~(somereg_1.get_mask_register())

    somereg_2 = FukuType.get_random_operand_dst_x64(
        AllowInstruction.REGISTER.value, inst_size, changes_regflags,
        FlagRegister.SP.value |
        FlagRegister.ESP.value
    )

    if not somereg_2:
        return False

    out_regflags &= ~(somereg_2.get_mask_register())
    inst: FukuInst = ctx.payload_inst_iter.peek()

    ctx.f_asm.mov(somereg_1, dst_1)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags
    ctx.f_asm.context.inst.flags.inst_flags = additation_inst_flag
    ctx.restore_disp_relocate(dst_1, inst.disp_reloc, inst.flags.inst_used_disp)

    ctx.f_asm.mov(somereg_2, dst_2)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags
    ctx.f_asm.context.inst.flags.inst_flags = additation_inst_flag

    ctx.f_asm.mov(dst_1, somereg_2)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags
    ctx.f_asm.context.inst.flags.inst_flags = additation_inst_flag
    ctx.restore_disp_relocate(dst_1, inst.disp_reloc, inst.flags.inst_used_disp)

    ctx.f_asm.mov(dst_2, somereg_1)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags
    ctx.f_asm.context.inst.flags.inst_flags = additation_inst_flag

    return True

def _xchg_64_op_reg_tmpl(ctx: FukuMutationCtx) -> bool:
    pass
