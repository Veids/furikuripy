from common import trace
from random import randint
from capstone import x86_const

from fuku_misc import FukuInstFlags
from fuku_inst import FukuInst, FukuRipRelocation, FukuCodeLabel
from x86.misc import FukuOperandSize, FukuCondition
from x86.fuku_type import FukuType, FukuT0Types
from x86.fuku_register import FukuRegister, FukuRegisterEnum
from x86.fuku_immediate import FukuImmediate
from x86.fuku_mutation_ctx import FukuMutationCtx
from x86.fuku_register_math_metadata import ODI_FL_JCC

# inverted jcc to inst after real jcc
# jmp jcc_dst
def _jcc_64_multi_tmpl_1(ctx: FukuMutationCtx, dst: FukuType, inst_size: int) -> bool:
    if ctx.is_next_last_inst:
        return False

    inst: FukuInst = ctx.payload_inst_iter.peek()
    cond: FukuCondition = FukuCondition.from_capstone(ctx.instruction.id)

    ctx.f_asm.jcc(FukuCondition(cond.value ^ 1), FukuImmediate(immediate_value = 0xFFFFFFFF).ftype)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    ctx.f_asm.context.inst.rip_reloc = ctx.code_holder.create_relocation(
        FukuRipRelocation(
            label = ctx.code_holder.create_label(
                FukuCodeLabel(
                    inst = ctx.next_inst_iter.peek()
                )
            ),
            offset = ctx.f_asm.context.immediate_offset
        )
    )
    ctx.f_asm.context.inst.flags.inst_flags = ctx.inst_flags | FukuInstFlags.FUKU_INST_NO_MUTATE.value

    ctx.f_asm.jmp(FukuImmediate(immediate_value = 0xFFFFFFFF).ftype)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    ctx.f_asm.context.inst.flags.inst_flags = ctx.inst_flags | FukuInstFlags.FUKU_INST_NO_MUTATE.value

    ctx.restore_rip_relocate_in_imm(dst, inst.rip_reloc, inst.flags.inst_used_disp, inst_size)

    trace.info("jcc dst -> ^jcc inst_after_real_jcc; jmp dst")
    return True

def _jcc_64_imm_tmpl(ctx: FukuMutationCtx) -> bool:
    imm_src = FukuImmediate(immediate_value = ctx.instruction.operands[0].imm)
    return _jcc_64_multi_tmpl_1(ctx, imm_src.ftype, ctx.instruction.operands[0].size)

def fukutate_64_jcc(ctx: FukuMutationCtx) -> bool:
    return _jcc_64_imm_tmpl(ctx)
