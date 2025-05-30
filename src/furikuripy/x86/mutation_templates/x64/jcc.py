from furikuripy.common import trace_inst
from furikuripy.fuku_misc import FukuInstFlags
from furikuripy.fuku_inst import FukuRipRelocation, FukuCodeLabel
from furikuripy.x86.misc import FukuCondition
from furikuripy.x86.fuku_type import FukuType
from furikuripy.x86.fuku_immediate import FukuImmediate
from furikuripy.x86.fuku_mutation_ctx import FukuMutationCtx


# inverted jcc to inst after real jcc
# jmp jcc_dst
def _jcc_64_multi_tmpl_1(ctx: FukuMutationCtx, dst: FukuType, inst_size: int) -> bool:
    if ctx.is_next_last_inst:
        return False

    opcodes = []
    rip_reloc = ctx.payload_inst.rip_reloc
    cond: FukuCondition = FukuCondition.from_capstone(ctx.instruction.id)

    ctx.f_asm.jcc(FukuCondition(cond.value ^ 1), FukuImmediate(0xFFFFFFFF).ftype)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    ctx.f_asm.context.inst.rip_reloc = ctx.code_holder.create_rip_relocation(
        FukuRipRelocation(
            label=ctx.code_holder.create_label(FukuCodeLabel(inst=ctx.next_inst)),
            offset=ctx.f_asm.context.immediate_offset,
        )
    )
    ctx.f_asm.context.inst.flags = ctx.inst_flags | FukuInstFlags.FUKU_INST_NO_MUTATE
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.jmp(FukuImmediate(0xFFFFFFFF).ftype)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    ctx.f_asm.context.inst.flags = ctx.inst_flags | FukuInstFlags.FUKU_INST_NO_MUTATE
    ctx.restore_rip_relocate_in_imm(dst, rip_reloc, inst_size)
    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("jcc dst -> ^jcc inst_after_real_jcc; jmp dst", opcodes, ctx)
    return True


def _jcc_64_imm_tmpl(ctx: FukuMutationCtx) -> bool:
    imm_src = FukuImmediate(ctx.instruction.operands[0].imm)
    return _jcc_64_multi_tmpl_1(ctx, imm_src.ftype, ctx.instruction.operands[0].size)


def fukutate_64_jcc(ctx: FukuMutationCtx) -> bool:
    return _jcc_64_imm_tmpl(ctx)
