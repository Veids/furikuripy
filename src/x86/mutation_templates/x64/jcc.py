from common import trace_inst
from fuku_misc import FukuInstFlags
from fuku_inst import FukuRipRelocation, FukuCodeLabel
from x86.misc import FukuCondition
from x86.fuku_type import FukuType
from x86.fuku_immediate import FukuImmediate
from x86.fuku_mutation_ctx import FukuMutationCtx

# inverted jcc to inst after real jcc
# jmp jcc_dst
def _jcc_64_multi_tmpl_1(ctx: FukuMutationCtx, dst: FukuType, inst_size: int) -> bool:
    if ctx.is_next_last_inst:
        return False

    opcodes = []
    rip_reloc = ctx.payload_inst.rip_reloc
    inst_used_disp = ctx.payload_inst.flags.inst_used_disp
    cond: FukuCondition = FukuCondition.from_capstone(ctx.instruction.id)

    ctx.f_asm.jcc(FukuCondition(cond.value ^ 1), FukuImmediate(0xFFFFFFFF).ftype)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    ctx.f_asm.context.inst.rip_reloc = ctx.code_holder.create_rip_relocation(
        FukuRipRelocation(
            label = ctx.code_holder.create_label(
                FukuCodeLabel(
                    inst = ctx.next_inst
                )
            ),
            offset = ctx.f_asm.context.immediate_offset
        )
    )
    ctx.f_asm.context.inst.flags.inst_flags = ctx.inst_flags | FukuInstFlags.FUKU_INST_NO_MUTATE.value
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.jmp(FukuImmediate(0xFFFFFFFF).ftype)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    ctx.f_asm.context.inst.flags.inst_flags = ctx.inst_flags | FukuInstFlags.FUKU_INST_NO_MUTATE.value
    ctx.restore_rip_relocate_in_imm(dst, rip_reloc, inst_used_disp, inst_size)
    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("jcc dst -> ^jcc inst_after_real_jcc; jmp dst", opcodes)
    return True

def _jcc_64_imm_tmpl(ctx: FukuMutationCtx) -> bool:
    imm_src = FukuImmediate(ctx.instruction.operands[0].imm)
    return _jcc_64_multi_tmpl_1(ctx, imm_src.ftype, ctx.instruction.operands[0].size)

def fukutate_64_jcc(ctx: FukuMutationCtx) -> bool:
    return _jcc_64_imm_tmpl(ctx)
