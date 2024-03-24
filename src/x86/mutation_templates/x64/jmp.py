from capstone import x86_const

from common import rng, trace_inst
from fuku_misc import FukuInstFlags
from fuku_inst import FukuRipRelocation
from x86.misc import FukuOperandSize, FukuCondition
from x86.fuku_operand import FukuOperand
from x86.fuku_type import FukuType, FukuT0Types
from x86.fuku_register import FukuRegister, FukuRegisterEnum
from x86.fuku_immediate import FukuImmediate
from x86.fuku_mutation_ctx import FukuMutationCtx
from x86.fuku_register_math_metadata import ODI_FL_JCC

# push dst
# ret
def _jmp_64_multi_tmpl_1(ctx: FukuMutationCtx, src: FukuType) -> bool:
    if ctx.settings.is_not_allowed_relocations:
        return False

    if src.type == FukuT0Types.FUKU_T0_IMMEDIATE:
        return False

    if not ctx.is_allowed_stack_operations:
        return False

    opcodes = []
    disp_reloc = ctx.payload_inst.disp_reloc

    ctx.f_asm.push(src)
    ctx.restore_disp_relocate(src, disp_reloc)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.ret(FukuImmediate().ftype)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("jmp dst -> push dst; ret", opcodes)
    return True

# je dst
# jne dst
def _jmp_64_multi_tmpl_2(ctx: FukuMutationCtx, src: FukuType) -> bool:
    if src.type != FukuT0Types.FUKU_T0_IMMEDIATE:
        return False

    opcodes = []
    rip_reloc = ctx.payload_inst.rip_reloc

    cond = rng.randint(0, 15)
    ctx.f_asm.jcc(FukuCondition(cond), FukuImmediate(0xFFFFFFFF).ftype)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    ctx.f_asm.context.inst.rip_reloc = ctx.code_holder.create_rip_relocation(
        FukuRipRelocation(
            label = rip_reloc.label,
            offset = ctx.f_asm.context.immediate_offset
        )
    )
    ctx.f_asm.context.inst.flags = ctx.inst_flags | FukuInstFlags.FUKU_INST_NO_MUTATE
    opcodes.append(ctx.f_asm.context.inst.opcode)

    rev_cond = FukuCondition(cond ^ 1)
    ctx.f_asm.jcc(rev_cond, FukuImmediate(0xFFFFFFFF).ftype)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags & (~ODI_FL_JCC[rev_cond.value])
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    ctx.f_asm.context.inst.rip_reloc = ctx.code_holder.create_rip_relocation(
        FukuRipRelocation(
            label = rip_reloc.label,
            offset = ctx.f_asm.context.immediate_offset
        )
    )
    ctx.f_asm.context.inst.flags = ctx.inst_flags | FukuInstFlags.FUKU_INST_NO_MUTATE
    opcodes.append(ctx.f_asm.context.inst.opcode)

    rip_reloc.label = None
    ctx.code_holder.rip_relocations.remove(rip_reloc)

    trace_inst("jmp dst -> je dst; jne dst", opcodes)
    return True

# mov randreg, dst
# jmp randreg
def _jmp_64_multi_tmpl_3(ctx: FukuMutationCtx, src: FukuType) -> bool:
    if ctx.settings.is_not_allowed_relocations:
        return False

    rand_reg: FukuRegister = FukuRegister(
        FukuRegisterEnum.get_random_free_register(
            ctx.cpu_registers,
            FukuOperandSize.SIZE_64,
            True
        )
    )

    if rand_reg.reg == FukuRegisterEnum.REG_NONE:
        return False

    opcodes = []
    disp_reloc = ctx.payload_inst.disp_reloc
    rip_reloc = ctx.payload_inst.rip_reloc
    out_regflags = ctx.cpu_registers & ~(rand_reg.ftype.get_mask_register() | src.get_mask_register())

    if src.type == FukuT0Types.FUKU_T0_IMMEDIATE:
        ctx.f_asm.mov(rand_reg.ftype, FukuImmediate(0xFFFFFFFFFFFFFFFF).ftype)
        ctx.restore_rip_to_imm_relocate(src, rip_reloc)
    else:
        ctx.f_asm.mov(rand_reg.ftype, src)
        ctx.restore_disp_relocate(src, disp_reloc)

    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.jmp(rand_reg.ftype)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags
    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("jmp dst -> mov randreg, dst; jmp randreg", opcodes)
    return True

def _jmp_64_reg_tmpl(ctx: FukuMutationCtx) -> bool:
    reg_src: FukuRegister = FukuRegister(FukuRegisterEnum.from_capstone(ctx.instruction.operands[0]))

    match rng.randint(0, 1):
        case 0:
            return _jmp_64_multi_tmpl_1(ctx, reg_src.ftype)

        case 1:
            return _jmp_64_multi_tmpl_3(ctx, reg_src.ftype)

def _jmp_64_op_tmpl(ctx: FukuMutationCtx) -> bool:
    op_src: FukuOperand = FukuOperand.from_capstone(ctx.instruction.operands[0])

    match rng.randint(0, 1):
        case 0:
            return _jmp_64_multi_tmpl_1(ctx, op_src.ftype)

        case 1:
            return _jmp_64_multi_tmpl_3(ctx, op_src.ftype)

def _jmp_64_imm_tmpl(ctx: FukuMutationCtx) -> bool:
    imm_src = FukuImmediate(ctx.instruction.operands[0].imm)

    match rng.randint(0, 1):
        case 0:
            return _jmp_64_multi_tmpl_2(ctx, imm_src.ftype)

        case 1:
            return _jmp_64_multi_tmpl_3(ctx, imm_src.ftype)

def fukutate_64_jmp(ctx: FukuMutationCtx) -> bool:
    op0_t = ctx.instruction.operands[0].type

    match op0_t:
        case x86_const.X86_OP_REG:
            return _jmp_64_reg_tmpl(ctx)

        case x86_const.X86_OP_MEM:
            return _jmp_64_op_tmpl(ctx)

        case x86_const.X86_OP_IMM:
            return _jmp_64_imm_tmpl(ctx)

    return False
