from capstone import x86_const

from furikuripy.common import rng, trace_inst
from furikuripy.fuku_misc import FukuInstFlags
from furikuripy.x86.misc import FukuOperandSize
from furikuripy.x86.fuku_operand import FukuOperand, qword_ptr
from furikuripy.x86.fuku_type import FukuType, FukuT0Types
from furikuripy.x86.fuku_register import FukuRegister, FukuRegisterEnum, FukuRegisterIndex
from furikuripy.x86.fuku_immediate import FukuImmediate
from furikuripy.x86.fuku_mutation_ctx import FukuMutationCtx
from furikuripy.x86.fuku_register_math import has_free_eflags


# (sub esp,4) or (lea esp,[esp - 4])
# mov [esp],reg
def _push_64_multi_tmpl_1(ctx: FukuMutationCtx, src: FukuType, inst_size: int) -> bool:
    if src.type == FukuT0Types.FUKU_T0_REGISTER and src.register.index == FukuRegisterIndex.INDEX_SP:
        return False

    opcodes = []
    disp_reloc = ctx.payload_inst.disp_reloc
    out_regflags = ctx.cpu_registers & ~(src.get_mask_register())

    if has_free_eflags(
        ctx.cpu_flags,
        x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
        x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
        x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_MODIFY_PF
    ):
        ctx.f_asm.sub(FukuRegister(FukuRegisterEnum.REG_RSP).ftype, FukuImmediate(inst_size).ftype)
        ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
        ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    else:
        ctx.f_asm.lea(
            FukuRegister(FukuRegisterEnum.REG_RSP).ftype,
            qword_ptr(
                base = FukuRegister(FukuRegisterEnum.REG_RSP),
                disp = FukuImmediate(-inst_size))
            .ftype
        )
        ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
        ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers

    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.mov(
        FukuOperand(
            base = FukuRegister(FukuRegisterEnum.REG_RSP),
            size = FukuOperandSize(inst_size)
        ).ftype,
        src
    )
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags
    ctx.restore_disp_relocate(src, disp_reloc)
    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("push src -> sub rsp, 8 or lea rsp, [rsp, 8]; mov [rsp], reg", opcodes)
    return True

# mov [esp - 4],reg
# (sub esp,4) or (lea esp,[esp - 4])
def _push_64_multi_tmpl_2(ctx: FukuMutationCtx, src: FukuType, inst_size: int) -> bool:
    if ctx.settings.is_not_allowed_unstable_stack:
        return False

    if src.type == FukuT0Types.FUKU_T0_REGISTER and src.register.index == FukuRegisterIndex.INDEX_SP:
        return False

    opcodes = []
    disp_reloc = ctx.payload_inst.disp_reloc

    ctx.f_asm.mov(
        FukuOperand(
            base = FukuRegister(FukuRegisterEnum.REG_RSP),
            disp = FukuImmediate(-inst_size),
            size = FukuOperandSize(inst_size)
        ).ftype,
        src
    )
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    out_regflags = ctx.cpu_registers & ~(src.get_mask_register())
    ctx.restore_disp_relocate(src, disp_reloc)
    opcodes.append(ctx.f_asm.context.inst.opcode)

    if has_free_eflags(
        ctx.cpu_flags,
        x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
        x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
        x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_MODIFY_PF
    ):
        ctx.f_asm.sub(FukuRegister(FukuRegisterEnum.REG_RSP).ftype, FukuImmediate(inst_size).ftype)
        ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
        ctx.f_asm.context.inst.cpu_registers = out_regflags
        ctx.f_asm.context.inst.flags = FukuInstFlags.FUKU_INST_BAD_STACK
    else:
        ctx.f_asm.lea(
            FukuRegister(FukuRegisterEnum.REG_RSP).ftype,
            qword_ptr(
                base = FukuRegister(FukuRegisterEnum.REG_RSP),
                disp = FukuImmediate(immediate_value=-inst_size))
            .ftype
        )
        ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
        ctx.f_asm.context.inst.cpu_registers = out_regflags
        ctx.f_asm.context.inst.flags = FukuInstFlags.FUKU_INST_BAD_STACK

    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("push src -> mov [rsp - 8], reg; sub rsp, 8 or lea rsp, [rsp, 8]", opcodes)
    return True

def _push_64_imm_tmpl(ctx: FukuMutationCtx) -> bool:
    imm_src = FukuImmediate(ctx.instruction.operands[0].imm).ftype

    match rng.randint(0, 1):
        case 0:
            return _push_64_multi_tmpl_1(ctx, imm_src, ctx.instruction.operands[0].size)

        case 1:
            return _push_64_multi_tmpl_2(ctx, imm_src, ctx.instruction.operands[0].size)

def _push_64_reg_tmpl(ctx: FukuMutationCtx) -> bool:
    reg_src = FukuRegister.from_capstone(ctx.instruction.operands[0]).ftype

    match rng.randint(0, 1):
        case 0:
            return _push_64_multi_tmpl_1(ctx, reg_src, ctx.instruction.operands[0].size)

        case 1:
            return _push_64_multi_tmpl_2(ctx, reg_src, ctx.instruction.operands[0].size)

def fukutate_64_push(ctx: FukuMutationCtx) -> bool:
    match ctx.instruction.operands[0].type:
        case x86_const.X86_OP_REG:
            return _push_64_reg_tmpl(ctx)

        case x86_const.X86_OP_IMM:
            return _push_64_imm_tmpl(ctx)

    return False
