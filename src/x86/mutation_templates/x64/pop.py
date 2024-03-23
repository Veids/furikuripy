from capstone import x86_const

from common import rng, trace_inst
from fuku_misc import FukuInstFlags
from x86.misc import FukuOperandSize
from x86.fuku_operand import FukuOperand, qword_ptr
from x86.fuku_type import FukuType, FukuT0Types
from x86.fuku_register import FukuRegister, FukuRegisterEnum, FukuRegisterIndex
from x86.fuku_immediate import FukuImmediate
from x86.fuku_mutation_ctx import FukuMutationCtx
from x86.fuku_register_math import has_free_eflags


# add rsp,8 or lea rsp, [rsp + 8]
# mov reg, [rsp - 8]
def _pop_64_multi_tmpl_1(ctx: FukuMutationCtx, dst: FukuType, inst_size: int) -> bool:
    if ctx.settings.is_not_allowed_unstable_stack:
        return False

    if dst.type == FukuT0Types.FUKU_T0_REGISTER and dst.register.index == FukuRegisterIndex.INDEX_SP:
        return False

    opcodes = []
    disp_reloc = ctx.payload_inst.disp_reloc
    inst_used_disp = ctx.payload_inst.flags.inst_used_disp

    if has_free_eflags(
        ctx.cpu_flags,
        x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
        x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
        x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_MODIFY_PF
    ):
        ctx.f_asm.add(FukuRegister(FukuRegisterEnum.REG_RSP).ftype, FukuImmediate(inst_size).ftype)
        ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
        ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    else:
        ctx.f_asm.lea(
            FukuRegister(FukuRegisterEnum.REG_RSP).ftype,
            qword_ptr(
                base = FukuRegister(FukuRegisterEnum.REG_RSP),
                disp = FukuImmediate(inst_size))
            .ftype
        )
        ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
        ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers

    opcodes.append(ctx.f_asm.context.inst.opcode)
    out_regflags = ctx.cpu_registers & ~(dst.get_mask_register())

    ctx.f_asm.mov(
        dst,
        FukuOperand(
            base = FukuRegister(FukuRegisterEnum.REG_RSP),
            disp = FukuImmediate(-inst_size),
            size = FukuOperandSize(inst_size)
        ).ftype
    )
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags
    ctx.f_asm.context.inst.flags.inst_flags = FukuInstFlags.FUKU_INST_BAD_STACK.value
    ctx.restore_disp_relocate(dst, disp_reloc, inst_used_disp)
    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("pop dst -> add rsp, 8 or lea rsp, [rsp + 8]; mov reg, [rsp - 8]", opcodes)
    return True


# mov reg, [rsp]
# add rsp, 8 or lea rsp, [rsp + 8]
def _pop_64_multi_tmpl_2(ctx: FukuMutationCtx, dst: FukuType, inst_size: int) -> bool:
    if dst.type == FukuT0Types.FUKU_T0_REGISTER and dst.register.index == FukuRegisterIndex.INDEX_SP:
        return False

    opcodes = []
    disp_reloc = ctx.payload_inst.disp_reloc
    inst_used_disp = ctx.payload_inst.flags.inst_used_disp

    ctx.f_asm.mov(
        dst, 
        FukuOperand(
            base = FukuRegister(FukuRegisterEnum.REG_RSP),
            size = FukuOperandSize(inst_size)
        ).ftype,
    )
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    ctx.restore_disp_relocate(dst, disp_reloc, inst_used_disp)
    opcodes.append(ctx.f_asm.context.inst.opcode)

    out_regflags = ctx.cpu_registers & ~(dst.get_mask_register())

    if has_free_eflags(
        ctx.cpu_flags,
        x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
        x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
        x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_MODIFY_PF
    ):
        ctx.f_asm.add(FukuRegister(FukuRegisterEnum.REG_RSP).ftype, FukuImmediate(inst_size).ftype)
        ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
        ctx.f_asm.context.inst.cpu_registers = out_regflags
    else:
        ctx.f_asm.lea(
            FukuRegister(FukuRegisterEnum.REG_RSP).ftype,
            qword_ptr(
                base = FukuRegister(FukuRegisterEnum.REG_RSP),
                disp = FukuImmediate(inst_size))
            .ftype
        )
        ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
        ctx.f_asm.context.inst.cpu_registers = out_regflags

    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("pop dst -> mov reg, [rsp]; add rsp, 8 or lea rsp, [rsp + 8]", opcodes)
    return True

def _pop_64_reg_tmpl(ctx: FukuMutationCtx) -> bool:
    reg_dst = FukuRegister.from_capstone(ctx.instruction.operands[0]).ftype

    match rng.randint(0, 1):
        case 0:
            return _pop_64_multi_tmpl_1(ctx, reg_dst, ctx.instruction.operands[0].size)

        case 1:
            return _pop_64_multi_tmpl_2(ctx, reg_dst, ctx.instruction.operands[0].size)

def fukutate_64_pop(ctx: FukuMutationCtx) -> bool:
    match ctx.instruction.operands[0].type:
        case x86_const.X86_OP_REG:
            return _pop_64_reg_tmpl(ctx)

    return False
