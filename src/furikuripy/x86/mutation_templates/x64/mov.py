from capstone import x86_const

from furikuripy.common import rng, trace_inst
from furikuripy.x86.misc import FukuOperandSize
from furikuripy.x86.fuku_type import FukuType, FukuT0Types
from furikuripy.x86.fuku_operand import FukuOperand
from furikuripy.x86.fuku_register import (
    FukuRegister,
    FukuRegisterEnum,
    FukuRegisterIndex,
)
from furikuripy.x86.fuku_immediate import FukuImmediate
from furikuripy.x86.fuku_mutation_ctx import FukuMutationCtx
from furikuripy.x86.fuku_register_math import has_free_eflags
from furikuripy.x86.fuku_register_math_metadata import AllowInstruction, FlagRegister


# mov somereg, src
# xchg dst, somereg
def _mov_64_multi_tmpl_1(
    ctx: FukuMutationCtx, dst: FukuType, src: FukuType, inst_size: int
) -> bool:
    changes_regflags = ctx.cpu_registers & ~(
        dst.get_mask_register() | src.get_mask_register()
    )

    somereg = FukuType.get_random_operand_dst_x64(
        AllowInstruction.REGISTER.value,
        inst_size,
        changes_regflags,
        FlagRegister.SP.value | FlagRegister.ESP.value | FlagRegister.RSP.value,
    )

    if not somereg:
        return False

    opcodes = []
    disp_reloc = ctx.payload_inst.disp_reloc
    imm_reloc = ctx.payload_inst.imm_reloc
    out_regflags = changes_regflags & ~(
        somereg.register.get_flag_complex(FukuOperandSize.SIZE_64)
    )

    ctx.f_asm.mov(somereg, src)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    ctx.restore_imm_or_disp(src, disp_reloc, imm_reloc, inst_size)
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.xchg(dst, somereg)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags
    ctx.restore_disp_relocate(src, disp_reloc)
    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("mov dst, src -> mov somereg, src; xchg dst, somereg", opcodes, ctx)
    return True


# xor dst, dst
# add dst, src
def _mov_64_multi_tmpl_2(
    ctx: FukuMutationCtx, dst: FukuType, src: FukuType, inst_size: int
) -> bool:
    if not has_free_eflags(
        ctx.cpu_flags,
        x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_CF
        | x86_const.X86_EFLAGS_MODIFY_PF,
    ):
        return False

    # mov rax, gs:[eax]
    if (
        src.type == FukuT0Types.FUKU_T0_OPERAND
        and dst.type == FukuT0Types.FUKU_T0_REGISTER
        and (
            dst.register.index == src.register.index
            or dst.register.index == src.index.index
        )
    ):
        return False

    opcodes = []
    out_regflags = ctx.cpu_registers & ~(
        dst.get_mask_register() | src.get_mask_register()
    )

    ctx.f_asm.xor(dst, dst)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    opcodes.append(ctx.f_asm.context.inst.opcode)

    try:
        ctx.f_asm.add(dst, src)
        ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
        ctx.f_asm.context.inst.cpu_registers = out_regflags
        opcodes.append(ctx.f_asm.context.inst.opcode)
    except AssertionError:
        from IPython import embed

        embed()
        exit(0)

    trace_inst("mov dst, src -> xor dst, dst; add dst, src", opcodes, ctx)
    return True


# push src
# pop randreg
# mov dst, randreg
def _mov_64_multi_tmpl_3(
    ctx: FukuMutationCtx, dst: FukuType, src: FukuType, inst_size: int
) -> bool:
    if (
        not ctx.is_allowed_stack_operations
        or inst_size == FukuOperandSize.SIZE_8.value
        or (
            src.type == FukuT0Types.FUKU_T0_IMMEDIATE
            and inst_size != FukuOperandSize.SIZE_32.value
        )
    ):
        return False

    if (
        dst.register.index == FukuRegisterIndex.INDEX_SP
        if dst.type == FukuT0Types.FUKU_T0_REGISTER
        else False
    ) or (
        src.register.index == FukuRegisterIndex.INDEX_SP
        if src.type == FukuT0Types.FUKU_T0_REGISTER
        else False
    ):
        return False

    opcodes = []
    disp_reloc = ctx.payload_inst.disp_reloc
    imm_reloc = ctx.payload_inst.imm_reloc
    out_regflags = ctx.cpu_registers & ~(
        dst.get_mask_register() | src.get_mask_register()
    )

    if inst_size != FukuOperandSize.SIZE_64.value:
        randreg = FukuType.get_random_operand_dst_x64(
            AllowInstruction.REGISTER.value,
            inst_size,
            out_regflags,
            FlagRegister.SP.value | FlagRegister.ESP.value | FlagRegister.RSP.value,
        )

        if not randreg:
            return False

        out_regflags = out_regflags & ~(randreg.get_mask_register())

        ctx.f_asm.push(src)
        ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
        ctx.f_asm.context.inst.cpu_registers = out_regflags
        ctx.restore_imm_or_disp(src, disp_reloc, imm_reloc, inst_size)
        opcodes.append(ctx.f_asm.context.inst.opcode)

        ctx.f_asm.pop(randreg)
        ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
        ctx.f_asm.context.inst.cpu_registers = out_regflags
        opcodes.append(ctx.f_asm.context.inst.opcode)

        ctx.f_asm.mov(dst, randreg)
        ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
        ctx.f_asm.context.inst.cpu_registers = out_regflags
        ctx.restore_disp_relocate(dst, disp_reloc)
        opcodes.append(ctx.f_asm.context.inst.opcode)
        trace_inst(
            "mov dst, src -> push src; pop rand_reg; mov dst, rand_reg", opcodes, ctx
        )
    else:
        ctx.f_asm.push(src)
        ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
        ctx.f_asm.context.inst.cpu_registers = out_regflags
        ctx.restore_imm_or_disp(src, disp_reloc, imm_reloc, inst_size)
        opcodes.append(ctx.f_asm.context.inst.opcode)

        ctx.f_asm.pop(dst)
        ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
        ctx.f_asm.context.inst.cpu_registers = out_regflags
        ctx.restore_disp_relocate(dst, disp_reloc)
        opcodes.append(ctx.f_asm.context.inst.opcode)
        trace_inst("mov dst, src -> push src; pop dst", opcodes, ctx)

    return True


# xor dst, dst
# add dst, imm_0
# add dst, imm_1
# add dst, imm_2
def _mov_64_reg_imm_tmpl_1(ctx, dst: FukuType, src: FukuType, inst_size: int) -> bool:
    if not has_free_eflags(
        ctx.cpu_flags,
        x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_MODIFY_AF
        | x86_const.X86_EFLAGS_MODIFY_CF
        | x86_const.X86_EFLAGS_MODIFY_PF,
    ):
        return False

    # mov rax, gs:[eax]
    if (
        src.type == FukuT0Types.FUKU_T0_OPERAND
        and dst.type == FukuT0Types.FUKU_T0_REGISTER
        and (
            dst.register.index == src.register.index
            or dst.register.index == src.index.index
        )
    ):
        return False

    opcodes = []
    out_regflags = ctx.cpu_registers & ~(dst.get_mask_register())

    ctx.f_asm.xor(dst, dst)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = out_regflags
    opcodes.append(ctx.f_asm.context.inst.opcode)

    max_parts = rng.randint(2, 7)
    parts_added = 0
    imm_val_left = src.disp.immediate_value
    while parts_added != max_parts and imm_val_left:
        imm_val = rng.randint(1, imm_val_left)
        if max_parts - 1 == parts_added:
            imm_val = imm_val_left
        imm_val_left -= imm_val

        ctx.f_asm.add(dst, FukuImmediate(imm_val).ftype)
        ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
        ctx.f_asm.context.inst.cpu_registers = out_regflags
        opcodes.append(ctx.f_asm.context.inst.opcode)
        parts_added += 1

    trace_inst(
        "mov dst, src -> xor dst, dst; add dst, imm_0; add dst, imm_1; ...",
        opcodes,
        ctx,
    )
    return True


def _mov_64_reg_reg_tmpl(ctx: FukuMutationCtx) -> bool:
    reg_dst = FukuRegister(
        FukuRegisterEnum.from_capstone(ctx.instruction.operands[0])
    ).ftype
    reg_src = FukuRegister(
        FukuRegisterEnum.from_capstone(ctx.instruction.operands[1])
    ).ftype

    match rng.randint(0, 2):
        case 0:
            return _mov_64_multi_tmpl_1(
                ctx, reg_dst, reg_src, ctx.instruction.operands[0].size
            )

        case 1:
            return _mov_64_multi_tmpl_2(
                ctx, reg_dst, reg_src, ctx.instruction.operands[0].size
            )

        case 2:
            return _mov_64_multi_tmpl_3(
                ctx, reg_dst, reg_src, ctx.instruction.operands[0].size
            )


def _mov_64_reg_imm_tmpl(ctx: FukuMutationCtx) -> bool:
    reg_dst = FukuRegister(
        FukuRegisterEnum.from_capstone(ctx.instruction.operands[0])
    ).ftype
    imm_src = FukuImmediate(ctx.instruction.operands[1].imm).ftype

    match rng.randint(0, 3):
        case 0:
            return _mov_64_multi_tmpl_1(
                ctx, reg_dst, imm_src, ctx.instruction.operands[0].size
            )

        case 1:
            return _mov_64_multi_tmpl_2(
                ctx, reg_dst, imm_src, ctx.instruction.operands[0].size
            )

        case 2:
            return _mov_64_multi_tmpl_3(
                ctx, reg_dst, imm_src, ctx.instruction.operands[0].size
            )

        case 3:
            return _mov_64_reg_imm_tmpl_1(
                ctx, reg_dst, imm_src, ctx.instruction.operands[0].size
            )


def _mov_64_reg_op_tmpl(ctx: FukuMutationCtx) -> bool:
    reg_dst = FukuRegister(
        FukuRegisterEnum.from_capstone(ctx.instruction.operands[0])
    ).ftype
    op_src = FukuOperand.from_capstone(ctx.instruction.operands[1]).ftype

    match rng.randint(0, 2):
        case 0:
            return _mov_64_multi_tmpl_1(
                ctx, reg_dst, op_src, ctx.instruction.operands[0].size
            )

        case 1:
            return _mov_64_multi_tmpl_2(
                ctx, reg_dst, op_src, ctx.instruction.operands[0].size
            )

        case 2:
            return _mov_64_multi_tmpl_3(
                ctx, reg_dst, op_src, ctx.instruction.operands[0].size
            )


def _mov_64_op_reg_tmpl(ctx: FukuMutationCtx) -> bool:
    op_dst = FukuOperand.from_capstone(ctx.instruction.operands[0]).ftype
    reg_src = FukuRegister(
        FukuRegisterEnum.from_capstone(ctx.instruction.operands[1])
    ).ftype

    match rng.randint(0, 1):
        case 0:
            return _mov_64_multi_tmpl_1(
                ctx, op_dst, reg_src, ctx.instruction.operands[0].size
            )

        case 1:
            return _mov_64_multi_tmpl_3(
                ctx, op_dst, reg_src, ctx.instruction.operands[0].size
            )


def _mov_64_op_imm_tmpl(ctx: FukuMutationCtx) -> bool:
    op_dst = FukuOperand.from_capstone(ctx.instruction.operands[0]).ftype
    imm_src = FukuImmediate(ctx.instruction.operands[1].imm).ftype

    match rng.randint(0, 1):
        case 0:
            return _mov_64_multi_tmpl_1(
                ctx, op_dst, imm_src, ctx.instruction.operands[0].size
            )

        case 1:
            return _mov_64_multi_tmpl_3(
                ctx, op_dst, imm_src, ctx.instruction.operands[0].size
            )


def fukutate_64_mov(ctx: FukuMutationCtx) -> bool:
    operands = ctx.instruction.operands
    if operands[0].type == x86_const.X86_OP_REG:
        if operands[1].type == x86_const.X86_OP_REG:  # mov reg, reg
            return _mov_64_reg_reg_tmpl(ctx)
        elif operands[1].type == x86_const.X86_OP_IMM:  # mov reg, imm
            return _mov_64_reg_imm_tmpl(ctx)
        elif operands[1].type == x86_const.X86_OP_MEM:  # mov reg, [op]
            return _mov_64_reg_op_tmpl(ctx)
    elif operands[0].type == x86_const.X86_OP_MEM:
        if operands[1].type == x86_const.X86_OP_REG:  # mov [op], reg
            return _mov_64_op_reg_tmpl(ctx)
        elif operands[1].type == x86_const.X86_OP_IMM:  # mov [op], imm
            return _mov_64_op_imm_tmpl(ctx)

    return False
