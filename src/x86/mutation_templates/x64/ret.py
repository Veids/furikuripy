from common import trace_inst
from fuku_misc import FukuInstFlags
from x86.fuku_operand import qword_ptr
from x86.fuku_register import FukuRegister, FukuRegisterEnum
from x86.fuku_immediate import FukuImmediate
from x86.fuku_mutation_ctx import FukuMutationCtx

# lea rsp, [rsp + (8 + stack_offset)]
# jmp [rsp - 8 - stack_offset]
def _ret_64_multi_tmpl_1(ctx: FukuMutationCtx, ret_stack: int) -> bool:
    opcodes = []

    ctx.f_asm.lea(
        FukuRegister(FukuRegisterEnum.FUKU_REG_RSP).ftype,
        qword_ptr(
            base = FukuRegister(FukuRegisterEnum.FUKU_REG_RSP),
            disp = FukuImmediate(8 + ret_stack)
        ).ftype
    )
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.jmp(
        qword_ptr(
            base = FukuRegister(FukuRegisterEnum.FUKU_REG_RSP),
            disp = FukuImmediate(-8 - ret_stack)
        ).ftype
    )
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    ctx.f_asm.context.inst.flags.inst_flags = FukuInstFlags.FUKU_INST_BAD_STACK.value
    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("ret -> lea rsp, [rsp + (8 + stack_offset)]; jmp [rsp - 8 - stack_offset]", opcodes)
    return True


def _ret_64_imm_tmpl(ctx: FukuMutationCtx) -> bool:
    ret_stack = 0

    if len(ctx.instruction.operands):
        ret_stack = ctx.instruction.operands[0].imm

    return _ret_64_multi_tmpl_1(ctx, ret_stack)


def fukutate_64_ret(ctx: FukuMutationCtx) -> bool:
    return _ret_64_imm_tmpl(ctx)
