from common import trace
from random import randint
from capstone import x86_const

from fuku_misc import FukuInstFlags
from fuku_inst import FukuInst, FukuRipRelocation, FukuCodeLabel
from x86.misc import FukuOperandSize, FukuCondition
from x86.fuku_operand import FukuOperand
from x86.fuku_type import FukuType, FukuT0Types
from x86.fuku_register import FukuRegister, FukuRegisterEnum
from x86.fuku_immediate import FukuImmediate
from x86.fuku_mutation_ctx import FukuMutationCtx
from x86.fuku_register_math_metadata import ODI_FL_JCC

# lea rsp, [rsp + (8 + stack_offset)]
# jmp [rsp - 8 - stack_offset]
def _ret_64_multi_tmpl_1(ctx: FukuMutationCtx, ret_stack: int) -> bool:
    ctx.f_asm.lea(
            FukuRegister(FukuRegisterEnum.FUKU_REG_RSP).ftype,
            qword_ptr(
                base = FukuRegister(FukuRegisterEnum.FUKU_REG_RSP),
                disp = FukuImmediate(immediate_value = 8 + ret_stack)
            ).ftype
    )
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers

    ctx.f_asm.jmp(
        qword_ptr(
            base = FukuRegister(FukuRegisterEnum.FUKU_REG_RSP),
            disp = FukuImmediate(immediate_value = -8 - ret_stack)
        ).ftype
    )
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    cts.f_asm.context.inst.flags.inst_flags = FukuInstFlags.FUKU_INST_BAD_STACK

    trace.info("ret -> lea rsp, [rsp + (8 + stack_offset)]; jmp [rsp - 8 - stack_offset]")
    return True

def _ret_64_imm_tmpl(ctx: FukuMutationCtx) -> bool:
    ret_stack = 0
    
    if len(ctx.instruction.operands):
        ret_stack = ctx.instruction.operands[0].imm

    return _ret_64_multi_tmpl_1(ctx, ret_stack)

def fukutate_64_ret(ctx: FukuMutationCtx) -> bool:
    return _ret_64_imm_tmpl(ctx)
