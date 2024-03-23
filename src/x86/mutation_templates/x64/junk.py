from capstone import x86_const

from common import rng, trace_inst
from fuku_misc import FukuInstFlags
from fuku_inst import FukuRipRelocation
from x86.misc import FukuOperandSize, FukuCondition
from x86.fuku_type import FukuType, FukuT0Types
from x86.fuku_register import FukuRegister, FukuRegisterEnum
from x86.fuku_immediate import FukuImmediate
from x86.fuku_mutation_ctx import FukuMutationCtx
from x86.fuku_register_math import has_free_eflags, has_flag_free_register
from x86.fuku_register_math_metadata import AllowInstruction, FlagRegister

REG_SIZES_64 = [1, 2, 4, 8]
REG_SIZES_16_64 = [2, 8]

# transfer reg1, reg2
# transfer reg1, val
def junk_64_low_pattern_1(ctx: FukuMutationCtx) -> bool:
    choice = rng.randint(0, 7)

    match choice:
        case 0:
            reg_size = FukuOperandSize(REG_SIZES_64[rng.randint(0, 2)])

            dst = FukuType.get_random_operand_dst_x64(
                AllowInstruction.REGISTER.value, reg_size, ctx.cpu_registers,
                FlagRegister.SPL.value | FlagRegister.SP.value |
                FlagRegister.ESP.value | FlagRegister.RSP.value
            )

            if not dst:
                return False

            src = FukuType.get_random_operand_src_x64(
                AllowInstruction.REGISTER.value | AllowInstruction.IMMEDIATE.value |
                (0 if dst.type == FukuT0Types.FUKU_T0_OPERAND else AllowInstruction.OPERAND.value),
                reg_size,
                0
            )

            if not src:
                return False

            ctx.f_asm.mov(dst, src)
            trace_inst("junk: mov dst, src", [ctx.f_asm.context.inst.opcode])

        case 1:
            dst = FukuType.get_random_operand_dst_x64(
                AllowInstruction.REGISTER.value | AllowInstruction.OPERAND.value,
                FukuOperandSize.SIZE_8,
                ctx.cpu_registers,
                FlagRegister.SPL.value | FlagRegister.SP.value |
                FlagRegister.ESP.value | FlagRegister.RSP.value
            )

            if not dst:
                return False

            ctx.f_asm.setcc(FukuCondition(rng.randint(0, 15)), dst)
            trace_inst("junk: setcc dst", [ctx.f_asm.context.inst.opcode])

        case 2:
            reg_size = FukuOperandSize(REG_SIZES_64[rng.randint(1, 3)])

            dst = FukuType.get_random_operand_dst_x64(
                AllowInstruction.REGISTER.value, reg_size, ctx.cpu_registers,
                FlagRegister.SPL.value | FlagRegister.SP.value |
                FlagRegister.ESP.value | FlagRegister.RSP.value
            )

            if not dst:
                return False

            src = FukuType.get_random_operand_src_x64(
                AllowInstruction.REGISTER.value | AllowInstruction.OPERAND.value,
                reg_size,
                0
            )

            if not src:
                return False

            ctx.f_asm.cmovcc(FukuCondition(rng.randint(0, 15)), dst, src)
            trace_inst("junk: cmovcc dst, src", [ctx.f_asm.context.inst.opcode])

        case 3:
            reg_size = FukuOperandSize(REG_SIZES_64[rng.randint(0, 3)])

            dst_1 = FukuType.get_random_operand_dst_x64(
                AllowInstruction.REGISTER.value, reg_size, ctx.cpu_registers,
                FlagRegister.SPL.value | FlagRegister.SP.value |
                FlagRegister.ESP.value | FlagRegister.RSP.value
            )

            if not dst_1:
                return False

            dst_2 = FukuType.get_random_operand_dst_x64(
                AllowInstruction.REGISTER.value |
                (0 if dst_1.type == FukuT0Types.FUKU_T0_OPERAND else AllowInstruction.OPERAND.value),
                reg_size, ctx.cpu_registers,
                0
            )

            if not dst_2:
                return False


            ctx.f_asm.xchg(dst_1, dst_2)
            trace_inst("junk: xchg dst1, dst2", [ctx.f_asm.context.inst.opcode])

        case 4 | 5:
            reg_size = FukuOperandSize(REG_SIZES_64[rng.randint(1, 3)])

            dst = FukuType.get_random_operand_dst_x64(
                AllowInstruction.REGISTER.value, reg_size, ctx.cpu_registers,
                FlagRegister.SPL.value | FlagRegister.SP.value |
                FlagRegister.ESP.value | FlagRegister.RSP.value
            )

            if not dst:
                return False

            if reg_size != FukuOperandSize.SIZE_16:
                reg_size = FukuOperandSize(REG_SIZES_64[rng.randint(0, 1)])
            else:
                reg_size = FukuOperandSize.SIZE_8


            src = FukuType.get_random_operand_src_x64(
                AllowInstruction.REGISTER.value | AllowInstruction.OPERAND.value,
                reg_size,
                0
            )

            if not src:
                return False

            if choice == 4:
                ctx.f_asm.movzx(dst, src)
                trace_inst("junk: movzx dst, src", [ctx.f_asm.context.inst.opcode])
            else:
                ctx.f_asm.movsx(dst, src)
                trace_inst("junk: movsx dst, src", [ctx.f_asm.context.inst.opcode])

        case 6:
            # TODO: Check capstone properly dissasemblying this
            return False
            reg_size = FukuOperandSize(REG_SIZES_64[rng.randint(1, 3)])

            dst = FukuType.get_random_operand_dst_x64(
                AllowInstruction.REGISTER.value, reg_size, ctx.cpu_registers,
                FlagRegister.SPL.value | FlagRegister.SP.value |
                FlagRegister.ESP.value | FlagRegister.RSP.value
            )

            if not dst:
                return False

            src = FukuType.get_random_operand_src_x64(
                AllowInstruction.REGISTER.value |
                (0 if dst.type == FukuT0Types.FUKU_T0_OPERAND else AllowInstruction.OPERAND.value),
                reg_size,
                0
            )

            if not src:
                return False

            ctx.f_asm.movsxd(dst, src)
            trace_inst("junk: movsxd dst, src", [ctx.f_asm.context.inst.opcode])

        case 7:
            reg_size = FukuOperandSize(REG_SIZES_64[rng.randint(1, 2)])

            dst = FukuType.get_random_operand_dst_x64(
                AllowInstruction.REGISTER.value, reg_size, ctx.cpu_registers,
                FlagRegister.SPL.value | FlagRegister.SP.value |
                FlagRegister.ESP.value | FlagRegister.RSP.value
            )

            if not dst:
                return False

            ctx.f_asm.bswap(dst)
            trace_inst("junk: bswap dst", [ctx.f_asm.context.inst.opcode])

    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers

    return True

# logical reg1,reg2
# logical reg1,val
def junk_64_low_pattern_2(ctx: FukuMutationCtx) -> bool:
    if not has_free_eflags(
        ctx.cpu_flags,
        x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
        x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
        x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_MODIFY_PF
    ):
        return False

    reg_size = FukuOperandSize(REG_SIZES_64[rng.randint(0, 3)])

    dst = FukuType.get_random_operand_dst_x64(
        AllowInstruction.REGISTER.value | AllowInstruction.OPERAND.value,
        reg_size, ctx.cpu_registers,
        FlagRegister.SPL.value | FlagRegister.SP.value |
        FlagRegister.ESP.value | FlagRegister.RSP.value
    )

    if not dst:
        return False

    src = FukuType.get_random_operand_src_x64(
        AllowInstruction.REGISTER.value | AllowInstruction.IMMEDIATE.value |
        (0 if dst.type == FukuT0Types.FUKU_T0_OPERAND else AllowInstruction.OPERAND.value),
        reg_size,
        0
    )

    match rng.randint(0 if src else 4, 4):
        case 0:
            ctx.f_asm.xor(dst, src)
            trace_inst("junk: xor dst, src", [ctx.f_asm.context.inst.opcode])

        case 1:
            ctx.f_asm.and_(dst, src)
            trace_inst("junk: and dst, src", [ctx.f_asm.context.inst.opcode])

        case 2:
            ctx.f_asm.or_(dst, src)
            trace_inst("junk: or dst, src", [ctx.f_asm.context.inst.opcode])

        case 3:
            ctx.f_asm.test(dst, src)
            trace_inst("junk: test dst, src", [ctx.f_asm.context.inst.opcode])

        case 4:
            ctx.f_asm.not_(dst)
            trace_inst("junk: not dst", [ctx.f_asm.context.inst.opcode])

    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers

    return True

# arithmetic reg1,reg2
# arithmetic reg1,val
def junk_64_low_pattern_3(ctx: FukuMutationCtx) -> bool:
    if not has_free_eflags(
        ctx.cpu_flags,
        x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
        x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
        x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_MODIFY_PF
    ):
        return False

    reg_size = FukuOperandSize(REG_SIZES_64[rng.randint(0, 3)])

    dst = FukuType.get_random_operand_dst_x64(
        AllowInstruction.REGISTER.value | AllowInstruction.OPERAND.value,
        reg_size, ctx.cpu_registers,
        FlagRegister.SP.value | FlagRegister.ESP.value
    )

    if not dst:
        return False

    src = FukuType.get_random_operand_src_x64(
        AllowInstruction.REGISTER.value | AllowInstruction.IMMEDIATE.value |
        (0 if dst.type == FukuT0Types.FUKU_T0_OPERAND else AllowInstruction.OPERAND.value),
        reg_size,
        0
    )

    match rng.randint(0 if src else 5, 7):
        case 0:
            ctx.f_asm.add(dst, src)
            trace_inst("junk: add dst, src", [ctx.f_asm.context.inst.opcode])

        case 1:
            ctx.f_asm.adc(dst, src)
            trace_inst("junk: adc dst, src", [ctx.f_asm.context.inst.opcode])

        case 2:
            ctx.f_asm.sub(dst, src)
            trace_inst("junk: sub dst, src", [ctx.f_asm.context.inst.opcode])

        case 3:
            ctx.f_asm.sbb(dst, src)
            trace_inst("junk: sbb dst, src", [ctx.f_asm.context.inst.opcode])

        case 4:
            ctx.f_asm.cmp(dst, src)
            trace_inst("junk: cmp dst, src", [ctx.f_asm.context.inst.opcode])

        case 5:
            ctx.f_asm.inc(dst)
            trace_inst("junk: inc dst", [ctx.f_asm.context.inst.opcode])

        case 6:
            ctx.f_asm.dec(dst)
            trace_inst("junk: dec dst", [ctx.f_asm.context.inst.opcode])

        case 7:
            ctx.f_asm.neg(dst)
            trace_inst("junk: neg dst", [ctx.f_asm.context.inst.opcode])

    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers

    return True

# rotate reg1,val
# rotate reg1,cl
def junk_64_low_pattern_4(ctx: FukuMutationCtx) -> bool:
    if not has_free_eflags(
        ctx.cpu_flags,
        x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_CF
    ):
        return False

    reg_size = FukuOperandSize(REG_SIZES_64[rng.randint(0, 3)])

    dst = FukuType.get_random_operand_dst_x64(
        AllowInstruction.REGISTER.value | AllowInstruction.OPERAND.value,
        reg_size, ctx.cpu_registers,
        FlagRegister.SPL.value | FlagRegister.SP.value |
        FlagRegister.ESP.value | FlagRegister.RSP.value
    )

    if not dst:
        return False

    if rng.randint(0, 1):
        src = FukuRegister(FukuRegisterEnum.FUKU_REG_CL).ftype
    else:
        src = FukuImmediate(rng.randint(1, reg_size.value * 16 - 1)).ftype

    match rng.randint(0, 3):
        case 0:
            ctx.f_asm.rol(dst, src)
            trace_inst("junk: rol dst, src", [ctx.f_asm.context.inst.opcode])

        case 1:
            ctx.f_asm.ror(dst, src)
            trace_inst("junk: rol dst, src", [ctx.f_asm.context.inst.opcode])

        case 2:
            ctx.f_asm.rcl(dst, src)
            trace_inst("junk: rcl dst, src", [ctx.f_asm.context.inst.opcode])

        case 3:
            ctx.f_asm.rcr(dst, src)
            trace_inst("junk: rcr dst, src", [ctx.f_asm.context.inst.opcode])

    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers

    return True

# shift reg1,val
# shift reg1,cl
def junk_64_low_pattern_5(ctx: FukuMutationCtx) -> bool:
    if not has_free_eflags(
        ctx.cpu_flags,
        x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
        x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
        x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_MODIFY_PF
    ):
        return False

    reg_size = FukuOperandSize(REG_SIZES_64[rng.randint(0, 2)])

    dst = FukuType.get_random_operand_dst_x64(
        AllowInstruction.REGISTER.value | AllowInstruction.OPERAND.value,
        reg_size, ctx.cpu_registers,
        FlagRegister.SPL.value | FlagRegister.SP.value |
        FlagRegister.ESP.value | FlagRegister.RSP.value
    )

    if not dst:
        return False

    if rng.randint(0, 1):
        src = FukuRegister(FukuRegisterEnum.FUKU_REG_CL).ftype
    else:
        src = FukuImmediate(rng.randint(1, reg_size.value * 16 - 1)).ftype

    match rng.randint(0, 2):
        case 0:
            ctx.f_asm.sar(dst, src)
            trace_inst("junk: sar dst, src", [ctx.f_asm.context.inst.opcode])

        case 1:
            ctx.f_asm.shl(dst, src)
            trace_inst("junk: shl dst, src", [ctx.f_asm.context.inst.opcode])

        case 2:
            ctx.f_asm.shr(dst, src)
            trace_inst("junk: shr dst, src", [ctx.f_asm.context.inst.opcode])

    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers

    return True

# bittest reg1,val
# bittest reg1,reg
def junk_64_low_pattern_6(ctx: FukuMutationCtx) -> bool:
    if not has_free_eflags(
        ctx.cpu_flags,
        x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
        x86_const.X86_EFLAGS_MODIFY_AF | x86_const.X86_EFLAGS_MODIFY_CF |
        x86_const.X86_EFLAGS_MODIFY_PF
    ):
        return False

    reg_size = FukuOperandSize(REG_SIZES_64[rng.randint(1, 3)])

    dst = FukuType.get_random_operand_dst_x64(
        AllowInstruction.REGISTER.value | AllowInstruction.OPERAND.value,
        reg_size, ctx.cpu_registers,
        FlagRegister.SPL.value | FlagRegister.SP.value |
        FlagRegister.ESP.value | FlagRegister.RSP.value
    )

    if not dst:
        return False

    src = FukuType.get_random_operand_src_x64(
        AllowInstruction.REGISTER.value | AllowInstruction.IMMEDIATE.value,
        FukuOperandSize.SIZE_8,
        0
    )

    if not src:
        return False

    match rng.randint(0, 3):
        case 0:
            ctx.f_asm.bt(dst, src)
            trace_inst("junk: bt dst, src", [ctx.f_asm.context.inst.opcode])

        case 1:
            ctx.f_asm.btc(dst, src)
            trace_inst("junk: btc dst, src", [ctx.f_asm.context.inst.opcode])

        case 2:
            ctx.f_asm.bts(dst, src)
            trace_inst("junk: bts dst, src", [ctx.f_asm.context.inst.opcode])

        case 3:
            ctx.f_asm.btr(dst, src)
            trace_inst("junk: btr dst, src", [ctx.f_asm.context.inst.opcode])

    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers

    return True

# convert byte\word to word\dword
def junk_64_low_pattern_7(ctx: FukuMutationCtx) -> bool:
    reg_size = FukuOperandSize(REG_SIZES_64[rng.randint(1, 3)])

    dst = FukuType.get_random_operand_dst_x64(
        AllowInstruction.REGISTER.value,
        reg_size, ctx.cpu_registers,
        FlagRegister.AL.value |
        FlagRegister.RCX.value | FlagRegister.ECX.value | FlagRegister.CX.value | FlagRegister.CL.value |
        FlagRegister.DL.value |
        FlagRegister.RBX.value | FlagRegister.EBX.value | FlagRegister.BX.value | FlagRegister.BL.value |
        FlagRegister.RSP.value | FlagRegister.ESP.value | FlagRegister.SP.value | FlagRegister.SPL.value |
        FlagRegister.RBP.value | FlagRegister.EBP.value | FlagRegister.BP.value | FlagRegister.BPL.value |
        FlagRegister.RSI.value | FlagRegister.ESI.value | FlagRegister.SI.value | FlagRegister.SIL.value |
        FlagRegister.RDI.value | FlagRegister.EDI.value | FlagRegister.DI.value | FlagRegister.DIL.value
    )

    if not dst:
        return False


    match dst.register.reg:
        case FukuRegisterEnum.FUKU_REG_AX:
            ctx.f_asm.cbw()
            trace_inst("junk: cbw", [ctx.f_asm.context.inst.opcode])

        case FukuRegisterEnum.FUKU_REG_EAX:
            ctx.f_asm.cwde()
            trace_inst("junk: cwde", [ctx.f_asm.context.inst.opcode])

        case FukuRegisterEnum.FUKU_REG_RAX:
            ctx.f_asm.cdqe()
            trace_inst("junk: cdqe", [ctx.f_asm.context.inst.opcode])

        case FukuRegisterEnum.FUKU_REG_DX:
            if not has_flag_free_register(ctx.cpu_registers, FlagRegister.AX.value):
                return False

            ctx.f_asm.cwd()
            trace_inst("junk: cwd", [ctx.f_asm.context.inst.opcode])

        case FukuRegisterEnum.FUKU_REG_EDX:
            if not has_flag_free_register(ctx.cpu_registers, FlagRegister.EAX.value):
                return False

            ctx.f_asm.cdq()
            trace_inst("junk: cdq", [ctx.f_asm.context.inst.opcode])

        case FukuRegisterEnum.FUKU_REG_RDX:
            if not has_flag_free_register(ctx.cpu_registers, FlagRegister.RAX.value):
                return False

            ctx.f_asm.cqo()
            trace_inst("junk: cqo", [ctx.f_asm.context.inst.opcode])

    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers

    return True

# set / reset flag
def junk_64_low_pattern_8(ctx: FukuMutationCtx) -> bool:
    match rng.randint(0, 4):
        case 0:
            if not has_free_eflags(ctx.cpu_flags, x86_const.X86_EFLAGS_MODIFY_CF):
                return False

            ctx.f_asm.stc()
            trace_inst("junk: stc", [ctx.f_asm.context.inst.opcode])

        case 1:
            if not has_free_eflags(ctx.cpu_flags, x86_const.X86_EFLAGS_MODIFY_CF):
                return False

            ctx.f_asm.clc()
            trace_inst("junk: clc", [ctx.f_asm.context.inst.opcode])

        case 2:
            if not has_free_eflags(ctx.cpu_flags, x86_const.X86_EFLAGS_MODIFY_CF):
                return False

            ctx.f_asm.cmc()
            trace_inst("junk: cmc", [ctx.f_asm.context.inst.opcode])

        case 3:
            if not has_free_eflags(ctx.cpu_flags, x86_const.X86_EFLAGS_MODIFY_CF):
                return False

            ctx.f_asm.cld()
            trace_inst("junk: cld", [ctx.f_asm.context.inst.opcode])

        case 4:
            if not has_free_eflags(ctx.cpu_flags, x86_const.X86_EFLAGS_MODIFY_DF):
                return False

            ctx.f_asm.std()
            trace_inst("junk: std", [ctx.f_asm.context.inst.opcode])

    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers

    return True

# inc reg
# neg reg
# inc reg
# neg reg
def junk_64_high_pattern_1(ctx: FukuMutationCtx) -> bool:
    if not has_free_eflags(
        ctx.cpu_flags,
        x86_const.X86_EFLAGS_MODIFY_OF | x86_const.X86_EFLAGS_MODIFY_SF |
        x86_const.X86_EFLAGS_MODIFY_ZF | x86_const.X86_EFLAGS_MODIFY_AF |
        x86_const.X86_EFLAGS_MODIFY_CF | x86_const.X86_EFLAGS_MODIFY_PF
    ):
        return False

    reg_size = FukuOperandSize(REG_SIZES_64[rng.randint(0, 3)])

    dst = FukuType.get_random_operand_dst_x64(
        AllowInstruction.REGISTER.value | AllowInstruction.OPERAND.value,
        reg_size, ctx.cpu_registers,
        FlagRegister.SPL.value | FlagRegister.SP.value | FlagRegister.ESP.value | FlagRegister.RSP.value
    )

    if not dst:
        return False

    opcodes = []

    ctx.f_asm.inc(dst)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.neg(dst)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.inc(dst)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.neg(dst)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("junk: inc reg; neg reg; inc reg; neg reg", opcodes)
    return True

# not reg1
# not reg1
def junk_64_high_pattern_2(ctx: FukuMutationCtx) -> bool: # what the hell rex64 "not" clear high 32 bits of 64 bits register all time
    reg_size = FukuOperandSize(REG_SIZES_64[rng.randint(0, 3)])

    dst = FukuType.get_random_operand_dst_x64(
        AllowInstruction.REGISTER.value | AllowInstruction.OPERAND.value,
        reg_size, ctx.cpu_registers,
        FlagRegister.SPL.value | FlagRegister.SP.value | FlagRegister.ESP.value | FlagRegister.RSP.value
    )

    if not dst:
        return False

    opcodes = []

    ctx.f_asm.not_(dst)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.not_(dst)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("junk: not dst; not dst", opcodes)
    return True

# push reg1
# pop reg1
def junk_64_high_pattern_3(ctx: FukuMutationCtx) -> bool:
    if not ctx.is_allowed_stack_operations:
        return False

    reg_size = FukuOperandSize(REG_SIZES_16_64[rng.randint(0, 1)])

    src = FukuType.get_random_operand_src_x64(
        AllowInstruction.REGISTER.value,
        reg_size,
        FlagRegister.SPL.value | FlagRegister.SP.value | FlagRegister.ESP.value | FlagRegister.RSP.value
    )

    if not src:
        return False

    opcodes = []
    flag_reg = src.register.get_flag_complex(reg_size)

    ctx.f_asm.push(src)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    opcodes.append(ctx.f_asm.context.inst.opcode)

    ctx.f_asm.pop(src)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers | flag_reg
    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("junk: push reg, pop reg", opcodes)
    return True

# jcc next_inst
def junk_64_high_pattern_4(ctx: FukuMutationCtx) -> bool:
    if ctx.is_next_last_inst:
        return False

    cond = FukuCondition(rng.randint(0, 15))

    ctx.f_asm.jcc(cond, FukuImmediate(-1).ftype)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    ctx.f_asm.context.inst.rip_reloc = ctx.code_holder.create_rip_relocation(
        FukuRipRelocation(
            label = ctx.generate_payload_label(),
            offset = ctx.f_asm.context.immediate_offset
        )
    )

    trace_inst("junk: jcc next_inst", [ctx.f_asm.context.inst.opcode])
    return True


# jmp next_inst
# some code trash
def junk_64_high_pattern_5(ctx: FukuMutationCtx) -> bool:
    if ctx.is_next_last_inst:
        return False

    opcodes = []
    label = ctx.generate_payload_label()
    label.inst = ctx.next_inst

    ctx.f_asm.jmp(FukuImmediate(-1).ftype)
    ctx.f_asm.context.inst.cpu_flags = ctx.cpu_flags
    ctx.f_asm.context.inst.cpu_registers = ctx.cpu_registers
    ctx.f_asm.context.inst.rip_reloc = ctx.code_holder.create_rip_relocation(
        FukuRipRelocation(
            label = label,
            offset = ctx.f_asm.context.immediate_offset
        )
    )
    opcodes.append(ctx.f_asm.context.inst.opcode)

    trash = bytearray(rng.randint(0, 0xFF) for i in range(1, 15))

    ctx.f_asm.nop()
    ctx.f_asm.context.inst.opcode = trash
    ctx.f_asm.context.inst.flags.inst_flags = FukuInstFlags.FUKU_INST_JUNK_CODE.value
    opcodes.append(ctx.f_asm.context.inst.opcode)

    trace_inst("junk: jcc next_inst; some code trash", opcodes)
    return True


def fuku_junk_64_generic_low(ctx: FukuMutationCtx) -> bool:
    match rng.randint(0, 7):
        case 0:
            return junk_64_low_pattern_1(ctx)

        case 1:
            return junk_64_low_pattern_2(ctx)

        case 2:
            return junk_64_low_pattern_3(ctx)

        case 3:
            return junk_64_low_pattern_4(ctx)

        case 4:
            return junk_64_low_pattern_5(ctx)

        case 5:
            return junk_64_low_pattern_6(ctx)

        case 6:
            return junk_64_low_pattern_7(ctx)

        case 7:
            return junk_64_low_pattern_8(ctx)


def fuku_junk_64_generic_high(ctx: FukuMutationCtx) -> bool:
    match rng.randint(0, 4):
        case 0:
            return junk_64_high_pattern_1(ctx)

        case 1:
            return junk_64_high_pattern_2(ctx)

        case 2:
            return junk_64_high_pattern_3(ctx)

        case 3:
            return junk_64_high_pattern_4(ctx)

        case 4:
            return junk_64_high_pattern_5(ctx)


def fuku_junk_64_generic(ctx: FukuMutationCtx) -> bool:
    match rng.randint(0, 1):
        case 0:
            return fuku_junk_64_generic_low(ctx)

        case 1:
            return fuku_junk_64_generic_high(ctx)
