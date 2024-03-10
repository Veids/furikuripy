import capstone

from copy import copy
from typing import Optional, List
from pydantic import BaseModel, ConfigDict
from capstone import x86_const

from common import log
from fuku_misc import FUKU_ASSEMBLER_ARCH
from fuku_code_holder import FukuCodeHolder
from x86.fuku_register_math_tables import CAPSTONE_REGISTER_FLAGS
from x86.fuku_register_math_metadata import FlagRegister, EflagsGroup, TESTED_FLAGS_TABLE, EXCLUDED_FLAGS_TABLE, RegisterAccess
from x86.fuku_register_math import get_flag_complex_register, get_flag_complex_register_by_size


def get_bits_included(src, include_mask, exclude_mask):
    return (((src) & (include_mask)) & (~(exclude_mask)))


def get_operand_access(instruction, op_num, op_access, table, default_access):
    op = instruction.operands[op_num]

    if op.type == x86_const.X86_OP_MEM:
        if op.mem.base != x86_const.X86_REG_INVALID:
            op_access.append(
                FukuRegAccess(
                    reg = table[op.mem.base],
                    access = RegisterAccess.READ.value
                )
            )

        if op.mem.index != x86_const.X86_REG_INVALID:
            op_access.append(
                FukuRegAccess(
                    reg = table[op.mem.index],
                    access = RegisterAccess.READ.value
                )
            )
    elif op.type == x86_const.X86_OP_REG:
        op_access.append(
            FukuRegAccess(
                reg = table[op.reg],
                access = default_access
            )
        )


class FukuRegAccess(BaseModel):
    reg: int = 0
    access: int = 0


class FukuCodeProfiler(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    arch: FUKU_ASSEMBLER_ARCH
    registers_table: Optional[List[int]] = None
    dirty_registers_table: bool = False
    cs: capstone.Cs

    def __init__(self, **kwargs):
        kwargs["cs"] = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32 if kwargs["arch"] == FUKU_ASSEMBLER_ARCH.X86 else capstone.CS_MODE_64)
        kwargs["cs"].detail = True

        super().__init__(**kwargs)

    def profile_graph_registers(self, code: FukuCodeHolder, instructions):
        included_registers = 0
        excluded_registers = 0

        op_access: List[FukuRegAccess] = list()

        if self.dirty_registers_table:
            self.registers_table = CAPSTONE_REGISTER_FLAGS.copy()
            self.dirty_registers_table = False

        for current_inst in instructions:
            instruction = next(self.cs.disasm(current_inst.opcode, 0, count = 1))

            match current_inst.id:
                case (
                    x86_const.X86_INS_JMP | x86_const.X86_INS_RET | x86_const.X86_INS_CALL |
                    x86_const.X86_INS_JAE | x86_const.X86_INS_JA | x86_const.X86_INS_JBE |
                    x86_const.X86_INS_JB | x86_const.X86_INS_JE | x86_const.X86_INS_JGE |
                    x86_const.X86_INS_JG | x86_const.X86_INS_JLE | x86_const.X86_INS_JL |
                    x86_const.X86_INS_JNE | x86_const.X86_INS_JNO | x86_const.X86_INS_JNP |
                    x86_const.X86_INS_JNS | x86_const.X86_INS_JO | x86_const.X86_INS_JP |
                    x86_const.X86_INS_JS
                ):
                    return included_registers

            handled = self.get_instruction_operand_access(instruction, op_access)
            if not handled:
                log.warn("not profiled %s %s" % (instruction.mnemonic, instruction.op_str))
                return included_registers

            current_included_registers = 0
            current_excluded_registers = 0

            for x in op_access:
                if x.access & RegisterAccess.READ.value:
                    current_excluded_registers |= get_flag_complex_register(x.reg)
                if x.access & RegisterAccess.WRITE.value:
                    current_included_registers |= get_flag_complex_register_by_size(x.reg)

            excluded_registers |= current_excluded_registers
            included_registers |= current_included_registers & (~excluded_registers)

        return included_registers

    def profile_graph_eflags(self, code: FukuCodeHolder, instructions):
        included_flags = 0
        excluded_flags = 0

        for current_inst in instructions:
            current_id = current_inst.id
            current_eflags = current_inst.cpu_flags

            if current_eflags & EflagsGroup.TEST.value:
                for eflag, ex_eflag in zip(TESTED_FLAGS_TABLE, EXCLUDED_FLAGS_TABLE):
                    if current_eflags & eflag:
                        excluded_flags |= ex_eflag

            if excluded_flags == (EflagsGroup.MODIFY.value | EflagsGroup.SET.value | EflagsGroup.RESET.value | EflagsGroup.UNDEFINED.value):
                return included_flags

            if current_id == (x86_const.X86_INS_JMP | x86_const.X86_INS_RET | x86_const.X86_INS_CALL):
                return included_flags

            included_flags |= get_bits_included(
                current_eflags,
                EflagsGroup.MODIFY.value | EflagsGroup.SET.value | EflagsGroup.RESET.value | EflagsGroup.UNDEFINED.value,
                excluded_flags
            )

            if included_flags == (EflagsGroup.MODIFY.value | EflagsGroup.SET.value | EflagsGroup.RESET.value | EflagsGroup.UNDEFINED.value):
                return included_flags

        return included_flags

    def get_instruction_operand_access(self, instruction, op_access):
        default_stack_pointer = FlagRegister.ESP.value if self.arch == FUKU_ASSEMBLER_ARCH.X86 else FlagRegister.RSP.value
        default_frame_pointer = FlagRegister.EBP.value if self.arch == FUKU_ASSEMBLER_ARCH.X86 else FlagRegister.RBP.value

        handled = False

        match instruction.id:
            case (
                x86_const.X86_INS_AAA |
                x86_const.X86_INS_AAD |
                x86_const.X86_INS_AAM |
                x86_const.X86_INS_AAS |
                x86_const.X86_INS_DAA |
                x86_const.X86_INS_DAS |
                x86_const.X86_INS_ANDN |
                x86_const.X86_INS_CMPXCHG16B |
                x86_const.X86_INS_CMPXCHG |
                x86_const.X86_INS_CMPXCHG8B |
                x86_const.X86_INS_BZHI |
                x86_const.X86_INS_CPUID |
                x86_const.X86_INS_CRC32 |
                x86_const.X86_INS_JCXZ |
                x86_const.X86_INS_JECXZ |
                x86_const.X86_INS_JRCXZ |
                x86_const.X86_INS_LFENCE |
                x86_const.X86_INS_LOOP |
                x86_const.X86_INS_LOOPE |
                x86_const.X86_INS_LOOPNE |
                x86_const.X86_INS_XADD |
                x86_const.X86_INS_MOVQ |
                x86_const.X86_INS_MOVD |
                x86_const.X86_INS_MOVBE |
                x86_const.X86_INS_MOVSS |
                x86_const.X86_INS_POPCNT |
                x86_const.X86_INS_RDRAND |
                x86_const.X86_INS_RDSEED |
                x86_const.X86_INS_RDTSC |
                x86_const.X86_INS_RDTSCP |
                x86_const.X86_INS_SHLD |
                x86_const.X86_INS_SHRD |
                x86_const.X86_INS_STGI |
                x86_const.X86_INS_SAHF |
                x86_const.X86_INS_TZCNT |
                x86_const.X86_INS_XTEST |
                x86_const.X86_INS_CMPSS
            ):
                pass

            case x86_const.X86_INS_XOR:
                if (
                    instruction.operands[0].type == x86_const.X86_OP_REG and
                    instruction.operands[1].type == x86_const.X86_OP_REG and
                    instruction.operands[0].reg == instruction.operands[1].reg
                ):
                    get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.WRITE.value)
                else:
                    get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.READ.value | RegisterAccess.WRITE.value)
                    get_operand_access(instruction, 1, op_access, self.registers_table, RegisterAccess.READ.value)

                handled = True

            case (
                x86_const.X86_INS_BTC |
                x86_const.X86_INS_BTR |
                x86_const.X86_INS_BTS |
                x86_const.X86_INS_OR |
                x86_const.X86_INS_SUB |
                x86_const.X86_INS_SBB |
                x86_const.X86_INS_AND |
                x86_const.X86_INS_ADC |
                x86_const.X86_INS_ADCX |
                x86_const.X86_INS_ADD |
                x86_const.X86_INS_RCR |
                x86_const.X86_INS_RCL |
                x86_const.X86_INS_ROL |
                x86_const.X86_INS_ROR |
                x86_const.X86_INS_RORX |
                x86_const.X86_INS_SAL |
                x86_const.X86_INS_SAR |
                x86_const.X86_INS_SARX |
                x86_const.X86_INS_SHL |
                x86_const.X86_INS_SHLX |
                x86_const.X86_INS_SHR |
                x86_const.X86_INS_SHRX
            ):
                get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.READ.value | RegisterAccess.WRITE.value)
                get_operand_access(instruction, 1, op_access, self.registers_table, RegisterAccess.READ.value)
                handled = True

            case (
                x86_const.X86_INS_CMOVA |
                x86_const.X86_INS_CMOVAE |
                x86_const.X86_INS_CMOVB |
                x86_const.X86_INS_CMOVBE |
                x86_const.X86_INS_CMOVE |
                x86_const.X86_INS_CMOVG |
                x86_const.X86_INS_CMOVGE |
                x86_const.X86_INS_CMOVL |
                x86_const.X86_INS_CMOVLE |
                x86_const.X86_INS_CMOVNE |
                x86_const.X86_INS_CMOVNO |
                x86_const.X86_INS_CMOVNP |
                x86_const.X86_INS_CMOVNS |
                x86_const.X86_INS_CMOVO |
                x86_const.X86_INS_CMOVP |
                x86_const.X86_INS_CMOVS |
                x86_const.X86_INS_MOV |
                x86_const.X86_INS_MOVABS |
                x86_const.X86_INS_MOVSXD |
                x86_const.X86_INS_MOVSX |
                x86_const.X86_INS_MOVZX |
                x86_const.X86_INS_LEA |
                x86_const.X86_INS_BSF |
                x86_const.X86_INS_BSR |
                x86_const.X86_INS_BLSR |
                x86_const.X86_INS_BLSI
            ):
                get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.WRITE.value)
                get_operand_access(instruction, 1, op_access, self.registers_table, RegisterAccess.READ.value)
                handled = True

            case x86_const.X86_INS_XCHG:
                if (
                    instruction.operands[0].type == x86_const.X86_OP_REG and
                    instruction.operands[1].type == x86_const.X86_OP_REG
                ):
                    self.registers_table[instruction.operands[0].reg], self.registers_table[instruction.operands[1].reg] = (
                        self.registers_table[instruction.operands[1].reg], self.registers_table[instruction.operands[0].reg]
                    )
                    self.dirty_registers_table = True
                else:
                    get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.READ.value | RegisterAccess.WRITE.value)
                    get_operand_access(instruction, 1, op_access, self.registers_table, RegisterAccess.READ.value | RegisterAccess.WRITE.value)

                handled = True

            case (
                x86_const.X86_INS_BT |
                x86_const.X86_INS_TEST |
                x86_const.X86_INS_CMP
            ):
                get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.READ.value)
                get_operand_access(instruction, 1, op_access, self.registers_table, RegisterAccess.READ.value)
                handled = True

            case (
                x86_const.X86_INS_BSWAP |
                x86_const.X86_INS_DEC |
                x86_const.X86_INS_INC |
                x86_const.X86_INS_NOT |
                x86_const.X86_INS_NEG
            ):
                get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.READ.value | RegisterAccess.WRITE.value)
                handled = True

            case x86_const.X86_INS_PUSHAW:
                op_access.append(FukuRegAccess(reg = FlagRegister.AX.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.CX.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.DX.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.BX.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.SP.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.BP.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.SI.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.DI.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = default_stack_pointer, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                handled = True

            case x86_const.X86_INS_PUSHAL:
                op_access.append(FukuRegAccess(reg = FlagRegister.EAX.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.ECX.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.EDX.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.EBX.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.ESP.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.EBP.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.ESI.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.EDI.value, access = RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = default_stack_pointer, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                handled = True

            case x86_const.X86_INS_POPAW:
                op_access.append(FukuRegAccess(reg = FlagRegister.AX.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.CX.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.DX.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.BX.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.SP.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.BP.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.SI.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.DI.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = default_stack_pointer, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                handled = True

            case x86_const.X86_INS_POPAL:
                op_access.append(FukuRegAccess(reg = FlagRegister.EAX.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.ECX.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.EDX.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.EBX.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.ESP.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.EBP.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.ESI.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.EDI.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = default_stack_pointer, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                handled = True

            case x86_const.X86_INS_PUSH:
                get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.READ.value)
                op_access.append(FukuRegAccess(reg = default_stack_pointer, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                handled = True

            case x86_const.X86_INS_POP:
                get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.WRITE.value)
                op_access.append(FukuRegAccess(reg = default_stack_pointer, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                handled = True

            case x86_const.X86_INS_RET:
                op_access.append(FukuRegAccess(reg = default_stack_pointer, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                handled = True

            case x86_const.X86_INS_LEAVE:
                op_access.append(FukuRegAccess(reg = default_frame_pointer, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = default_stack_pointer, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                handled = True

            case x86_const.X86_INS_LEAVE:
                op_access.append(FukuRegAccess(reg = default_frame_pointer, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = default_stack_pointer, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                handled = True

            case (
                x86_const.X86_INS_IDIV |
                x86_const.X86_INS_DIV
            ):
                get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.READ.value)

                match instruction.operands[0].size:
                    case 1:
                        op_access.append(FukuRegAccess(reg = FlagRegister.AX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                    case 2:
                        op_access.append(FukuRegAccess(reg = FlagRegister.AX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                        op_access.append(FukuRegAccess(reg = FlagRegister.DX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                    case 4:
                        op_access.append(FukuRegAccess(reg = FlagRegister.EAX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                        op_access.append(FukuRegAccess(reg = FlagRegister.EDX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                    case 8:
                        op_access.append(FukuRegAccess(reg = FlagRegister.RAX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                        op_access.append(FukuRegAccess(reg = FlagRegister.RDX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))

                handled = True

            case x86_const.X86_INS_MUL:
                get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.READ.value)

                match instruction.operands[0].size:
                    case 1:
                        op_access.append(FukuRegAccess(reg = FlagRegister.AX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                    case 2:
                        op_access.append(FukuRegAccess(reg = FlagRegister.AX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                        op_access.append(FukuRegAccess(reg = FlagRegister.DX.value, access = RegisterAccess.WRITE.value))
                    case 4:
                        op_access.append(FukuRegAccess(reg = FlagRegister.EAX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                        op_access.append(FukuRegAccess(reg = FlagRegister.EDX.value, access = RegisterAccess.WRITE.value))
                    case 8:
                        op_access.append(FukuRegAccess(reg = FlagRegister.RAX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                        op_access.append(FukuRegAccess(reg = FlagRegister.RDX.value, access = RegisterAccess.WRITE.value))

                handled = True

            case x86_const.X86_INS_IMUL:
                match len(instruction.operands):
                    case 1:
                        get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.READ.value)

                        match instruction.operands[0].size:
                            case 1:
                                op_access.append(FukuRegAccess(reg = FlagRegister.AX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                            case 2:
                                op_access.append(FukuRegAccess(reg = FlagRegister.AX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                                op_access.append(FukuRegAccess(reg = FlagRegister.DX.value, access = RegisterAccess.WRITE.value))
                            case 4:
                                op_access.append(FukuRegAccess(reg = FlagRegister.EAX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                                op_access.append(FukuRegAccess(reg = FlagRegister.EDX.value, access = RegisterAccess.WRITE.value))
                            case 8:
                                op_access.append(FukuRegAccess(reg = FlagRegister.RAX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                                op_access.append(FukuRegAccess(reg = FlagRegister.RDX.value, access = RegisterAccess.WRITE.value))
                    case 2:
                        get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.WRITE.value | RegisterAccess.READ.value)
                        get_operand_access(instruction, 1, op_access, self.registers_table, RegisterAccess.READ.value)
                    case 3:
                        get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.WRITE.value)
                        get_operand_access(instruction, 1, op_access, self.registers_table, RegisterAccess.READ.value)

                handled = True

            case (
                x86_const.X86_INS_JAE |
                x86_const.X86_INS_JA |
                x86_const.X86_INS_JBE |
                x86_const.X86_INS_JB |
                x86_const.X86_INS_JE |
                x86_const.X86_INS_JGE |
                x86_const.X86_INS_JG |
                x86_const.X86_INS_JLE |
                x86_const.X86_INS_JL |
                x86_const.X86_INS_JNE |
                x86_const.X86_INS_JNO |
                x86_const.X86_INS_JNP |
                x86_const.X86_INS_JNS |
                x86_const.X86_INS_JO |
                x86_const.X86_INS_JP |
                x86_const.X86_INS_JS
            ):
                handled = True

            case (
                x86_const.X86_INS_CALL |
                x86_const.X86_INS_JMP
            ):
                get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.READ.value)
                handled = True

            case (
                x86_const.X86_INS_SETAE |
                x86_const.X86_INS_SETA |
                x86_const.X86_INS_SETBE |
                x86_const.X86_INS_SETB |
                x86_const.X86_INS_SETE |
                x86_const.X86_INS_SETGE |
                x86_const.X86_INS_SETG |
                x86_const.X86_INS_SETLE |
                x86_const.X86_INS_SETL |
                x86_const.X86_INS_SETNE |
                x86_const.X86_INS_SETNO |
                x86_const.X86_INS_SETNP |
                x86_const.X86_INS_SETNS |
                x86_const.X86_INS_SETO |
                x86_const.X86_INS_SETP |
                x86_const.X86_INS_SETS
            ):
                get_operand_access(instruction, 0, op_access, self.registers_table, RegisterAccess.WRITE.value)
                handled = True

            case (
                x86_const.X86_INS_POPF |
                x86_const.X86_INS_POPFD |
                x86_const.X86_INS_POPFQ |
                x86_const.X86_INS_PUSHFQ |
                x86_const.X86_INS_PUSHFD |
                x86_const.X86_INS_PUSHF
            ):
                op_access.append(FukuRegAccess(reg = default_stack_pointer, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                handled = True

            case (
                x86_const.X86_INS_CMPSB |
                x86_const.X86_INS_CMPSW |
                x86_const.X86_INS_CMPSD |
                x86_const.X86_INS_CMPSQ |
                x86_const.X86_INS_MOVSB |
                x86_const.X86_INS_MOVSW |
                x86_const.X86_INS_MOVSD |
                x86_const.X86_INS_MOVSQ |
                x86_const.X86_INS_STOSB |
                x86_const.X86_INS_STOSW |
                x86_const.X86_INS_STOSD |
                x86_const.X86_INS_STOSQ |
                x86_const.X86_INS_LODSB |
                x86_const.X86_INS_LODSW |
                x86_const.X86_INS_LODSD |
                x86_const.X86_INS_LODSQ |
                x86_const.X86_INS_SCASB |
                x86_const.X86_INS_SCASW |
                x86_const.X86_INS_SCASD |
                x86_const.X86_INS_SCASQ
            ):
                for reg_read in instruction.regs_read:
                    op_access.append(FukuRegAccess(reg = self.registers_table[reg_read], access = RegisterAccess.READ.value))

                for reg_write in instruction.regs_write:
                    op_access.append(FukuRegAccess(reg = self.registers_table[reg_write], access = RegisterAccess.WRITE.value))

                handled = True

            case (
                x86_const.X86_INS_CLC |
                x86_const.X86_INS_CLD |
                x86_const.X86_INS_CLI |
                x86_const.X86_INS_CMC |
                x86_const.X86_INS_STI |
                x86_const.X86_INS_STC |
                x86_const.X86_INS_STD |
                x86_const.X86_INS_CLAC |
                x86_const.X86_INS_INT3 |
                x86_const.X86_INS_INT1 |
                x86_const.X86_INS_INT |
                x86_const.X86_INS_NOP
            ):
                handled = True

            case x86_const.X86_INS_CWD:
                op_access.append(FukuRegAccess(reg = FlagRegister.AX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.DX.value, access = RegisterAccess.WRITE.value))
                handled = True

            case x86_const.X86_INS_CDQ:
                op_access.append(FukuRegAccess(reg = FlagRegister.EAX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.EDX.value, access = RegisterAccess.WRITE.value))
                handled = True

            case x86_const.X86_INS_CQO:
                op_access.append(FukuRegAccess(reg = FlagRegister.RAX.value, access = RegisterAccess.WRITE.value | RegisterAccess.READ.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.RDX.value, access = RegisterAccess.WRITE.value))
                handled = True

            case x86_const.X86_INS_CBW:
                op_access.append(FukuRegAccess(reg = FlagRegister.AX.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.AL.value, access = RegisterAccess.READ.value))
                handled = True

            case x86_const.X86_INS_CWDE:
                op_access.append(FukuRegAccess(reg = FlagRegister.EAX.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.AX.value, access = RegisterAccess.READ.value))
                handled = True

            case x86_const.X86_INS_CDQE:
                op_access.append(FukuRegAccess(reg = FlagRegister.RAX.value, access = RegisterAccess.WRITE.value))
                op_access.append(FukuRegAccess(reg = FlagRegister.EAX.value, access = RegisterAccess.READ.value))
                handled = True

        return handled

    def profile_code(self, code: FukuCodeHolder) -> bool:
        if self.arch != code.arch:
            return False

        self.registers_table = CAPSTONE_REGISTER_FLAGS.copy()

        iterator = iter(code.instructions)
        try:
            while True:
                instructions = copy(iterator)

                line = next(iterator)
                line.cpu_flags = self.profile_graph_eflags(code, copy(instructions))
                line.cpu_registers = self.profile_graph_registers(code, copy(instructions))
        except StopIteration:
            pass

        return True
