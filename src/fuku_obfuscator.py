from common import log
from pydantic import BaseModel

from fuku_asm import FukuAsm, FukuAsmHoldType
from capstone import x86_const
from fuku_misc import FUKU_ASSEMBLER_ARCH, FukuObfuscationSettings
from fuku_code_holder import FukuCodeHolder
from x86.misc import FukuCondition
from x86.fuku_register import FukuRegister, FukuRegisterEnum
from x86.fuku_immediate import FukuImmediate
from x86.fuku_mutation_x86 import FukuMutationX86
from x86.fuku_mutation_x64 import FukuMutationX64


class FukuObfuscator(BaseModel):
    destination_virtual_address: int = 0
    settings: FukuObfuscationSettings
    code: FukuCodeHolder

    def obfuscate_code(self):
        before_size = len(self.code.instructions)

        mutator = None
        if self.code.arch == FUKU_ASSEMBLER_ARCH.X86:
            mutator = FukuMutationX86(settings=self.settings)
        elif self.code.arch == FUKU_ASSEMBLER_ARCH.X64:
            mutator = FukuMutationX64(settings=self.settings)

        self.handle_jumps()

        for i in range(self.settings.number_of_passes):
            if self.settings.junk_chance > 0 or self.settings.mutate_chance > 0:
                mutator.obfuscate(self.code)

            if self.settings.block_chance > 0:
                self.spagetty_code()

        self.code.update_current_address(self.destination_virtual_address)

        after_size = len(self.code.instructions)
        log.info(
            f"Instructions count before/after obfuscation: {before_size}/{after_size}"
        )

    def spagetty_code(self):
        pass

    def handle_jumps(self):
        fuku_asm = FukuAsm()

        fuku_asm.set_holder(
            code_holder=self.code,
            hold_type=FukuAsmHoldType.ASSEMBLER_HOLD_TYPE_FIRST_OVERWRITE,
        )

        for line in self.code.instructions[:]:
            match line.id:
                case x86_const.X86_INS_JMP:
                    if line.opcode[line.prefix_count()] == 0xEB:  # near jump
                        line.opcode[line.prefix_count()] = 0xE9
                        line.opcode.extend([0, 0, 0])

                case (
                    x86_const.X86_INS_JO
                    | x86_const.X86_INS_JNO
                    | x86_const.X86_INS_JB
                    | x86_const.X86_INS_JAE
                    | x86_const.X86_INS_JE
                    | x86_const.X86_INS_JNE
                    | x86_const.X86_INS_JBE
                    | x86_const.X86_INS_JA
                    | x86_const.X86_INS_JS
                    | x86_const.X86_INS_JNS
                    | x86_const.X86_INS_JP
                    | x86_const.X86_INS_JNP
                    | x86_const.X86_INS_JL
                    | x86_const.X86_INS_JGE
                    | x86_const.X86_INS_JLE
                    | x86_const.X86_INS_JG
                ):
                    if (line.opcode[line.prefix_count()] & 0xF0) == 0x70:  # near jump
                        opcode = line.opcode.copy()
                        opcode[line.prefix_count()] = 0x0F
                        opcode[line.prefix_count() + 1] = (
                            0x80 | line.opcode[line.prefix_count()] & 0x0F
                        )
                        opcode.extend([0, 0, 0, 0])
                        line.opcode = opcode
                        line.rip_reloc.offset = 2

                case (
                    x86_const.X86_INS_JCXZ
                    | x86_const.X86_INS_JECXZ
                    | x86_const.X86_INS_JRCXZ
                ):
                    fuku_asm.first_emit = True
                    fuku_asm.position = self.code.instructions.index(line)

                    label = line.label
                    rip_reloc = line.rip_reloc

                    reg = None

                    if line.id == x86_const.X86_INS_JRCXZ:  # or rcx, rcx
                        reg = FukuRegister(FukuRegisterEnum.REG_RCX).ftype
                    if line.id == x86_const.X86_INS_JECXZ:  # or ecx, ecx
                        reg = FukuRegister(FukuRegisterEnum.REG_ECX).ftype
                    else:  # or cx, cx
                        reg = FukuRegister(FukuRegisterEnum.REG_CX).ftype

                    fuku_asm.or_(reg, reg)
                    fuku_asm.context.inst.label = label

                    fuku_asm.jcc(FukuCondition.EQUAL, FukuImmediate().ftype)
                    fuku_asm.context.inst.rip_reloc = rip_reloc

                    rip_reloc.offset = fuku_asm.context.immediate_offset

                case x86_const.X86_INS_LOOP:
                    fuku_asm.first_emit = True
                    fuku_asm.position = self.code.instructions.index(line)

                    label = line.label
                    rip_reloc = line.rip_reloc

                    fuku_asm.dec(FukuRegister(FukuRegisterEnum.REG_ECX).ftype)
                    fuku_asm.context.inst.label = label

                    fuku_asm.jcc(FukuCondition.NOT_EQUAL, FukuImmediate().ftype)  # jnz
                    fuku_asm.context.inst.rip_reloc = rip_reloc

                    rip_reloc.offset = fuku_asm.context.immediate_offset

                case x86_const.X86_INS_LOOPE:
                    fuku_asm.first_emit = True
                    fuku_asm.position = self.code.instructions.index(line)

                    label = line.label
                    rip_reloc = line.rip_reloc

                    fuku_asm.dec(FukuRegister(FukuRegisterEnum.REG_ECX).ftype)
                    fuku_asm.context.inst.label = label

                    fuku_asm.jcc(FukuCondition.EQUAL, FukuImmediate().ftype)  # jz
                    fuku_asm.context.inst.rip_reloc = rip_reloc

                    rip_reloc.offset = fuku_asm.context.immediate_offset

                case x86_const.X86_INS_LOOPNE:
                    fuku_asm.first_emit = True
                    fuku_asm.position = self.code.instructions.index(line)

                    label = line.label
                    rip_reloc = line.rip_reloc

                    fuku_asm.dec(FukuRegister(FukuRegisterEnum.REG_ECX))
                    fuku_asm.context.inst.label = label

                    fuku_asm.jcc(FukuCondition.NOT_EQUAL, FukuImmediate().ftype)  # jne
                    fuku_asm.context.inst.rip_reloc = rip_reloc

                    rip_reloc.offset = fuku_asm.context.immediate_offset
