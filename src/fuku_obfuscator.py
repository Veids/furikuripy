from pydantic import BaseModel

from fuku_asm import FukuAsm, FukuAsmHoldType
from capstone import x86_const
from fuku_misc import FUKU_ASSEMBLER_ARCH, FukuObfuscationSettings
from fuku_code_holder import FukuCodeHolder
from x86.fuku_mutation_x86 import FukuMutationX86
from x86.fuku_mutation_x64 import FukuMutationX64


class FukuObfuscator(BaseModel):
    destination_virtual_address: int = 0
    settings: FukuObfuscationSettings
    code: FukuCodeHolder

    def obfuscate_code(self):
        mutator = None
        if self.code.arch == FUKU_ASSEMBLER_ARCH.X86:
            mutator = FukuMutationX86(settings = self.settings)
        elif self.code.arch == FUKU_ASSEMBLER_ARCH.X64:
            mutator = FukuMutationX64(settings = self.settings)

        self.handle_jumps()

    def handle_jumps(self):
        fuku_asm = FukuAsm(
            code_holder = self.code,
            hold_type = FukuAsmHoldType.ASSEMBLER_HOLD_TYPE_FIRST_OVERWRITE
        )

        for line in self.code.instructions:
            match line.id:
                case x86_const.X86_INS_JMP:
                    if line.opcode[line.prefix_count()] == 0xEB: # near jump
                        print("here")
                        opcode = list(line.opcode)
                        opcode[line.prefix_count()] = 0xE9
                        opcode.extend([0, 0, 0])
                        line.opcode = opcode

                case (
                    x86_const.X86_INS_JO |
                    x86_const.X86_INS_JNO |
                    x86_const.X86_INS_JB |
                    x86_const.X86_INS_JAE |
                    x86_const.X86_INS_JE |
                    x86_const.X86_INS_JNE |
                    x86_const.X86_INS_JBE |
                    x86_const.X86_INS_JA |
                    x86_const.X86_INS_JS |
                    x86_const.X86_INS_JNS |
                    x86_const.X86_INS_JP |
                    x86_const.X86_INS_JNP |
                    x86_const.X86_INS_JL |
                    x86_const.X86_INS_JGE |
                    x86_const.X86_INS_JLE |
                    x86_const.X86_INS_JG
                ):
                    if (line.opcode[line.prefix_count()] & 0xF0) == 0x70: # near jump
                        opcode = list(line.opcode)
                        opcode[line.prefix_count()] = 0x0F
                        opcode[line.prefix_count() + 1] = (0x80 | line.opcode[line.prefix_count()] & 0x0F)
                        opcode.extend([0, 0, 0, 0])
                        line.opcode = opcode
                        line.rip_reloc.offset = 2

                case (
                    x86_const.X86_INS_JCXZ |
                    x86_const.X86_INS_JECXZ
                ):
                    label = line.label
                    rip_reloc = line.rip_reloc

                    if line.id == x86_const.X86_INS_JECXZ: # or ecx, ecx
                        reg = 0
                    else:
                        reg = 1
