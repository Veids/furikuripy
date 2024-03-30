import struct
from typing import Optional
from capstone import x86_const, Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from pydantic import BaseModel

from fuku_inst import FukuCodeLabel, FukuRipRelocation, FukuRelocation
from fuku_misc import FUKU_ASSEMBLER_ARCH, X86_REL_ADDR
from fuku_code_holder import FukuCodeHolder


class FukuCodeAnalyzer(BaseModel):
    arch: FUKU_ASSEMBLER_ARCH
    code: Optional[FukuCodeHolder] = None

    def analyze_code(
        self, analyzed_code, src: bytes, virtual_address: int, relocations
    ):
        md = Cs(
            CS_ARCH_X86,
            CS_MODE_32 if self.arch == FUKU_ASSEMBLER_ARCH.X86 else CS_MODE_64,
        )
        md.detail = True

        count = 0
        for current_inst in md.disasm(src, 0):
            line = analyzed_code.add_inst()

            line.source_address = virtual_address + current_inst.address
            line.current_address = virtual_address + current_inst.address
            line.opcode = bytearray(
                src[current_inst.address : current_inst.address + current_inst.size]
            )
            line.cpu_flags = current_inst.eflags
            line.id = current_inst.id
            line.offset = (
                current_inst.encoding.disp_offset << 8
                | current_inst.encoding.imm_offset
            )

            for operand in current_inst.operands:
                if (
                    operand.type == x86_const.X86_OP_MEM
                    and operand.mem.base == x86_const.X86_REG_RIP
                ):
                    code_label = FukuCodeLabel(
                        address=virtual_address + X86_REL_ADDR(current_inst)
                    )

                    rip_reloc = FukuRipRelocation()
                    rip_reloc.offset = current_inst.encoding.disp_offset
                    rip_reloc.label = analyzed_code.create_label(code_label)

                    line.rip_reloc = analyzed_code.create_rip_relocation(rip_reloc)

            match current_inst.id:
                case (
                    x86_const.X86_INS_CALL
                    | x86_const.X86_INS_JO
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
                    | x86_const.X86_INS_JMP
                    | x86_const.X86_INS_JECXZ
                    | x86_const.X86_INS_JCXZ
                    | x86_const.X86_INS_JRCXZ
                    | x86_const.X86_INS_LOOP
                    | x86_const.X86_INS_LOOPE
                    | x86_const.X86_INS_LOOPNE
                ):
                    if current_inst.operands[0].type == x86_const.X86_OP_IMM:
                        code_label = FukuCodeLabel(
                            address=virtual_address + current_inst.operands[0].imm
                        )

                        rip_reloc = FukuRipRelocation()
                        rip_reloc.offset = current_inst.encoding.imm_offset
                        rip_reloc.label = analyzed_code.create_label(code_label)

                        line.rip_reloc = analyzed_code.create_rip_relocation(rip_reloc)
            count += 1

        if not count:
            return False

        analyzed_code.update_source_insts()

        if relocations is not None:
            for reloc in relocations:
                line = analyzed_code.get_source_inst_range(reloc.virtual_address)

                if line is None:
                    raise Exception("Relocation is not found")

                reloc_offset = (reloc.virtual_address - line.current_address) & 0xFF
                reloc_dst = None
                if self.code.arch == FUKU_ASSEMBLER_ARCH.X86:
                    reloc_dst = struct.unpack(
                        "<I", line.opcode[reloc_offset : reloc_offset + 4]
                    )
                else:
                    reloc_dst = struct.unpack(
                        "<Q", line.opcode[reloc_offset : reloc_offset + 8]
                    )

                if reloc_offset == (line.offset & 0xFF):
                    code_label = FukuCodeLabel(address=reloc_dst)

                    reloc = FukuRelocation(
                        label=analyzed_code.create_label(code_label),
                        offset=reloc_offset,
                        reloc_id=reloc.reloc_id,
                    )

                    line.disp_reloc = analyzed_code.create_relocation(reloc)
                elif reloc_offset == ((line.offset >> 8) & 0xFF):
                    code_label = FukuCodeLabel(address=reloc_dst)

                    reloc = FukuRelocation(
                        label=analyzed_code.create_label(code_label),
                        offset=reloc_offset,
                        reloc_id=reloc.reloc_id,
                    )
                else:
                    raise Exception("Unhandled case")

        analyzed_code.resolve_labels()
        return True
