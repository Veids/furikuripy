from typing import Annotated
from annotated_types import Gt
from pydantic import BaseModel
from capstone import x86_const
from enum import Enum


class FUKU_ASSEMBLER_ARCH(Enum):
    X86 = "X86"
    X64 = "X64"


UnsignedInt = Annotated[int, Gt(0)]


class FukuObfuscationSettings(BaseModel):
    complexity: UnsignedInt # number of passes for single line
    number_of_passes: UnsignedInt # number of passes for full code

    junk_chance: float # 0.f - 100.f chance of adding junk
    block_chance: float  # 0.f - 100.f chance of generation new code graph
    mutate_chance: float # 0.f - 100.f chance of mutation line
    asm_cfg: int # assembler builder flags

    not_allowed_unstable_stack: bool # if true then obfuscator don't use stack above esp
    not_allowed_relocations: bool # if true then obfuscator don't create new relocations in code


def X86_REL_ADDR(inst):
    if inst.operands[0].type == x86_const.X86_OP_IMM:
        return inst.operands[0].imm
    else:
        return inst.address + inst.size + inst.disp
