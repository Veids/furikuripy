from __future__ import annotations

import struct
from typing import Optional
from pydantic import BaseModel

from fuku_inst import FukuInst
from fuku_misc import FUKU_ASSEMBLER_ARCH
from x86.fuku_immediate import FukuImmediate
from x86.fuku_register import FukuRegister, FukuRegisterIndex
from x86.fuku_operand import FukuOperand, FukuMemOperandType, FukuOperandScale
from x86.misc import FukuAsmShortCfg
from x86.fuku_asm_ctx_pattern import FukuAsmCtxPattern


class RawOperand(BaseModel):
    ctx: FukuAsmCtx
    data: bytes = bytearray(8)
    operand_size: int = 0

    def set_modrm(self, mod, reg: FukuRegisterIndex, rm: FukuRegisterIndex):
        assert mod < 3
        self.data[0] = mod << 6 | reg.value << 3 | rm.value
        if self.operand_size < 1:
            self.operand_size = 1

    def set_sib(self, scale: FukuOperandScale, reg_idx_index: FukuRegisterIndex, reg_idx_base: FukuRegisterIndex):
        assert self.operand_size < 1
        assert scale.value < 3
        self.data[1] = (scale.value << 6) | (reg_idx_index.value << 3) | reg_idx_base.value
        if self.operand_size < 2:
            self.operand_size = 2

    def set_disp8(self, disp):
        self.data[self.operand_size] = disp
        self.ctx.displacment_offset = len(self.ctx.bytecode) + self.operand_size
        self.operand_size += 1

    def set_dispr(self, disp):
        self.data[self.operand_size:self.operand_size + 4] = struct.pack("<I", disp)
        self.ctx.displacment_offset = len(self.ctx.bytecode) + self.operand_size
        self.operand_size += 4


class FukuAsmCtx(BaseModel, FukuAsmCtxPattern):
    arch: FUKU_ASSEMBLER_ARCH
    bytecode: bytes = bytearray()

    displacment_offset: int = 0
    immediate_offset: int = 0
    disp_reloc: bool = False
    imm_reloc: bool = False

    short_cfg: int

    inst: FukuInst

    @property
    def is_used_short_eax(self) -> bool:
        return self.short_cfg & FukuAsmShortCfg.USE_EAX_SHORT.value

    @property
    def is_used_short_imm(self) -> bool:
        return self.short_cfg & FukuAsmShortCfg.USE_IMM_SHORT.value

    @property
    def is_used_short_disp(self) -> bool:
        return self.short_cfg & FukuAsmShortCfg.USE_DISP_SHORT.value

    def gen_func_return(self, id, cap_eflags):
        inst = FukuInst()
        inst.opcode = self.bytecode.copy()
        inst.id = id
        inst.cpu_flags = cap_eflags

        self.inst.update(inst)

    def clear(self):
        self.bytecode = bytearray()
        self.displacment_offset = 0
        self.immediate_offset = 0
        self.disp_reloc = False
        self.imm_reloc = False

    def emit_b(self, x):
        self.bytecode.append(x)

    def emit_w(self, x):
        self.bytecode += struct.pack("<H", x)

    def emit_dw(self, x):
        self.bytecode += struct.pack("<I", x)

    def emit_qw(self, x):
        self.bytecode += struct.pack("<Q", x)

    def emit_immediate_b(self, src: FukuImmediate):
        self.immediate_offset = len(self.bytecode)
        self.emit_b(src.immediate8)
        self.imm_reloc = src.is_relocate

    def emit_immediate_w(self, src: FukuImmediate):
        self.immediate_offset = len(self.bytecode)
        self.emit_w(src.immediate16)
        self.imm_reloc = src.is_relocate

    def emit_immediate_dw(self, src: FukuImmediate):
        self.immediate_offset = len(self.bytecode)
        self.emit_dw(src.immediate32)
        self.imm_reloc = src.is_relocate

    def emit_immediate_qw(self, src: FukuImmediate):
        self.immediate_offset = len(self.bytecode)
        self.emit_qw(src.immediate64)
        self.imm_reloc = src.is_relocate

    """
                              is base 64 ext(B)
             is reg 64 ext(R)  /
                     |        /
        REX 0100 0   0   0   0
                 |        \
          is 64bit size(W) \
                          is index 64 ext(X)
    """
    def emit_rex_64(self, rm_reg: Optional[FukuRegister | FukuOperand] = None, reg: Optional[FukuRegister] = None):
        if self.arch == FUKU_ASSEMBLER_ARCH.X86:
            return

        if rm_reg is None and reg is None:
            self.emit_b(0x48)
        elif isinstance(rm_reg, FukuRegister) and isinstance(reg, FukuRegister):
            self.emit_b(0x48 | (1 if reg.is_ext64 else 0) << 2 | (1 if rm_reg.is_ext64 else 0))
        elif isinstance(rm_reg, FukuOperand) and isinstance(reg, FukuRegister):
            self.emit_b(0x48 | (1 if reg.is_ext64 else 0) << 2 | rm_reg.low_rex)
        elif isinstance(rm_reg, FukuRegister) and reg is None:
            self.emit_b(0x48 | (1 if rm_reg.is_ext64 else 0))
        elif isinstance(rm_reg, FukuOperand) and reg is None:
            self.emit_b(0x48 | rm_reg.low_rex)

    def emit_optional_rex_32(self, rm_reg, reg = None):
        if self.arch == FUKU_ASSEMBLER_ARCH.X86:
            return

        if isinstance(rm_reg, FukuRegister) and isinstance(reg, FukuRegister):
            rex_bits = (1 if reg.is_ext64 else 0) << 2 | (1 if rm_reg.is_ext64 else 0)
            if rex_bits != 0 or rm_reg.arch64 or reg.arch64:
                self.emit_b(0x40 | rex_bits)
        elif isinstance(rm_reg, FukuOperand) and isinstance(reg, FukuRegister):
            rex_bits = (1 if reg.is_ext64 else 0) << 2 | rm_reg.low_rex
            if rex_bits != 0 or reg.arch64:
                self.emit_b(0x40 | rex_bits)
        elif isinstance(rm_reg, FukuRegister) and reg is None:
            if rm_reg.is_ext64:
                self.emit_b(0x41)
            elif rm_reg.arch64:
                self.emit_b(0x40)
        elif isinstance(rm_reg, FukuOperand):
            if rm_reg.low_rex != 0:
                self.emit_b(0x40 | rm_reg.low_rex)

    def emit_modrm(self, rm_reg: FukuRegister, reg: FukuRegister | int):
        val = reg.index.value if isinstance(reg, FukuRegister) else reg
        self.emit_b(0xC0 | val << 3 | rm_reg.index.value)

    def emit_operand_x86(self, rm_reg: FukuOperand, reg: FukuRegisterIndex):
        assert len(self.bytecode) != 0

        raw_operand = RawOperand(
            ctx = self
        )
        base_idx = rm_reg.base.index
        index_idx = rm_reg.index.index

        match rm_reg.type:
            case FukuMemOperandType.FUKU_MEM_OPERAND_DISP_ONLY:
                raw_operand.set_modrm(0, reg, FukuRegisterIndex.FUKU_REG_INDEX_BP)
                raw_operand.set_dispr(rm_reg.disp.immediate32)

            case (
                FukuMemOperandType.FUKU_MEM_OPERAND_BASE_ONLY |
                FukuMemOperandType.FUKU_MEM_OPERAND_BASE_DISP
            ):
                if base_idx == FukuRegisterIndex.FUKU_REG_INDEX_SP:
                    raw_operand.set_sib(
                        FukuOperandScale.FUKU_OPERAND_SCALE_1,
                        FukuRegisterIndex.FUKU_REG_INDEX_SP,
                        base_idx
                    )

                disp = rm_reg.disp

                # [base + disp/r]
                if disp.immediate32 == 0 and base_idx != FukuRegisterIndex.FUKU_REG_INDEX_BP:
                    raw_operand.set_modrm(1, reg, base_idx)
                elif self.is_used_short_disp and disp.is_8:
                    # [base + disp8]
                    raw_operand.set_modrm(1, reg, base_idx)
                    raw_operand.set_disp8(disp.immediate8)
                else:
                    # [base + disp/r]
                    raw_operand.set_modrm(2, reg, base_idx)
                    raw_operand.set_dispr(disp.immediate32)

            case (
                FukuMemOperandType.FUKU_MEM_OPERAND_BASE_INDEX |
                FukuMemOperandType.FUKU_MEM_OPERAND_BASE_INDEX_DISP
            ):
                raw_operand.set_sib(rm_reg.scale, index_idx, base_idx)

                # [base + index*scale + disp/r]
                if rm_reg.disp.immediate32 == 0 and base_idx != FukuRegisterIndex.FUKU_REG_INDEX_BP:
                    # [base + index*scale]
                    raw_operand.set_modrm(0, reg, FukuRegisterIndex.FUKU_REG_INDEX_SP)
                elif self.is_used_short_disp and rm_reg.disp.is_8:
                    # [base + index*scale + disp8]
                    raw_operand.set_modrm(1, reg, FukuRegisterIndex.FUKU_REG_INDEX_SP)
                    raw_operand.set_disp8(rm_reg.disp.immediate8)
                else:
                    # [base + index*scale + disp/r]
                    raw_operand.set_modrm(2, reg, FukuRegisterIndex.FUKU_REG_INDEX_SP)
                    raw_operand.set_dispr(rm_reg.disp.immediate32)

            case FukuMemOperandType.FUKU_MEM_OPERAND_INDEX_DISP:
                assert index_idx != FukuRegisterIndex.FUKU_REG_INDEX_SP

                raw_operand.set_modrm(0, reg, FukuRegisterIndex.FUKU_REG_INDEX_SP)
                raw_operand.set_sib(rm_reg.scale, index_idx, FukuRegisterIndex.FUKU_REG_INDEX_BP)
                raw_operand.set_dispr(rm_reg.disp.immediate32)

            case _:
                raise AssertionError("Unhandled case")

        self.bytecode += raw_operand.data[:raw_operand.operand_size]

    def emit_operand_x64(self, rm_reg: FukuOperand, reg: FukuRegisterIndex):
        raw_operand = RawOperand(
            ctx = self
        )

        base_idx = rm_reg.base.index
        index_idx = rm_reg.index.index

        match rm_reg.type:
            case FukuMemOperandType.FUKU_MEM_OPERAND_DISP_ONLY:
                raw_operand.set_modrm(0, reg, FukuRegisterIndex.FUKU_REG_INDEX_BP)
                raw_operand.set_dispr(rm_reg.disp.immediate32)

            case (
                FukuMemOperandType.FUKU_MEM_OPERAND_BASE_ONLY |
                FukuMemOperandType.FUKU_MEM_OPERAND_BASE_DISP
            ):
                if base_idx == FukuRegisterIndex.FUKU_REG_INDEX_SP:
                    raw_operand.set_sib(
                        FukuOperandScale.FUKU_OPERAND_SCALE_1,
                        FukuRegisterIndex.FUKU_REG_INDEX_SP,
                        base_idx
                    )

                disp = rm_reg.disp

                # [base + disp/r]
                if disp.immediate32 == 0 and base_idx != FukuRegisterIndex.FUKU_REG_INDEX_BP:
                    # [base]
                    raw_operand.set_modrm(0, reg, base_idx)
                elif self.is_used_short_disp and disp.is_8:
                    # [base + disp8]
                    raw_operand.set_modrm(1, reg, base_idx)
                    raw_operand.set_disp8(disp.immediate8)
                else:
                    # [base + disp/r]
                    raw_operand.set_modrm(2, reg, base_idx)
                    raw_operand.set_dispr(disp.immediate32)

            case (
                FukuMemOperandType.FUKU_MEM_OPERAND_BASE_INDEX |
                FukuMemOperandType.FUKU_MEM_OPERAND_BASE_INDEX_DISP
            ):
                assert index_idx != FukuRegisterIndex.FUKU_REG_INDEX_SP

                raw_operand.set_sib(rm_reg.scale, index_idx, base_idx)
                # [base + index*scale + disp/r]
                if rm_reg.disp.immediate32 == 0 and base_idx != FukuRegisterIndex.FUKU_REG_INDEX_BP:
                    raw_operand.set_modrm(0, reg, FukuRegisterIndex.FUKU_REG_INDEX_SP)
                elif self.is_used_short_disp and rm_reg.disp.is_8:
                    # [base + index*scale + disp8]
                    raw_operand.set_modrm(1, reg, FukuRegisterIndex.FUKU_REG_INDEX_BP)
                    raw_operand.set_disp8(rm_reg.disp.immediate8)
                else:
                    # [base + index*scale + disp/r]
                    raw_operand.set_modrm(2, reg, FukuRegisterIndex.FUKU_REG_INDEX_SP)
                    raw_operand.set_dispr(rm_reg.disp.immediate32)

            case FukuMemOperandType.FUKU_MEM_OPERAND_INDEX_DISP:
                assert index_idx != FukuRegisterIndex.FUKU_REG_INDEX_SP

                # [index*scale + disp/r]
                raw_operand.set_modrm(0, reg, FukuRegisterIndex.FUKU_REG_INDEX_SP)
                raw_operand.set_sib(rm_reg.scale, index_idx, FukuRegisterIndex.FUKU_REG_INDEX_BP)
                raw_operand.set_dispr(rm_reg.disp.immediate32)

            case _:
                assert True

        self.bytecode.append(raw_operand.data[0] | reg.value << 3)
        self.bytecode += raw_operand.data[1:raw_operand.operand_size]

    def emit_operand(self, rm_reg: FukuOperand, reg: FukuRegister | int = None):
        index = reg.index if isinstance(reg, FukuRegister) else FukuRegisterIndex(reg)
        if self.arch == FUKU_ASSEMBLER_ARCH.X86:
            self.emit_operand_x86(rm_reg, index)
        else:
            self.emit_operand_x64(rm_reg, index)

RawOperand.model_rebuild()
