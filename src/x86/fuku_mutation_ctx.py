from copy import copy
from typing import Iterable, Optional, Iterator
from pydantic import BaseModel, ConfigDict
from capstone import CsInsn
from more_itertools import seekable

from x86.misc import FukuOperandSize
from x86.fuku_type import FukuType, FukuT0Types
from fuku_asm import FukuAsm
from fuku_code_holder import FukuCodeHolder
from fuku_misc import FukuInstFlags, FukuObfuscationSettings
from fuku_inst import FukuCodeLabel, FukuInst, FukuRelocation


class FukuMutationCtx(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    f_asm: FukuAsm
    code_holder: FukuCodeHolder
    settings: FukuObfuscationSettings

    instruction: Optional[CsInsn] = None

    prev_inst_iter: Optional[Iterable] = None # previus inst iter
    original_inst_iter: Optional[Iterable] = None # current insts row iter
    payload_inst_iter: Optional[Iterable] = None # current insts "payload" iter
    next_inst_iter: Optional[Iterable] = None # next inst iter

    original_start_label: Optional[FukuCodeLabel] = None
    payload_start_label: Optional[FukuCodeLabel] = None

    is_first_inst: bool = False # is inst iter on begin
    is_next_last_inst: bool = False # is next inst iter on end
    has_source_address: bool = False # is inst has source address

    inst_flags: int = 0
    cpu_flags: int = 0
    cpu_registers: int = 0
    source_address: int = 0

    def initialize_context(self, iter: Iterable):
        inst: FukuInst = iter.peek()

        self.is_first_inst = self.code_holder.instructions.index(inst) == 0

        idx = self.code_holder.instructions.index(iter.peek())
        self.prev_inst_iter = seekable(self.code_holder.instructions)
        if not self.is_first_inst:
            self.prev_inst_iter.seek(idx)

        self.original_inst_iter = copy(iter)
        self.payload_inst_iter = copy(iter)
        self.next_inst_iter = copy(iter)
        next(self.next_inst_iter)

        self.is_next_last_inst = not bool(self.next_inst_iter)

        self.original_start_label = inst.label
        self.payload_start_label = None

        self.cpu_flags = inst.cpu_flags
        self.cpu_registers = inst.cpu_registers
        self.inst_flags = inst.flags.inst_flags
        self.has_source_address = inst.has_source_address

        if self.has_source_address:
            self.source_address = inst.source_address

    def generate_payload_label(self):
        if not self.payload_start_label:
            self.payload_start_label = self.code_holder.create_label(FukuCodeLabel())

        return self.payload_start_label

    def calc_original_inst_iter(self) -> Iterator:
        if self.is_first_inst:
            return seekable(self.code_holder.instructions)
        else:
            idx = self.code_holder.instructions.index(self.prev_inst_iter.peek())
            iter = seekable(self.code_holder.instructions)
            iter.seek(idx + 1)
            return iter

    def update_payload_inst_iter(self) -> Iterator:
        idx = self.code_holder.instructions.index(self.next_inst_iter.peek())
        iter = seekable(self.code_holder.instructions)
        iter.seek(idx)
        return iter

    def calc_next_inst_iter(self) -> Iterator:
        idx = self.code_holder.instructions.index(self.next_inst_iter.peek())
        iter = seekable(self.code_holder.instructions)
        iter.seek(idx)
        return iter

    @property
    def is_allowed_stack_operations(self) -> bool:
        return not (self.inst_flags & FukuInstFlags.FUKU_INST_BAD_STACK.value)

    def restore_disp_relocate(self, op: FukuType, disp_reloc, used_disp_reloc) -> bool:
        if op.type == FukuT0Types.FUKU_T0_OPERAND and disp_reloc and used_disp_reloc:
            self.f_asm.context.inst.disp_reloc = disp_reloc
            disp_reloc.offset = self.f_asm.context.displacment_offset
            return True

        return False

    def restore_imm_relocate(self, op: FukuType, imm_reloc, inst_size: int) -> bool:
        if (
            inst_size == FukuOperandSize.FUKU_OPERAND_SIZE_64.value and
            op.type == FukuT0Types.FUKU_T0_IMMEDIATE and imm_reloc
        ):
            self.f_asm.context.inst.imm_reloc = imm_reloc
            imm_reloc.offset = self.f_asm.context.immediate_offset
            return True

        return False

    def restore_rip_to_imm_relocate(self, op: FukuType, rip_reloc, used_disp_reloc) -> bool:
        if op.type == FukuT0Types.FUKU_T0_IMMEDIATE and rip_reloc and not used_disp_reloc:
            self.f_asm.context.inst.imm_reloc = self.code_holder.create_relocation(
                FukuRelocation(
                    label = rip_reloc.label,
                    offset = self.f_asm.context.immediate_offset
                )
            )
            rip_reloc.label = None
            self.code_holder.rip_relocations.remove(rip_reloc)
            return True

        return False

    def restore_rip_relocate_in_imm(self, op: FukuType, rip_reloc, used_disp_reloc: bool, inst_size: int) -> bool:
        if (
            inst_size == FukuOperandSize.FUKU_OPERAND_SIZE_64.value and
            op.type == FukuT0Types.FUKU_T0_IMMEDIATE and
            rip_reloc and not used_disp_reloc
        ):
            self.f_asm.context.inst.rip_reloc = rip_reloc
            rip_reloc.offset = self.f_asm.context.immediate_offset
            return True

        return False

    def restore_imm_or_disp(self, op: FukuType, disp_reloc, used_disp_reloc, imm_reloc, inst_size):
        if not self.restore_disp_relocate(op, disp_reloc, used_disp_reloc):
            self.restore_imm_relocate(op, imm_reloc, inst_size)
