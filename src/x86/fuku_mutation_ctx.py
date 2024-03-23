from typing import Optional
from pydantic import BaseModel, ConfigDict
from capstone import CsInsn

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

    prev_inst: Optional[FukuInst] = None
    payload_inst: Optional[FukuInst] = None
    next_inst: Optional[FukuInst] = None

    original_start_label: Optional[FukuCodeLabel] = None
    payload_start_label: Optional[FukuCodeLabel] = None

    is_first_inst: bool = False # is inst iter on begin
    is_next_last_inst: bool = False # is next inst iter on end
    has_source_address: bool = False # is inst has source address

    inst_flags: int = 0
    cpu_flags: int = 0
    cpu_registers: int = 0
    source_address: int = 0

    def initialize_context(self, inst: FukuInst, next_inst: Optional[FukuInst]):
        cur_idx = self.code_holder.instructions.index(inst)

        self.is_first_inst = cur_idx == 0
        if not self.is_first_inst:
            self.prev_inst = self.code_holder.instructions[cur_idx - 1]

        self.payload_inst = inst

        if cur_idx == len(self.code_holder.instructions) - 1:
            self.next_inst = None
            self.is_next_last_inst = True
        else:
            self.next_inst = self.code_holder.instructions[cur_idx + 1]
            self.is_next_last_inst = False

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

    def calc_original_inst(self) -> FukuInst:
        if self.is_first_inst:
            return self.code_holder.instructions[0]
        else:
            idx = self.code_holder.instructions.index(self.prev_inst) + 1
            return self.code_holder.instructions[idx]

    def update_payload_inst_iter(self):
        if not self.next_inst:
            return self.code_holder.instructions[-1]

        idx = self.code_holder.instructions.index(self.next_inst) - 1
        return self.code_holder.instructions[idx]

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
            inst_size == FukuOperandSize.SIZE_64.value and
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
            inst_size == FukuOperandSize.SIZE_64.value and
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
