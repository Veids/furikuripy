from typing import Optional, ForwardRef
from pydantic import BaseModel, StrictBytes

FukuInst = ForwardRef("FukuInst")


class FukuCodeLabel(BaseModel):
    __hash__ = object.__hash__

    label_tag: int = 0
    label_id: int = 0

    address: Optional[int] = None
    inst: Optional[FukuInst] = None

    @property
    def has_linked_instruction(self):
        return self.inst is not None


class FukuRelocation(BaseModel):
    reloc_id: int = 0
    offset: int = 0
    label: Optional[FukuCodeLabel] = None


class FukuRipRelocation(BaseModel):
    offset: int = 0
    label: Optional[FukuCodeLabel] = None


class Flags(BaseModel):
    inst_used_disp: int = 0
    inst_has_address: int = 0
    inst_flags: int = 0


class FukuInst(BaseModel):
    id: int = -1

    opcode: Optional[StrictBytes] = None

    source_address: Optional[int] = None
    current_address: int = 0

    _label: Optional[FukuCodeLabel] = None

    imm_reloc: Optional[FukuRelocation] = None

    disp_reloc: Optional[FukuRelocation] = None
    rip_reloc: Optional[FukuRipRelocation] = None

    cpu_flags: int = 0
    cpu_registers: int = 0

    flags: Flags = Flags()

    @property
    def inst_has_address(self):
        return self.source_address is not None

    @property
    def has_source_address(self):
        return self.source_address is not None

    @property
    def inst_used_disp(self):
        return self.disp_reloc is not None

    @property
    def label(self):
        return self._label

    @label.setter
    def label(self, value):
        self._label = value

        if self._label:
            self._label.inst = self

    def prefix_count(self) -> int:
        i = 0

        for i, byte in enumerate(self.opcode):
            if byte not in [
                0xF0, # lock
                0xF3, # repe
                0x2E, # repne
                0x36, # ss
                0x3E, # ds
                0x26, # es
                0x64, # fs
                0x65, # gs
            ]:
                return i

        return i

    def update(self, src: FukuInst):
        self.opcode = src.opcode
        self.id = src.id

        self.source_address = src.source_address
        self.current_address = src.current_address
        self.label = src.label
        self.imm_reloc = src.imm_reloc
        self.disp_reloc = src.disp_reloc
        self.cpu_flags = src.cpu_flags
        self.cpu_registers = src.cpu_registers
        self.flags.inst_flags = src.flags.inst_flags
        self.flags.inst_used_disp = src.flags.inst_used_disp
        self.flags.inst_has_address = src.flags.inst_has_address
