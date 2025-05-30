from __future__ import annotations


from abc import ABC
from typing import Any, Optional, Self, Type
from pydantic import BaseModel, StrictBytes

from furikuripy.fuku_misc import FukuInstFlags
from furikuripy.fuku_relocation import FukuImageRelocationX64Type, IMAGE_R_AMD64_REL32


class FukuCodeLabel(BaseModel):
    __hash__ = object.__hash__

    label_tag: int = 0
    label_id: int = 0

    address: Optional[int] = None
    inst: Optional[FukuInst] = None

    @property
    def has_linked_instruction(self):
        return self.inst is not None


class FukuRelocationBase(BaseModel, ABC):
    type: Any

    def get_reloc_dst(self, line: FukuInst, reloc_offset: int) -> int:
        return self.type.get_reloc_dst(line, reloc_offset)

    def set_reloc_dst(self, line: FukuInst, reloc_offset: int, address: int):
        self.type.set_reloc_dst(line, reloc_offset, address)


class FukuRelocation(FukuRelocationBase):
    reloc_id: int = 0
    offset: int = 0
    label: Optional[FukuCodeLabel] = None
    type: FukuImageRelocationX64Type
    symbol: str


class FukuRipRelocation(FukuRelocationBase):
    offset: int = 0
    label: Optional[FukuCodeLabel] = None
    type: Type[IMAGE_R_AMD64_REL32] = IMAGE_R_AMD64_REL32


class FukuInst(BaseModel):
    __eq__ = object.__eq__
    __hash__ = object.__hash__

    id: int = -1

    opcode: Optional[StrictBytes] = None

    source_address: Optional[int] = None
    current_address: int = 0

    _label: Optional[FukuCodeLabel] = None

    imm_reloc: Optional[FukuRelocation] = None

    disp_reloc: Optional[FukuRelocation] = None
    _rip_reloc: Optional[FukuRipRelocation] = None

    cpu_flags: int = 0
    cpu_registers: int = 0

    offset: int = 0
    flags: FukuInstFlags = FukuInstFlags(0)

    @property
    def inst_has_address(self):
        return self.source_address is not None

    @property
    def has_source_address(self):
        return self.source_address is not None

    @property
    def label(self):
        return self._label

    @label.setter
    def label(self, value):
        self._label = value

        if self._label:
            self._label.inst = self

    @property
    def rip_reloc(self):
        return self._rip_reloc

    @rip_reloc.setter
    def rip_reloc(self, value):
        self._rip_reloc = value

    def prefix_count(self) -> int:
        i = 0

        for i, byte in enumerate(self.opcode):
            if byte not in [
                0xF0,  # lock
                0xF3,  # repe
                0x2E,  # repne
                0x36,  # ss
                0x3E,  # ds
                0x26,  # es
                0x64,  # fs
                0x65,  # gs
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
        self.rip_reloc = src.rip_reloc
        self.cpu_flags = src.cpu_flags
        self.cpu_registers = src.cpu_registers
        self.flags = src.flags
        self.offset = src.offset
