import itertools

from typing import List, Tuple, Dict, Optional
from pydantic import BaseModel

from furikuripy.fuku_inst import (
    FukuInst,
    FukuRipRelocation,
    FukuCodeLabel,
    FukuRelocation,
    FukuRelocationBase,
)
from furikuripy.fuku_misc import FUKU_ASSEMBLER_ARCH, FukuInstFlags
from furikuripy.fuku_relocation import FukuImageRelocationX64Type
from furikuripy.common import log


class FukuImageRelocation(FukuRelocationBase):
    relocation_id: int = 0
    virtual_address: int = 0
    symbol: str = ""


class FukuImageRelocationX64(FukuImageRelocation):
    type: FukuImageRelocationX64Type


class FukuCodeHolder(BaseModel):
    arch: FUKU_ASSEMBLER_ARCH

    labels: List[FukuCodeLabel] = list()
    relocations: List[FukuRelocation] = list()
    rip_relocations: List[FukuRipRelocation] = list()

    available_relocations: List[FukuRelocation] = list()
    available_rip_relocations: List[FukuRipRelocation] = list()

    source_intructions: List[FukuInst] = list()

    instructions: List[FukuInst] = list()

    def clear(self):
        self.labels.clear()
        self.relocations.clear()
        self.rip_relocations.clear()
        self.available_rip_relocations.clear()
        self.source_intructions.clear()
        self.instructions.clear()

    def update_source_insts(self):
        self.source_intructions.clear()

        for inst in self.instructions:
            if inst.has_source_address:
                self.source_intructions.append(inst)

        self.source_intructions.sort(key=lambda x: x.source_address)

    def create_label(self, label):
        if label.inst is not None and label.inst.label:
            return label.inst.label

        self.labels.append(label)
        return label

    # TODO: eliminate this
    def create_relocation(self, reloc: FukuRelocation) -> FukuRelocation:
        if len(self.available_relocations):
            _ = self.available_relocations.pop()
            return reloc
        else:
            self.relocations.append(reloc)
            return reloc

    # TODO: eliminate this
    def create_rip_relocation(self, rip_relloc: FukuRipRelocation):
        if len(self.available_rip_relocations):
            _ = self.available_rip_relocations.pop()
            return rip_relloc
        else:
            self.rip_relocations.append(rip_relloc)
            return rip_relloc

    def dump_code(self) -> bytearray:
        code = bytearray()

        for inst in self.instructions:
            code += inst.opcode

        return code

    def finalize_code(self, symbol="") -> Tuple[bool, Dict, List]:
        associations = {}
        relocations = []

        for inst in self.instructions:
            if inst.has_source_address:
                associations[inst.source_address] = inst.current_address

            if inst.disp_reloc:
                if inst.disp_reloc.symbol == symbol:
                    if inst.disp_reloc.label.has_linked_instruction:
                        inst.disp_reloc.set_reloc_dst(
                            inst,
                            inst.disp_reloc.offset,
                            inst.disp_reloc.label.inst.current_address,
                        )
                    else:
                        inst.disp_reloc.set_reloc_dst(
                            inst, inst.disp_reloc.offset, inst.disp_reloc.label.address
                        )

                relocations.append(
                    FukuImageRelocation(
                        relocation_id=inst.disp_reloc.reloc_id,
                        virtual_address=inst.current_address + inst.disp_reloc.offset,
                        type=inst.disp_reloc.type,
                    )
                )
            elif inst.rip_reloc:
                if inst.rip_reloc.label.has_linked_instruction:
                    value = (
                        inst.rip_reloc.label.inst.current_address
                        - inst.current_address
                        - len(inst.opcode)
                    )
                else:
                    value = (
                        inst.rip_reloc.label.address
                        - inst.current_address
                        - len(inst.opcode)
                    )

                inst.rip_reloc.set_reloc_dst(inst, inst.rip_reloc.offset, value)

            if inst.imm_reloc:
                if inst.imm_reloc.label.has_linked_instruction:
                    inst.imm_reloc.set_reloc_dst(
                        inst,
                        inst.imm_reloc.offset,
                        inst.imm_reloc.label.inst.current_address,
                    )
                else:
                    inst.imm_reloc.set_reloc_dst(
                        inst, inst.imm_reloc.offset, inst.imm_reloc.label.address
                    )

                relocations.append(
                    FukuImageRelocation(
                        relocation_id=inst.imm_reloc.reloc_id,
                        virtual_address=inst.current_address + inst.imm_reloc.offset,
                        type=inst.imm_reloc.type,
                    )
                )

        return True, associations, relocations

    def add_inst(self):
        new_inst = FukuInst()
        self.instructions.append(new_inst)

        return new_inst

    def get_source_inst_range(self, virtual_address: int) -> Optional[FukuInst]:
        if (
            len(self.source_intructions)
            and self.source_intructions[0].source_address <= virtual_address
            and (
                self.source_intructions[-1].source_address
                + len(self.source_intructions[-1].opcode)
            )
            >= virtual_address
        ):
            left = 0
            right = len(self.source_intructions)
            mid = 0

            while left < right:
                mid = left + (right - left) // 2

                inst = self.source_intructions[mid]
                if (
                    inst.source_address <= virtual_address
                    and (inst.source_address + len(inst.opcode)) > virtual_address
                ):
                    return inst
                elif inst.source_address > virtual_address:
                    right = mid
                else:
                    left = mid + 1

        return None

    def get_source_inst_direct(self, virtual_address):
        if (
            len(self.source_intructions)
            and self.source_intructions[0].source_address <= virtual_address
            and self.source_intructions[-1].source_address >= virtual_address
        ):
            left = 0
            right = len(self.source_intructions)
            mid = 0

            while left < right:
                mid = left + (right - left) // 2

                if self.source_intructions[mid].source_address == virtual_address:
                    return self.source_intructions[mid]
                elif self.source_intructions[mid].source_address > virtual_address:
                    right = mid
                else:
                    left = mid + 1

        return None

    def resolve_labels(self):
        delete_labels = list()
        remap_labels = {}

        for label in self.labels:
            if not label.has_linked_instruction:
                inst_dst = self.get_source_inst_direct(label.address)

                if inst_dst:
                    if inst_dst.label is not None:
                        delete_labels.append(label)
                        remap_labels[label] = inst_dst.label
                    else:
                        label.inst = inst_dst
                        inst_dst.label = label

                    if inst_dst.flags & FukuInstFlags.FUKU_INST_DATA_CODE:
                        log.critical(
                            "Some instruction referenced data code, ensure it's handled properly on your own"
                        )

        if not len(remap_labels):
            return

        for reloc in itertools.chain(self.relocations, self.rip_relocations):
            if reloc.label is not None:
                if reloc_map_label := remap_labels.get(reloc.label):
                    reloc.label = reloc_map_label

        for x in reversed(delete_labels):
            self.labels.remove(x)

    def update_current_address(self, virtual_address: int):
        for inst in self.instructions:
            inst.current_address = virtual_address
            virtual_address += len(inst.opcode)
