import itertools
from typing import List

from fuku_inst import FukuInst, FukuRipRelocation, FukuCodeLabel, FukuRelocation
from fuku_misc import FUKU_ASSEMBLER_ARCH
from pydantic import BaseModel


class FukuCodeHolder(BaseModel):
    arch: FUKU_ASSEMBLER_ARCH

    labels: List[FukuCodeLabel] = list()
    relocations: List[FukuRelocation] = list()
    rip_relocations: List[FukuRipRelocation] = list()

    available_rip_relocations: List[FukuRipRelocation] = list()

    source_intructions: List[FukuInst] = list()

    instructions: List[FukuInst] = list()

    def clear(self):
        pass

    def update_source_insts(self):
        self.source_intructions.clear()

        for inst in self.instructions:
            if inst.has_source_address:
                self.source_intructions.append(inst)

        self.source_intructions.sort(key = lambda x: x.source_address)

    def create_label(self, label):
        if label.inst is not None and label.inst.get_label():
            return label.inst.get_label()

        self.labels.append(label)
        return label

    def create_rip_relocation(self, rip_relloc: FukuRipRelocation):
        if len(self.available_rip_relocations):
            _ = self.available_rip_relocations.pop()
            return rip_relloc
        else:
            self.rip_relocations.append(rip_relloc)
            return rip_relloc

    def add_inst(self):
        new_inst = FukuInst()
        self.instructions.append(new_inst)

        return new_inst

    def get_source_inst_direct(self, virtual_address):
        if (
            len(self.source_intructions) and
            self.source_intructions[0].source_address <= virtual_address and
            self.source_intructions[-1].source_address >= virtual_address
        ):
            left = 0
            right = len(self.source_intructions)
            mid = 0

            while left < right:
                mid = int(left + (right - left) / 2)

                if self.source_intructions[mid].source_address == virtual_address:
                    return self.source_intructions[mid]
                elif self.source_intructions[mid].source_address > virtual_address:
                    right = mid
                else:
                    left = mid + 1

        return 0

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

        if len(remap_labels):
            return

        for reloc in itertools.chain(self.relocations, self.rip_relocations):
            if reloc.label is not None:
                if reloc_map_label := remap_labels.get(label):
                    reloc.label = reloc_map_label

        for x in reversed(delete_labels):
            self.labels.remove(x)
