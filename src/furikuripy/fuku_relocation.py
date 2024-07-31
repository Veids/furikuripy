from abc import ABC
import ctypes
import struct
from typing import Annotated, Callable

from pydantic import (
    InstanceOf,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    WrapValidator,
)


class RelocationBase(ABC):
    struct_format: str
    field_size: int
    converter: Callable

    @classmethod
    def get_reloc_dst(cls, line: "FukuInst", reloc_offset: int) -> int:
        return struct.unpack(
            cls.struct_format, line.opcode[reloc_offset : reloc_offset + cls.field_size]
        )[0]

    @classmethod
    def set_reloc_dst(cls, line: "FukuInst", reloc_offset: int, address: int):
        line.opcode[reloc_offset : reloc_offset + cls.field_size] = struct.pack(
            cls.struct_format, cls.converter(address).value
        )


class IMAGE_R_AMD64_REL32(RelocationBase):
    struct_format = "<I"
    field_size = 4
    converter = ctypes.c_uint32


class R_X86_64_PC32(RelocationBase):
    struct_format = "<I"
    field_size = 4
    converter = ctypes.c_uint32


image_relocation_types_map = {4: IMAGE_R_AMD64_REL32}


class UnandledRelocationTypeException(Exception):
    pass


def get_relocation_type(
    v: int | InstanceOf[RelocationBase],
    handler: ValidatorFunctionWrapHandler,
    info: ValidationInfo,
) -> InstanceOf[RelocationBase]:
    if isinstance(v, int):
        if r := image_relocation_types_map.get(v):
            return r
        else:
            raise UnandledRelocationTypeException(f"Relocation type {v} is not handled")
    elif issubclass(v, RelocationBase):
        return v

    raise UnandledRelocationTypeException(f"Invalid relocation type: {v}")


FukuImageRelocationX64Type = Annotated[
    InstanceOf[RelocationBase], WrapValidator(get_relocation_type)
]
