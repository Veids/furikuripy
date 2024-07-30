from abc import ABC, abstractmethod
import ctypes
from enum import Enum
import struct
from typing import Annotated, Any

from pydantic import (
    InstanceOf,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    WrapValidator,
)


class R_AMD64(ABC):
    @classmethod
    @abstractmethod
    def get_reloc_dst(cls, line: "FukuInst", reloc_offset: int) -> int:
        pass

    @classmethod
    @abstractmethod
    def set_reloc_dst(cls, line: "FukuInst", reloc_offset: int, address: int):
        pass


class R_AMD64_PLT32(R_AMD64):
    struct_format = "<I"
    field_size = 4

    @classmethod
    def get_reloc_dst(cls, line: "FukuInst", reloc_offset: int) -> int:
        return struct.unpack(
            cls.struct_format, line.opcode[reloc_offset : reloc_offset + cls.field_size]
        )[0]

    @classmethod
    def set_reloc_dst(cls, line: "FukuInst", reloc_offset: int, address: int):
        line.opcode[reloc_offset : reloc_offset + cls.field_size] = struct.pack(
            cls.struct_format, ctypes.c_uint32(address).value
        )


relocation_types_map = {4: R_AMD64_PLT32}


class UnandledRelocationTypeException(Exception):
    pass


def get_relocation_type(
    v: int | InstanceOf[R_AMD64],
    handler: ValidatorFunctionWrapHandler,
    info: ValidationInfo,
) -> InstanceOf[R_AMD64]:
    if isinstance(v, int):
        if r := relocation_types_map.get(v):
            return r
        else:
            raise UnandledRelocationTypeException(f"Relocation type {v} is not handled")
    elif issubclass(v, R_AMD64):
        return v

    raise UnandledRelocationTypeException(f"Invalid relocation type: {v}")


FukuRelocationX64Type = Annotated[
    InstanceOf[R_AMD64], WrapValidator(get_relocation_type)
]
