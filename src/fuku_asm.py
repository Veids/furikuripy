from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict

from fuku_inst import FukuInst, FukuCodeLabel
from fuku_code_holder import FukuCodeHolder
from x86.fuku_asm_ctx import FukuAsmCtx
from x86.fuku_asm_body import FukuAsmBody


class FukuAsmHoldType(Enum):
    ASSEMBLER_HOLD_TYPE_NOOVERWRITE = 0
    ASSEMBLER_HOLD_TYPE_FIRST_OVERWRITE = 1
    ASSEMBLER_HOLD_TYPE_FULL_OVERWRITE = 2


class FukuAsm(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    inst: FukuInst = FukuInst()
    context: Optional[FukuAsmCtx] = None

    hold_type: FukuAsmHoldType = FukuAsmHoldType.ASSEMBLER_HOLD_TYPE_NOOVERWRITE
    code_holder: FukuCodeHolder

    first_emit: bool = True
    has_label_to_set: bool = False
    label: Optional[FukuCodeLabel] = None

    asm: FukuAsmBody = FukuAsmBody()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        kwargs["context"] = FukuAsmCtx(
            arch = kwargs["code_holder"].arch,
            short_cfg = 0xFF,
            inst = self.inst
        )

        from IPython import embed; embed()  # DEBUG


#     def set_holder(self, code_holder: FukuCodeHolder, hold_type: FukuAsmHoldType):
#         self.code_holder = code_holder
#         self.hold_type = hold_type
#         # this->position = this->code_holder->get_insts().begin();
