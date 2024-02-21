from pydantic import BaseModel, ConfigDict

from capstone import *
from fuku_misc import FukuObfuscationSettings


class FukuMutationX64(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    settings: FukuObfuscationSettings
    cs: Cs

    def __init__(self, **kwargs):
        kwargs["cs"] = Cs(CS_ARCH_X86, CS_MODE_64)
        kwargs["cs"].detail = True

        super().__init__(**kwargs)
