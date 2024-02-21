from pydantic import BaseModel
from fuku_misc import FukuObfuscationSettings


class FukuMutationX86(BaseModel):
    settings: FukuObfuscationSettings
