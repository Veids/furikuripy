from pydantic import BaseModel

from furikuripy.fuku_misc import FukuObfuscationSettings


class FukuMutationX86(BaseModel):
    settings: FukuObfuscationSettings
