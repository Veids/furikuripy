from .jmp import fukutate_64_jmp
from .jcc import fukutate_64_jcc
from .ret import fukutate_64_ret
from .mov import fukutate_64_mov
from .xchg import fukutate_64_xchg
from .push import fukutate_64_push
from .pop import fukutate_64_pop

from .junk import fuku_junk_64_generic

__all__ = [
    fukutate_64_jmp,
    fukutate_64_jcc,
    fukutate_64_ret,
    fukutate_64_mov,
    fukutate_64_xchg,
    fukutate_64_push,
    fukutate_64_pop,

    fuku_junk_64_generic
]
