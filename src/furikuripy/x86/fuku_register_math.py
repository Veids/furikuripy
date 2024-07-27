from capstone import x86_const

from furikuripy.common import rng
from furikuripy.x86.fuku_register_math_tables import FULL_INCLUDE_FLAGS_TABLE
from furikuripy.x86.fuku_register_math_metadata import EflagsMod


def bit_scan_forward(index, mask):
    while index < 64:
        if mask & (1 << index):
            return index

        index += 1

    return None


def bit_scan_backward(index, mask):
    while index != -1:
        if mask & (1 << index):
            return index

        index -= 1

    return None


def get_random_bit_by_mask(mask: int, min_index: int, max_index: int):
    rand_idx = rng.randint(min_index, max_index)

    if rand_idx == min_index:
        return bit_scan_forward(rand_idx, mask)
    elif rand_idx == max_index:
        return bit_scan_backward(rand_idx, mask)

    index = bit_scan_forward(rand_idx, mask)

    if not index or index > max_index:
        index = bit_scan_backward(rand_idx, mask)

    return index

def has_flag_free_register(regs_flags: int, reg: int) -> bool:
    return (regs_flags & reg) == reg

def has_free_eflags(inst_eflags: int, flags: int) -> bool:
    pairs = (
        (x86_const.X86_EFLAGS_MODIFY_CF, EflagsMod.CF.value),
        (x86_const.X86_EFLAGS_MODIFY_OF, EflagsMod.OF.value),
        (x86_const.X86_EFLAGS_MODIFY_ZF, EflagsMod.ZF.value),
        (x86_const.X86_EFLAGS_MODIFY_DF, EflagsMod.DF.value),
        (x86_const.X86_EFLAGS_MODIFY_SF, EflagsMod.SF.value),
        (x86_const.X86_EFLAGS_MODIFY_PF, EflagsMod.PF.value),
        (x86_const.X86_EFLAGS_MODIFY_AF, EflagsMod.AF.value),
    )

    for x, y in pairs:
        if flags & x:
            if not (inst_eflags & y):
                return False

    return True


def get_flag_complex_register(flag_reg: int) -> int:
    index = 0

    if not (index := bit_scan_forward(index, flag_reg)):
        return 0

    reg_index = int(index % 16)

    return FULL_INCLUDE_FLAGS_TABLE[reg_index]


def get_flag_complex_register_by_size(flag_reg):
    index = 0

    if not (index := bit_scan_forward(index, flag_reg)):
        return 0

    size = int((index / 16) + 1)
    reg_index = int(index % 16)

    match size:
        case 1:
            return FULL_INCLUDE_FLAGS_TABLE[reg_index] & 0xFFFF

        case 2:
            return FULL_INCLUDE_FLAGS_TABLE[reg_index] & 0xFFFFFFFF

        case 3:
            return FULL_INCLUDE_FLAGS_TABLE[reg_index] & 0xFFFFFFFFFFFF

        case 4:
            return FULL_INCLUDE_FLAGS_TABLE[reg_index] & 0xFFFFFFFFFFFFFFFF

    return FULL_INCLUDE_FLAGS_TABLE[reg_index]
