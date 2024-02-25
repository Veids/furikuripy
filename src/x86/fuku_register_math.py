from x86.fuku_register_math_tables import FULL_INCLUDE_FLAGS_TABLE


def bit_scan_forward(index, mask):
    while index < 64:
        if mask & (1 << index):
            return index

        index += 1

    return None


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
