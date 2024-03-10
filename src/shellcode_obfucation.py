import sys
import time

from fuku_obfuscator import FukuObfuscator
from fuku_code_holder import FukuCodeHolder
from fuku_code_analyzer import FukuCodeAnalyzer
from fuku_code_profiler import FukuCodeProfiler
from fuku_misc import FUKU_ASSEMBLER_ARCH, FukuObfuscationSettings
from x86.misc import FukuAsmShortCfg

if __name__ == "__main__":
    relocations_allowed = True

    arch = FUKU_ASSEMBLER_ARCH.X86 if sys.argv[1] == "x86" else FUKU_ASSEMBLER_ARCH.X64
    data = open(sys.argv[2], "rb").read()

    code_holder = FukuCodeHolder(arch = arch)
    code_analyzer = FukuCodeAnalyzer(arch = arch)

    code_analyzer.analyze_code(code_holder, data[:-28], 0, None)

    code_profiler = FukuCodeProfiler(arch = arch)
    code_profiler.profile_code(code_holder)

    obfuscation_code_analyzer = FukuCodeAnalyzer(arch = arch, code = code_holder)

    settings = FukuObfuscationSettings(
        complexity = 3,
        number_of_passes = 1,
        junk_chance = 30,
        block_chance = 30,
        mutate_chance = 30,
        asm_cfg = (
            FukuAsmShortCfg.FUKU_ASM_SHORT_CFG_USE_EAX_SHORT.value |
            FukuAsmShortCfg.FUKU_ASM_SHORT_CFG_USE_DISP_SHORT.value |
            FukuAsmShortCfg.FUKU_ASM_SHORT_CFG_USE_IMM_SHORT.value
        ),
        not_allowed_unstable_stack = False,
        not_allowed_relocations = not relocations_allowed
    )

    obfuscator = FukuObfuscator(
        code = obfuscation_code_analyzer.code,
        settings = settings
    )

    start_time = time.time()

    obfuscator.obfuscate_code()

    res, associations, relocations = obfuscation_code_analyzer.code.finalize_code()
    code = obfuscation_code_analyzer.code.dump_code()
    code += data[-28:]
