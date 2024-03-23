import typer
import random
import sys
import time

from datetime import datetime
from typing import Annotated, Optional

from common import log, rng
from fuku_obfuscator import FukuObfuscator
from fuku_code_holder import FukuCodeHolder
from fuku_code_analyzer import FukuCodeAnalyzer
from fuku_code_profiler import FukuCodeProfiler
from fuku_misc import FUKU_ASSEMBLER_ARCH, FukuObfuscationSettings
from x86.misc import FukuAsmShortCfg

app = typer.Typer(pretty_exceptions_show_locals=False)


def get_rand_seed() -> int:
    return random.randrange(sys.maxsize)


@app.command()
def main(
    arch: FUKU_ASSEMBLER_ARCH,
    input: Annotated[typer.FileBinaryRead, typer.Argument()],
    output: Annotated[typer.FileBinaryRead, typer.Argument(mode="wb+")],
    seed: Annotated[int, typer.Option(default_factory=get_rand_seed)],
    ranges: Annotated[
        Optional[int],
        typer.Option(help="specify ranges to skip data (ex. 1-100,120-500)"),
    ] = None,
    relocations_allowed: Annotated[
        bool, typer.Option(help="allow relocations")
    ] = False,
    complexity: Annotated[
        int, typer.Option(help="number of passes for single line")
    ] = 3,
    number_of_passes: Annotated[int, typer.Option(min=1)] = 2,
    junk_chance: Annotated[int, typer.Option(min=0, max=100)] = 30,
    block_chance: Annotated[int, typer.Option(min=0, max=100)] = 30,
    mutate_chance: Annotated[int, typer.Option(min=0, max=100)] = 30,
    forbid_stack_operations: bool = False,
):
    log.info(f"Seed: {seed}")

    rng.seed(seed)
    data = input.read()
    if not ranges:
        ranges = len(data)

    virtual_address = 0
    code_holder = FukuCodeHolder(arch=arch)
    code_analyzer = FukuCodeAnalyzer(arch=arch)

    code_analyzer.analyze_code(code_holder, data[:ranges], virtual_address, None)

    # debug
    inst = code_holder.add_inst()
    inst.source_address = virtual_address + data.index(data[ranges])
    inst.opcode = bytearray(data[ranges:])
    inst.id = -1
    code_holder.update_source_insts()
    code_holder.resolve_labels()
    # debug_end

    code_profiler = FukuCodeProfiler(arch=arch)
    code_profiler.profile_code(code_holder)

    obfuscation_code_analyzer = FukuCodeAnalyzer(arch=arch, code=code_holder)

    settings = FukuObfuscationSettings(
        complexity=complexity,
        number_of_passes=number_of_passes,
        junk_chance=junk_chance,
        block_chance=block_chance,
        mutate_chance=mutate_chance,
        asm_cfg=(
            FukuAsmShortCfg.USE_EAX_SHORT.value
            | FukuAsmShortCfg.USE_DISP_SHORT.value
            | FukuAsmShortCfg.USE_IMM_SHORT.value
        ),
        is_not_allowed_unstable_stack=forbid_stack_operations,
        is_not_allowed_relocations=not relocations_allowed,
    )

    obfuscator = FukuObfuscator(code=obfuscation_code_analyzer.code, settings=settings)

    start_time = time.time()

    obfuscator.obfuscate_code()

    res, associations, relocations = obfuscation_code_analyzer.code.finalize_code()
    code = obfuscation_code_analyzer.code.dump_code()
    end_time = time.time()

    # code += data[ranges:]

    log.info(
        f"Finished in {datetime.fromtimestamp(end_time) - datetime.fromtimestamp(start_time)}"
    )
    output.write(code)


if __name__ == "__main__":
    app()
