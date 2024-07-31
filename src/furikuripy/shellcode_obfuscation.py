import typer
import random
import sys
import time
import importlib.metadata

from datetime import datetime
from binascii import unhexlify
from typing import Annotated, Optional, List

from .common import log, rng, parse_ranges_from_args, parse_definitions
from .fuku_obfuscator import FukuObfuscator
from .fuku_code_holder import FukuCodeHolder, FukuImageRelocationX64
from .fuku_code_analyzer import FukuCodeAnalyzer
from .fuku_code_profiler import FukuCodeProfiler
from .fuku_misc import FUKU_ASSEMBLER_ARCH, FukuObfuscationSettings
from .x86.misc import FukuAsmShortCfg

app = typer.Typer(pretty_exceptions_show_locals=False)


def get_rand_seed() -> int:
    return random.randrange(sys.maxsize)


@app.command()
def main(
    arch: FUKU_ASSEMBLER_ARCH,
    input: Annotated[typer.FileBinaryRead, typer.Argument()],
    output: Annotated[typer.FileBinaryRead, typer.Argument(mode="wb+")],
    seed: Annotated[int, typer.Option(default_factory=get_rand_seed)],
    patches: Annotated[
        Optional[List[str]],
        typer.Option(
            help="specify patches to apply (ex. start:PATCHINHEX - 0:665f)",
            default_factory=list,
        ),
    ],
    ranges: Annotated[
        Optional[List[str]],
        typer.Option(help="specify ranges for code/data blocks (ex. c:0:10 or d:10:e)"),
    ] = ["c:0:e"],
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
    virtual_address: int = 0,
    definitions: Annotated[
        Optional[typer.FileText],
        typer.Option(
            "--definitions", "--defs", help="yaml file that contains ranges and patches"
        ),
    ] = None,
    relocations: Annotated[
        Optional[List[str]],
        typer.Option(
            help="specify relocations in format <vaddress>:<type>:<symbol> (e.g. 2:4:.data)"
        ),
    ] = None,
):
    if arch != FUKU_ASSEMBLER_ARCH.X64:
        raise Exception("Unimplemented")

    log.info("Version: %s", importlib.metadata.version("furikuripy"))
    log.info("Seed: %d", seed)

    rng.seed(seed)
    data = bytearray(input.read())

    if definitions:
        ranges, patches = parse_definitions(len(data), definitions.read())
    else:
        ranges = parse_ranges_from_args(len(data), ranges)

    for patch in patches:
        start, bts = patch.split(":")
        start = int(start)
        bts = unhexlify(bts)

        if start < 0:
            start %= len(data)

        for i, b in enumerate(bts):
            data[start + i] = b

    code_holder = FukuCodeHolder(arch=arch)
    code_analyzer = FukuCodeAnalyzer(arch=arch)

    relocs = []
    for i, reloc in enumerate(relocations):
        va, ty, symbol = reloc.split(":")
        va = int(va)
        ty = int(ty)

        if arch == FUKU_ASSEMBLER_ARCH.X64:
            relocs.append(
                FukuImageRelocationX64(
                    relocation_id=i, virtual_address=va, type=ty, symbol=symbol
                )
            )

    for t, start, end in ranges:
        if t.lower() == "c":
            code_analyzer.analyze_code(
                code_holder, data[start:end], virtual_address + start, relocs
            )
        else:
            inst = code_holder.add_inst()
            inst.source_address = virtual_address + start
            inst.opcode = bytearray(data[start:end])
            inst.id = -1
            code_holder.update_source_insts()
            code_holder.resolve_labels()

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

    res, associations, relocationsObfuscated = (
        obfuscation_code_analyzer.code.finalize_code()
    )
    code = obfuscation_code_analyzer.code.dump_code()
    end_time = time.time()

    log.info(
        f"Finished in {datetime.fromtimestamp(end_time) - datetime.fromtimestamp(start_time)}"
    )
    output.write(code)


if __name__ == "__main__":
    app()
