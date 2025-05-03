import pstats
import cProfile
import typer
import pickle
import random
import sys
import time
import importlib.metadata

from datetime import datetime
from binascii import unhexlify
from dataclasses import dataclass
from typing import Annotated, Optional

from furikuripy.common import log, trace, rng
from furikuripy.cli import (
    RangeAsset,
    RangeType,
    parse_ranges_from_args,
    parse_definitions,
)
from furikuripy.fuku_obfuscator import FukuObfuscator
from furikuripy.fuku_code_holder import FukuCodeHolder, FukuImageRelocationX64
from furikuripy.fuku_code_analyzer import FukuCodeAnalyzer
from furikuripy.fuku_code_profiler import FukuCodeProfiler
from furikuripy.fuku_misc import FUKU_ASSEMBLER_ARCH, FukuObfuscationSettings
from furikuripy.x86.misc import FukuAsmShortCfg

app = typer.Typer(
    pretty_exceptions_show_locals=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


@dataclass(frozen=True)
class Relocation:
    virtual_address: int
    type: int
    symbol: str

    @classmethod
    def parse_relocation(cls, s: str):
        try:
            va, ty, sym = s.split(":")
            return Relocation(int(va), int(ty), sym)
        except ValueError:  # not exactly 3 parts or int conversion failed
            raise typer.BadParameter(f"Invalid relocation '{s}'")


@dataclass(frozen=True)
class Patch:
    start: int
    payload: bytes

    @staticmethod
    def parse_patch(patch_str: str, data_len: int) -> "Patch":
        start, bts = patch_str.split(":")
        start = int(start)
        payload = unhexlify(bts)

        if start < 0:
            start %= data_len

        return Patch(start, payload)


def apply_patches(data, patch_objs: list[Patch]):
    for patch in patch_objs:
        for i, b in enumerate(patch.payload):
            data[patch.start + i] = b


def get_rand_seed() -> int:
    return random.randrange(sys.maxsize)


def perform_analysis(
    data: bytearray,
    arch: FUKU_ASSEMBLER_ARCH,
    definitions: Optional[typer.FileText],
    ranges: list[str],
    patches: list[str],
    relocations: list[str],
    virtual_address: int,
) -> FukuCodeHolder:
    ranges: list[RangeAsset]
    if definitions:
        ranges, patches = parse_definitions(len(data), definitions.read())
    else:
        ranges = parse_ranges_from_args(len(data), ranges)

    patch_objs = [Patch.parse_patch(p, len(data)) for p in patches]
    apply_patches(data, patch_objs)

    code_holder = FukuCodeHolder(arch=arch)
    code_analyzer = FukuCodeAnalyzer(arch=arch)

    relocs = []
    for i, reloc in enumerate(relocations):
        reloc = Relocation.parse_relocation(reloc)

        if arch == FUKU_ASSEMBLER_ARCH.X64:
            relocs.append(
                FukuImageRelocationX64(
                    relocation_id=i,
                    virtual_address=reloc.virtual_address,
                    type=reloc.type,
                    symbol=reloc.symbol,
                )
            )

    for r in ranges:
        if r.t == RangeType.code:
            code_analyzer.analyze_code(
                code_holder,
                data[r.start : r.end],
                virtual_address + r.start,
                relocs,
                r.inst_flags,
            )
        else:
            inst = code_holder.add_inst()
            inst.source_address = virtual_address + r.start
            inst.opcode = bytearray(data[r.start : r.end])
            inst.id = -1
            inst.flags = r.inst_flags
            code_holder.update_source_insts()
            code_holder.resolve_labels()

    code_profiler = FukuCodeProfiler(arch=arch)
    code_profiler.profile_code(code_holder)

    return code_holder


@app.command()
def obfuscate(
    input: Annotated[
        typer.FileBinaryRead,
        typer.Option("-i", "--input", help="Input file", mode="rb"),
    ],
    output: Annotated[typer.FileBinaryRead, typer.Option("-o", "--output", mode="wb+")],
    seed: Annotated[
        int,
        typer.Option(
            default_factory=get_rand_seed, rich_help_panel="Obfuscation options"
        ),
    ],
    patches: Annotated[
        list[str],
        typer.Option(
            help="specify patches to apply (ex. start:PATCHINHEX - 0:665f)",
            default_factory=list,
            rich_help_panel="Analysis options",
        ),
    ],
    arch: Annotated[
        Optional[FUKU_ASSEMBLER_ARCH],
        typer.Option(help="Architecture", rich_help_panel="Analysis options"),
    ] = None,
    input_is_analysis: Annotated[
        bool, typer.Option(help="Input file represents analysis file (pickle)")
    ] = False,
    ranges: Annotated[
        list[str],
        typer.Option(
            help="specify ranges for code/data blocks (ex. c:0:10 or d:10:e)",
            rich_help_panel="Analysis options",
        ),
    ] = ["c:0:e"],
    relocations_allowed: Annotated[
        bool,
        typer.Option(help="allow relocations", rich_help_panel="Obfuscation options"),
    ] = False,
    complexity: Annotated[
        int,
        typer.Option(
            help="number of passes for single line",
            rich_help_panel="Obfuscation options",
        ),
    ] = 3,
    number_of_passes: Annotated[
        int, typer.Option(min=1, rich_help_panel="Obfuscation options")
    ] = 2,
    junk_chance: Annotated[
        int, typer.Option(min=0, max=100, rich_help_panel="Obfuscation options")
    ] = 30,
    block_chance: Annotated[
        int, typer.Option(min=0, max=100, rich_help_panel="Obfuscation options")
    ] = 30,
    mutate_chance: Annotated[
        int, typer.Option(min=0, max=100, rich_help_panel="Obfuscation options")
    ] = 30,
    forbid_stack_operations: Annotated[
        bool, typer.Option(rich_help_panel="Obfuscation options")
    ] = False,
    virtual_address: Annotated[
        int, typer.Option(rich_help_panel="Analysis options")
    ] = 0,
    definitions: Annotated[
        Optional[typer.FileText],
        typer.Option(
            "--definitions",
            "--defs",
            help="yaml file that contains ranges and patches",
            rich_help_panel="Analysis options",
        ),
    ] = None,
    relocations: Annotated[
        list[str],
        typer.Option(
            help="specify relocations in format <vaddress>:<type>:<symbol> (e.g. 2:4:.data)",
            rich_help_panel="Analysis options",
        ),
    ] = [],
    trace_inst: Annotated[bool, typer.Option(help="Enable instruction trace")] = False,
):
    with cProfile.Profile() as profile:
        log.info("Version: %s", importlib.metadata.version("furikuripy"))
        log.info("Seed: %d", seed)
        rng.seed(seed)

        if not trace_inst:
            trace.disabled = True

        if input_is_analysis:
            code_holder = pickle.load(input)
        else:
            if arch != FUKU_ASSEMBLER_ARCH.X64:
                raise NotImplementedError("Only x64 is supported today")

            data = bytearray(input.read())
            code_holder = perform_analysis(
                data, arch, definitions, ranges, patches, relocations, virtual_address
            )

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

        obfuscator = FukuObfuscator(code=code_holder, settings=settings)

        start_time = time.time()

        obfuscator.obfuscate_code()

        res, associations, relocationsObfuscated = code_holder.finalize_code()
        code = code_holder.dump_code()
        end_time = time.time()

        log.info(
            f"Finished in {datetime.fromtimestamp(end_time) - datetime.fromtimestamp(start_time)}"
        )
        output.write(code)

    results = pstats.Stats(profile)
    results.sort_stats(pstats.SortKey.TIME)
    results.print_stats()
    results.dump_stats("profile.pprof")


@app.command()
def analyse(
    arch: Annotated[
        FUKU_ASSEMBLER_ARCH,
        typer.Option(help="Architecture", rich_help_panel="Analysis options"),
    ],
    input: Annotated[
        typer.FileBinaryRead,
        typer.Option("-i", "--input", help="Input file", mode="rb"),
    ],
    output: Annotated[
        typer.FileBinaryWrite,
        typer.Option("-o", "--output", help="Where to store analysis file", mode="wb+"),
    ],
    patches: Annotated[
        list[str],
        typer.Option(
            help="specify patches to apply (ex. start:PATCHINHEX - 0:665f)",
            default_factory=list,
            rich_help_panel="Analysis options",
        ),
    ],
    ranges: Annotated[
        list[str],
        typer.Option(
            help="specify ranges for code/data blocks (ex. c:0:10 or d:10:e)",
            rich_help_panel="Analysis options",
        ),
    ] = ["c:0:e"],
    definitions: Annotated[
        Optional[typer.FileText],
        typer.Option(
            "--definitions",
            "--defs",
            help="yaml file that contains ranges and patches",
            rich_help_panel="Analysis options",
        ),
    ] = None,
    relocations: Annotated[
        list[str],
        typer.Option(
            help="specify relocations in format <vaddress>:<type>:<symbol> (e.g. 2:4:.data)",
            rich_help_panel="Analysis options",
        ),
    ] = [],
    virtual_address: Annotated[
        int, typer.Option(rich_help_panel="Analysis options")
    ] = 0,
):
    log.info("Version: %s", importlib.metadata.version("furikuripy"))

    if arch != FUKU_ASSEMBLER_ARCH.X64:
        raise Exception("Unimplemented")

    data = bytearray(input.read())
    code_holder = perform_analysis(
        data, arch, definitions, ranges, patches, relocations, virtual_address
    )
    pickle.dump(code_holder, output)


if __name__ == "__main__":
    app()
