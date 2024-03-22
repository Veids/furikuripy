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
from fuku_inst import FukuInst
from x86.misc import FukuAsmShortCfg

app = typer.Typer(pretty_exceptions_show_locals=False)



@app.command()
def main(
    arch: FUKU_ASSEMBLER_ARCH,
    input: Annotated[typer.FileBinaryRead, typer.Argument()],
    ranges: Annotated[Optional[int], typer.Option(help="specify ranges to skip data (ex. 1-100,120-500)")] = None,
):
    data = input.read()

    if not ranges:
        ranges = len(data)

    virtual_address = 0
    code_holder = FukuCodeHolder(arch = arch)
    code_analyzer = FukuCodeAnalyzer(arch = arch)

    code_analyzer.analyze_code(code_holder, data[:ranges], virtual_address, None)

    #debug
    inst = code_holder.add_inst()
    inst.source_address = virtual_address + data.index(data[ranges])
    inst.opcode = bytearray(data[ranges:])
    inst.id = -1
    code_holder.update_source_insts()
    code_holder.resolve_labels()
    #debug_end

    code_profiler = FukuCodeProfiler(arch = arch)
    code_profiler.profile_code(code_holder)
    from IPython import embed; embed()  # DEBUG

if __name__ == "__main__":
    app()
