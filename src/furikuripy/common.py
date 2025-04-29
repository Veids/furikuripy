import random
import logging

from pydantic import StrictBytes
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from rich import print
from rich.syntax import Syntax
from rich.panel import Panel
from rich.markup import escape
from rich.logging import RichHandler
from rich.columns import Columns

FORMAT = "%(message)s"
logging.basicConfig(
    level=logging.INFO, format=FORMAT, datefmt="[%X]", handlers=[RichHandler()]
)

log = logging.getLogger("furikuri")
trace = logging.getLogger("furikuri-trace")
rng = random.Random()

md = Cs(
    CS_ARCH_X86,
    CS_MODE_64,
)


def trace_inst(msg: str, opcodes: list[StrictBytes], ctx=None):
    hexcodes = ["".join(f"\\x{x:02x}" for x in opcode) for opcode in opcodes]
    bt = " ".join(hexcodes)

    trace.info(f"{escape(msg)} ([bold]{bt}[bold])", extra={"markup": True})

    if ctx and not trace.disabled:
        syntax_a = Syntax(
            f"{ctx.instruction.mnemonic} {ctx.instruction.op_str}",
            "gas",
            theme="monokai",
            background_color="default",
        )
        pl = Panel(syntax_a)

        assembly_2 = []
        for opcode in opcodes:
            ins = next(md.disasm(opcode, 0))
            assembly_2.append(f"{ins.mnemonic} {ins.op_str}")

        assembly_2 = "\n".join(assembly_2)

        syntax_b = Syntax(
            assembly_2, "gas", theme="monokai", background_color="default"
        )
        pl_b = Panel(syntax_b)

        cols = [pl, pl_b]
        columns = Columns(cols)
        print(columns)
