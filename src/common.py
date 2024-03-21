import random
import logging

from typing import List
from pydantic import StrictBytes
from rich.markup import escape
from rich.logging import RichHandler

FORMAT = "%(message)s"
logging.basicConfig(
    level=logging.INFO, format=FORMAT, datefmt="[%X]", handlers=[RichHandler()]
)

log = logging.getLogger("furikuri")
trace = logging.getLogger("furikuri-trace")
rng = random.Random()

def trace_inst(msg: str, opcodes: List[StrictBytes]):
    opcodes = ["".join(f"\\x{x:02x}" for x in opcode) for opcode in opcodes]
    bt = " ".join(opcodes)

    trace.info(f"{escape(msg)} ([bold]{bt}[bold])", extra = {"markup": True})
