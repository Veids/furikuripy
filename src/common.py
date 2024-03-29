import yaml
import typer
import random
import logging

from typing import List, Tuple, Dict
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


class RangesProcessor:
    def __init__(self, data_size: int):
        self.data_size = data_size

    def parse_start_end(self, start, end):
        if isinstance(end, str) and end.lower() == "e":
            end = self.data_size

        start = int(start)
        end = int(end)

        if start < 0:
            start %= self.data_size

        if end < 0:
            end %= self.data_size

        return start, end

    def post_process_ranges(self, blocks):
        blocks.sort(key = lambda x: x[1])

        last_end = 0
        for (_, start, end) in blocks:
            if last_end != start:
                raise Exception(f"Missing range between {last_end} and {start} bytes\n{blocks}")

            last_end = end

        if last_end != self.data_size:
            raise Exception(f"Missing range between {last_end} and {data_size} bytes\n{blocks}")

        return blocks

    def parse_ranges_from_args(self, ranges: List[str]) -> List:
        blocks = []
        for x in ranges:
            t, start, end = x.split(':')

            if t.lower() not in ["c", "d"]:
                raise Exception(f"'{t}' is not a correct type of range, use 'c' for a code and 'd' for a data")

            start, end = self.parse_start_end(start, end)
            blocks.append((t, start, end))

        self.post_process_ranges(blocks)
        return blocks

    def parse_ranges_from_definitions(self, ranges: Dict) -> List:
        blocks = []
        for r in ranges:
            if r["id"] not in ["c", "d"]:
                raise Exception(f"'{t}' is not a correct type of range, use 'c' for a code and 'd' for a data")

            start, end = self.parse_start_end(r["start"], r["end"])
            blocks.append((r["id"].lower(), start, end))

        self.post_process_ranges(blocks)
        return blocks

def parse_ranges_from_args(data_size: int, ranges: List[str]) -> List:
    rp = RangesProcessor(data_size)
    return rp.parse_ranges_from_args(ranges)

def parse_definitions(data_size: int, definitions: str) -> Tuple[List, List]:
    definitions = yaml.load(definitions, yaml.CLoader)

    ranges = [("c",0,data_size)]
    if d_ranges := definitions.get("ranges"):
        rp = RangesProcessor(data_size)
        ranges = rp.parse_ranges_from_definitions(d_ranges)

    patches = []
    if d_patches := definitions.get("patches"):
        for patch in d_patches:
            patches.append(f"{patch['start']}:{patch['bytes']}")

    return ranges, patches
