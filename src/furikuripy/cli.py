import yaml

from enum import Enum
from pydantic import BaseModel

from furikuripy.fuku_misc import FukuInstFlags


class RangeType(Enum):
    code = "code"
    data = "data"


class RangeAsset(BaseModel):
    start: int
    end: int
    t: RangeType
    inst_flags: FukuInstFlags


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

    def post_process_ranges(self, blocks: list[RangeAsset]):
        blocks.sort(key=lambda x: x.start)

        last_end = 0
        for r in blocks:
            if last_end != r.start:
                raise Exception(
                    f"Missing range between {last_end} and {r.start} bytes\n{blocks}"
                )

            last_end = r.end

        if last_end != self.data_size:
            raise Exception(
                f"Missing range between {last_end} and {self.data_size} bytes\n{blocks}"
            )

        return blocks

    def parse_ranges_from_args(self, ranges: list[str]) -> list[RangeAsset]:
        blocks = []
        for x in ranges:
            t, start, end, inst_flags = x.split(":")
            start, end = self.parse_start_end(start, end)

            blocks.append(
                RangeAsset(
                    start=int(start),
                    end=int(end),
                    t=RangeType(t),
                    inst_flags=FukuInstFlags(int(inst_flags)),
                )
            )

        self.post_process_ranges(blocks)
        return blocks

    def parse_ranges_from_definitions(self, ranges: dict) -> list[RangeAsset]:
        blocks = []
        for r in ranges:
            t = r["id"]
            inst_flags = r["inst_flags"]
            start, end = self.parse_start_end(r["start"], r["end"])

            blocks.append(
                RangeAsset(
                    start=start,
                    end=end,
                    t=RangeType(t),
                    inst_flags=FukuInstFlags(inst_flags),
                )
            )
        self.post_process_ranges(blocks)
        return blocks


def parse_definitions(data_size: int, definitions: str) -> tuple[list, list]:
    definitions_yaml = yaml.load(definitions, yaml.CLoader)

    ranges = [("c", 0, data_size)]
    if d_ranges := definitions_yaml.get("ranges"):
        rp = RangesProcessor(data_size)
        ranges = rp.parse_ranges_from_definitions(d_ranges)

    patches = []
    if d_patches := definitions_yaml.get("patches"):
        for patch in d_patches:
            patches.append(f"{patch['start']}:{patch['bytes']}")

    return ranges, patches


def parse_ranges_from_args(data_size: int, ranges: list[str]) -> list[RangeAsset]:
    rp = RangesProcessor(data_size)
    return rp.parse_ranges_from_args(ranges)
