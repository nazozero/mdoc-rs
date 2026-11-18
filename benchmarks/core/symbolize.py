#!/usr/bin/env python3
"""Resolve allocation stack offsets from --profile using addr2line."""
import argparse
import csv
import subprocess
from collections import defaultdict
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    for path in sorted([*args.directory.glob("*-allocations.csv"), *args.directory.glob("*-allocations.tsv")]):
        with path.open() as file:
            comment = next(file).strip()
            rows = list(csv.DictReader(file))
        objects = defaultdict(set)
        for row in rows:
            objects[row["object"]].add(row["elf_offset"])
        symbols = {}
        for obj, offsets in objects.items():
            offsets = sorted(offsets)
            result = subprocess.run(["addr2line", "-f", "-C", "-e", obj, *["0x" + offset for offset in offsets]], check=True, text=True, capture_output=True)
            lines = result.stdout.splitlines()
            if len(lines) != len(offsets) * 2:
                raise RuntimeError("unexpected addr2line output")
            for index, offset in enumerate(offsets):
                symbols[(obj, offset)] = (lines[index * 2], lines[index * 2 + 1])
        allocations = defaultdict(list)
        for row in rows:
            allocations[row["allocation"]].append(row)
        report = [f"# {path.stem}", "", comment, "", "| Call site | Calls | Requested bytes |", "| --- | ---: | ---: |"]
        groups = defaultdict(lambda: [0, 0])
        stack_lines = []
        for allocation, stack in allocations.items():
            stack_lines.append(f"allocation {allocation}, requested bytes {stack[0]['requested_bytes']}")
            site = "unresolved"
            for row in stack:
                symbol, location = symbols[(row["object"], row["elf_offset"])]
                stack_lines.append(f"  {symbol} at {location}")
                if site == "unresolved" and symbol.startswith(("nazo_mdoc::", "<nazo_mdoc::", "ciborium::", "<ciborium::", "coset::", "<coset::", "x509_cert::", "<x509_cert::")):
                    site = f"{symbol} ({location})"
            groups[site][0] += 1
            groups[site][1] += int(stack[0]["requested_bytes"])
        for site, (calls, size) in sorted(groups.items(), key=lambda item: -item[1][1]):
            report.append(f"| `{site}` | {calls} | {size} |")
        path.with_suffix(".md").write_text("\n".join(report) + "\n")
        path.with_suffix(".stacks.txt").write_text("\n".join(stack_lines) + "\n")


if __name__ == "__main__":
    main()
