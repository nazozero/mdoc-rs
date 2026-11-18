#!/usr/bin/env python3
"""Resolve allocation stack offsets from --profile using addr2line."""
import argparse
import csv
import hashlib
import subprocess
from collections import defaultdict
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--executable", type=Path, help="relocated copy of the recorded executable")
    args = parser.parse_args()
    metadata = dict(line.split("=", 1) for line in (args.directory / "metadata.txt").read_text().splitlines() if "=" in line)
    if args.executable and hashlib.sha256(args.executable.read_bytes()).hexdigest() != metadata["executable_sha256"]:
        raise RuntimeError("executable hash differs from the recorded profile")
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
            executable = args.executable if args.executable and obj == metadata["executable"] else obj
            result = subprocess.run(["addr2line", "-a", "-f", "-C", "-i", "-e", str(executable), *["0x" + offset for offset in offsets]], check=True, text=True, capture_output=True)
            lines = result.stdout.splitlines()
            index = 0
            for offset in offsets:
                if index >= len(lines) or int(lines[index], 16) != int(offset, 16):
                    raise RuntimeError("unexpected addr2line address")
                index += 1
                frames = []
                while index < len(lines) and not lines[index].startswith("0x"):
                    frames.append((lines[index], lines[index + 1]))
                    index += 2
                symbols[(obj, offset)] = frames
            if index != len(lines):
                raise RuntimeError("unexpected addr2line output")
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
                for symbol, location in symbols[(row["object"], row["elf_offset"])]:
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
