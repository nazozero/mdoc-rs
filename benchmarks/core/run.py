#!/usr/bin/env python3
"""Run independently linked variants in alternating process order."""
import argparse
import csv
import hashlib
import json
import math
import subprocess
from pathlib import Path


def quantile(values, percentage):
    return sorted(values)[math.ceil(len(values) * percentage / 100) - 1]


def summarize(output):
    rows = []
    for directory in sorted(output.glob("round-*/*")):
        source = directory / "samples.csv"
        if not source.exists():
            continue
        cases = {}
        with source.open() as file:
            for row in csv.DictReader(file):
                cases.setdefault(row["case"], []).append(row)
        for case, samples in cases.items():
            row = {"round": directory.parent.name, "variant": directory.name, "case": case, "observations": len(samples)}
            for field in ("wall_ns", "thread_cpu_ns", "allocations", "requested_bytes"):
                values = [int(sample[field]) for sample in samples]
                for percentile in (50, 95, 99):
                    row[f"{field}_p{percentile}"] = quantile(values, percentile)
                row[f"{field}_mean"] = sum(values) / len(values)
            rows.append(row)
    if rows:
        with (output / "summary.csv").open("w") as file:
            writer = csv.DictWriter(file, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--case")
    parser.add_argument("--unchanged-control", action="store_true", help="Require both paths to have the same binary SHA-256")
    args = parser.parse_args()
    if args.out.exists():
        parser.error("output directory already exists; retain prior observations")
    if args.rounds < 2 or args.samples < 1000 or args.warmup < 16:
        parser.error("use at least 2 rounds, 1000 samples, and 16 warmups")
    binaries = {"baseline": args.baseline.resolve(), "candidate": args.candidate.resolve()}
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()}
    if args.unchanged_control and hashes["baseline"] != hashes["candidate"]:
        parser.error("unchanged control requires the identical executable")
    args.out.mkdir(parents=True)
    runs = []
    inputs = None
    for round_number in range(1, args.rounds + 1):
        order = ["baseline", "candidate"] if round_number % 2 else ["candidate", "baseline"]
        for position, variant in enumerate(order):
            target = args.out / f"round-{round_number:02}" / variant
            target.mkdir(parents=True)
            command = [str(binaries[variant]), "--fixture", str(args.fixture.resolve()), "--out", str(target.resolve()), "--samples", str(args.samples), "--warmup", str(args.warmup)]
            if args.cpu is not None:
                command += ["--cpu", str(args.cpu)]
            if args.case:
                command += ["--case", args.case]
            print(f"Round {round_number}, position {position}: {variant}", flush=True)
            with (target / "execution.log").open("w") as log:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
            runs.append({"round": round_number, "position": position, "variant": variant, "command": command, "returncode": result.returncode, "sha256": hashes[variant]})
            (args.out / "runs.json").write_text(json.dumps({"unchanged_control": args.unchanged_control, "runs": runs}, indent=2) + "\n")
            if result.returncode:
                summarize(args.out)
                raise SystemExit(f"Failed run retained at {target}")
            current = (target / "inputs.txt").read_bytes()
            if inputs is not None and current != inputs:
                raise SystemExit(f"Input or deterministic-output mismatch retained at {target}")
            inputs = current
            summarize(args.out)
    summarize(args.out)


if __name__ == "__main__":
    main()
