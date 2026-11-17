#!/usr/bin/env python3
"""Render the recorded CSVs; never substitutes predictions for measurements."""

import argparse
import csv
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    with (args.evidence / "summary.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows or any(int(row["n"]) < 1000 for row in rows):
        raise SystemExit("a report requires at least 1000 real observations per row")
    report = [
        "# Recorded production comparison",
        "",
        "Values below are computed from `summary.csv`; every observation is in `samples.csv`.",
        "P50/P95/P99 use nearest-rank quantiles. Times are microseconds per operation.",
        "Each timing invocation and allocation invocation is a separate execution.",
        "Output destruction is included. External trust, status HTTP and application admission are excluded.",
        "",
        "## Thread CPU and elapsed time",
        "",
        "| Operation | Variant | N | CPU P50 / P95 / P99 (µs) | Elapsed P50 / P95 / P99 (µs) |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for row in rows:
        cpu = " / ".join(f"{int(row[f'cpu_p{p}_ns']) / 1000:.3f}" for p in (50, 95, 99))
        wall = " / ".join(f"{int(row[f'wall_p{p}_ns']) / 1000:.3f}" for p in (50, 95, 99))
        report.append(f"| `{row['case']}` | {row['variant']} | {row['n']} | {cpu} | {wall} |")
    report += [
        "", "## Allocation requests", "",
        "Bytes are total successful requested allocation capacities, including the full new size of reallocations; they are not peak heap or copied bytes.",
        "",
        "| Operation | Variant | Allocation count P50 / mean | Requested bytes P50 / mean |",
        "| --- | --- | ---: | ---: |",
    ]
    for row in rows:
        report.append(
            f"| `{row['case']}` | {row['variant']} | {row['allocations_p50']} / {row['allocations_mean']} "
            f"| {row['allocated_bytes_p50']} / {row['allocated_bytes_mean']} |"
        )
    report += [
        "", "## Comparison boundaries", "",
        "| Operation | Recorded comparison class |", "| --- | --- |",
    ]
    seen = set()
    for row in rows:
        if row["case"] not in seen:
            seen.add(row["case"])
            report.append(f"| `{row['case']}` | `{row['comparability']}` |")
    report += [
        "",
        "The legacy DeviceAuthentication constructors omit the outer Tag 24 and do not produce equivalent protocol output.",
        "The preflight proves that the unmodified baseline full verifier rejects the Final holder signature; its failing path is not measured as a successful baseline verification.",
        "The candidate-only full protocol row is a pending-trust result, not NazoAuth's final credential admission or an HTTP endpoint.",
        "The issuance row uses the same real local fixture signer. Candidate adds schema/key/certificate checks and confirms the returned signature against the leaf certificate's public key; baseline sign has no equivalent post-signing verification.",
        "NazoAuth's external signer path already checks signatures against the leased public JWK. Core certificate-key confirmation is a separate binding; the application must not skip it or infer that its local signing path already performs the external-key check.",
        "See the harness README and metadata.txt for source identity, dependency-feature unification, hardware, affinity and limitations.",
        "",
    ]
    destination = args.evidence / "report.md"
    destination.write_text("\n".join(report))
    print(destination)


if __name__ == "__main__":
    main()
