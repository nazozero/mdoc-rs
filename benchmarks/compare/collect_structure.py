#!/usr/bin/env python3
"""Build identical parser consumers and record actual dependency/artifact sizes."""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

BASELINE_REVISION = "9dd3ef60fb98b427065d7ad940cfbdd9a400b2bc"


def checked(command: list[str], *, cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"command failed: {command!r}\n{result.stderr}")
    return result.stdout


def file_fact(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def source_counts(root: Path) -> dict[str, int]:
    sources = sorted((root / "src").rglob("*.rs"))
    lines = [line for source in sources for line in source.read_text().splitlines()]
    return {
        "rust_source_files": len(sources),
        "rust_source_lines": len(lines),
        "rust_source_nonblank_lines": sum(bool(line.strip()) for line in lines),
    }


def normal_packages(metadata: dict, root_id: str) -> list[dict]:
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    packages = {package["id"]: package for package in metadata["packages"]}
    visited = {root_id}
    pending = [root_id]
    while pending:
        current = pending.pop()
        for edge in nodes[current]["deps"]:
            if not any(kind["kind"] is None for kind in edge["dep_kinds"]):
                continue
            if edge["pkg"] not in visited:
                visited.add(edge["pkg"])
                pending.append(edge["pkg"])
    visited.remove(root_id)
    return sorted(
        ({"name": packages[identifier]["name"], "version": packages[identifier]["version"], "id": identifier}
         for identifier in visited),
        key=lambda package: (package["name"], package["version"], package["id"]),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--rustc", default="rustc")
    args = parser.parse_args()
    harness = Path(__file__).resolve().parent
    repository = harness.parent.parent
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CARGO_BUILD_JOBS="1")
    version = checked([args.rustc, "-Vv"], cwd=repository, env=env)
    host = next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))
    (evidence / "structure-rustc.txt").write_text(version)
    fixture = evidence / "annex-d.cbor"
    fixture.write_bytes(bytes.fromhex((repository / "tests/vectors/iso_18013_5_annex_d_mdl.hex").read_text()))
    configurations = [
        ("baseline_issue", "baseline", "mdoc-rs", []),
        ("candidate_minimal", "candidate", "nazo-mdoc", ["--no-default-features"]),
        ("candidate_issue", "candidate", "nazo-mdoc", ["--no-default-features", "--features", "issue"]),
        ("candidate_all", "candidate", "nazo-mdoc", ["--all-features"]),
    ]
    results = []
    for label, consumer, core_name, features in configurations:
        manifest = harness / "consumers" / consumer / "Cargo.toml"
        print(f"Building {label} with one job", flush=True)
        command = [args.cargo, "build", "--release", "--manifest-path", str(manifest),
                   "--target", host, "--target-dir", str(args.target.resolve()),
                   "--message-format=json-render-diagnostics", *features]
        with (evidence / f"{label}-artifacts.jsonl").open("w") as stdout, (evidence / f"{label}-build.log").open("w") as stderr:
            status = subprocess.run(command, cwd=repository, env=env, stdout=stdout, stderr=stderr).returncode
        if status:
            raise RuntimeError(f"{label} failed; see {evidence / (label + '-build.log')}")
        metadata_text = checked([args.cargo, "metadata", "--format-version", "1", "--locked",
                                 "--manifest-path", str(manifest), "--filter-platform", host, *features],
                                cwd=repository, env=env)
        (evidence / f"{label}-metadata.json").write_text(metadata_text)
        metadata = json.loads(metadata_text)
        core = next(package for package in metadata["packages"] if package["name"] == core_name)
        core_id = core["id"]
        core_root = Path(core["manifest_path"]).parent
        if consumer == "baseline":
            revision = checked(["git", "rev-parse", "HEAD"], cwd=core_root, env=env).strip()
            if revision != BASELINE_REVISION:
                raise RuntimeError(f"wrong baseline revision: {revision}")
        else:
            revision = checked(["git", "rev-parse", "HEAD"], cwd=core_root, env=env).strip()
        artifacts = [json.loads(line) for line in (evidence / f"{label}-artifacts.jsonl").read_text().splitlines() if line.startswith("{")]
        library = next(artifact for artifact in artifacts
                       if artifact.get("reason") == "compiler-artifact"
                       and artifact["package_id"] == core_id
                       and "lib" in artifact["target"]["kind"])
        archive = next(Path(filename) for filename in library["filenames"] if filename.endswith(".rlib"))
        executable = next(Path(artifact["executable"]) for artifact in artifacts
                          if artifact.get("reason") == "compiler-artifact"
                          and artifact.get("executable")
                          and "bin" in artifact["target"]["kind"])
        snapshot = evidence / f"{label}-minimal-consumer.bin"
        shutil.copy2(executable, snapshot)
        run = checked([str(snapshot), str(fixture)], cwd=repository, env=env).strip()
        if run != "documents=1":
            raise RuntimeError(f"unexpected consumer output {label}: {run}")
        dependencies = normal_packages(metadata, core_id)
        (evidence / f"{label}-normal-dependencies.json").write_text(json.dumps(dependencies, indent=2) + "\n")
        active_features = next(node["features"] for node in metadata["resolve"]["nodes"] if node["id"] == core_id)
        details = {
            "variant": label,
            "git_head": revision,
            "active_core_features": active_features,
            "host": host,
            "build_command": command,
            "profile": library["profile"],
            "normal_unique_dependency_packages": len(dependencies),
            "normal_unique_dependency_names": len({package["name"] for package in dependencies}),
            **source_counts(core_root),
            "rlib": file_fact(archive),
            "minimal_parser_consumer": file_fact(snapshot),
            "rustflags": env.get("RUSTFLAGS", ""),
            "encoded_rustflags": env.get("CARGO_ENCODED_RUSTFLAGS", ""),
        }
        (evidence / f"{label}-structure.json").write_text(json.dumps(details, indent=2) + "\n")
        results.append(details)
        print(f"Finished {label}: dependencies={len(dependencies)}, rlib={details['rlib']['bytes']}, consumer={details['minimal_parser_consumer']['bytes']}", flush=True)
    columns = ["variant", "normal_unique_dependency_packages", "normal_unique_dependency_names", "rust_source_files", "rust_source_lines", "rust_source_nonblank_lines", "release_rlib_bytes", "minimal_parser_consumer_bytes"]
    with (evidence / "structure.csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()
        for details in results:
            row = {column: details[column] for column in columns if column in details}
            row["release_rlib_bytes"] = details["rlib"]["bytes"]
            row["minimal_parser_consumer_bytes"] = details["minimal_parser_consumer"]["bytes"]
            writer.writerow(row)
    report = [
        "# Measured dependency, source and artifact sizes", "",
        "Both consumers use exactly the same main source and a runtime-supplied Annex D input; each successfully reports one document.",
        "Release flags: opt-level 3, thin LTO, one codegen unit, Cargo's default release debug/panic/strip settings. No package feature unification across the independent consumer workspaces.",
        "Normal dependency counts exclude the core itself, dev/build edges and inactive target edges; versions/sources are distinct packages. Reachable proc-macro packages are included.",
        "Rust source line counts cover src/**/*.rs, including comments and inline tests. Nonblank lines are not semantic code-only SLOC.",
        "Rlibs contain compiled code/IR and Rust metadata. The minimal binary exercises parsing, not every library capability. These are distinct size measurements.", "",
        "| Variant | Unique normal packages | Rust files | Rust lines / nonblank | Release rlib bytes | Minimal parser binary bytes |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for detail in results:
        report.append(f"| {detail['variant']} | {detail['normal_unique_dependency_packages']} | {detail['rust_source_files']} | {detail['rust_source_lines']} / {detail['rust_source_nonblank_lines']} | {detail['rlib']['bytes']} | {detail['minimal_parser_consumer']['bytes']} |")
    report += ["", "See each *-structure.json, Cargo compiler-artifact JSONL, dependency list and build log for exact features, flags, hashes and paths.", ""]
    (evidence / "structure.md").write_text("\n".join(report))
    print(evidence / "structure.md", flush=True)


if __name__ == "__main__":
    main()
