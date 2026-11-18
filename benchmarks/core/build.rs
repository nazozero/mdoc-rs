use std::{path::Path, process::Command};
fn main() {
    let root = Path::new("../..");
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .unwrap();
    println!(
        "cargo:rustc-env=BENCH_BUILD_HEAD={}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
    let output = Command::new("rustc").arg("-Vv").output().unwrap();
    println!(
        "cargo:rustc-env=BENCH_BUILD_RUSTC={}",
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .replace('\n', ";")
    );
    for key in [
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_CFG_TARGET_FEATURE",
        "TARGET",
    ] {
        println!(
            "cargo:rustc-env=BENCH_BUILD_{key}={}",
            std::env::var(key)
                .unwrap_or_default()
                .replace('\u{1f}', " ")
        );
    }
    let mut paths = vec![
        "Cargo.toml".into(),
        "Cargo.lock".into(),
        "rust-toolchain.toml".into(),
        "tests/common/mod.rs".into(),
    ];
    collect(root, Path::new("src"), &mut paths);
    collect(root, Path::new("benchmarks/core"), &mut paths);
    paths.sort();
    let output = Command::new("sha256sum")
        .args(&paths)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(output.status.success());
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("source-manifest.txt"), output.stdout).unwrap();
    for path in paths {
        println!("cargo:rerun-if-changed=../../{path}");
    }
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    let reference = Command::new("git")
        .args(["symbolic-ref", "HEAD"])
        .current_dir(root)
        .output()
        .unwrap();
    if reference.status.success() {
        println!(
            "cargo:rerun-if-changed=../../.git/{}",
            String::from_utf8_lossy(&reference.stdout).trim()
        );
    }
}
fn collect(root: &Path, relative: &Path, paths: &mut Vec<String>) {
    for entry in std::fs::read_dir(root.join(relative)).unwrap() {
        let entry = entry.unwrap();
        let path = relative.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            if entry.file_name() != "target" {
                collect(root, &path, paths);
            }
        } else if matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("rs" | "toml" | "lock")
        ) {
            paths.push(path.to_str().unwrap().into());
        }
    }
}
