//! Embeds what this build was made from in `buildInfo()`: the routstr-confidential
//! commit the vendored crates come from (`crates/vendor/UPSTREAM`), the mpz2 rev
//! (Cargo.lock) and a SHA-256 digest of every source file that goes into the
//! wasm. The digest depends on file contents only (no time, no paths outside
//! the repository), so the build stays reproducible, and
//! `node scripts/source-digest.mjs` recomputes it from a checkout.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Files and directories (from the repository root) that make up the wasm's source.
pub const SOURCES: &[&str] = &[
    ".cargo/config.toml",
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    "crates/client-wasm/Cargo.toml",
    "crates/client-wasm/build.rs",
    "crates/client-wasm/src",
    "crates/vendor/UPSTREAM",
    "crates/vendor/cu-crypto",
    "crates/vendor/twopc",
    "crates/vendor/zkbench",
];

fn walk(root: &Path, rel: &str, out: &mut Vec<String>) {
    let p = root.join(rel);
    if p.is_dir() {
        let mut names: Vec<String> = std::fs::read_dir(&p)
            .expect("read_dir")
            .map(|e| e.expect("dir entry").file_name().into_string().expect("utf-8 file name"))
            .filter(|n| !n.starts_with('.') && n != "target")
            .collect();
        names.sort();
        for n in names {
            walk(root, &format!("{rel}/{n}"), out);
        }
    } else if p.is_file() {
        out.push(rel.to_string());
    }
}

fn main() {
    let root: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root");
    let mut files = Vec::new();
    for s in SOURCES {
        println!("cargo:rerun-if-changed={}", root.join(s).display());
        walk(&root, s, &mut files);
    }
    files.sort();
    files.dedup();
    let mut h = Sha256::new();
    for f in &files {
        let data = std::fs::read(root.join(f)).expect("read source file");
        h.update(f.as_bytes());
        h.update([0u8]);
        h.update((data.len() as u64).to_be_bytes());
        h.update(&data);
    }
    let digest = hex(&h.finalize()[..8]);

    let upstream = std::fs::read_to_string(root.join("crates/vendor/UPSTREAM"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let upstream: String = upstream.chars().take(12).collect();
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap_or_default();
    let mpz = lock
        .lines()
        .find_map(|l| l.strip_prefix("source = \"git+https://github.com/tlsnotary/mpz2").and_then(|r| r.split('#').nth(1)))
        .map(|r| r.trim_end_matches('"').chars().take(7).collect::<String>())
        .unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=CU_UPSTREAM={upstream}");
    println!("cargo:rustc-env=CU_MPZ2={mpz}");
    println!("cargo:rustc-env=CU_SOURCE_DIGEST={digest}");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
