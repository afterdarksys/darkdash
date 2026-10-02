#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# Homebrew rustc is ahead of rust-toolchain.toml and is what a child `rustc`
# resolves to. The 1.97.1 target libraries are invisible to it.
sysroot="$(rustup run 1.97.1 rustc --print sysroot)"
export PATH="${sysroot}/bin:${PATH}"
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
if command -v cargo-deny >/dev/null 2>&1; then
    cargo deny check
else
    echo "cargo deny skipped"
fi
