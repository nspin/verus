#!/usr/bin/env bash

set -eu -o pipefail

# for using nightly-only features on stable, required by verus code
export RUSTC_BOOTSTRAP=1

# for verifying vstd
export RUST_MIN_STACK=$(expr 10 '*' 1024 '*' 1024)

# require VERUS_Z3_PATH and VERUS_SINGULAR_PATH to be set
[ -n "$VERUS_Z3_PATH" ]
[ -n "$VERUS_SINGULAR_PATH" ]

cargo build -p verus-driver --features singular

# verify an example without codegen (like cargo check) and without applying rustc (like rust_verify without --compile)
cargo run -p cargo-verus -- --check -p doubly-linked-xor

# verify an example without codegen (like cargo check)
cargo run -p cargo-verus -- --check -p doubly-linked-xor

# build and verify an example with codegen (like cargo build)
cargo run -p cargo-verus -- -p doubly-linked-xor

# run it
../target/debug/doubly-linked-xor

# build and verify examples from ../rust_verify/example
cargo run -p cargo-verus -- -p rust-verify-examples --examples
