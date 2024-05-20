#!/usr/bin/env bash

set -eu -o pipefail

# require VERUS_Z3_PATH and VERUS_SINGULAR_PATH to be set
[ -n "$VERUS_Z3_PATH" ]
[ -n "$VERUS_SINGULAR_PATH" ]

# for using nightly-only features on stable
export RUSTC_BOOTSTRAP=1

cargo build -p verus-driver --features singular

# verify an example without codegen (like cargo check) and without applying rustc (like rust_verify without --compile)
cargo run -p cargo-verus -- --check --just-verify -p doubly-linked-xor

# verify an example without codegen (like cargo check)
cargo run -p cargo-verus -- --check -p doubly-linked-xor

# build and verify an example with codegen (like cargo build)
cargo run -p cargo-verus -- -p doubly-linked-xor

# run it
../target/debug/doubly-linked-xor

# build and verify examples from ../rust_verify/example
cargo run -p cargo-verus -- -p rust-verify-examples --examples

# build and verify example using pre-built sysroot

verus_sysroot_parent=$(realpath ../verus-sysroot-dummy)

pushd $verus_sysroot_parent
./build-verus-sysroot.sh
popd

verus_sysroot=$verus_sysroot_parent/verus-sysroot

VERUS_SYSROOT=$verus_sysroot \
    cargo run -p cargo-verus -- -p doubly-linked-xor-using-verus-sysroot
