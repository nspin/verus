#!/usr/bin/env bash

# This script demonstrates the flow enabled by integration with Cargo. It can be run in a fresh
# checkout of the Verus repository. That is, it does not depend on Vargo or any other current Verus
# project build system code infrastructure. It does, however, require `$VERUS_Z3_PATH` and
# `$VERUS_SINGULAR_PATH` to be set.

set -eu -o pipefail

# require VERUS_Z3_PATH and VERUS_SINGULAR_PATH to be set
[ -n "$VERUS_Z3_PATH" ]
[ -n "$VERUS_SINGULAR_PATH" ]

RUSTC_BOOTSTRAP=1 cargo build -p verus-driver --features singular

# verify an example without codegen (like cargo check) and without applying rustc (like rust_verify without --compile)
cargo run -p cargo-verus -- --check --just-verify -p doubly-linked-xor-test

# verify an example without codegen (like cargo check)
cargo run -p cargo-verus -- --check -p doubly-linked-xor-test

# build and verify an example with codegen (like cargo build)
cargo run -p cargo-verus -- -p doubly-linked-xor-test

# this time with an argument for verus
cargo run -p cargo-verus -- -p doubly-linked-xor-test -- --verus-arg=--rlimit=60

# run it
../target/debug/doubly-linked-xor-test

# build and verify examples from ../rust_verify/example
cargo run -p cargo-verus -- --manifest-path rust-verify-examples/Cargo.toml --examples

# build and verify example using pre-built sysroot

verus_sysroot_parent=$(realpath ../verus-sysroot-dummy)

pushd $verus_sysroot_parent
./build-verus-sysroot.sh
popd

verus_sysroot=$verus_sysroot_parent/verus-sysroot

VERUS_SYSROOT=$verus_sysroot \
    cargo run -p cargo-verus -- -p doubly-linked-xor-test-using-verus-sysroot

# specify sysroot another way

cargo run -p cargo-verus -- -p doubly-linked-xor-test-using-verus-sysroot -- \
    --verus-driver-arg=--verus-sysroot=$verus_sysroot
