//
// Copyright (c) 2024 The Verus Contributors
// Copyright (c) 2014-2024 The Rust Project Developers
//
// SPDX-License-Identifier: MIT
//
// Derived, with significant modification, from:
// https://github.com/rust-lang/rust-clippy/blob/master/src/main.rs
//

use std::env;
use std::path::PathBuf;
use std::process::{self, Command};

fn show_help() {
    println!("{}", help_message());
}

fn show_version() {
    let version_info = rustc_tools_util::get_version_info!();
    println!("{version_info}");
}

pub fn main() {
    // Choose offset into args according to whether we are being run as `cargo-verus` or `cargo verus`.
    // (See https://doc.rust-lang.org/cargo/reference/external-tools.html#custom-subcommands)
    let run_as_cargo_subcommand = matches!(env::args().nth(1).as_deref(), Some("verus"));
    let args = || env::args().skip(1 + if run_as_cargo_subcommand { 1 } else { 0 });

    if args().any(|a| a == "--help" || a == "-h") {
        show_help();
        return;
    }

    if args().any(|a| a == "--version" || a == "-V") {
        show_version();
        return;
    }

    if let Err(code) = process(args()) {
        process::exit(code);
    }
}

struct VerusCmd {
    cargo_subcommand: &'static str,
    no_deps: bool,
    args: Vec<String>,
    verus_args: Vec<String>,
}

impl VerusCmd {
    fn new<I>(mut old_args: I) -> Self
    where
        I: Iterator<Item = String>,
    {
        let mut cargo_subcommand = "check";
        let mut no_deps = false;
        let mut args = vec![];
        let mut verus_args: Vec<String> = vec![];

        for arg in old_args.by_ref() {
            match arg.as_str() {
                "--compile" => {
                    cargo_subcommand = "build";
                    continue;
                }
                "--no-deps" => {
                    no_deps = true;
                    continue;
                }
                "--" => break,
                _ => {}
            }

            args.push(arg);
        }

        verus_args.append(&mut (old_args.collect()));

        Self { cargo_subcommand, no_deps, args, verus_args }
    }

    fn path() -> PathBuf {
        let mut path = env::current_exe()
            .expect("current executable path invalid")
            .with_file_name("verus-driver");

        if cfg!(windows) {
            path.set_extension("exe");
        }

        path
    }

    fn into_std_cmd(self) -> Command {
        let mut cmd = Command::new(env::var("CARGO").unwrap_or("cargo".into()));
        let verus_args: String = self
            .verus_args
            .iter()
            .map(|arg| ["__VERUS_HACKERY__", arg])
            .flatten()
            .collect::<String>();

        cmd.env("RUSTC_WORKSPACE_WRAPPER", Self::path())
            .env("__VERUS_ARGS__", verus_args)
            .arg(self.cargo_subcommand)
            .args(&self.args);

        if self.no_deps {
            cmd.env("__VERUS_NO_DEPS__", "1");
        }

        cmd
    }
}

fn process<I>(old_args: I) -> Result<(), i32>
where
    I: Iterator<Item = String>,
{
    let cmd = VerusCmd::new(old_args);

    let mut cmd = cmd.into_std_cmd();

    // eprintln!("XXX {:?}", cmd);

    let exit_status =
        cmd.spawn().expect("could not run cargo").wait().expect("failed to wait for cargo?");

    if exit_status.success() {
        Ok(())
    } else {
        Err(exit_status.code().unwrap_or(-1))
    }
}

#[must_use]
pub fn help_message() -> &'static str {
    "TODO

Usage:
    cargo verus [OPTIONS] [--] [<ARGS>...]

OPTIONS are passed to cargo check or cargo build, except the following, which are handled specially:
    --no-deps                Run Verus only on the given crate, without verifying the dependencies
    --compile
    -h, --help               Print this message
    -V, --version            Print version info and exit

ARGS are passed to verus-driver.
"
}
