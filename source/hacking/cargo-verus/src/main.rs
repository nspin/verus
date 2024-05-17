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

use cargo_metadata::{Metadata, MetadataCommand};
use serde::Deserialize;

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
    let args =
        env::args().skip(1 + if run_as_cargo_subcommand { 1 } else { 0 }).collect::<Vec<_>>();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        show_help();
        return;
    }

    if args.iter().any(|a| a == "--version" || a == "-V") {
        show_version();
        return;
    }

    if let Err(code) = process(&args) {
        process::exit(code);
    }
}

struct VerusCmd {
    cargo_subcommand: &'static str,
    cargo_args: Vec<String>,
    verus_driver_args: Vec<String>,
}

impl VerusCmd {
    fn new(args: &[String]) -> Self {
        let mut cargo_subcommand = "check";
        let mut cargo_args = vec![];
        let mut verus_driver_args: Vec<String> = vec![];

        let mut args_iter = args.iter();

        while let Some(arg) = args_iter.next() {
            match arg.as_str() {
                "--compile" => {
                    cargo_subcommand = "build";
                    verus_driver_args.push("--verus-arg=--compile".to_owned());
                    continue;
                }
                "--" => break,
                _ => {}
            }

            cargo_args.push(arg.clone());
        }

        verus_driver_args.extend(args_iter.cloned());

        Self { cargo_subcommand, cargo_args, verus_driver_args }
    }

    fn metadata(&self) -> Metadata {
        let standalone_flags = &["--frozen", "--locked", "--offline"];

        let flags_with_values = &["--config", "--manifest-path", "-Z"];

        let cargo_metadata_args =
            filter_args(self.cargo_args.iter(), standalone_flags, flags_with_values);

        let mut cmd = MetadataCommand::new();
        cmd.other_options(cargo_metadata_args);
        cmd.exec().unwrap_or_else(|err| {
            panic!("cargo metadata command {:?} failed: {:?}", cmd, err);
        })
    }

    fn verus_driver_path() -> PathBuf {
        let mut path = env::current_exe()
            .expect("current executable path invalid")
            .with_file_name("verus-driver");

        if cfg!(windows) {
            path.set_extension("exe");
        }

        path
    }

    fn into_std_cmd(self) -> Command {
        let verus_driver_args = pack_verus_driver_args(self.verus_driver_args.iter());

        let mut cmd = Command::new(env::var("CARGO").unwrap_or("cargo".into()));

        cmd.env("RUSTC_WRAPPER", Self::verus_driver_path())
            .env("__VERUS_DRIVER_ARGS__", verus_driver_args)
            .arg(self.cargo_subcommand)
            .args(&self.cargo_args);

        let metadata = self.metadata();

        for package in metadata.packages.iter() {
            let verus_metadata = package
                .metadata
                .as_object()
                .and_then(|obj| obj.get("verus"))
                .map(|v| {
                    serde_json::from_value::<VerusMetadata>(v.clone()).unwrap_or_else(|err| {
                        panic!(
                            "failed to parse {}-{}.metadata.verus: {}",
                            package.name, package.version, err
                        )
                    })
                })
                .unwrap_or_default();

            if verus_metadata.verify {
                cmd.env(format!("__VERUS_DRIVER_VERIFY_{}-{}", package.name, package.version), "1");
            }

            let mut verus_driver_args_for_package = vec![];

            if verus_metadata.no_vstd {
                verus_driver_args_for_package.push("--verus-arg=--no-vstd".to_owned());
            }

            cmd.env(
                format!("__VERUS_DRIVER_ARGS_FOR_{}-{}", package.name, package.version),
                pack_verus_driver_args(verus_driver_args_for_package.iter()),
            );
        }

        cmd
    }
}

fn process(args: &[String]) -> Result<(), i32> {
    let cmd = VerusCmd::new(args);

    let mut cmd = cmd.into_std_cmd();

    let exit_status =
        cmd.spawn().expect("could not run cargo").wait().expect("failed to wait for cargo?");

    if exit_status.success() {
        Ok(())
    } else {
        Err(exit_status.code().unwrap_or(-1))
    }
}

#[derive(Debug, Default, Deserialize)]
struct VerusMetadata {
    #[serde(default)]
    verify: bool,
    #[serde(rename = "no-vstd", default)]
    no_vstd: bool,
}

fn filter_args(
    mut orig_args: impl Iterator<Item = impl AsRef<str>>,
    standalone_flags: &[impl AsRef<str>],
    flags_with_values: &[impl AsRef<str>],
) -> Vec<String> {
    let mut acc = vec![];
    while let Some(arg) = orig_args.next() {
        if standalone_flags.iter().any(|flag| flag.as_ref() == arg.as_ref()) {
            acc.push(arg.as_ref().to_owned());
        } else if flags_with_values.iter().any(|flag| flag.as_ref() == arg.as_ref()) {
            acc.push(arg.as_ref().to_owned());
            acc.push(
                orig_args
                    .next()
                    .unwrap_or_else(|| {
                        panic!("expected {} to be followed by a value", arg.as_ref())
                    })
                    .as_ref()
                    .to_owned(),
            );
        } else {
            for flag in flags_with_values {
                if let Some(_val) = arg
                    .as_ref()
                    .strip_prefix(flag.as_ref())
                    .and_then(|without_flag| without_flag.strip_prefix("="))
                {
                    acc.push(arg.as_ref().to_owned());
                }
                break;
            }
        }
    }
    acc
}

fn pack_verus_driver_args(args: impl Iterator<Item = impl AsRef<str>>) -> String {
    args.map(|arg| ["__VERUS_DRIVER_ARGS_SEP__".to_owned(), arg.as_ref().to_owned()])
        .flatten()
        .collect()
}

#[must_use]
pub fn help_message() -> &'static str {
    "TODO

Usage:
    cargo verus [OPTIONS] [--] [<ARGS>...]

OPTIONS are passed to 'cargo check' (default) or 'cargo build' (when --compile is specified), except the following, which are handled specially:
    --compile                Selects the 'cargo build' subcommand and passes --verus-arg=--compile to 'verus-driver'
    -h, --help               Print this message
    -V, --version            Print version info and exit

ARGS are passed to 'verus-driver'.
"
}
