#![feature(closure_lifetime_binder)]
#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_interface;
extern crate rustc_session;
extern crate rustc_span;
extern crate rustc_target;

use std::collections::BTreeMap;
use std::env;
use std::io::Read;
use std::mem;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::Arc;

use rustc_driver::{Callbacks, RunCompiler};
use rustc_session::config::ErrorOutputType;
use rustc_session::EarlyDiagCtxt;
use rustc_span::ErrorGuaranteed;

use clap::Parser;
use sha2::{Digest, Sha256};

mod callback_utils;
mod dep_tracker;
mod verifier;

use callback_utils::{
    probe_after_crate_root_parsing, probe_config, ConfigCallbackWrapper, DefaultCallbacks,
};
use dep_tracker::{DepTracker, DepTrackerConfigCallback};

const BUG_REPORT_URL: &str = "https://github.com/verus-lang/verus/issues/new";

pub fn main() {
    let early_dcx = EarlyDiagCtxt::new(ErrorOutputType::default());

    rustc_driver::init_rustc_env_logger(&early_dcx);

    let using_internal_features = if false {
        rustc_driver::install_ice_hook(BUG_REPORT_URL, |handler| {
            // FIXME: this macro calls unwrap internally but is called in a panicking context!  It's not
            // as simple as moving the call from the hook to main, because `install_ice_hook` doesn't
            // accept a generic closure.
            let version_info = rustc_tools_util::get_version_info!();
            handler.note(format!("Verus version: {version_info}"));
        })
    } else {
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))
    };

    exit(rustc_driver::catch_with_exit_code(move || {
        let mut orig_args = env::args().collect::<Vec<_>>();

        if orig_args.get(1).map(String::as_str) == Some(verifier::LIFETIME_DRIVER_ARG) {
            orig_args.remove(1);
            let mut buffer = String::new();
            std::io::stdin().read_to_string(&mut buffer).expect("failed to read stdin");
            verifier::lifetime_rustc_driver(&orig_args, buffer);
            exit(0);
        }

        // Make "verus-driver --rustc" work like a subcommand that passes further args to "rustc"
        // for example `verus-driver --rustc --version` will print the rustc version that verus-driver
        // uses
        if let Some(pos) = orig_args.iter().position(|arg| arg == "--rustc") {
            orig_args.remove(pos);
            orig_args[0] = "rustc".to_string();
            return RunCompiler::new(&orig_args, &mut DefaultCallbacks).run();
        }

        if orig_args.iter().any(|a| a == "--version" || a == "-V") {
            let version_info = rustc_tools_util::get_version_info!();
            println!("{version_info}");
            exit(0);
        }

        // Setting RUSTC_WRAPPER causes Cargo to pass 'rustc' as the first argument.
        // We're invoking the compiler programmatically, so we ignore this.
        let wrapper_mode =
            orig_args.get(1).map(Path::new).and_then(Path::file_stem) == Some("rustc".as_ref());

        if wrapper_mode {
            // we still want to be able to invoke it normally though
            orig_args.remove(1);
        }

        if !wrapper_mode
            && (orig_args.iter().any(|a| a == "--help" || a == "-h") || orig_args.len() == 1)
        {
            display_help();
            exit(0);
        }

        let this_invocation_is_cargo_probing =
            orig_args.windows(2).any(|window| window[0] == "--crate-name" && window[1] == "___");

        if this_invocation_is_cargo_probing {
            return RunCompiler::new(&orig_args, &mut DefaultCallbacks).run();
        }

        let mut dep_tracker = DepTracker::default();

        // During development track the `verus-driver` executable so that cargo will re-run verus
        // whenever it is rebuilt
        if cfg!(debug_assertions) {
            if let Ok(current_exe) = env::current_exe() {
                dep_tracker.mark_file(current_exe);
            }
        }

        let package_id = get_package_id_from_env(&mut dep_tracker);

        if let Some(package_id) = &package_id {
            let verify_package =
                dep_tracker.get_env(&format!("__VERUS_DRIVER_VERIFY_{package_id}")).as_deref()
                    == Some("1");

            let is_build_script = dep_tracker
                .get_env("CARGO_CRATE_NAME")
                .map(|name| name.starts_with("build_script_"))
                .unwrap_or(false);

            let verify_crate = verify_package && !is_build_script;

            if !verify_crate {
                let is_builtin = dep_tracker
                    .get_env(&format!("__VERUS_DRIVER_IS_BUILTIN_{package_id}"))
                    .as_deref()
                    == Some("1");
                let is_builtin_macros = dep_tracker
                    .get_env(&format!("__VERUS_DRIVER_IS_BUILTIN_MACROS_{package_id}"))
                    .as_deref()
                    == Some("1");

                if is_builtin || is_builtin_macros {
                    extend_rustc_args_for_builtin_and_builtin_macros(&mut orig_args);
                }

                return RunCompiler::new(
                    &orig_args,
                    &mut ConfigCallbackWrapper::new(
                        &mut DepTrackerConfigCallback::new(Arc::new(dep_tracker)),
                        &mut DefaultCallbacks,
                    ),
                )
                .set_using_internal_features(using_internal_features.clone())
                .run();
            }
        }

        let mut all_args = orig_args.clone();

        if let Some(package_id) = &package_id {
            if let Some(val) = dep_tracker.get_env("__VERUS_DRIVER_ARGS__") {
                all_args.extend(unpack_verus_driver_args_for_env(&val));
            }
            if let Some(val) = dep_tracker.get_env(&format!("__VERUS_DRIVER_ARGS_FOR_{package_id}"))
            {
                all_args.extend(unpack_verus_driver_args_for_env(&val));
            }
        }

        let mut verus_driver_inner_args = vec![];
        extract_inner_args("--verus-driver-arg", &mut all_args, |inner_arg| {
            verus_driver_inner_args.push(inner_arg)
        });

        let mut verus_inner_args = vec![];
        extract_inner_args("--verus-arg", &mut all_args, |inner_arg| {
            verus_inner_args.push(inner_arg)
        });

        let orig_rustc_args = all_args;

        let orig_rustc_opts = probe_config(&orig_rustc_args, |config| config.opts.clone()).unwrap();

        let mut rustc_args = orig_rustc_args;

        // HACK: clap expects exe in first arg
        verus_driver_inner_args.insert(0, "dummy".to_owned());

        let parsed_verus_driver_inner_args =
            VerusDriverInnerArgs::try_parse_from(&verus_driver_inner_args).unwrap_or_else(|err| {
                panic!(
                "failed to parse verus driver inner args from {verus_driver_inner_args:?}: {err}"
            )
            });

        {
            let is_primary_package = dep_tracker.get_env("CARGO_PRIMARY_PACKAGE").is_some();

            let compile = if is_primary_package {
                parsed_verus_driver_inner_args.compile_when_primary_package
            } else {
                parsed_verus_driver_inner_args.compile_when_not_primary_package
            };

            if compile {
                verus_inner_args.push("--compile".to_owned());
            }
        }

        let mut externs = BTreeMap::<String, Vec<PathBuf>>::new();

        if let Some(verus_sysroot) = parsed_verus_driver_inner_args
            .verus_sysroot
            .or_else(|| dep_tracker.get_env("VERUS_SYSROOT"))
        {
            let target_triple = &orig_rustc_opts.target_triple;

            let mut add_extern = |key: &str, pattern: String| {
                let mut paths = glob::glob(pattern.as_str()).unwrap();
                let path = paths.next().unwrap().unwrap();
                assert!(paths.next().is_none());
                rustc_args.push("--extern".to_owned());
                rustc_args.push(format!("{key}={}", path.display()));
                externs.insert(key.to_owned(), vec![path]);
            };

            add_extern(
                "builtin_macros",
                format!("{verus_sysroot}/lib/rustlib/lib/libbuiltin_macros-*.so"),
            );
            add_extern(
                "builtin",
                format!("{verus_sysroot}/lib/rustlib/{target_triple}/lib/libbuiltin-*.rlib"),
            );
            add_extern(
                "vstd",
                format!("{verus_sysroot}/lib/rustlib/{target_triple}/lib/libvstd-*.rlib"),
            );

            rustc_args.push("-L".to_owned());
            rustc_args.push(format!("dependency={verus_sysroot}/lib/rustlib/lib"));
            rustc_args.push("-L".to_owned());
            rustc_args.push(format!("dependency={verus_sysroot}/lib/rustlib/{target_triple}/lib"));
        }

        for (key, entry) in orig_rustc_opts.externs.iter() {
            if let Some(files) = entry.files() {
                externs
                    .insert(key.clone(), files.map(|path| path.canonicalized()).cloned().collect());
            }
        }

        for key in &parsed_verus_driver_inner_args.find_import {
            let paths = externs.get(key).unwrap();
            assert_eq!(paths.len(), 1);
            let path = &paths[0];
            assert!(["rlib", "rmeta"].contains(&path.extension().unwrap().to_str().unwrap()));
            let vir_path = path.with_extension("vir");
            verus_inner_args
                .extend(["--import".to_owned(), format!("{key}={}", vir_path.display())]);
            dep_tracker.mark_file(vir_path);
        }

        let vir_path = {
            // TODO
            // This is a very inefficient way of determining the .vir output path. One good solution
            // would be integrating the function of the --export into the callbacks in a way where
            // we can grab .output_filenames() sometime when it's convenient.

            let crate_meta_path =
                probe_after_crate_root_parsing(&rustc_args, |_compiler, queries| {
                    queries.global_ctxt().unwrap().enter(move |tcx| {
                        tcx.output_filenames(())
                            .output_path(rustc_session::config::OutputType::Metadata)
                    })
                })
                .unwrap();

            crate_meta_path.with_extension("vir")
        };

        verus_inner_args.extend(["--export".to_owned(), format!("{}", vir_path.display())]);

        // Track env vars used by Verus
        dep_tracker.get_env("VERUS_Z3_PATH");
        dep_tracker.get_env("VERUS_SINGULAR_PATH");

        let mut dep_tracker_config_callback = DepTrackerConfigCallback::new(Arc::new(dep_tracker));

        let mk_file_loader = || rustc_span::source_map::RealFileLoader;

        let compiler_runner = for<'a, 'b> |args: &'a [String],
                                           callbacks: &'b mut (dyn Callbacks + Send)|
                     -> Result<(), ErrorGuaranteed> {
            let mut wrapped_callbacks =
                ConfigCallbackWrapper::new(&mut dep_tracker_config_callback, callbacks);
            RunCompiler::new(args, &mut wrapped_callbacks)
                .set_using_internal_features(using_internal_features.clone())
                .run()
        };

        verifier::run(verus_inner_args.into_iter(), &rustc_args, mk_file_loader, compiler_runner)
    }))
}

fn get_package_id_from_env(dep_tracker: &mut DepTracker) -> Option<String> {
    match (
        dep_tracker.get_env("CARGO_PKG_NAME"),
        dep_tracker.get_env("CARGO_PKG_VERSION"),
        dep_tracker.get_env("CARGO_MANIFEST_DIR"),
    ) {
        (Some(name), Some(version), Some(manifest_dir)) => {
            Some(mk_package_id(name, version, format!("{manifest_dir}/Cargo.toml")))
        }
        _ => None,
    }
}

fn mk_package_id(
    name: impl AsRef<str>,
    version: impl AsRef<str>,
    manifest_path: impl AsRef<str>,
) -> String {
    let manifest_path_hash = {
        let mut hasher = Sha256::new();
        hasher.update(manifest_path.as_ref().as_bytes());
        hex::encode(hasher.finalize())
    };
    format!("{}-{}-{}", name.as_ref(), version.as_ref(), &manifest_path_hash[..12])
}

fn unpack_verus_driver_args_for_env(val: &str) -> Vec<String> {
    val.split("__VERUS_DRIVER_ARGS_SEP__").skip(1).map(ToOwned::to_owned).collect()
}

fn extract_inner_args(
    tag: &str,
    args: &mut Vec<String>,
    mut consume_inner_arg: impl FnMut(String),
) {
    let mut new = vec![];

    {
        let mut drain = args.drain(..);
        while let Some(arg) = drain.next() {
            let mut split = arg.splitn(2, '=');
            if split.next() == Some(tag) {
                if let Some(inner_arg) =
                    split.next().map(ToOwned::to_owned).or_else(|| drain.next())
                {
                    consume_inner_arg(inner_arg);
                }
            } else {
                new.push(arg);
            }
        }
    }

    mem::swap(args, &mut new);
}

#[derive(Debug, Parser)]
struct VerusDriverInnerArgs {
    #[arg(long)]
    compile_when_primary_package: bool,
    #[arg(long)]
    compile_when_not_primary_package: bool,
    #[arg(long)]
    is_builtin: bool,
    #[arg(long)]
    is_builtin_macros: bool,
    #[arg(long)]
    find_import: Vec<String>,
    #[arg(long)]
    verus_sysroot: Option<String>,
}

fn extend_rustc_args_for_builtin_and_builtin_macros(args: &mut Vec<String>) {
    args.extend(["--cfg", "verus_keep_ghost"].map(ToOwned::to_owned));
}

fn display_help() {
    println!("{}", help_message());
}

#[must_use]
fn help_message() -> &'static str {
    "TODO

Usage:
    verus-driver [OPTIONS] INPUT

Common options:
    -h, --help               Print this message
    -V, --version            Print version info and exit
    --rustc                  Pass all arguments to rustc
"
}
