#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_interface;
extern crate rustc_session;
extern crate rustc_span;

use std::env;
use std::mem;
use std::path::Path;
use std::process::exit;
use std::time::Instant;

use rustc_interface::interface;
use rustc_session::config::ErrorOutputType;
use rustc_session::parse::ParseSess;
use rustc_session::EarlyDiagCtxt;
use rustc_span::symbol::Symbol;

use rust_verify::driver::is_verifying_entire_crate;
use rust_verify::verifier::{Verifier, VerifierCallbacksEraseMacro};

mod glue;

fn extract_sub_args(tag: &str, args: &mut Vec<String>, mut consume_sub_arg: impl FnMut(String)) {
    let mut new = vec![];

    {
        let mut drain = args.drain(..);
        while let Some(arg) = drain.next() {
            let mut split = arg.splitn(2, '=');
            if split.next() == Some(tag) {
                if let Some(sub_arg) = split.next().map(ToOwned::to_owned).or_else(|| drain.next())
                {
                    consume_sub_arg(sub_arg);
                }
            } else {
                new.push(arg);
            }
        }
    }

    mem::swap(args, &mut new);
}

fn track_verus_args(psess: &mut ParseSess, args_env_var: &Option<String>) {
    psess
        .env_depinfo
        .get_mut()
        .insert((Symbol::intern("VERUS_ARGS"), args_env_var.as_deref().map(Symbol::intern)));
}

/// Track files that may be accessed at runtime in `file_depinfo` so that cargo will re-run verus
/// when any of them are modified
fn track_files(psess: &mut ParseSess) {
    let file_depinfo = psess.file_depinfo.get_mut();

    // During development track the `verus-driver` executable so that cargo will re-run verus whenever
    // it is rebuilt
    if cfg!(debug_assertions) {
        if let Ok(current_exe) = env::current_exe() {
            if let Some(current_exe) = current_exe.to_str() {
                file_depinfo.insert(Symbol::intern(current_exe));
            }
        }
    }
}

struct DefaultCallbacks;

impl rustc_driver::Callbacks for DefaultCallbacks {}

/// This is different from `DefaultCallbacks` that it will inform Cargo to track the value of
/// `VERUS_ARGS` environment variable.
struct RustcCallbacks {
    verus_args_var: Option<String>,
}

impl rustc_driver::Callbacks for RustcCallbacks {
    fn config(&mut self, config: &mut interface::Config) {
        let verus_args_var = self.verus_args_var.take();
        config.parse_sess_created = Some(Box::new(move |psess| {
            track_verus_args(psess, &verus_args_var);
        }));
    }
}

struct VerusCallbacks {
    verus_args_var: Option<String>,
}

impl rustc_driver::Callbacks for VerusCallbacks {
    fn config(&mut self, config: &mut interface::Config) {
        let verus_args_var = self.verus_args_var.take();
        config.parse_sess_created = Some(Box::new(move |psess| {
            track_verus_args(psess, &verus_args_var);
            track_files(psess);
        }));
    }
}

fn display_help() {
    println!("{}", help_message());
}

const BUG_REPORT_URL: &str = "https://github.com/verus-lang/verus/issues/new";

pub fn main() {
    // HACK to avoid:
    //
    // warning: failed to connect to jobserver from environment variable `CARGO_MAKEFLAGS="-j
    // --jobserver-fds=7,8 --jobserver-auth=7,8"`: cannot open file descriptor 7 from the jobserver
    // environment variable value: Bad file descriptor (os error 9)
    std::env::remove_var("CARGO_MAKEFLAGS");

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
        let mut orig_args = env::args_os()
            .enumerate()
            .map(|(i, arg)| {
                arg.into_string().unwrap_or_else(|arg| {
                    early_dcx.early_error(format!("argument {i} is not valid Unicode: {arg:?}"))
                })
            })
            .collect::<Vec<_>>();

        // Make "verus-driver --rustc" work like a subcommand that passes further args to "rustc"
        // for example `verus-driver --rustc --version` will print the rustc version that verus-driver
        // uses
        if let Some(pos) = orig_args.iter().position(|arg| arg == "--rustc") {
            orig_args.remove(pos);
            orig_args[0] = "rustc".to_string();

            let args: Vec<String> = orig_args.clone();

            return rustc_driver::RunCompiler::new(&args, &mut DefaultCallbacks).run();
        }

        if orig_args.iter().nth(1).map(String::as_str)
            == Some(rust_verify::lifetime::LIFETIME_DRIVER_ARG)
        {
            orig_args.remove(1);
            let mut buffer = String::new();
            use std::io::Read;
            std::io::stdin().read_to_string(&mut buffer).expect("cannot read stdin");
            rust_verify::lifetime::lifetime_rustc_driver(&orig_args, buffer);
            return Ok(());
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

        let mut verus_exclusive_args = vec![];

        let verus_exclusive_arg_tag = "--verus-arg";

        let mut args: Vec<String> = orig_args.clone();

        extract_sub_args(verus_exclusive_arg_tag, &mut args, |sub_arg| {
            verus_exclusive_args.push(sub_arg)
        });

        let verus_args_var = env::var("__VERUS_ARGS__").ok();
        let mut verus_args = verus_args_var
            .as_deref()
            .unwrap_or_default()
            .split("__VERUS_HACKERY__")
            .skip(1)
            .map(ToOwned::to_owned)
            .collect::<Vec<String>>();

        extract_sub_args(verus_exclusive_arg_tag, &mut verus_args, |sub_arg| {
            verus_exclusive_args.push(sub_arg)
        });

        // eprintln!("XXX args = {:?}", args);
        // eprintln!("XXX verus_args = {:?}", verus_args);
        // eprintln!("XXX verus_exclusive_args = {:?}", verus_exclusive_args);

        let crate_name = env::var("CARGO_CRATE_NAME").unwrap_or_default();

        let no_deps = matches!(env::var("__VERUS_NO_DEPS__").ok().as_deref(), Some("1"));

        let in_primary_package = env::var("CARGO_PRIMARY_PACKAGE").is_ok();

        let this_invocation_is_cargo_probing =
            args.windows(2).any(|window| window[0] == "--crate-name" && window[1] == "___");

        let low_level_crate =
            ["builtin", "builtin_macros", "state_machines_macros"].contains(&crate_name.as_str());

        let verus_enabled = (!no_deps || in_primary_package)
            && !this_invocation_is_cargo_probing
            && !low_level_crate;
        if !verus_enabled {
            // if crate_name == "builtin" {
            if low_level_crate {
                args.extend(["--cfg", "verus_keep_ghost"].map(ToOwned::to_owned));
            }
            return rustc_driver::RunCompiler::new(&args, &mut RustcCallbacks { verus_args_var })
                .set_using_internal_features(using_internal_features.clone())
                .run();
        }

        args.extend(verus_args);

        if ["builtin", "builtin_macros", "vstd"].contains(&crate_name.as_str()) {
            verus_exclusive_args.push("--no-vstd".to_owned());
        }

        let (parsed_verus_exclusive_args, unparsed) = rust_verify::config::parse_args_with_imports(
            &"TODO".to_owned(),
            verus_exclusive_args.iter().cloned(),
            None,
        );

        // eprintln!("XXX parsed_verus_exclusive_args = {:#?}", parsed_verus_exclusive_args);

        assert!(unparsed.len() == 1 && unparsed[0] == "TODO", "{:?}", unparsed);

        assert!(!parsed_verus_exclusive_args.version);

        let mk_file_loader = || rust_verify::file_loader::RealFileLoader;

        let verifier = Verifier::new(parsed_verus_exclusive_args);

        let mut verifier_callbacks = VerifierCallbacksEraseMacro {
            verifier,
            rust_start_time: Instant::now(),
            rust_end_time: None,
            lifetime_start_time: None,
            lifetime_end_time: None,
            rustc_args: args.clone(),
            file_loader: Some(Box::new(mk_file_loader())),
        };

        let mut rustc_args_for_keep_ghost = args.clone();
        extend_rustc_args_for_keep_ghost(&mut rustc_args_for_keep_ghost);

        let status =
            rustc_driver::RunCompiler::new(&rustc_args_for_keep_ghost, &mut verifier_callbacks)
                .set_using_internal_features(using_internal_features.clone())
                .run();

        let VerifierCallbacksEraseMacro { verifier, .. } = verifier_callbacks;

        if !verifier.args.output_json && !verifier.encountered_vir_error {
            eprintln!(
                "verification results:: {} verified, {} errors{}",
                verifier.count_verified,
                verifier.count_errors,
                if !is_verifying_entire_crate(&verifier) {
                    " (partial verification with `--verify-*`)"
                } else {
                    ""
                }
            );
        }

        if status.is_err() || verifier.encountered_vir_error {
            panic!("EEE V {:?} {:?}", status, verifier.encountered_vir_error);
        }

        let compile_status = if !verifier.args.compile && verifier.args.no_lifetime {
            Ok(())
        } else {
            let mut rustc_args_for_erase_ghost = args.clone();
            extend_rustc_args_for_erase_ghost(&mut rustc_args_for_erase_ghost);
            let do_compile = verifier.args.compile;
            rustc_driver::RunCompiler::new(
                &rustc_args_for_erase_ghost,
                &mut CompilerCallbacksEraseMacro { do_compile },
            )
            .set_using_internal_features(using_internal_features)
            .run()
        };

        if compile_status.is_err() {
            panic!("EEE C {:?}", status);
        }

        compile_status

        // rustc_driver::RunCompiler::new(&args, &mut VerusCallbacks { verus_args_var })
        //     .set_using_internal_features(using_internal_features)
        //     .run()
    }))
}

pub struct CompilerCallbacksEraseMacro {
    pub do_compile: bool,
}

impl rustc_driver::Callbacks for CompilerCallbacksEraseMacro {
    fn after_crate_root_parsing<'tcx>(
        &mut self,
        _compiler: &rustc_interface::interface::Compiler,
        queries: &'tcx rustc_interface::Queries<'tcx>,
    ) -> rustc_driver::Compilation {
        if !self.do_compile {
            rust_verify::lifetime::check(queries);
            rustc_driver::Compilation::Stop
        } else {
            rustc_driver::Compilation::Continue
        }
    }
}

fn extend_rustc_args_for_erase_ghost(args: &mut Vec<String>) {
    rust_verify::config::enable_default_features_and_verus_attr(args, true, true);
    let allow = &[
        "unused_imports",
        "unused_variables",
        "unused_assignments",
        "unreachable_patterns",
        "unused_parens",
        "unused_braces",
        "dead_code",
        "unreachable_code",
        "unused_mut",
        "unused_labels",
        "unused_attributes",
    ];
    for a in allow {
        args.extend(["-A", a].map(ToOwned::to_owned));
    }
    args.extend(["--cfg", "verus_keep_ghost"].map(ToOwned::to_owned));
}

fn extend_rustc_args_for_keep_ghost(args: &mut Vec<String>) {
    rust_verify::config::enable_default_features_and_verus_attr(args, true, false);
    args.extend(["--cfg", "verus_keep_ghost"].map(ToOwned::to_owned));
    args.extend(["--cfg", "verus_keep_ghost_body"].map(ToOwned::to_owned));
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
