#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_interface;
extern crate rustc_session;
extern crate rustc_span;

use std::collections::BTreeMap;
use std::env;
use std::io::Read;
use std::mem;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::Instant;

use rustc_interface::interface;
use rustc_session::config::ErrorOutputType;
use rustc_session::parse::ParseSess;
use rustc_session::EarlyDiagCtxt;
use rustc_span::symbol::Symbol;

use clap::Parser;
use sha2::{Digest, Sha256};

use rust_verify::driver::is_verifying_entire_crate;
use rust_verify::verifier::{Verifier, VerifierCallbacksEraseMacro};

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

        if orig_args.get(1).map(String::as_str) == Some(rust_verify::lifetime::LIFETIME_DRIVER_ARG)
        {
            orig_args.remove(1);
            let mut buffer = String::new();
            std::io::stdin().read_to_string(&mut buffer).expect("failed to read stdin");
            rust_verify::lifetime::lifetime_rustc_driver(&orig_args, buffer);
            exit(0);
        }

        // Make "verus-driver --rustc" work like a subcommand that passes further args to "rustc"
        // for example `verus-driver --rustc --version` will print the rustc version that verus-driver
        // uses
        if let Some(pos) = orig_args.iter().position(|arg| arg == "--rustc") {
            orig_args.remove(pos);
            orig_args[0] = "rustc".to_string();
            return rustc_driver::RunCompiler::new(&orig_args, &mut DefaultCallbacks).run();
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
            return rustc_driver::RunCompiler::new(&orig_args, &mut DefaultCallbacks).run();
        }

        let package_id = get_package_id_from_env();

        let mut all_args = orig_args.clone();

        let verus_args_var = None; // TODO

        all_args.extend(unpack_verus_driver_args_for_env(
            &env::var("__VERUS_DRIVER_ARGS__").unwrap_or_default(),
        ));
        all_args.extend(unpack_verus_driver_args_for_env(
            &env::var(format!("__VERUS_DRIVER_ARGS_FOR_{package_id}")).unwrap_or_default(),
        ));

        let mut verus_driver_inner_args = vec![];
        extract_inner_args("--verus-driver-arg", &mut all_args, |inner_arg| {
            verus_driver_inner_args.push(inner_arg)
        });

        let mut verus_inner_args = vec![];
        extract_inner_args("--verus-arg", &mut all_args, |inner_arg| {
            verus_inner_args.push(inner_arg)
        });

        let mut rustc_args = all_args;

        let parsed_verus_driver_inner_args =
            VerusDriverInnerArgs::try_parse_from(&verus_driver_inner_args).unwrap_or_else(|err| {
                panic!(
                "failed to parse verus driver inner args from {verus_driver_inner_args:?}: {err}"
            )
            });

        let cargo_crate_name = env::var("CARGO_CRATE_NAME").unwrap();

        let is_build_script = cargo_crate_name.starts_with("build_script_");

        let verify_crate = !parsed_verus_driver_inner_args.skip_verification && !is_build_script;

        let is_primary_package = env::var_os("CARGO_PRIMARY_PACKAGE").is_some();

        let compile = if is_primary_package {
            parsed_verus_driver_inner_args.compile_when_primary_package
        } else {
            parsed_verus_driver_inner_args.compile_when_primary_package
        };

        if compile {
            verus_inner_args.push("--compile".to_owned());
        }

        let probe = {
            let mut callbacks = ProbeCallbacks::new();
            let status = rustc_driver::RunCompiler::new(&rustc_args, &mut callbacks).run();
            assert!(status.is_ok(), "{:?}", status); // TODO
            callbacks.completed.unwrap()
        };

        // eprintln!("XXX {:?}", probe);

        verus_inner_args.extend([
            "--export".to_owned(),
            format!("{}", probe.crate_meta_path.with_extension("vir").display()),
        ]);

        {
            let mut remaining_imports = parsed_verus_driver_inner_args.find_import.clone();
            let mut it = orig_args.iter();
            while let Some(arg) = it.next() {
                if arg == "--extern" {
                    let pair = it.next().unwrap();
                    let mut split = pair.splitn(2, '=');
                    let key = split.next().unwrap();
                    if let Some(i) = remaining_imports.iter().position(|import| import == &key) {
                        remaining_imports.remove(i);
                        let rmeta_path = split.next().unwrap();
                        let vir_path = PathBuf::from(rmeta_path).with_extension("vir");
                        verus_inner_args.extend([
                            "--import".to_owned(),
                            format!("{key}={}", vir_path.display()),
                        ]);
                    }
                }
            }
            assert!(remaining_imports.is_empty(), "{:?}", remaining_imports);
        }

        if !verify_crate {
            extend_rustc_args_for_excluded(&mut rustc_args);
            return rustc_driver::RunCompiler::new(
                &rustc_args,
                &mut RustcCallbacks { verus_args_var: verus_args_var.clone() },
            )
            .set_using_internal_features(using_internal_features.clone())
            .run();
        }

        let program_name_for_config = "TODO";

        let (parsed_verus_inner_args, unparsed) = rust_verify::config::parse_args_with_imports(
            &program_name_for_config.to_owned(),
            verus_inner_args.iter().cloned(),
            None,
        );

        // TODO proper error message
        assert!(unparsed.len() == 1 && unparsed[0] == program_name_for_config, "{:?}", unparsed);

        // HACK
        assert!(!parsed_verus_inner_args.version);

        let mk_file_loader = || rust_verify::file_loader::RealFileLoader;

        let verifier = Verifier::new(parsed_verus_inner_args);

        let mut rustc_args_for_keep_ghost = rustc_args.clone();
        extend_rustc_args_for_keep_ghost(&mut rustc_args_for_keep_ghost);

        let mut verifier_callbacks = VerusCallbacksWrapper::new(
            verus_args_var.clone(),
            VerifierCallbacksEraseMacro {
                verifier,
                rust_start_time: Instant::now(),
                rust_end_time: None,
                lifetime_start_time: None,
                lifetime_end_time: None,
                rustc_args: rustc_args_for_keep_ghost.clone(),
                file_loader: Some(Box::new(mk_file_loader())),
            },
        );

        let status =
            rustc_driver::RunCompiler::new(&rustc_args_for_keep_ghost, &mut verifier_callbacks)
                .set_using_internal_features(using_internal_features.clone())
                .run();

        let VerifierCallbacksEraseMacro { verifier, .. } = verifier_callbacks.unwrap();

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
            // TODO proper error message
            panic!(
                "status.is_err() || verifier.encountered_vir_error... {:?} {:?}",
                status, verifier.encountered_vir_error
            );
        }

        let compile_status = if !verifier.args.compile && verifier.args.no_lifetime {
            Ok(())
        } else {
            let mut rustc_args_for_erase_ghost = rustc_args.clone();
            extend_rustc_args_for_erase_ghost(&mut rustc_args_for_erase_ghost);
            let do_compile = verifier.args.compile;
            rustc_driver::RunCompiler::new(
                &rustc_args_for_erase_ghost,
                &mut VerusCallbacksWrapper::new(
                    verus_args_var.clone(),
                    CompilerCallbacksEraseMacro { do_compile },
                ),
            )
            .set_using_internal_features(using_internal_features)
            .run()
        };

        if compile_status.is_err() {
            // TODO proper error message
            panic!("compile_status.is_err()... {:?}", status);
        }

        compile_status
    }))
}

fn display_help() {
    println!("{}", help_message());
}

#[derive(Debug, Parser)]
struct VerusDriverInnerArgs {
    #[arg(long)]
    compile_when_primary_package: bool,
    #[arg(long)]
    compile_when_not_primary_package: bool,
    #[arg(long)]
    skip_verification: bool,
    #[arg(long)]
    find_import: Vec<String>,
}

fn get_package_id_from_env() -> String {
    let name = env::var("CARGO_PKG_NAME").unwrap();
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    mk_package_id(name, version, format!("{manifest_dir}/Cargo.toml"))
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

// TODO more
fn track_verus_args(psess: &mut ParseSess, args_env_var: &Option<String>) {
    psess.env_depinfo.get_mut().insert((
        Symbol::intern("__VERUS_DRIVER_ARGS__"),
        args_env_var.as_deref().map(Symbol::intern),
    ));
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

fn extend_rustc_args_for_excluded(args: &mut Vec<String>) {
    args.extend(["--cfg", "verus_keep_ghost"].map(ToOwned::to_owned));
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

struct DefaultCallbacks;

impl rustc_driver::Callbacks for DefaultCallbacks {}

/// This is different from `DefaultCallbacks` that it will inform Cargo to track the value of
/// `__VERUS_ARGS__` environment variable.
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

#[allow(dead_code)]
#[derive(Debug)]
struct ProbeCompleted {
    crate_name: String,
    crate_types: Vec<rustc_session::config::CrateType>,
    crate_meta_path: PathBuf,
    extern_crate_meta_paths: BTreeMap<String, PathBuf>,
}

struct ProbeCallbacks {
    completed: Option<ProbeCompleted>,
}

impl ProbeCallbacks {
    fn new() -> Self {
        Self { completed: None }
    }
}

impl rustc_driver::Callbacks for ProbeCallbacks {
    fn after_crate_root_parsing<'tcx>(
        // fn after_expansion<'tcx>(
        &mut self,
        _compiler: &rustc_interface::interface::Compiler,
        queries: &'tcx rustc_interface::Queries<'tcx>,
    ) -> rustc_driver::Compilation {
        let completed = queries.global_ctxt().unwrap().enter(|tcx| ProbeCompleted {
            crate_name: tcx.crate_name(rustc_span::def_id::LOCAL_CRATE).as_str().to_owned(),
            crate_types: tcx.crate_types().to_vec(),
            crate_meta_path: tcx
                .output_filenames(())
                .output_path(rustc_session::config::OutputType::Metadata),
            extern_crate_meta_paths: tcx
                .crates(())
                .iter()
                .map(|&crate_num| {
                    let name = tcx.crate_name(crate_num).as_str().to_owned();
                    // let path = tcx.used_crate_source(crate_num).rmeta.as_ref().unwrap().0.clone();
                    // let x = tcx.crate_extern_paths(crate_num);
                    // eprintln!("{name}: {x:?}");
                    let path = PathBuf::new();
                    (name, path)
                })
                .collect(),
        });
        self.completed.replace(completed);
        rustc_driver::Compilation::Stop
    }
}

struct VerusCallbacksWrapper<T> {
    verus_args_var: Option<String>,
    wrapped: T,
}

impl<T> VerusCallbacksWrapper<T> {
    fn new(verus_args_var: Option<String>, wrapped: T) -> Self {
        Self { verus_args_var, wrapped }
    }

    fn unwrap(self) -> T {
        self.wrapped
    }
}

impl<T: rustc_driver::Callbacks> rustc_driver::Callbacks for VerusCallbacksWrapper<T> {
    fn config(&mut self, config: &mut interface::Config) {
        let verus_args_var = self.verus_args_var.take();
        config.parse_sess_created = Some(Box::new(move |psess| {
            track_verus_args(psess, &verus_args_var);
            track_files(psess);
        }));
        self.wrapped.config(config)
    }

    fn after_crate_root_parsing<'tcx>(
        &mut self,
        compiler: &rustc_interface::interface::Compiler,
        queries: &'tcx rustc_interface::Queries<'tcx>,
    ) -> rustc_driver::Compilation {
        self.wrapped.after_crate_root_parsing(compiler, queries)
    }

    fn after_expansion<'tcx>(
        &mut self,
        compiler: &rustc_interface::interface::Compiler,
        queries: &'tcx rustc_interface::Queries<'tcx>,
    ) -> rustc_driver::Compilation {
        self.wrapped.after_expansion(compiler, queries)
    }

    fn after_analysis<'tcx>(
        &mut self,
        compiler: &rustc_interface::interface::Compiler,
        queries: &'tcx rustc_interface::Queries<'tcx>,
    ) -> rustc_driver::Compilation {
        self.wrapped.after_analysis(compiler, queries)
    }
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
