#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use sbx_core::EXIT_PROTECTION_UNAVAILABLE;
use sbx_probe::{report_from_facts, ProbeFacts};
use sbx_runner::{prepare, RunError, RunOptions};
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "sbx",
    version,
    about = "Run untrusted programs in a restrictive, rootless Linux sandbox"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Probe which isolation features this machine really supports
    Doctor {
        /// Emit the stable machine-readable schema
        #[arg(long)]
        json: bool,
    },
    /// Run a command inside the sandbox
    Run(RunArgs),
}

#[derive(Debug, clap::Args)]
struct RunArgs {
    /// Bind a host path read-only at the same absolute path inside the sandbox
    #[arg(long = "ro", value_name = "PATH")]
    ro: Vec<PathBuf>,

    /// Bind a host path read-write at the same absolute path inside the sandbox
    #[arg(long = "rw", value_name = "PATH")]
    rw: Vec<PathBuf>,

    /// Copy this host environment variable into the sandbox
    #[arg(long = "env", value_name = "KEY")]
    env: Vec<String>,

    /// Working directory inside the sandbox (default: /home/sbx)
    #[arg(long, value_name = "PATH")]
    cwd: Option<PathBuf>,

    /// UTS-namespace hostname (default: sbx)
    #[arg(long, value_name = "NAME", default_value = sbx_runner::DEFAULT_HOSTNAME)]
    hostname: String,

    /// Do not print the protection summary (it is still applied)
    #[arg(long)]
    quiet: bool,

    /// Allow exposing paths the default policy marks as dangerous
    #[arg(long = "i-know-this-is-dangerous")]
    dangerous: bool,

    /// Run without the named protection layer; the summary reports it as off
    #[arg(long = "allow-degraded", value_name = "FEATURE")]
    allow_degraded: Vec<String>,

    /// The command and its arguments, after `--`
    #[arg(last = true, required = true, value_name = "CMD")]
    command: Vec<OsString>,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Doctor { json } => doctor(json),
        Command::Run(args) => run(args),
    };
    std::process::exit(code);
}

fn run(args: RunArgs) -> i32 {
    if let Some(feature) = args
        .allow_degraded
        .iter()
        .find(|feature| feature.as_str() != "landlock")
    {
        eprintln!("sbx: unknown --allow-degraded feature `{feature}`; supported: landlock");
        return sbx_core::EXIT_INTERNAL_ERROR;
    }

    let options = RunOptions {
        ro: args.ro,
        rw: args.rw,
        env: args.env,
        cwd: args.cwd,
        hostname: args.hostname,
        command: args.command,
        dangerous: args.dangerous,
        allow_degraded_landlock: args
            .allow_degraded
            .iter()
            .any(|feature| feature == "landlock"),
    };

    let prepared = match prepare(options) {
        Ok(prepared) => prepared,
        Err(error) => return report_error(error),
    };

    if !args.quiet {
        eprint!("{}", prepared.summary().render());
    }

    match prepared.execute() {
        Ok(code) => code,
        Err(error) => report_error(error),
    }
}

fn report_error(error: RunError) -> i32 {
    eprintln!("sbx: {error}");
    error.code
}

fn doctor(json: bool) -> i32 {
    let facts = ProbeFacts::collect();
    let report = report_from_facts(env!("CARGO_PKG_VERSION"), &facts);

    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(e) => {
                eprintln!("sbx: could not serialise doctor report: {e}");
                return sbx_core::EXIT_INTERNAL_ERROR;
            }
        }
    } else {
        println!("sbx doctor - probing real host capabilities (no settings changed)");
        println!();
        print!("{}", sbx_probe::render_table(&report));
        println!();
        if report.milestones_1_3_ready {
            println!("Host capabilities required by sbx: present");
        } else {
            let missing: Vec<&str> = report
                .blocking()
                .iter()
                .map(|feature| feature.label.as_str())
                .collect();
            println!(
                "Host capabilities required by sbx: MISSING or degraded: {}",
                missing.join(", ")
            );
            println!("sbx run will refuse to start (exit {EXIT_PROTECTION_UNAVAILABLE}).");
        }
    }

    if report.milestones_1_3_ready {
        0
    } else {
        EXIT_PROTECTION_UNAVAILABLE
    }
}
