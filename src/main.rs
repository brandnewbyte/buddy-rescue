use buddy_rescue::{
    ExportKind, ExportRequest, Inspection, Integrity, RescueError, Result, export, inspect,
};
use clap::{Parser, Subcommand};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "buddy-rescue",
    version,
    about = "Inspect and recover Buddy password vaults without the desktop app"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate a database and list its vaults without decrypting entries.
    Inspect {
        /// Buddy SQLite database to inspect.
        database: PathBuf,

        /// Attachment tree; defaults to attachments/ beside the database.
        #[arg(long)]
        attachments: Option<PathBuf>,

        /// Emit a machine-readable inspection report.
        #[arg(long)]
        json: bool,
    },

    /// Decrypt one vault and write a documented recovery export.
    Export {
        /// Buddy SQLite database to export.
        database: PathBuf,

        /// Vault ID from `buddy-rescue inspect`; required for multi-vault databases.
        #[arg(long)]
        vault: Option<String>,

        /// Export representation. JSON preserves the complete entry payload.
        #[arg(long, value_enum, default_value_t = ExportKind::Json)]
        format: ExportKind,

        /// Destination directory.
        #[arg(short, long, default_value = "buddy-export")]
        output: PathBuf,

        /// Attachment tree; defaults to attachments/ beside the database.
        #[arg(long)]
        attachments: Option<PathBuf>,

        /// Read one exact password line from standard input instead of prompting.
        #[arg(long)]
        password_stdin: bool,

        /// Replace an existing directory only if it is a prior buddy-rescue export.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Inspect {
            database,
            attachments,
            json,
        } => {
            let report = inspect(&database, attachments.as_deref())?;
            if json {
                let stdout = io::stdout();
                let mut output = stdout.lock();
                serde_json::to_writer_pretty(&mut output, &report)?;
                output
                    .write_all(b"\n")
                    .map_err(|error| RescueError::io("write inspection report", error))?;
            } else {
                print_inspection(&report);
            }
            Ok(if report.compatible {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::Export {
            database,
            vault,
            format,
            output,
            attachments,
            password_stdin,
            force,
        } => {
            let password = read_password(password_stdin)?;
            let summary = export(ExportRequest {
                database,
                attachments,
                vault_id: vault,
                password,
                kind: format,
                output,
                force,
            })?;

            println!(
                "Recovered {} entries and {} attachments to {}",
                summary.entries,
                summary.attachments,
                summary.output.display()
            );
            if let Some(warning) = summary.warning {
                eprintln!("warning: {warning}");
            }
            if summary.issues != 0 {
                eprintln!(
                    "warning: {} record issue(s) are documented in manifest.json",
                    summary.issues
                );
                return Ok(ExitCode::from(2));
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn read_password(from_stdin: bool) -> Result<Zeroizing<String>> {
    if !from_stdin {
        return rpassword::prompt_password("Master password: ")
            .map(Zeroizing::new)
            .map_err(|error| RescueError::io("read master password", error));
    }

    let mut password = String::new();
    io::stdin()
        .lock()
        .read_line(&mut password)
        .map_err(|error| RescueError::io("read master password from standard input", error))?;
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    Ok(Zeroizing::new(password))
}

fn print_inspection(report: &Inspection) {
    println!("Format: {}", report.format);
    match &report.integrity {
        Integrity::Ok => println!("SQLite integrity: ok"),
        Integrity::Failed { messages } => {
            println!("SQLite integrity: failed");
            for message in messages {
                println!("  - {message}");
            }
        }
    }
    println!(
        "Schema migration: {}",
        report
            .schema_version
            .map(|version| version.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!("Attachments: {}", report.attachments_directory.display());

    if report.vaults.is_empty() {
        println!("Vaults: none readable");
    } else {
        println!("Vaults: {}", report.vaults.len());
    }

    for vault in &report.vaults {
        println!();
        println!("{}", vault.name);
        println!("  ID: {}", vault.id);
        println!("  Vault version: {}", vault.version);
        println!(
            "  Entries: {} live, {} trashed",
            vault.live_entries, vault.trashed_entries
        );
        println!(
            "  Attachments: {} records, {} present, {} missing",
            vault.attachments, vault.attachment_files_present, vault.attachment_files_missing
        );
        println!(
            "  KDF: {} · {} KiB · t={} · p={} · version {}",
            vault.kdf.algorithm,
            vault.kdf.memory_kib,
            vault.kdf.iterations,
            vault.kdf.parallelism,
            vault.kdf.version
        );
        println!(
            "  Password hint: {}",
            if vault.hint_present {
                "present"
            } else {
                "none"
            }
        );
        println!(
            "  Status: {}",
            if vault.compatible {
                "compatible"
            } else {
                "attention required"
            }
        );
        for issue in &vault.issues {
            println!("    - {issue}");
        }
    }

    for issue in &report.issues {
        println!("Issue: {issue}");
    }
}
