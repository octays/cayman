mod cli;

use cayman::sync::{Action, compare_directories};
use clap::Parser;
use cli::{Cli, Command};
use std::{
    io::{self, Write},
    process::ExitCode,
};

async fn run() -> Result<ExitCode, cayman::crypto::direct::Error> {
    match Cli::parse().command {
        Command::Send {
            source,
            listen,
            relay,
            once,
            code_file,
        } => {
            if let Some(listen) = listen {
                cayman::sync::remote::send(&source, listen, once, code_file.as_deref()).await?;
            } else {
                cayman::sync::remote::send_relay(
                    &source,
                    relay.address(),
                    &relay.password()?,
                    once,
                    code_file.as_deref(),
                )
                .await?;
            }
        }
        Command::Receive {
            output,
            connect,
            relay,
            code_file,
            replace_existing,
            max_bytes,
        } => {
            use std::io::{BufRead, Read};
            let mut code = zeroize::Zeroizing::new(String::new());
            if let Some(path) = code_file {
                std::fs::File::open(path)?
                    .take(256)
                    .read_to_string(&mut code)?;
            } else {
                eprintln!("Paste the sender's pairing code:");
                io::stdin().lock().take(256).read_line(&mut code)?;
            }
            if let Some(connect) = connect {
                cayman::sync::remote::receive(&output, connect, &code, replace_existing, max_bytes)
                    .await?;
            } else {
                cayman::sync::remote::receive_relay(
                    &output,
                    relay.address(),
                    &relay.password()?,
                    &code,
                    replace_existing,
                    max_bytes,
                )
                .await?;
            }
        }
        Command::Compare {
            source,
            target,
            chunk_size,
            json,
        } => {
            let plan = compare_directories(&source, &target, chunk_size as usize)?;
            let mut out = io::BufWriter::new(io::stdout().lock());
            if json {
                serde_json::to_writer_pretty(&mut out, &plan)?;
                writeln!(out)?;
            } else {
                for entry in &plan.entries {
                    if entry.action != Action::Unchanged {
                        writeln!(
                            out,
                            "{:?}\t{:?}\tmissing={} reusable={}",
                            entry.action, entry.path, entry.missing_bytes, entry.reusable_bytes
                        )?;
                    }
                }
                writeln!(
                    out,
                    "Read-only plan: {} entries; {} bytes missing, {} bytes reusable.",
                    plan.entries.len(),
                    plan.missing_bytes,
                    plan.reusable_bytes
                )?;
                writeln!(
                    out,
                    "Read-only comparison. Use send / receive for remote synchronization."
                )?;
            }
            out.flush()?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("cayman: {error}");
            ExitCode::FAILURE
        }
    }
}
