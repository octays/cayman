mod cli;

use clap::Parser;
use cli::{Cli, Command};
use std::{io, process::ExitCode};

async fn run() -> Result<ExitCode, cayman::crypto::direct::Error> {
    match Cli::parse().command {
        Command::Send {
            source,
            listen,
            relay,
            watch,
            delete,
            bidirectional,
            limits,
            code_file,
        } => {
            cayman::sync::session::send(
                &source,
                listen,
                relay.address(),
                &relay.password()?,
                cayman::sync::session::SendOptions {
                    watch,
                    delete,
                    bidirectional,
                    limits: limits.into(),
                },
                code_file.as_deref(),
            )
            .await?;
        }
        Command::Receive {
            output,
            connect,
            relay,
            code_file,
            replace_existing,
            delete,
            bidirectional,
            limits,
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
            cayman::sync::session::receive(
                &output,
                connect,
                relay.address(),
                &relay.password()?,
                &code,
                cayman::sync::session::ReceiveOptions {
                    allow_delete: delete,
                    bidirectional,
                    replace_existing,
                    limits: limits.into(),
                },
            )
            .await?;
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
