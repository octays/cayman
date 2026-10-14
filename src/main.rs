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
            code_file,
        } => {
            if let Some(listen) = listen {
                cayman::sync::remote::send(&source, listen, !watch, code_file.as_deref()).await?;
            } else {
                cayman::sync::remote::send_relay(
                    &source,
                    relay.address(),
                    &relay.password()?,
                    !watch,
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
