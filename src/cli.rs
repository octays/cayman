use clap::{Args, Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "Cayman: encrypted remote incremental synchronization",
    long_about = "Remote incremental synchronization through a croc relay by default, with SPAKE2 short-code pairing and end-to-end TLS. Use --listen / --connect explicitly for direct TCP."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Share a file or directory through a relay and display a one-time invitation.
    #[command(visible_alias = "s")]
    Send {
        /// FILE sends one file; DIR includes its name; DIR/ or DIR/. sends its contents.
        source: PathBuf,
        /// Explicit direct mode: listen on this IP:port instead of using a relay.
        #[arg(long, conflicts_with_all = ["relay", "relay_password_file"])]
        listen: Option<SocketAddr>,
        #[command(flatten)]
        relay: RelayArgs,
        /// Continuously watch for changes and synchronize incrementally (poll every second).
        #[arg(long)]
        watch: bool,
        /// Write invitation to a new private file outside the source instead of displaying it.
        #[arg(long)]
        code_file: Option<PathBuf>,
    },
    /// Connect to a sender; read its invitation interactively or from a file.
    #[command(visible_alias = "r")]
    Receive {
        /// Local destination directory.
        #[arg(value_name = "TARGET")]
        output: PathBuf,
        /// Explicit direct mode: connect to sender IP:port instead of using a relay.
        #[arg(long, conflicts_with_all = ["relay", "relay_password_file"])]
        connect: Option<SocketAddr>,
        #[command(flatten)]
        relay: RelayArgs,
        #[arg(long)]
        code_file: Option<PathBuf>,
        /// Allow initial differing target files to be replaced, retaining backup copies.
        #[arg(long)]
        replace_existing: bool,
        /// Maximum sum of offered file sizes per round, in bytes.
        #[arg(long, default_value_t = 10 * 1024 * 1024 * 1024_u64)]
        max_bytes: u64,
    },
}

#[derive(Args)]
pub struct RelayArgs {
    /// Override the default croc relay (croc.schollz.com:9009); both peers must use the same relay.
    #[arg(long, value_name = "HOST:PORT")]
    pub relay: Option<String>,
    /// Read a private relay password from a file (default relay password: pass123).
    #[arg(long, value_name = "FILE")]
    pub relay_password_file: Option<PathBuf>,
}
impl RelayArgs {
    pub fn address(&self) -> &str {
        self.relay
            .as_deref()
            .unwrap_or(cayman::relay::DEFAULT_RELAY)
    }
    pub fn password(&self) -> Result<zeroize::Zeroizing<String>, cayman::crypto::direct::Error> {
        use std::io::Read;
        let mut password = zeroize::Zeroizing::new(String::new());
        if let Some(path) = &self.relay_password_file {
            std::fs::File::open(path)?
                .take(4097)
                .read_to_string(&mut password)?;
            if password.len() > 4096 {
                return Err("relay password file exceeds 4096 bytes".into());
            }
            let length = password.trim_end().len();
            password.truncate(length);
        } else {
            password.push_str("pass123");
        }
        Ok(password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relay_is_default_and_direct_mode_is_explicit() {
        let cli = Cli::try_parse_from(["cayman", "send", "source"]).unwrap();
        let Command::Send {
            listen,
            relay,
            watch,
            ..
        } = cli.command
        else {
            panic!("wrong command")
        };
        assert!(listen.is_none());
        assert!(!watch, "a single transfer round is the default");
        let cli = Cli::try_parse_from(["cayman", "send", "source", "--watch"]).unwrap();
        let Command::Send { watch, .. } = cli.command else {
            panic!("wrong command")
        };
        assert!(
            watch,
            "--watch must enable continuous incremental synchronization"
        );
        assert!(Cli::try_parse_from(["cayman", "send", "source", "--once"]).is_err());
        assert_eq!(relay.address(), cayman::relay::DEFAULT_RELAY);
        let cli = Cli::try_parse_from(["cayman", "receive", "target"]).unwrap();
        let Command::Receive { connect, relay, .. } = cli.command else {
            panic!("wrong command")
        };
        assert!(connect.is_none());
        assert_eq!(relay.address(), cayman::relay::DEFAULT_RELAY);
        let cli = Cli::try_parse_from(["cayman", "send", "source", "--relay", "example.org:9009"])
            .unwrap();
        let Command::Send { relay, .. } = cli.command else {
            panic!("wrong command")
        };
        assert_eq!(relay.address(), "example.org:9009");
        assert!(
            Cli::try_parse_from([
                "cayman",
                "send",
                "source",
                "--listen",
                "127.0.0.1:9009",
                "--relay",
                "example.org:9009"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "cayman",
                "receive",
                "target",
                "--connect",
                "127.0.0.1:9009",
                "--relay-password-file",
                "secret"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from(["cayman", "send", "source", "--listen", "127.0.0.1:9009"]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["cayman", "receive", "target", "--connect", "127.0.0.1:9009"])
                .is_ok()
        );
    }
}
