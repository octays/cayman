//! Negotiated synchronization policy and authenticated in-process reconnection.
use super::{
    receiver::Storage,
    remote::{self, Conflicts, IO_TIMEOUT, MAX_FILE, MAX_FILES, Message, read, write},
    watch::Watch,
};
use crate::{
    crypto::{
        direct::{self, Error, Invitation},
        pairing::{self, ShortCode},
    },
    protocol::frame::{FrameError, Framed, MAX_RECORD},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_file_bytes: u64,
    pub max_files: usize,
    pub max_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: MAX_FILE,
            max_files: MAX_FILES,
            max_bytes: 1024 * 1024 * 1024 * 1024,
        }
    }
}
impl Limits {
    fn validate(&self) -> Result<(), Error> {
        if self.max_files == 0 || self.max_files > MAX_FILES || self.max_file_bytes > MAX_FILE {
            return Err("resource limits exceed protocol bounds".into());
        }
        Ok(())
    }
}
#[derive(Default)]
pub struct SendOptions {
    pub watch: bool,
    pub delete: bool,
    pub bidirectional: bool,
    pub limits: Limits,
}
#[derive(Default)]
pub struct ReceiveOptions {
    pub allow_delete: bool,
    pub bidirectional: bool,
    pub replace_existing: bool,
    pub limits: Limits,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    chunking: String,
    scope: String,
    prefix: String,
    file: bool,
    watch: bool,
    delete: bool,
    bidirectional: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum Control {
    Start(Config),
    Rejected { reason: String },
    Accepted { root: String },
    Cycle { rehash: bool },
    Poll,
    Changed { changed: bool },
    Stop,
}
async fn send_control<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut Framed<S>,
    message: &Control,
) -> Result<(), Error> {
    io.send(&serde_json::to_vec(message)?).await?;
    Ok(())
}
async fn recv_control<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut Framed<S>,
) -> Result<Control, Error> {
    Ok(serde_json::from_slice(&io.receive().await?)?)
}
fn cycle_result(result: Result<(), Error>) -> Result<bool, Error> {
    match result {
        Ok(()) => Ok(false),
        Err(e) if e.is::<Conflicts>() => Ok(true),
        Err(e) => Err(e),
    }
}

struct Monitor {
    root: PathBuf,
    file: bool,
    watch: Watch,
    snapshot: BTreeMap<PathBuf, std::fs::Metadata>,
}
impl Monitor {
    fn snapshot(root: &Path, file: bool) -> Result<BTreeMap<PathBuf, std::fs::Metadata>, Error> {
        if file && !root.try_exists()? {
            return Ok(BTreeMap::new());
        }
        remote::source_snapshot(root, file)
    }
    fn new(root: &Path, file: bool) -> Result<Self, Error> {
        let watched = if file && !root.try_exists()? {
            root.parent().ok_or("missing source parent")?
        } else {
            root
        };
        Ok(Self {
            root: root.to_owned(),
            file,
            watch: Watch::new(watched),
            snapshot: Self::snapshot(root, file)?,
        })
    }
    fn changed(&mut self) -> Result<bool, Error> {
        if !self.watch.changed() {
            return Ok(false);
        }
        Ok(!remote::same_snapshot(
            &self.snapshot,
            &Self::snapshot(&self.root, self.file)?,
        ))
    }
}

fn check_source(source: &Path, file: bool, limits: &Limits) -> Result<(), Error> {
    if file && !source.try_exists()? {
        return Ok(());
    }
    let entries = if file {
        vec![source.to_owned()]
    } else {
        super::compare::inventory(source)?
            .into_keys()
            .map(|p| source.join(p))
            .collect()
    };
    if entries.len() > limits.max_files {
        return Err("source exceeds configured entry limit".into());
    }
    let mut total = 0_u64;
    for path in entries {
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_file() {
            continue;
        }
        if metadata.len() > limits.max_file_bytes {
            return Err("source exceeds configured file size limit".into());
        }
        total = total
            .checked_add(metadata.len())
            .ok_or("source size overflow")?;
        if total > limits.max_bytes {
            return Err("source exceeds configured round byte limit".into());
        }
    }
    Ok(())
}

async fn send_round<S: AsyncRead + AsyncWrite + Unpin>(
    source: &Path,
    file: bool,
    delete: bool,
    io: &mut Framed<S>,
    state: &mut remote::SendState,
) -> Result<bool, Error> {
    if file && !source.try_exists()? {
        if !delete {
            return Err("source file disappeared; deletion propagation is disabled".into());
        }
        write(io, &Message::Begin { count: 0 }).await?;
        write(io, &Message::End { done: true }).await?;
        let Message::Report(report) = read(io).await? else {
            return Err("expected deletion report".into());
        };
        state.log.report(&report);
        return Ok(!report.conflicts.is_empty());
    }
    cycle_result(remote::sender_with_state(source, io, true, Duration::ZERO, state).await)
}
async fn receive_round<S: AsyncRead + AsyncWrite + Unpin>(
    storage: &mut Storage,
    io: &mut Framed<S>,
    limits: &Limits,
    delete: bool,
    log: &mut remote::RoundLog,
) -> Result<bool, Error> {
    cycle_result(
        remote::receiver_with_policy(
            storage,
            io,
            limits.max_bytes,
            delete,
            limits.max_files,
            limits.max_file_bytes,
            log,
        )
        .await,
    )
}

async fn sender_engine<S: AsyncRead + AsyncWrite + Unpin>(
    source: &Path,
    io: &mut Framed<S>,
    options: &SendOptions,
    authenticated: &mut bool,
    file: bool,
) -> Result<(), Error> {
    options.limits.validate()?;
    let (root, prefix) = if file && !source.try_exists()? {
        (
            source.to_owned(),
            PathBuf::from(source.file_name().ok_or("missing source filename")?),
        )
    } else {
        remote::source_layout(source)?
    };
    if root.try_exists()? && std::fs::symlink_metadata(&root)?.is_file() != file {
        return Err("source type changed".into());
    }
    if file && options.bidirectional {
        return Err("bidirectional synchronization requires a directory".into());
    }
    let prefix = prefix.to_str().ok_or("non-UTF8 source name")?.to_owned();
    let scope = format!("{}|{}|{}", root.display(), prefix, file);
    let config = Config {
        chunking: super::chunking::PROFILE.into(),
        scope: scope.clone(),
        prefix,
        file,
        watch: options.watch,
        delete: options.delete,
        bidirectional: options.bidirectional,
    };
    send_control(io, &Control::Start(config)).await?;
    let peer_root = match recv_control(io).await? {
        Control::Accepted { root } => root,
        Control::Rejected { reason } => {
            return Err(format!("receiver rejected policy: {reason}").into());
        }
        _ => return Err("expected receiver policy acceptance".into()),
    };
    if peer_root.len() > 8192 {
        return Err("invalid receiver root".into());
    }
    *authenticated = true;
    let mut storage = if options.bidirectional {
        let mut storage = Storage::open(&root, false)?;
        storage.bind_scope(&format!("two-way-source:{scope}:{peer_root}"), true)?;
        Some(storage)
    } else {
        None
    };
    // The effective receiver root already includes the source directory name.
    let outgoing = if file { root.clone() } else { root.join(".") };
    let mut full_check = Instant::now();
    let mut rehash = true;
    let mut send_state = remote::SendState::default();
    let mut receive_log = remote::RoundLog::default();
    loop {
        check_source(&root, file, &options.limits)?;
        send_control(io, &Control::Cycle { rehash }).await?;
        if rehash {
            send_state.clear_cache();
            if let Some(storage) = &mut storage {
                storage.clear_cache();
            }
        }
        let mut conflicts =
            send_round(&outgoing, file, options.delete, io, &mut send_state).await?;
        if let Some(storage) = &mut storage {
            let _ = receive_round(
                storage,
                io,
                &options.limits,
                options.delete,
                &mut receive_log,
            )
            .await?;
            // Reconcile baselines after the reverse phase; both-changed files
            // remain conflicts, receiver-only edits are now acknowledged.
            let final_conflicts =
                send_round(&outgoing, file, options.delete, io, &mut send_state).await?;
            conflicts = final_conflicts;
        }
        if !options.watch {
            send_control(io, &Control::Stop).await?;
            return if conflicts {
                Err(Box::new(Conflicts))
            } else {
                Ok(())
            };
        }
        let mut monitor = Monitor::new(&root, file)?;
        eprintln!(
            "Watching for changes ({}); authenticated reconnect enabled.",
            if monitor.watch.is_native() {
                "native events"
            } else {
                "polling fallback"
            }
        );
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            send_control(io, &Control::Poll).await?;
            let Control::Changed { changed } = recv_control(io).await? else {
                return Err("expected peer change status".into());
            };
            if monitor.changed()? || changed || full_check.elapsed() >= super::cache::RECHECK {
                rehash = full_check.elapsed() >= super::cache::RECHECK;
                if rehash {
                    full_check = Instant::now();
                }
                break;
            }
        }
    }
}

async fn receiver_engine<S: AsyncRead + AsyncWrite + Unpin>(
    output: &Path,
    io: &mut Framed<S>,
    options: &ReceiveOptions,
    authenticated: &mut bool,
    watch: &mut bool,
) -> Result<(), Error> {
    options.limits.validate()?;
    let Control::Start(config) = recv_control(io).await? else {
        return Err("expected synchronization policy".into());
    };
    if config.chunking != super::chunking::PROFILE {
        return Err("incompatible chunking profile; update both clients".into());
    }
    if config.delete && !options.allow_delete {
        let reason = "sender requested deletion; receiver must explicitly pass --delete";
        send_control(
            io,
            &Control::Rejected {
                reason: reason.into(),
            },
        )
        .await?;
        return Err(reason.into());
    }
    if config.bidirectional != options.bidirectional || (config.file && config.bidirectional) {
        let reason = "both peers must explicitly agree on --bidirectional";
        send_control(
            io,
            &Control::Rejected {
                reason: reason.into(),
            },
        )
        .await?;
        return Err(reason.into());
    }
    if config.scope.len() > 8192 || config.prefix.contains('/') {
        return Err("invalid synchronization scope".into());
    }
    if !config.prefix.is_empty() {
        super::receiver::validate_path(&config.prefix)?;
    }
    let effective = if config.file || config.prefix.is_empty() {
        output.to_owned()
    } else {
        output.join(&config.prefix)
    };
    // A sender-supplied directory name cannot redirect through a local symlink.
    if effective.try_exists()? && !super::platform::real_directory(&effective)? {
        return Err("unsafe receiver directory".into());
    }
    let mut storage = Storage::open(&effective, options.replace_existing)?;
    storage.bind_scope(
        &format!("receive:{}", config.scope),
        config.delete || config.bidirectional,
    )?;
    let root = std::fs::canonicalize(&effective)?;
    *authenticated = true;
    *watch = config.watch;
    send_control(
        io,
        &Control::Accepted {
            root: root.to_string_lossy().into_owned(),
        },
    )
    .await?;
    let mut monitor = if config.watch {
        Some(Monitor::new(&root, false)?)
    } else {
        None
    };
    let mut send_state = remote::SendState::default();
    let mut receive_log = remote::RoundLog::default();
    let mut conflicts = false;
    loop {
        match recv_control(io).await? {
            Control::Cycle { rehash } => {
                if rehash {
                    storage.clear_cache();
                    send_state.clear_cache();
                }
                conflicts = receive_round(
                    &mut storage,
                    io,
                    &options.limits,
                    config.delete,
                    &mut receive_log,
                )
                .await?;
                if config.bidirectional {
                    check_source(&root, false, &options.limits)?;
                    let _ = send_round(&root.join("."), false, config.delete, io, &mut send_state)
                        .await?;
                    conflicts = receive_round(
                        &mut storage,
                        io,
                        &options.limits,
                        config.delete,
                        &mut receive_log,
                    )
                    .await?;
                }
                if config.watch {
                    monitor = Some(Monitor::new(&root, false)?);
                }
            }
            Control::Poll if config.watch => {
                send_control(
                    io,
                    &Control::Changed {
                        changed: match monitor.as_mut() {
                            Some(monitor) => monitor.changed()?,
                            None => false,
                        },
                    },
                )
                .await?;
            }
            Control::Stop => {
                return if conflicts {
                    Err(Box::new(Conflicts))
                } else {
                    Ok(())
                };
            }
            _ => return Err("unexpected session control message".into()),
        }
    }
}

fn transient(error: &Error) -> bool {
    fn network(e: &std::io::Error) -> bool {
        matches!(
            e.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::NotConnected
        )
    }
    if let Some(e) = error.downcast_ref::<FrameError>() {
        return matches!(e, FrameError::Timeout) || matches!(e, FrameError::Io(e) if network(e));
    }
    error.downcast_ref::<std::io::Error>().is_some_and(network)
        || error.is::<tokio::time::error::Elapsed>()
}
fn resume_room(invitation: &Invitation) -> String {
    let mut hash = Sha256::new();
    hash.update(b"cayman/resume/v4");
    hash.update(invitation.pin);
    hash.update(invitation.secret.as_ref());
    format!(
        "cayman-resume-{}",
        hash.finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}
async fn relay_stream(address: &str, password: &str, room: &str) -> Result<TcpStream, Error> {
    let result = timeout(Duration::from_secs(60), async {
        crate::relay::pair(crate::relay::connect(address, password, room).await?).await
    })
    .await?;
    match result {
        Err(error) if error.to_string() == "relay room is already occupied" => {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "relay room is draining a previous connection",
            )
            .into())
        }
        other => other,
    }
}
async fn tls_server<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    config: Arc<rustls::ServerConfig>,
    invitation: &Invitation,
) -> Result<Framed<tokio_rustls::server::TlsStream<S>>, Error> {
    let tls = timeout(
        Duration::from_secs(15),
        TlsAcceptor::from(config).accept(stream),
    )
    .await??;
    let mut io = Framed::new(tls, MAX_RECORD, IO_TIMEOUT)?;
    let secret = Zeroizing::new(timeout(Duration::from_secs(15), io.receive()).await??);
    if secret.len() != 32 || !bool::from(secret.as_slice().ct_eq(invitation.secret.as_ref())) {
        return Err("peer authentication failed".into());
    }
    io.send(b"cayman-session/4").await?;
    Ok(io)
}
async fn tls_client<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    invitation: &Invitation,
) -> Result<Framed<tokio_rustls::client::TlsStream<S>>, Error> {
    let tls = timeout(
        Duration::from_secs(15),
        TlsConnector::from(direct::client(invitation)?)
            .connect("cayman.invalid".try_into()?, stream),
    )
    .await??;
    let mut io = Framed::new(tls, MAX_RECORD, IO_TIMEOUT)?;
    io.send(invitation.secret.as_ref()).await?;
    if io.receive().await? != b"cayman-session/4" {
        return Err("incompatible peer; update both clients".into());
    }
    Ok(io)
}
async fn delay(attempt: u32) {
    tokio::time::sleep(Duration::from_secs((1_u64 << attempt.min(5)).min(30))).await;
}

pub async fn send(
    source: &Path,
    listen: Option<SocketAddr>,
    address: &str,
    password: &str,
    options: SendOptions,
    code_file: Option<&Path>,
) -> Result<(), Error> {
    let source = remote::normalized_source(source)?;
    let file = source.is_file();
    options.limits.validate()?;
    if options.bidirectional && !source.is_dir() {
        return Err("--bidirectional requires a directory".into());
    }
    let listener = if let Some(listen) = listen {
        Some(TcpListener::bind(listen).await?)
    } else {
        None
    };
    let (config, invitation) = direct::server()?;
    let code = ShortCode::generate()?;
    let initial = if let Some(listener) = &listener {
        remote::write_code(&source, &code.encode(), code_file)?;
        eprintln!(
            "Listening on {}. Receiver selects its own output directory.",
            listener.local_addr()?
        );
        timeout(Duration::from_secs(600), listener.accept())
            .await??
            .0
    } else {
        eprintln!("Connecting to croc relay {address}...");
        let stream = crate::relay::connect(address, password, &code.relay_room()).await?;
        remote::write_code(&source, &code.encode(), code_file)?;
        eprintln!("Relay ready. Waiting for receiver.");
        crate::relay::pair(stream).await?
    };
    initial.set_nodelay(true)?;
    let initial = pairing::send(initial, &code, &invitation).await?;
    let mut stream = Some(initial);
    let mut authenticated = false;
    let mut attempts = 0;
    loop {
        let connection = match stream.take() {
            Some(stream) => Ok(stream),
            None => {
                if let Some(listener) = &listener {
                    timeout(Duration::from_secs(60), listener.accept())
                        .await
                        .map_err(|e| Box::new(e) as Error)
                        .and_then(|r| r.map(|(s, _)| s).map_err(Into::into))
                } else {
                    relay_stream(address, password, &resume_room(&invitation)).await
                }
            }
        };
        let result = async {
            let stream = connection?;
            stream.set_nodelay(true)?;
            let mut io = tls_server(stream, Arc::clone(&config), &invitation).await?;
            authenticated = true;
            sender_engine(&source, &mut io, &options, &mut authenticated, file).await
        }
        .await;
        match result {
            Ok(()) => return Ok(()),
            Err(error) if options.watch && authenticated && transient(&error) && attempts < 10 => {
                eprintln!(
                    "Connection lost: {error}. Reconnecting with authenticated session credentials..."
                );
                delay(attempts).await;
                attempts += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

pub async fn receive(
    output: &Path,
    connect: Option<SocketAddr>,
    address: &str,
    password: &str,
    code: &str,
    options: ReceiveOptions,
) -> Result<(), Error> {
    options.limits.validate()?;
    let code = ShortCode::parse(code)?;
    let initial = if let Some(address) = connect {
        timeout(Duration::from_secs(15), TcpStream::connect(address)).await??
    } else {
        eprintln!("Connecting to croc relay {address}...");
        relay_stream(address, password, &code.relay_room()).await?
    };
    initial.set_nodelay(true)?;
    let (initial, invitation) = pairing::receive(initial, &code).await?;
    let mut stream = Some(initial);
    let mut authenticated = false;
    let mut watch = false;
    let mut attempts = 0;
    loop {
        let connection = match stream.take() {
            Some(stream) => Ok(stream),
            None => {
                if let Some(address) = connect {
                    timeout(Duration::from_secs(15), TcpStream::connect(address))
                        .await
                        .map_err(|e| Box::new(e) as Error)
                        .and_then(|r| r.map_err(Into::into))
                } else {
                    relay_stream(address, password, &resume_room(&invitation)).await
                }
            }
        };
        let result = async {
            let stream = connection?;
            stream.set_nodelay(true)?;
            let mut io = tls_client(stream, &invitation).await?;
            receiver_engine(output, &mut io, &options, &mut authenticated, &mut watch).await
        }
        .await;
        match result {
            Ok(()) => return Ok(()),
            Err(error) if watch && authenticated && transient(&error) && attempts < 10 => {
                eprintln!(
                    "Connection lost: {error}. Reconnecting with authenticated session credentials..."
                );
                delay(attempts).await;
                attempts += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[tokio::test]
    async fn incompatible_chunking_profile_cannot_create_output() {
        let target = tempdir().unwrap();
        let output = target.path().join("must-not-exist");
        let (a, b) = tokio::io::duplex(4096);
        let mut a = Framed::new(a, MAX_RECORD, Duration::from_secs(3)).unwrap();
        let mut b = Framed::new(b, MAX_RECORD, Duration::from_secs(3)).unwrap();
        send_control(
            &mut a,
            &Control::Start(Config {
                chunking: "unknown-profile".into(),
                scope: "source".into(),
                prefix: String::new(),
                file: false,
                watch: false,
                delete: false,
                bidirectional: false,
            }),
        )
        .await
        .unwrap();
        let result = receiver_engine(
            &output,
            &mut b,
            &ReceiveOptions::default(),
            &mut false,
            &mut false,
        )
        .await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("incompatible chunking profile")
        );
        assert!(!output.exists());
    }
    async fn exchange(
        source: &Path,
        target: &Path,
        two_way: bool,
        delete: bool,
        allow_delete: bool,
    ) -> (Result<(), Error>, Result<(), Error>) {
        let (a, b) = tokio::io::duplex(4096);
        let send = async {
            let mut io = Framed::new(a, MAX_RECORD, Duration::from_secs(3)).unwrap();
            sender_engine(
                source,
                &mut io,
                &SendOptions {
                    bidirectional: two_way,
                    delete,
                    ..Default::default()
                },
                &mut false,
                source.is_file(),
            )
            .await
        };
        let receive = async {
            let mut io = Framed::new(b, MAX_RECORD, Duration::from_secs(3)).unwrap();
            receiver_engine(
                target,
                &mut io,
                &ReceiveOptions {
                    bidirectional: two_way,
                    allow_delete,
                    ..Default::default()
                },
                &mut false,
                &mut false,
            )
            .await
        };
        tokio::join!(send, receive)
    }

    #[tokio::test]
    async fn continuous_native_session_propagates_receiver_edits() {
        let source = tempdir().unwrap();
        let target = tempdir().unwrap();
        std::fs::write(source.path().join("file"), b"initial").unwrap();
        let root = source.path().join(".");
        let (a, b) = tokio::io::duplex(8192);
        let sender = async {
            let mut io = Framed::new(a, MAX_RECORD, Duration::from_secs(3)).unwrap();
            sender_engine(
                &root,
                &mut io,
                &SendOptions {
                    watch: true,
                    bidirectional: true,
                    ..Default::default()
                },
                &mut false,
                false,
            )
            .await
        };
        let receiver = async {
            let mut io = Framed::new(b, MAX_RECORD, Duration::from_secs(3)).unwrap();
            receiver_engine(
                target.path(),
                &mut io,
                &ReceiveOptions {
                    bidirectional: true,
                    ..Default::default()
                },
                &mut false,
                &mut false,
            )
            .await
        };
        let edit = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert_eq!(
                std::fs::read(target.path().join("file")).unwrap(),
                b"initial"
            );
            std::fs::write(target.path().join("file"), b"edited at receiver").unwrap();
            loop {
                if std::fs::read(source.path().join("file")).unwrap() == b"edited at receiver" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        timeout(Duration::from_secs(8), async {
            tokio::select! {
                result = async { tokio::join!(sender, receiver) } => panic!("session ended early: {result:?}"),
                () = edit => {},
            }
        }).await.unwrap();
    }

    #[tokio::test]
    async fn directory_layout_and_single_file_work_through_negotiation() {
        let parent = tempdir().unwrap();
        let target = tempdir().unwrap();
        let source = parent.path().join("docs");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("a"), b"hello").unwrap();
        let (s, r) = exchange(&source, target.path(), false, false, false).await;
        s.unwrap();
        r.unwrap();
        assert_eq!(
            std::fs::read(target.path().join("docs/a")).unwrap(),
            b"hello"
        );
        let output = tempdir().unwrap();
        let (s, r) = exchange(&source.join("a"), output.path(), false, false, false).await;
        s.unwrap();
        r.unwrap();
        assert_eq!(std::fs::read(output.path().join("a")).unwrap(), b"hello");
    }

    #[tokio::test]
    async fn bidirectional_merges_independent_changes_and_preserves_conflicts() {
        let source = tempdir().unwrap();
        let target = tempdir().unwrap();
        let root = source.path().join(".");
        std::fs::write(source.path().join("a"), b"first").unwrap();
        std::fs::write(target.path().join("b"), b"target only").unwrap();
        let (s, r) = exchange(&root, target.path(), true, false, false).await;
        s.unwrap();
        r.unwrap();
        assert_eq!(
            std::fs::read(source.path().join("b")).unwrap(),
            b"target only"
        );
        std::fs::write(target.path().join("a"), b"receiver edited").unwrap();
        let (s, r) = exchange(&root, target.path(), true, false, false).await;
        s.unwrap();
        r.unwrap();
        assert_eq!(
            std::fs::read(source.path().join("a")).unwrap(),
            b"receiver edited"
        );
        std::fs::write(source.path().join("a"), b"source edit").unwrap();
        std::fs::write(target.path().join("a"), b"target edit").unwrap();
        let (s, r) = exchange(&root, target.path(), true, false, false).await;
        assert!(s.unwrap_err().is::<Conflicts>());
        assert!(r.unwrap_err().is::<Conflicts>());
        assert_eq!(
            std::fs::read(source.path().join("a")).unwrap(),
            b"source edit"
        );
        assert_eq!(
            std::fs::read(target.path().join("a")).unwrap(),
            b"target edit"
        );
    }

    #[tokio::test]
    async fn deletions_require_consent_and_preserve_untracked_and_edited_files() {
        let source = tempdir().unwrap();
        let target = tempdir().unwrap();
        let root = source.path().join(".");
        std::fs::create_dir(source.path().join("dir")).unwrap();
        std::fs::write(source.path().join("dir/a"), b"first").unwrap();
        std::fs::write(source.path().join("b"), b"baseline").unwrap();
        let (s, r) = exchange(&root, target.path(), false, true, false).await;
        assert!(s.is_err() && r.is_err());
        assert!(!target.path().join("dir").exists());
        let (s, r) = exchange(&root, target.path(), false, true, true).await;
        s.unwrap();
        r.unwrap();
        std::fs::write(target.path().join("private"), b"keep").unwrap();
        std::fs::write(target.path().join("b"), b"local edit").unwrap();
        std::fs::remove_dir_all(source.path().join("dir")).unwrap();
        std::fs::remove_file(source.path().join("b")).unwrap();
        let (s, r) = exchange(&root, target.path(), false, true, true).await;
        assert!(s.unwrap_err().is::<Conflicts>());
        assert!(r.unwrap_err().is::<Conflicts>());
        assert!(!target.path().join("dir").exists());
        assert_eq!(
            std::fs::read(target.path().join("private")).unwrap(),
            b"keep"
        );
        assert_eq!(
            std::fs::read(target.path().join("b")).unwrap(),
            b"local edit"
        );
        assert!(
            std::fs::read_dir(target.path().join(".cayman"))
                .unwrap()
                .any(|e| e
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("history-"))
        );
    }

    #[tokio::test]
    async fn receiver_side_deletion_propagates_back_without_resurrection() {
        let source = tempdir().unwrap();
        let target = tempdir().unwrap();
        let root = source.path().join(".");
        std::fs::write(source.path().join("a"), b"data").unwrap();
        std::fs::create_dir(source.path().join("empty")).unwrap();
        let (s, r) = exchange(&root, target.path(), true, true, true).await;
        s.unwrap();
        r.unwrap();
        std::fs::remove_file(target.path().join("a")).unwrap();
        std::fs::remove_dir(target.path().join("empty")).unwrap();
        let (s, r) = exchange(&root, target.path(), true, true, true).await;
        s.unwrap();
        r.unwrap();
        assert!(!source.path().join("a").exists());
        assert!(!target.path().join("a").exists());
        assert!(!source.path().join("empty").exists());
        assert!(!target.path().join("empty").exists());
    }

    #[tokio::test]
    #[ignore = "requires loopback sockets; CI runs this network fault test explicitly"]
    async fn watch_reconnects_after_transport_is_cut() {
        let source = tempdir().unwrap();
        let target = tempdir().unwrap();
        let codes = tempdir().unwrap();
        let code_file = codes.path().join("invite");
        std::fs::write(source.path().join("file"), b"before drop").unwrap();
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let cut = Arc::new(tokio::sync::Notify::new());
        let proxy_cut = Arc::clone(&cut);
        let proxy_task = tokio::spawn(async move {
            let mut first = true;
            loop {
                let (mut incoming, _) = proxy.accept().await.unwrap();
                let mut outgoing = TcpStream::connect(address).await.unwrap();
                if first {
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing) => {},
                        _ = proxy_cut.notified() => {},
                    }
                    first = false;
                } else {
                    let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
                }
            }
        });
        let source_root = source.path().join(".");
        let sending = send(
            &source_root,
            Some(address),
            "",
            "",
            SendOptions {
                watch: true,
                ..Default::default()
            },
            Some(&code_file),
        );
        let receiving = async {
            while !code_file.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let code = std::fs::read_to_string(&code_file).unwrap();
            receive(
                target.path(),
                Some(proxy_address),
                "",
                "",
                &code,
                ReceiveOptions::default(),
            )
            .await
        };
        let controller = async {
            while std::fs::read(target.path().join("file")).ok().as_deref() != Some(b"before drop")
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            cut.notify_one();
            std::fs::write(source.path().join("file"), b"after reconnect").unwrap();
            while std::fs::read(target.path().join("file")).ok().as_deref()
                != Some(b"after reconnect")
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        let outcome = timeout(Duration::from_secs(30), async {
            tokio::select! {
                result = sending => panic!("sender stopped: {result:?}"),
                result = receiving => panic!("receiver stopped: {result:?}"),
                _ = controller => {},
            }
        })
        .await;
        proxy_task.abort();
        outcome.expect("transfer did not recover after connection loss");
    }

    #[tokio::test]
    async fn reconnected_tls_uses_pinned_high_entropy_identity() {
        let (config, invitation) = direct::server().unwrap();
        for _ in 0..2 {
            let (a, b) = tokio::io::duplex(4096);
            let (server, client) = tokio::join!(
                tls_server(a, Arc::clone(&config), &invitation),
                tls_client(b, &invitation)
            );
            server.unwrap();
            client.unwrap();
        }
        let bad = Invitation {
            pin: invitation.pin,
            secret: Zeroizing::new([17; 32]),
        };
        let (a, b) = tokio::io::duplex(4096);
        let (server, client) =
            tokio::join!(tls_server(a, config, &invitation), tls_client(b, &bad));
        assert!(server.is_err() && client.is_err());
        assert_ne!(resume_room(&invitation), resume_room(&bad));
        let dropped: Error = Box::new(FrameError::Io(std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof,
        )));
        assert!(transient(&dropped));
        assert!(!transient(&"peer authentication failed".into()));
    }
}
