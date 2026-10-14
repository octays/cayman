//! Relay/default and explicit direct TLS synchronization; writes are receiver-owned.
use super::compare::{Kind, inventory, same_version};
use crate::{
    crypto::{
        direct::{self, Error, Invitation},
        pairing::{self, ShortCode},
    },
    protocol::frame::{Framed, MAX_RECORD},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Seek, SeekFrom},
    net::SocketAddr,
    path::{Path, PathBuf},
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

pub const CHUNK: usize = 256 * 1024;
pub const MAX_FILE: u64 = 1024 * 1024 * 1024;
pub const MAX_FILES: usize = 10_000;
pub const IO_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Version {
    pub hash: [u8; 32],
    pub size: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Offer {
    pub path: String,
    pub directory: bool,
    pub version: Version,
    pub blocks: Vec<[u8; 32]>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub installed: usize,
    pub unchanged: usize,
    pub transferred_bytes: u64,
    pub reused_bytes: u64,
    pub conflicts: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum Message {
    Begin { count: usize },
    Offer(Offer),
    NeedBlocks,
    Blocks { hashes: Vec<[u8; 32]> },
    Recheck,
    Ping,
    Pong,
    Need { indices: Vec<usize> },
    Skip,
    Conflict,
    Data { index: usize, bytes: Vec<u8> },
    Finish,
    Committed,
    End { done: bool },
    Report(Report),
}

pub(super) async fn write<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut Framed<S>,
    message: &Message,
) -> Result<(), Error> {
    let encoded = serde_json::to_vec(message)?;
    io.send(&encoded).await?;
    Ok(())
}
pub(super) async fn read<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut Framed<S>,
) -> Result<Message, Error> {
    Ok(serde_json::from_slice(&io.receive().await?)?)
}

// Inspect the original spelling before canonicalization removes trailing separators.
fn source_layout(source: &Path) -> Result<(PathBuf, PathBuf), Error> {
    let raw = source.as_os_str().to_str().ok_or("non-UTF8 source path")?;
    let contents = raw.ends_with(std::path::is_separator)
        || raw.rsplit(std::path::is_separator).next() == Some(".");
    let lexical: PathBuf = source.components().collect();
    if !std::fs::symlink_metadata(&lexical)?.is_dir() {
        return Err("source must be a real directory".into());
    }
    let root = std::fs::canonicalize(&lexical)?;
    let prefix = if contents {
        PathBuf::new()
    } else {
        PathBuf::from(
            root.file_name()
                .ok_or("use a trailing slash to share root contents")?,
        )
    };
    if !prefix.as_os_str().is_empty() {
        super::receiver::validate_path(prefix.to_str().ok_or("non-UTF8 directory name")?)?;
    }
    Ok((root, prefix))
}

fn normalized_source(source: &Path) -> Result<PathBuf, Error> {
    let (root, prefix) = source_layout(source)?;
    Ok(if prefix.as_os_str().is_empty() {
        root.join(".")
    } else {
        root
    })
}

pub async fn send(
    source: &Path,
    listen: SocketAddr,
    once: bool,
    code_file: Option<&Path>,
) -> Result<(), Error> {
    let source = normalized_source(source)?;
    let listener = TcpListener::bind(listen).await?;
    let (config, invitation) = direct::server()?;
    let code = ShortCode::generate()?;
    write_code(&source, &code.encode(), code_file)?;
    eprintln!(
        "Listening on {}. Receiver selects its own output directory.",
        listener.local_addr()?
    );
    // One admission attempt per invitation. Fail closed instead of offering a guessing oracle.
    let (tcp, _) = timeout(Duration::from_secs(600), listener.accept()).await??;
    tcp.set_nodelay(true)?;
    let tcp = pairing::send(tcp, &code, &invitation).await?;
    accept_stream(tcp, config, &invitation, &source, once).await
}

fn write_code(source: &Path, code: &str, code_file: Option<&Path>) -> Result<(), Error> {
    if let Some(path) = code_file {
        if path.canonicalize().is_ok_and(|p| p.starts_with(source))
            || path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .canonicalize()?
                .starts_with(source)
        {
            return Err("invitation file must be outside the shared source".into());
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        std::io::Write::write_all(&mut file, code.as_bytes())?;
        file.sync_all()?;
    } else {
        eprintln!("Pairing code: {code}");
    }
    Ok(())
}

pub async fn send_relay(
    source: &Path,
    address: &str,
    password: &str,
    once: bool,
    code_file: Option<&Path>,
) -> Result<(), Error> {
    let source = normalized_source(source)?;
    let (config, invitation) = direct::server()?;
    let code = ShortCode::generate()?;
    eprintln!("Connecting to croc relay {address}...");
    let stream = crate::relay::connect(address, password, &code.relay_room()).await?;
    write_code(&source, &code.encode(), code_file)?;
    eprintln!("Relay ready. Waiting for receiver; receiver selects its own output directory.");
    let stream = crate::relay::pair(stream).await?;
    let stream = pairing::send(stream, &code, &invitation).await?;
    accept_stream(stream, config, &invitation, &source, once).await
}

pub async fn receive_relay(
    output: &Path,
    address: &str,
    password: &str,
    code: &str,
    replace_existing: bool,
    max_bytes: u64,
) -> Result<(), Error> {
    let code = ShortCode::parse(code)?;
    eprintln!("Connecting to croc relay {address}...");
    let stream = crate::relay::connect(address, password, &code.relay_room()).await?;
    eprintln!("Relay connected. Waiting for sender...");
    let stream = crate::relay::pair(stream).await?;
    eprintln!("Sender connected. Verifying pairing code...");
    let (stream, invitation) = pairing::receive(stream, &code).await?;
    receive_stream(stream, &invitation, output, replace_existing, max_bytes).await
}

async fn accept_stream<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    config: std::sync::Arc<rustls::ServerConfig>,
    invitation: &Invitation,
    source: &Path,
    once: bool,
) -> Result<(), Error> {
    let tls = timeout(
        Duration::from_secs(15),
        TlsAcceptor::from(config).accept(stream),
    )
    .await??;
    let mut io = Framed::new(tls, MAX_RECORD, IO_TIMEOUT)?;
    timeout(Duration::from_secs(15), async {
        let supplied = Zeroizing::new(io.receive().await?);
        if supplied.len() != 32
            || !bool::from(supplied.as_slice().ct_eq(invitation.secret.as_ref()))
        {
            return Err::<(), Error>("receiver authentication failed".into());
        }
        io.send(b"cayman-sync/2 ready").await?;
        Ok(())
    })
    .await??;
    sender_session(source, &mut io, once, Duration::from_secs(1)).await
}

pub async fn receive(
    output: &Path,
    connect: SocketAddr,
    code: &str,
    replace_existing: bool,
    max_bytes: u64,
) -> Result<(), Error> {
    let code = ShortCode::parse(code)?;
    eprintln!("Connecting to sender {connect}...");
    let tcp = timeout(Duration::from_secs(15), TcpStream::connect(connect)).await??;
    tcp.set_nodelay(true)?;
    eprintln!("Sender connected. Verifying pairing code...");
    let (tcp, invitation) = pairing::receive(tcp, &code).await?;
    receive_stream(tcp, &invitation, output, replace_existing, max_bytes).await
}

async fn receive_stream<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    invitation: &Invitation,
    output: &Path,
    replace_existing: bool,
    max_bytes: u64,
) -> Result<(), Error> {
    let config = direct::client(invitation)?;
    let tls = timeout(
        Duration::from_secs(15),
        TlsConnector::from(config).connect("cayman.invalid".try_into()?, stream),
    )
    .await??;
    let mut io = Framed::new(tls, MAX_RECORD, IO_TIMEOUT)?;
    io.send(invitation.secret.as_ref()).await?;
    if io.receive().await? != b"cayman-sync/2 ready" {
        return Err("sender authentication protocol mismatch".into());
    }
    let mut storage = super::receiver::Storage::open(output, replace_existing)?;
    eprintln!(
        "Secure connection established. Receiving into {:?}.",
        std::fs::canonicalize(output)?
    );
    eprintln!("Comparing files with sender...");
    receiver_session(&mut storage, &mut io, max_bytes).await
}

/// Print the first round and subsequent changes, without repeating idle polls.
#[derive(Default)]
struct RoundLog {
    started: bool,
    conflicts: Vec<String>,
}
impl RoundLog {
    fn report(&mut self, report: &Report) {
        if !self.started || report.installed > 0 || self.conflicts != report.conflicts {
            eprintln!(
                "Files: {} updated, {} unchanged | Conflicts: {}",
                report.installed,
                report.unchanged,
                report.conflicts.len()
            );
            eprintln!(
                "File data: {} bytes transferred, {} bytes reused locally",
                report.transferred_bytes, report.reused_bytes
            );
            for path in &report.conflicts {
                eprintln!("Conflict preserved: {path:?}");
            }
        }
        self.started = true;
        self.conflicts.clone_from(&report.conflicts);
    }
}

pub(super) async fn sender_session<S: AsyncRead + AsyncWrite + Unpin>(
    source: &Path,
    io: &mut Framed<S>,
    once: bool,
    interval: Duration,
) -> Result<(), Error> {
    let (source, prefix) = source_layout(source)?;
    let mut log = RoundLog::default();
    let mut cache = super::cache::ManifestCache::default();
    let mut rechecked = Instant::now();
    loop {
        let snapshot = source_snapshot(&source)?;
        let mut entries: Vec<_> = inventory(&source)?
            .into_iter()
            .filter(|(p, _)| !p.starts_with(".cayman"))
            .collect();
        if !prefix.as_os_str().is_empty() {
            entries.insert(0, (PathBuf::new(), Kind::Directory));
        }
        if entries.len() > MAX_FILES {
            return Err("too many source entries".into());
        }
        write(
            io,
            &Message::Begin {
                count: entries.len(),
            },
        )
        .await?;
        for (relative, kind) in entries {
            let destination = if relative.as_os_str().is_empty() {
                prefix.clone()
            } else {
                prefix.join(&relative)
            };
            let path = destination
                .to_str()
                .ok_or("non-UTF8 path")?
                .replace(std::path::MAIN_SEPARATOR, "/");
            super::receiver::validate_path(&path)?;
            let directory = kind == Kind::Directory;
            let full = source.join(&relative);
            let offer = if directory {
                Offer {
                    path,
                    directory,
                    version: Version {
                        hash: [0; 32],
                        size: 0,
                    },
                    blocks: Vec::new(),
                }
            } else {
                if std::fs::symlink_metadata(&full)?.len() > MAX_FILE {
                    return Err("file exceeds 1 GiB direct-prototype limit".into());
                }
                let m = cache.get(&full, CHUNK)?;
                Offer {
                    path,
                    directory,
                    version: Version {
                        hash: m.hash,
                        size: m.size,
                    },
                    blocks: m.blocks.iter().map(|b| b.hash).collect(),
                }
            };
            write(
                io,
                &Message::Offer(Offer {
                    path: offer.path.clone(),
                    directory,
                    version: offer.version.clone(),
                    blocks: Vec::new(),
                }),
            )
            .await?;
            let mut response = read(io).await?;
            if matches!(response, Message::NeedBlocks) && !directory {
                write(
                    io,
                    &Message::Blocks {
                        hashes: offer.blocks.clone(),
                    },
                )
                .await?;
                response = read(io).await?;
            }
            match response {
                Message::Skip | Message::Conflict => continue,
                Message::Need { indices } if !directory => {
                    if indices.len() > offer.blocks.len() {
                        return Err("invalid block request".into());
                    }
                    let mut seen = BTreeSet::new();
                    let mut file = File::open(&full)?;
                    for index in indices {
                        if index >= offer.blocks.len() || !seen.insert(index) {
                            return Err("invalid block request".into());
                        }
                        let offset = index as u64 * CHUNK as u64;
                        let length = (offer.version.size - offset).min(CHUNK as u64) as usize;
                        let mut bytes = vec![0; length];
                        file.seek(SeekFrom::Start(offset))?;
                        file.read_exact(&mut bytes)?;
                        let hash: [u8; 32] = Sha256::digest(&bytes).into();
                        if hash != offer.blocks[index] {
                            return Err(
                                "source changed during transfer; reconnect to rescan".into()
                            );
                        }
                        write(io, &Message::Data { index, bytes }).await?;
                    }
                    write(io, &Message::Finish).await?;
                    match read(io).await? {
                        Message::Committed | Message::Conflict => {}
                        _ => return Err("expected commit acknowledgement".into()),
                    }
                }
                _ => return Err("unexpected file response".into()),
            }
        }
        write(io, &Message::End { done: once }).await?;
        let Message::Report(report) = read(io).await? else {
            return Err("expected round report".into());
        };
        let first_round = !log.started;
        log.report(&report);
        if first_round && !once {
            eprintln!("Watching source for changes; press Ctrl+C to stop.");
        }
        if once {
            if !report.conflicts.is_empty() {
                return Err("synchronization has unresolved conflicts".into());
            }
            return Ok(());
        }
        loop {
            tokio::time::sleep(interval).await;
            if rechecked.elapsed() >= super::cache::RECHECK {
                cache.clear();
                write(io, &Message::Recheck).await?;
                rechecked = Instant::now();
                break;
            }
            if !same_snapshot(&snapshot, &source_snapshot(&source)?) {
                break;
            }
            write(io, &Message::Ping).await?;
            if !matches!(read(io).await?, Message::Pong) {
                return Err("expected heartbeat response".into());
            }
        }
    }
}

fn source_snapshot(root: &Path) -> Result<BTreeMap<PathBuf, std::fs::Metadata>, Error> {
    let entries = inventory(root)?;
    if entries.len() > MAX_FILES {
        return Err("too many source entries".into());
    }
    entries
        .into_keys()
        .filter(|p| !p.starts_with(".cayman"))
        .map(|relative| {
            Ok((
                relative.clone(),
                std::fs::symlink_metadata(root.join(relative))?,
            ))
        })
        .collect()
}

fn same_snapshot(
    a: &BTreeMap<PathBuf, std::fs::Metadata>,
    b: &BTreeMap<PathBuf, std::fs::Metadata>,
) -> bool {
    a.len() == b.len()
        && a.iter().all(|(path, meta)| {
            b.get(path).is_some_and(|other| {
                meta.file_type() == other.file_type() && same_version(meta, other)
            })
        })
}

pub(super) async fn receiver_session<S: AsyncRead + AsyncWrite + Unpin>(
    storage: &mut super::receiver::Storage,
    io: &mut Framed<S>,
    max_bytes: u64,
) -> Result<(), Error> {
    let mut log = RoundLog::default();
    loop {
        let message = read(io).await?;
        if matches!(message, Message::Recheck) {
            storage.clear_cache();
            continue;
        }
        if matches!(message, Message::Ping) {
            write(io, &Message::Pong).await?;
            continue;
        }
        let Message::Begin { count } = message else {
            return Err("expected round begin".into());
        };
        if count > MAX_FILES {
            return Err("too many remote entries".into());
        }
        let mut progress = super::progress::Progress::new(count, !log.started);
        let mut report = Report::default();
        let mut seen = BTreeSet::new();
        let mut total = 0_u64;
        for _ in 0..count {
            let Message::Offer(offer) = read(io).await? else {
                return Err("expected file offer".into());
            };
            super::receiver::validate_summary(&offer)?;
            if !seen.insert(offer.path.clone()) {
                return Err("duplicate offer path".into());
            }
            total = total
                .checked_add(offer.version.size)
                .ok_or("size overflow")?;
            if total > max_bytes {
                return Err("round exceeds receiver byte limit".into());
            }
            storage
                .handle_with_progress(io, offer, &mut report, &mut |done, total| {
                    progress.file(done, total);
                })
                .await?;
            progress.entry_done();
        }
        let Message::End { done } = read(io).await? else {
            return Err("expected round end".into());
        };
        progress.finish();
        let conflicts = !report.conflicts.is_empty();
        let first_round = !log.started;
        log.report(&report);
        write(io, &Message::Report(report)).await?;
        if first_round && !done {
            eprintln!(
                "Initial synchronization finished. Waiting for source changes; press Ctrl+C to stop."
            );
        }
        if done {
            if conflicts {
                return Err("synchronization has unresolved conflicts".into());
            }
            eprintln!("Synchronization complete.");
            return Ok(());
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn unchanged_files_send_only_summary_not_block_lists() {
        let source = tempdir().unwrap();
        let contents = source.path().join(".");
        std::fs::write(source.path().join("file"), vec![7; CHUNK * 4]).unwrap();
        let (a, b) = tokio::io::duplex(4096);
        let mut a = Framed::new(a, MAX_RECORD, Duration::from_secs(3)).unwrap();
        let mut b = Framed::new(b, MAX_RECORD, Duration::from_secs(3)).unwrap();
        let peer = async {
            assert!(matches!(
                read(&mut b).await.unwrap(),
                Message::Begin { count: 1 }
            ));
            let Message::Offer(offer) = read(&mut b).await.unwrap() else {
                panic!("summary expected")
            };
            assert!(offer.blocks.is_empty());
            assert_eq!(offer.version.size, (CHUNK * 4) as u64);
            write(&mut b, &Message::Skip).await.unwrap();
            assert!(matches!(
                read(&mut b).await.unwrap(),
                Message::End { done: true }
            ));
            write(
                &mut b,
                &Message::Report(Report {
                    unchanged: 1,
                    ..Report::default()
                }),
            )
            .await
            .unwrap();
        };
        let (sent, ()) = tokio::join!(
            sender_session(&contents, &mut a, true, Duration::ZERO),
            peer
        );
        sent.unwrap();
    }

    #[tokio::test]
    async fn invalid_requested_block_list_cannot_install_file() {
        let output = tempdir().unwrap();
        let mut storage = super::super::receiver::Storage::open(output.path(), false).unwrap();
        let (a, b) = tokio::io::duplex(4096);
        let mut a = Framed::new(a, MAX_RECORD, Duration::from_secs(3)).unwrap();
        let mut b = Framed::new(b, MAX_RECORD, Duration::from_secs(3)).unwrap();
        let peer = async {
            write(&mut a, &Message::Begin { count: 1 }).await.unwrap();
            write(
                &mut a,
                &Message::Offer(Offer {
                    path: "file".into(),
                    directory: false,
                    version: Version {
                        size: 1,
                        hash: [1; 32],
                    },
                    blocks: Vec::new(),
                }),
            )
            .await
            .unwrap();
            assert!(matches!(read(&mut a).await.unwrap(), Message::NeedBlocks));
            write(&mut a, &Message::Blocks { hashes: Vec::new() })
                .await
                .unwrap();
        };
        let ((), received) = tokio::join!(peer, receiver_session(&mut storage, &mut b, MAX_FILE));
        assert!(received.is_err());
        assert!(!output.path().join("file").exists());
    }

    #[tokio::test]
    async fn directory_spelling_controls_layout_and_incremental_updates() {
        let parent = tempdir().unwrap();
        let source = parent.path().join("docs");
        std::fs::create_dir_all(source.join("empty")).unwrap();
        std::fs::write(source.join("file"), b"first").unwrap();
        for suffix in ["", "/", "/."] {
            let output = tempdir().unwrap();
            let spelled = PathBuf::from(format!("{}{suffix}", source.display()));
            let normalized = normalized_source(&spelled).unwrap();
            let expected = if suffix.is_empty() {
                output.path().join("docs")
            } else {
                output.path().to_owned()
            };
            for data in [b"first".as_slice(), b"second".as_slice()] {
                std::fs::write(source.join("file"), data).unwrap();
                let (sent, received) = round(&normalized, output.path(), false, MAX_FILE).await;
                sent.unwrap();
                received.unwrap();
                assert_eq!(std::fs::read(expected.join("file")).unwrap(), data);
                assert!(expected.join("empty").is_dir());
            }
        }
        assert!(
            source_layout(Path::new("."))
                .unwrap()
                .1
                .as_os_str()
                .is_empty()
        );
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(&source, &link).unwrap();
        assert!(source_layout(&link.join("")).is_err());
    }

    #[tokio::test]
    async fn short_code_tls_transfer_and_wrong_code_preserve_output_boundary() {
        for valid in [true, false] {
            let source = tempdir().unwrap();
            let target = tempdir().unwrap();
            let output = target.path().join("received");
            std::fs::write(source.path().join("file"), b"short code transfer").unwrap();
            let (config, invitation) = direct::server().unwrap();
            let code = ShortCode::parse("123456-maple-river-otter-cloud").unwrap();
            let other = ShortCode::parse(if valid {
                "123456-maple-river-otter-cloud"
            } else {
                "123456-amber-river-otter-cloud"
            })
            .unwrap();
            let (a, b) = tokio::io::duplex(4096);
            let sender = async {
                let a = pairing::send(a, &code, &invitation).await?;
                accept_stream(a, config, &invitation, &source.path().join("."), true).await
            };
            let receiver = async {
                let (b, anchor) = pairing::receive(b, &other).await?;
                receive_stream(b, &anchor, &output, false, MAX_FILE).await
            };
            let (sent, got) = timeout(Duration::from_secs(5), async {
                tokio::join!(sender, receiver)
            })
            .await
            .unwrap();
            if valid {
                sent.unwrap();
                got.unwrap();
                assert_eq!(
                    std::fs::read(output.join("file")).unwrap(),
                    b"short code transfer"
                );
            } else {
                assert!(sent.is_err());
                assert!(got.is_err());
                assert!(!output.exists());
            }
        }
    }

    #[tokio::test]
    async fn relay_admission_pairing_and_end_to_end_tls_transfer() {
        let source = tempdir().unwrap();
        let output_parent = tempdir().unwrap();
        let output = output_parent.path().join("receiver-owned");
        let data = vec![47; CHUNK + 57];
        std::fs::write(source.path().join("file"), &data).unwrap();
        let (config, invitation) = direct::server().unwrap();
        let code = ShortCode::generate().unwrap();
        let received_code = ShortCode::parse(&code.encode()).unwrap();
        let room = code.relay_room();
        let (mut a, mut relay_a) = tokio::io::duplex(4096);
        let (mut b, mut relay_b) = tokio::io::duplex(4096);
        let sender = async {
            crate::relay::test_admit(&mut a, &room).await?;
            let stream = crate::relay::pair(a).await?;
            let stream = pairing::send(stream, &code, &invitation).await?;
            accept_stream(stream, config, &invitation, &source.path().join("."), true).await
        };
        let receiver = async {
            crate::relay::test_admit(&mut b, &room).await?;
            let stream = crate::relay::pair(b).await?;
            let (stream, received) = pairing::receive(stream, &received_code).await?;
            receive_stream(stream, &received, &output, false, MAX_FILE).await
        };
        let relay = async {
            let (room_a, room_b) = tokio::join!(
                crate::relay::test_server(&mut relay_a, b"ok"),
                crate::relay::test_server(&mut relay_b, b"ok")
            );
            assert_eq!(room_a, room);
            assert_eq!(room_b, room);
            // Relay forwards opaque bytes without any invitation secret or TLS key.
            let _ = tokio::io::copy_bidirectional(&mut relay_a, &mut relay_b).await;
        };
        let (sent, got, ()) = timeout(Duration::from_secs(15), async {
            tokio::join!(sender, receiver, relay)
        })
        .await
        .unwrap();
        sent.unwrap();
        got.unwrap();
        assert_eq!(std::fs::read(output.join("file")).unwrap(), data);
    }

    #[tokio::test]
    async fn full_tls_authentication_and_transfer_reject_invalid_invitations() {
        for failure in 0..3 {
            let source = tempdir().unwrap();
            let destination = tempdir().unwrap();
            let output = destination.path().join("received");
            let data = vec![73; CHUNK + 17];
            std::fs::write(source.path().join("file"), &data).unwrap();
            let (config, invitation) = direct::server().unwrap();
            let mut received = Invitation::parse(&invitation.encode()).unwrap();
            match failure {
                1 => received.secret[0] ^= 1,
                2 => received.pin[0] ^= 1,
                _ => (),
            }
            let (a, b) = tokio::io::duplex(4096);
            let (sent, got) = timeout(Duration::from_secs(5), async {
                let contents = source.path().join(".");
                tokio::join!(
                    accept_stream(a, config, &invitation, &contents, true),
                    receive_stream(b, &received, &output, false, MAX_FILE)
                )
            })
            .await
            .unwrap();
            if failure == 0 {
                sent.unwrap();
                got.unwrap();
                assert_eq!(std::fs::read(output.join("file")).unwrap(), data);
            } else {
                assert!(sent.is_err());
                assert!(got.is_err());
                assert!(!output.exists());
            }
        }
    }

    #[tokio::test]
    async fn continuous_session_reuses_unchanged_blocks() {
        let source = tempdir().unwrap();
        let output = tempdir().unwrap();
        let mut data = [vec![1; CHUNK], vec![2; CHUNK], vec![3; CHUNK]].concat();
        std::fs::write(source.path().join("file"), &data).unwrap();
        let (a, b) = tokio::io::duplex(4096);
        let sender = async {
            let mut io = Framed::new(a, MAX_RECORD, Duration::from_secs(3)).unwrap();
            sender_session(
                &source.path().join("."),
                &mut io,
                false,
                Duration::from_millis(10),
            )
            .await
        };
        let receiver = async {
            let mut io = Framed::new(b, MAX_RECORD, Duration::from_secs(3)).unwrap();
            let mut storage = super::super::receiver::Storage::open(output.path(), false).unwrap();
            for round in 0..2 {
                assert!(matches!(
                    read(&mut io).await.unwrap(),
                    Message::Begin { count: 1 }
                ));
                let Message::Offer(offer) = read(&mut io).await.unwrap() else {
                    panic!("missing offer")
                };
                let mut report = Report::default();
                storage.handle(&mut io, offer, &mut report).await.unwrap();
                assert!(matches!(
                    read(&mut io).await.unwrap(),
                    Message::End { done: false }
                ));
                assert_eq!(std::fs::read(output.path().join("file")).unwrap(), data);
                if round == 1 {
                    assert_eq!(report.transferred_bytes, CHUNK as u64);
                    assert_eq!(report.reused_bytes, (2 * CHUNK) as u64);
                }
                write(&mut io, &Message::Report(report)).await.unwrap();
                if round == 0 {
                    // An idle source sends only a heartbeat, not another file offer.
                    assert!(matches!(read(&mut io).await.unwrap(), Message::Ping));
                    write(&mut io, &Message::Pong).await.unwrap();
                }
                data[CHUNK + 9] ^= 1;
                std::fs::write(source.path().join("file"), &data).unwrap();
            }
        };
        let (sent, ()) = timeout(Duration::from_secs(5), async {
            tokio::join!(sender, receiver)
        })
        .await
        .unwrap();
        assert!(
            sent.is_err(),
            "receiver closure must stop the continuous sender"
        );
    }

    async fn round(
        source: &Path,
        output: &Path,
        replace: bool,
        max: u64,
    ) -> (Result<(), Error>, Result<(), Error>) {
        let (a, b) = tokio::io::duplex(4096);
        let mut a = Framed::new(a, MAX_RECORD, Duration::from_secs(3)).unwrap();
        let mut b = Framed::new(b, MAX_RECORD, Duration::from_secs(3)).unwrap();
        let mut storage = super::super::receiver::Storage::open(output, replace).unwrap();
        tokio::join!(
            sender_session(source, &mut a, true, Duration::ZERO),
            receiver_session(&mut storage, &mut b, max)
        )
    }

    #[tokio::test]
    async fn remote_sessions_transfer_then_update_and_preserve_local_conflicts() {
        let source = tempdir().unwrap();
        let output = tempdir().unwrap();
        let original = [vec![1; CHUNK], vec![2; CHUNK], vec![3; 11]].concat();
        std::fs::create_dir(source.path().join("nested")).unwrap();
        std::fs::write(source.path().join("nested/file"), &original).unwrap();
        std::fs::write(source.path().join("empty"), []).unwrap();
        let (a, b) = round(&source.path().join("."), output.path(), false, MAX_FILE).await;
        a.unwrap();
        b.unwrap();
        assert_eq!(
            std::fs::read(output.path().join("nested/file")).unwrap(),
            original
        );
        assert!(output.path().join("empty").exists());
        let mut updated = original;
        updated[CHUNK + 17] = 42;
        std::fs::write(source.path().join("nested/file"), &updated).unwrap();
        let (a, b) = round(&source.path().join("."), output.path(), false, MAX_FILE).await;
        a.unwrap();
        b.unwrap();
        assert_eq!(
            std::fs::read(output.path().join("nested/file")).unwrap(),
            updated
        );
        std::fs::write(output.path().join("nested/file"), b"local edit").unwrap();
        let (a, b) = round(&source.path().join("."), output.path(), false, MAX_FILE).await;
        assert!(a.is_err());
        assert!(b.is_err());
        assert_eq!(
            std::fs::read(output.path().join("nested/file")).unwrap(),
            b"local edit"
        );
    }

    #[tokio::test]
    async fn first_difference_requires_explicit_replace_and_limit_rejects() {
        let source = tempdir().unwrap();
        let output = tempdir().unwrap();
        std::fs::write(source.path().join("file"), b"new").unwrap();
        std::fs::write(output.path().join("file"), b"old").unwrap();
        let (a, b) = round(&source.path().join("."), output.path(), false, MAX_FILE).await;
        assert!(a.is_err());
        assert!(b.is_err());
        let (a, b) = round(&source.path().join("."), output.path(), true, MAX_FILE).await;
        a.unwrap();
        b.unwrap();
        assert_eq!(std::fs::read(output.path().join("file")).unwrap(), b"new");
        let (a, b) = round(&source.path().join("."), output.path(), false, 1).await;
        assert!(a.is_err());
        assert!(b.is_err());
    }
}
