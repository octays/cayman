#![cfg(unix)]
use std::{
    fs,
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};
use tempfile::tempdir;

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn wait(process: &mut Process) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "remote process did not terminate"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn exchange(source: &Path, output: &Path, wrong_secret: bool) -> (bool, bool) {
    let codes = tempdir().unwrap();
    let code_file = codes.path().join("invite");
    let mut sender = Process(
        Command::new(env!("CARGO_BIN_EXE_cayman"))
            .args(["send"])
            .arg(source.join("."))
            .args(["--listen", "127.0.0.1:0", "--code-file"])
            .arg(&code_file)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stderr = sender.0.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            if tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let ready = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(ready.starts_with("Listening on "), "{ready}");
    let address = ready
        .split_whitespace()
        .nth(2)
        .unwrap()
        .trim_end_matches('.');
    if wrong_secret {
        let code = fs::read_to_string(&code_file).unwrap();
        let mut parts: Vec<_> = code.split('-').collect();
        parts[1] = if parts[1] == "amber" {
            "maple"
        } else {
            "amber"
        };
        fs::write(&code_file, parts.join("-")).unwrap();
    }
    let mut receiver = Process(
        Command::new(env!("CARGO_BIN_EXE_cayman"))
            .args(["receive"])
            .arg(output)
            .args(["--connect", address, "--code-file"])
            .arg(&code_file)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let received = wait(&mut receiver).success();
    let sent = wait(&mut sender).success();
    reader.join().unwrap();
    (sent, received)
}

#[test]
#[ignore = "requires loopback socket permission; run with --ignored"]
fn actual_tcp_tls_processes_sync_and_reconnect() {
    let source = tempdir().unwrap();
    let destination = tempdir().unwrap();
    let output = destination.path().join("receiver-selected-path");
    let mut data = vec![5; 256 * 1024 + 123];
    fs::write(source.path().join("file"), &data).unwrap();
    assert_eq!(exchange(source.path(), &output, false), (true, true));
    assert_eq!(fs::read(output.join("file")).unwrap(), data);
    data[17] = 42;
    fs::write(source.path().join("file"), &data).unwrap();
    assert_eq!(exchange(source.path(), &output, false), (true, true));
    assert_eq!(fs::read(output.join("file")).unwrap(), data);
    assert!(output.join(".cayman/state.json").exists());
}

#[test]
#[ignore = "requires loopback socket permission; run with --ignored"]
fn wrong_receiver_secret_cannot_create_output() {
    let source = tempdir().unwrap();
    let destination = tempdir().unwrap();
    fs::write(source.path().join("file"), b"secret file").unwrap();
    let output = destination.path().join("must-not-be-created");
    assert_eq!(exchange(source.path(), &output, true), (false, false));
    assert!(!output.exists());
}

#[test]
fn help_exposes_roles_without_sender_target_path() {
    let output = Command::new(env!("CARGO_BIN_EXE_cayman"))
        .args(["send", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("<SOURCE>"));
    assert!(!help.contains("<TARGET>"));
    let output = Command::new(env!("CARGO_BIN_EXE_cayman"))
        .args(["receive", "--help"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Usage: cayman receive [OPTIONS] <TARGET>")
    );
}

#[test]
#[ignore = "requires croc v11.5.3 on PATH and loopback socket permission; run with --ignored"]
fn actual_go_croc_relay_transfers_and_rejects_wrong_password() {
    let version = Command::new("croc")
        .arg("--version")
        .output()
        .expect("install croc v11.5.3 for this test");
    assert!(version.status.success());
    assert!(
        String::from_utf8_lossy(&version.stdout).contains("11.5.3"),
        "compatibility target is croc v11.5.3"
    );
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let address = format!("127.0.0.1:{port}");
    let mut relay = Process(
        Command::new("croc")
            .args([
                "--pass",
                "pass123",
                "relay",
                "--host",
                "127.0.0.1",
                "--ports",
                &port.to_string(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("install croc v11.5.3 for this test"),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            relay.0.try_wait().unwrap().is_none(),
            "Go relay exited before readiness"
        );
        if std::net::TcpStream::connect(&address).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "Go relay did not become ready");
        std::thread::sleep(Duration::from_millis(20));
    }
    let source = tempdir().unwrap();
    let target = tempdir().unwrap();
    let codes = tempdir().unwrap();
    let output = target.path().join("received");
    let mut data = vec![3; 3 * 256 * 1024 + 7];
    for round in 0..2 {
        data[256 * 1024 + 11] = round;
        fs::write(source.path().join("file"), &data).unwrap();
        let invitation = codes.path().join(format!("invite-{round}"));
        let mut sender = Process(
            Command::new(env!("CARGO_BIN_EXE_cayman"))
                .args(["send"])
                .arg(source.path().join("."))
                .args(["--relay", &address, "--code-file"])
                .arg(&invitation)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stderr = sender.0.stderr.take().unwrap();
        let (tx, rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                if tx.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        loop {
            let line = rx
                .recv_timeout(Duration::from_secs(10))
                .expect("sender failed before relay readiness");
            if line.starts_with("Relay ready.") {
                break;
            }
            assert!(!line.starts_with("cayman:"), "{line}");
        }
        let mut receiver = Process(
            Command::new(env!("CARGO_BIN_EXE_cayman"))
                .args(["receive", "--relay", &address])
                .arg(&output)
                .arg("--code-file")
                .arg(&invitation)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        assert!(
            wait(&mut receiver).success(),
            "receiver failed through Go relay"
        );
        assert!(
            wait(&mut sender).success(),
            "sender failed through Go relay"
        );
        reader.join().unwrap();
        assert_eq!(fs::read(output.join("file")).unwrap(), data);
    }
    let password = codes.path().join("wrong-password");
    fs::write(&password, b"incorrect relay password").unwrap();
    let invite = codes.path().join("must-not-exist");
    let mut sender = Process(
        Command::new(env!("CARGO_BIN_EXE_cayman"))
            .args(["send"])
            .arg(source.path().join("."))
            .args(["--relay", &address, "--code-file"])
            .arg(&invite)
            .arg("--relay-password-file")
            .arg(&password)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(!wait(&mut sender).success());
    assert!(!invite.exists());
}
