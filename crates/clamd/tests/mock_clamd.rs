//! Protocol tests against an in-process fake clamd.

use std::time::Duration;

use clamd::{Client, Endpoint, Error, Limits, Verdict};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const EICAR: &[u8] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Fake clamd: answers PING/VERSION, and INSTREAM with FOUND when the stream holds EICAR.
/// Streams longer than `stream_max` get clamd's size-limit error.
async fn fake_clamd(stream_max: usize) -> Endpoint {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut cmd = Vec::new();
                let mut b = [0u8; 1];
                while s.read_exact(&mut b).await.is_ok() && b[0] != 0 {
                    cmd.push(b[0]);
                }
                let reply: Vec<u8> = match cmd.as_slice() {
                    b"zPING" => b"PONG\0".to_vec(),
                    b"zVERSION" => b"ClamAV 1.4.0/27000/Thu Nov 12 09:00:00 2026\0".to_vec(),
                    b"zINSTREAM" => {
                        let mut data = Vec::new();
                        loop {
                            let mut len = [0u8; 4];
                            if s.read_exact(&mut len).await.is_err() {
                                return;
                            }
                            let n = u32::from_be_bytes(len) as usize;
                            if n == 0 {
                                break;
                            }
                            if data.len() + n > stream_max {
                                let _ = s.write_all(b"INSTREAM size limit exceeded. ERROR\0").await;
                                return;
                            }
                            let mut chunk = vec![0u8; n];
                            if s.read_exact(&mut chunk).await.is_err() {
                                return;
                            }
                            data.extend_from_slice(&chunk);
                        }
                        if data.windows(EICAR.len()).any(|w| w == EICAR) {
                            b"stream: Eicar-Test-Signature FOUND\0".to_vec()
                        } else {
                            b"stream: OK\0".to_vec()
                        }
                    }
                    _ => b"UNKNOWN COMMAND\0".to_vec(),
                };
                let _ = s.write_all(&reply).await;
            });
        }
    });
    Endpoint::Tcp {
        host: "127.0.0.1".into(),
        port,
    }
}

fn limits(max: u64) -> Limits {
    Limits {
        connect_timeout: Duration::from_secs(2),
        io_timeout: Duration::from_secs(2),
        scan_timeout: Duration::from_secs(5),
        max_stream_bytes: max,
        chunk_bytes: 1024,
    }
}

#[tokio::test]
async fn ping_and_version() {
    let c = Client::new(fake_clamd(1 << 20).await, limits(1 << 20));
    c.ping().await.expect("ping");
    assert!(c.version().await.expect("version").starts_with("ClamAV"));
}

#[tokio::test]
async fn detects_eicar_and_passes_clean() {
    let c = Client::new(fake_clamd(1 << 20).await, limits(1 << 20));
    assert!(!c.instream(EICAR).await.expect("scan").is_clean());
    assert_eq!(
        c.instream(&b"hello"[..]).await.expect("scan"),
        Verdict::Clean
    );
}

#[tokio::test]
async fn refuses_streams_over_client_limit() {
    let c = Client::new(fake_clamd(1 << 20).await, limits(4096));
    let big = vec![b'a'; 8192];
    assert!(matches!(
        c.instream(&big[..]).await,
        Err(Error::StreamTooLarge(_))
    ));
}

#[tokio::test]
async fn reports_clamd_stream_limit_as_error() {
    let c = Client::new(fake_clamd(2048).await, limits(1 << 20));
    let big = vec![b'a'; 64 * 1024];
    assert!(matches!(
        c.instream(&big[..]).await,
        Err(Error::StreamTooLarge(_))
    ));
}

#[tokio::test]
async fn connect_failure_is_error() {
    let c = Client::new(
        Endpoint::Tcp {
            host: "127.0.0.1".into(),
            port: 1,
        },
        limits(1024),
    );
    assert!(c.ping().await.is_err());
}
