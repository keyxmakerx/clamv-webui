//! Shared test helpers.
#![allow(dead_code)]

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub const EICAR: &[u8] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// PING, VERSION, INSTREAM (FOUND on EICAR) and MULTISCAN (a hit, an error and a limit hit).
pub async fn fake_clamd() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut cmd = Vec::new();
                let mut b = [0u8; 1];
                while s.read_exact(&mut b).await.is_ok() && b[0] != 0 {
                    cmd.push(b[0]);
                }
                let reply: Vec<u8> = match cmd.as_slice() {
                    b"zPING" => b"PONG\0".to_vec(),
                    b"zSTATS" => b"POOLS: 1\n\nSTATE: VALID PRIMARY\nTHREADS: live 3  idle 1 max 10 idle-timeout 30\nQUEUE: 0 items\n\tSTATS 0.000025 \n\nMEMSTATS: heap N/A mmap N/A used N/A free N/A releasable N/A pools 1 pools_used 1.000M pools_total 2.000M\nEND\0".to_vec(),
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
                    c if c.starts_with(b"zMULTISCAN ") => {
                        let p = String::from_utf8_lossy(&c[11..]).into_owned();
                        format!(
                            "{p}/eicar.com: Eicar-Test-Signature FOUND\0{p}/locked: Can't open file or directory ERROR\0{p}/huge.iso: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0"
                        )
                        .into_bytes()
                    }
                    _ => b"UNKNOWN COMMAND\0".to_vec(),
                };
                let _ = s.write_all(&reply).await;
            });
        }
    });
    port
}
