//! `clamv-webui healthcheck`: the image has no curl, so the binary probes itself.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::Config;

pub async fn run(cfg: &Config) -> ExitCode {
    let mut addr = cfg.listen;
    if addr.ip().is_unspecified() {
        addr = match addr {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::LOCALHOST, addr.port())),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::LOCALHOST, addr.port())),
        };
    }
    match timeout(Duration::from_secs(3), probe(addr)).await {
        Ok(Ok(true)) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

async fn probe(addr: SocketAddr) -> std::io::Result<bool> {
    let mut s = TcpStream::connect(addr).await?;
    s.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut head = [0u8; 12];
    s.read_exact(&mut head).await?;
    Ok(head.starts_with(b"HTTP/1.") && &head[9..12] == b"200")
}
