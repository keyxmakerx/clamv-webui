//! Async client for the clamd wire protocol.
//!
//! Every operation is bounded: connect, write and read have timeouts, INSTREAM
//! refuses to send more than `max_stream_bytes`, and responses are capped. A
//! stream that is cut short by a limit is reported as an error, never as clean.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::time::timeout;

const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Where clamd listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// `tcp://host:port`
    Tcp { host: String, port: u16 },
    /// `unix:///path/to/clamd.sock`
    Unix(PathBuf),
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Tcp { host, port } => write!(f, "tcp://{host}:{port}"),
            Endpoint::Unix(p) => write!(f, "unix://{}", p.display()),
        }
    }
}

impl FromStr for Endpoint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if let Some(path) = s.strip_prefix("unix://") {
            if path.is_empty() {
                return Err(Error::InvalidEndpoint);
            }
            return Ok(Endpoint::Unix(PathBuf::from(path)));
        }
        let rest = s.strip_prefix("tcp://").unwrap_or(s);
        let (host, port) = rest.rsplit_once(':').ok_or(Error::InvalidEndpoint)?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let port: u16 = port.parse().map_err(|_| Error::InvalidEndpoint)?;
        if host.is_empty() || port == 0 {
            return Err(Error::InvalidEndpoint);
        }
        Ok(Endpoint::Tcp {
            host: host.to_owned(),
            port,
        })
    }
}

/// Client errors. None of them means "clean".
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid clamd endpoint, expected tcp://host:port or unix:///path")]
    InvalidEndpoint,
    #[error("clamd connection failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("clamd {0} timed out")]
    Timeout(&'static str),
    #[error("stream exceeds the {0}-byte limit and was not fully scanned")]
    StreamTooLarge(u64),
    #[error("clamd response exceeds the size limit")]
    ResponseTooLarge,
    #[error("unsupported characters in scan path")]
    InvalidPath,
    #[error("clamd error: {0}")]
    Clamd(String),
    #[error("unexpected clamd response: {0}")]
    Protocol(String),
}

/// One detection reported by clamd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// `stream` for INSTREAM, otherwise the path clamd reported.
    pub path: String,
    pub signature: String,
}

/// Result of a scan that clamd completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Infected(Vec<Detection>),
}

impl Verdict {
    pub fn is_clean(&self) -> bool {
        matches!(self, Verdict::Clean)
    }
}

/// Limits applied to every connection.
#[derive(Debug, Clone)]
pub struct Limits {
    pub connect_timeout: Duration,
    /// Per read/write step for short commands and while streaming.
    pub io_timeout: Duration,
    /// Wait for a scan verdict once all data is sent (path scans can take hours).
    pub scan_timeout: Duration,
    /// Keep at or below clamd's StreamMaxLength.
    pub max_stream_bytes: u64,
    pub chunk_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(30),
            scan_timeout: Duration::from_secs(24 * 3600),
            max_stream_bytes: 256 * 1024 * 1024,
            chunk_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Client {
    endpoint: Endpoint,
    limits: Limits,
}

trait Conn: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Conn for T {}

impl Client {
    pub fn new(endpoint: Endpoint, limits: Limits) -> Self {
        Self { endpoint, limits }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub async fn ping(&self) -> Result<(), Error> {
        let r = self.simple("PING").await?;
        if r == "PONG" {
            Ok(())
        } else {
            Err(Error::Protocol(r))
        }
    }

    pub async fn version(&self) -> Result<String, Error> {
        self.simple("VERSION").await
    }

    pub async fn stats(&self) -> Result<String, Error> {
        self.simple("STATS").await
    }

    pub async fn reload(&self) -> Result<(), Error> {
        let r = self.simple("RELOAD").await?;
        if r == "RELOADING" {
            Ok(())
        } else {
            Err(Error::Protocol(r))
        }
    }

    /// Stream `data` to clamd. Fails with [`Error::StreamTooLarge`] if it is
    /// longer than `max_stream_bytes` or clamd's own StreamMaxLength.
    pub async fn instream<R: AsyncRead + Unpin>(&self, mut data: R) -> Result<Verdict, Error> {
        let mut conn = self.connect().await?;
        self.write(&mut conn, b"zINSTREAM\0").await?;
        let mut buf = vec![0u8; self.limits.chunk_bytes.max(1)];
        let mut sent: u64 = 0;
        loop {
            let n = timeout(self.limits.io_timeout, data.read(&mut buf))
                .await
                .map_err(|_| Error::Timeout("input read"))??;
            if n == 0 {
                break;
            }
            sent += n as u64;
            if sent > self.limits.max_stream_bytes {
                return Err(Error::StreamTooLarge(self.limits.max_stream_bytes));
            }
            let len = u32::try_from(n).map_err(|_| Error::Protocol("chunk too large".into()))?;
            let step = async {
                conn.write_all(&len.to_be_bytes()).await?;
                conn.write_all(&buf[..n]).await
            };
            match timeout(self.limits.io_timeout, step).await {
                Ok(Ok(())) => {}
                // clamd closes early when its StreamMaxLength is hit; read why.
                Ok(Err(_)) => return self.early_reply(&mut conn).await,
                Err(_) => return Err(Error::Timeout("write")),
            }
        }
        if timeout(self.limits.io_timeout, conn.write_all(&0u32.to_be_bytes()))
            .await
            .map_err(|_| Error::Timeout("write"))?
            .is_err()
        {
            return self.early_reply(&mut conn).await;
        }
        let reply = self.read_reply(&mut conn, self.limits.scan_timeout).await?;
        parse_scan(&reply)
    }

    /// Ask clamd to scan a path it can see, using its worker threads.
    /// The caller must have checked the path against the allowed roots.
    pub async fn multiscan(&self, path: &Path) -> Result<Verdict, Error> {
        self.path_command("MULTISCAN", path).await
    }

    /// Like [`Client::multiscan`] but single-threaded inside clamd (lower disk load).
    pub async fn contscan(&self, path: &Path) -> Result<Verdict, Error> {
        self.path_command("CONTSCAN", path).await
    }

    async fn path_command(&self, cmd: &str, path: &Path) -> Result<Verdict, Error> {
        let p = path.to_str().ok_or(Error::InvalidPath)?;
        if p.is_empty() || p.contains(['\0', '\n', '\r']) {
            return Err(Error::InvalidPath);
        }
        let mut conn = self.connect().await?;
        self.write(&mut conn, format!("z{cmd} {p}\0").as_bytes())
            .await?;
        let reply = self.read_reply(&mut conn, self.limits.scan_timeout).await?;
        parse_scan(&reply)
    }

    async fn simple(&self, cmd: &str) -> Result<String, Error> {
        let mut conn = self.connect().await?;
        self.write(&mut conn, format!("z{cmd}\0").as_bytes())
            .await?;
        let r = self.read_reply(&mut conn, self.limits.io_timeout).await?;
        let r = r.trim();
        if r.is_empty() {
            return Err(Error::Protocol("empty response".into()));
        }
        Ok(r.to_owned())
    }

    async fn early_reply(&self, conn: &mut Box<dyn Conn>) -> Result<Verdict, Error> {
        let reply = self.read_reply(conn, self.limits.io_timeout).await?;
        match parse_scan(&reply) {
            Err(Error::Clamd(m)) if m.contains("size limit exceeded") => {
                Err(Error::StreamTooLarge(self.limits.max_stream_bytes))
            }
            other => other,
        }
    }

    async fn connect(&self) -> Result<Box<dyn Conn>, Error> {
        let t = self.limits.connect_timeout;
        let conn: Box<dyn Conn> = match &self.endpoint {
            Endpoint::Tcp { host, port } => Box::new(
                timeout(t, TcpStream::connect((host.as_str(), *port)))
                    .await
                    .map_err(|_| Error::Timeout("connect"))??,
            ),
            #[cfg(unix)]
            Endpoint::Unix(p) => Box::new(
                timeout(t, UnixStream::connect(p))
                    .await
                    .map_err(|_| Error::Timeout("connect"))??,
            ),
            #[cfg(not(unix))]
            Endpoint::Unix(_) => return Err(Error::InvalidEndpoint),
        };
        Ok(conn)
    }

    async fn write(&self, conn: &mut Box<dyn Conn>, bytes: &[u8]) -> Result<(), Error> {
        timeout(self.limits.io_timeout, conn.write_all(bytes))
            .await
            .map_err(|_| Error::Timeout("write"))??;
        Ok(())
    }

    /// clamd closes the connection after each non-session command, so read to EOF.
    async fn read_reply(&self, conn: &mut Box<dyn Conn>, idle: Duration) -> Result<String, Error> {
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = timeout(idle, conn.read(&mut buf))
                .await
                .map_err(|_| Error::Timeout("read"))??;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
            if out.len() > MAX_RESPONSE_BYTES {
                return Err(Error::ResponseTooLarge);
            }
        }
        let text = String::from_utf8_lossy(&out).replace('\0', "\n");
        Ok(text)
    }
}

/// Parse a scan reply. Any line that is neither `OK` nor `FOUND` is an error.
pub fn parse_scan(reply: &str) -> Result<Verdict, Error> {
    let mut found = Vec::new();
    let mut ok = false;
    for line in reply.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some(rest) = line.strip_suffix(" FOUND") {
            let (path, sig) = rest
                .rsplit_once(": ")
                .ok_or_else(|| Error::Protocol(line.to_owned()))?;
            found.push(Detection {
                path: path.to_owned(),
                signature: sig.to_owned(),
            });
        } else if line.ends_with(" OK") {
            ok = true;
        } else if let Some(msg) = line.strip_suffix(" ERROR") {
            return Err(Error::Clamd(msg.to_owned()));
        } else {
            return Err(Error::Protocol(line.to_owned()));
        }
    }
    if !found.is_empty() {
        Ok(Verdict::Infected(found))
    } else if ok {
        Ok(Verdict::Clean)
    } else {
        Err(Error::Protocol("no scan verdict".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_endpoints() {
        assert_eq!(
            "tcp://clamav:3310".parse::<Endpoint>().ok(),
            Some(Endpoint::Tcp {
                host: "clamav".into(),
                port: 3310
            })
        );
        assert_eq!(
            "[::1]:3310".parse::<Endpoint>().ok(),
            Some(Endpoint::Tcp {
                host: "::1".into(),
                port: 3310
            })
        );
        assert_eq!(
            "unix:///run/clamd.sock".parse::<Endpoint>().ok(),
            Some(Endpoint::Unix("/run/clamd.sock".into()))
        );
        assert!("clamav".parse::<Endpoint>().is_err());
        assert!("tcp://:3310".parse::<Endpoint>().is_err());
    }

    #[test]
    fn parses_verdicts() {
        assert_eq!(parse_scan("stream: OK\n").ok(), Some(Verdict::Clean));
        let v = parse_scan("stream: Eicar-Test-Signature FOUND").ok();
        assert_eq!(
            v,
            Some(Verdict::Infected(vec![Detection {
                path: "stream".into(),
                signature: "Eicar-Test-Signature".into()
            }]))
        );
        assert!(matches!(
            parse_scan("INSTREAM size limit exceeded. ERROR"),
            Err(Error::Clamd(_))
        ));
        assert!(parse_scan("").is_err());
        assert!(parse_scan("/data/x: lstat() failed: No such file").is_err());
    }
}
