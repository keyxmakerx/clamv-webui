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

/// Replies to short commands, and any single scan result line, are capped here.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// A scan reply is parsed as it arrives; past this many results the rest are
/// counted in one summary error instead of kept.
pub const MAX_REPORT_LINES: usize = 100_000;

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

impl Detection {
    /// `AlertExceedsMax` hits: the file was too big or deep to scan fully,
    /// which is not the same as malware.
    pub fn is_limit_exceeded(&self) -> bool {
        self.signature.starts_with("Heuristics.Limits.Exceeded")
    }
}

/// A file clamd could not scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileError {
    pub path: String,
    pub message: String,
}

/// Every per-file result of a scan. Errors are kept even when there are
/// detections, so a partial failure is never reported as a clean or plain hit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub detections: Vec<Detection>,
    pub errors: Vec<FileError>,
    /// Files clamd reported as OK (MULTISCAN reports only the root when all are clean).
    pub ok: u64,
}

impl ScanReport {
    pub fn is_clean(&self) -> bool {
        self.detections.is_empty() && self.errors.is_empty()
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
    pub async fn instream<R: AsyncRead + Unpin>(&self, mut data: R) -> Result<ScanReport, Error> {
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
        let r = self
            .read_scan(&mut conn, self.limits.scan_timeout, "stream")
            .await;
        self.instream_result(r)
    }

    fn instream_result(&self, r: Result<ScanReport, Error>) -> Result<ScanReport, Error> {
        match r {
            Err(Error::Clamd(m)) if m.contains("size limit exceeded") => {
                Err(Error::StreamTooLarge(self.limits.max_stream_bytes))
            }
            other => other,
        }
    }

    /// Ask clamd to scan a path it can see, using its worker threads.
    /// The caller must have checked the path against the allowed roots.
    pub async fn multiscan(&self, path: &Path) -> Result<ScanReport, Error> {
        self.path_command("MULTISCAN", path).await
    }

    /// Like [`Client::multiscan`] but single-threaded inside clamd (lower disk load).
    pub async fn contscan(&self, path: &Path) -> Result<ScanReport, Error> {
        self.path_command("CONTSCAN", path).await
    }

    async fn path_command(&self, cmd: &str, path: &Path) -> Result<ScanReport, Error> {
        let raw = path_bytes(path)?;
        if raw.is_empty() || raw.iter().any(|b| matches!(b, 0 | b'\n' | b'\r')) {
            return Err(Error::InvalidPath);
        }
        let mut line = Vec::with_capacity(raw.len() + cmd.len() + 3);
        line.push(b'z');
        line.extend_from_slice(cmd.as_bytes());
        line.push(b' ');
        line.extend_from_slice(raw);
        line.push(0);
        let mut conn = self.connect().await?;
        self.write(&mut conn, &line).await?;
        self.read_scan(
            &mut conn,
            self.limits.scan_timeout,
            &String::from_utf8_lossy(raw),
        )
        .await
    }

    async fn simple(&self, cmd: &str) -> Result<String, Error> {
        let mut conn = self.connect().await?;
        self.write(&mut conn, format!("z{cmd}\0").as_bytes())
            .await?;
        let r = self.read_reply(&mut conn, self.limits.io_timeout).await?;
        let r = String::from_utf8_lossy(&r).replace('\0', "\n");
        let r = r.trim();
        if r.is_empty() {
            return Err(Error::Protocol("empty response".into()));
        }
        Ok(r.to_owned())
    }

    async fn early_reply(&self, conn: &mut Box<dyn Conn>) -> Result<ScanReport, Error> {
        let r = self.read_scan(conn, self.limits.io_timeout, "stream").await;
        self.instream_result(r)
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
    async fn read_reply(&self, conn: &mut Box<dyn Conn>, idle: Duration) -> Result<Vec<u8>, Error> {
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
        Ok(out)
    }

    /// Read a scan reply to EOF, parsing each result as it arrives, so a reply
    /// of any size keeps every detection up to `MAX_REPORT_LINES`.
    async fn read_scan(
        &self,
        conn: &mut Box<dyn Conn>,
        idle: Duration,
        base: &str,
    ) -> Result<ScanReport, Error> {
        let mut p = Parser::new(base);
        let mut buf = [0u8; 8192];
        loop {
            let n = timeout(idle, conn.read(&mut buf))
                .await
                .map_err(|_| Error::Timeout("read"))??;
            if n == 0 {
                break;
            }
            p.feed(&buf[..n])?;
        }
        p.finish()
    }
}

/// Incremental `z`-mode reply parser; see [`parse_scan`].
struct Parser {
    base: String,
    report: ScanReport,
    pending: Vec<u8>,
    /// Bytes of `pending` already searched for a NUL.
    scanned: usize,
    nul_seen: bool,
    kept: usize,
    dropped: u64,
    dropped_hits: u64,
    unknown: Vec<String>,
    clamd_errors: Vec<String>,
}

enum Item {
    Hit(Detection),
    Ok,
    FileErr(FileError),
    Excluded,
    ClamdErr(String),
    Unknown(String),
}

fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

impl Parser {
    fn new(base: &str) -> Self {
        Self {
            base: base.to_owned(),
            report: ScanReport::default(),
            pending: Vec::new(),
            scanned: 0,
            nul_seen: false,
            kept: 0,
            dropped: 0,
            dropped_hits: 0,
            unknown: Vec::new(),
            clamd_errors: Vec::new(),
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.pending.extend_from_slice(bytes);
        let mut start = 0;
        while let Some(off) = self.pending[self.scanned..].iter().position(|b| *b == 0) {
            let end = self.scanned + off;
            self.nul_seen = true;
            let item = String::from_utf8_lossy(&self.pending[start..end]).into_owned();
            self.line(&item);
            start = end + 1;
            self.scanned = start;
        }
        self.pending.drain(..start);
        self.scanned = self.pending.len();
        if self.pending.len() > MAX_RESPONSE_BYTES {
            return Err(Error::ResponseTooLarge);
        }
        Ok(())
    }

    fn classify(&self, item: &str) -> Item {
        if let Some(rest) = item.strip_suffix(" FOUND") {
            return match rest.rsplit_once(": ") {
                Some((path, sig)) => Item::Hit(Detection {
                    path: path.to_owned(),
                    signature: sig.to_owned(),
                }),
                None => Item::Unknown(item.to_owned()),
            };
        }
        if item.ends_with(": OK") {
            return Item::Ok;
        }
        if let Some(rest) = item.strip_suffix(" ERROR") {
            return match split_path(rest, &self.base) {
                Some((path, message)) => Item::FileErr(FileError {
                    path: path.to_owned(),
                    message: message.to_owned(),
                }),
                None => Item::ClamdErr(rest.to_owned()),
            };
        }
        if item.ends_with(": Excluded") {
            // ExcludePath match inside clamd: not scanned by design.
            return Item::Excluded;
        }
        Item::Unknown(item.to_owned())
    }

    fn line(&mut self, raw: &str) {
        let item = raw.trim_end_matches(['\n', '\r']);
        if item.trim().is_empty() {
            return;
        }
        match self.classify(item) {
            Item::Ok => self.report.ok += 1,
            Item::Excluded => {}
            Item::ClamdErr(m) => {
                if self.clamd_errors.len() < 10 {
                    self.clamd_errors.push(clip(&m, 500));
                }
            }
            Item::Unknown(m) => {
                if self.unknown.len() < 10 {
                    self.unknown.push(clip(&m, 500));
                }
            }
            Item::Hit(d) if self.kept < MAX_REPORT_LINES => {
                self.kept += 1;
                self.report.detections.push(d);
            }
            Item::FileErr(e) if self.kept < MAX_REPORT_LINES => {
                self.kept += 1;
                self.report.errors.push(e);
            }
            Item::Hit(_) => {
                self.dropped += 1;
                self.dropped_hits += 1;
            }
            Item::FileErr(_) => self.dropped += 1,
        }
    }

    fn finish(mut self) -> Result<ScanReport, Error> {
        let rest = std::mem::take(&mut self.pending);
        let rest = String::from_utf8_lossy(&rest).into_owned();
        if self.nul_seen {
            self.line(&rest);
        } else {
            // Not `z` mode: newline-separated.
            for l in rest.split('\n') {
                self.line(l);
            }
        }
        let r = &self.report;
        let recognised = !r.detections.is_empty() || !r.errors.is_empty() || r.ok > 0;
        if !recognised && self.dropped == 0 {
            if let Some(m) = self.clamd_errors.into_iter().next() {
                return Err(Error::Clamd(m));
            }
            return Err(Error::Protocol(
                self.unknown
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| "no scan verdict".into()),
            ));
        }
        // Next to real results, odd lines become errors so nothing is lost or called clean.
        for m in self.clamd_errors {
            self.report.errors.push(FileError {
                path: self.base.clone(),
                message: m,
            });
        }
        for m in self.unknown {
            self.report.errors.push(FileError {
                path: self.base.clone(),
                message: format!("unrecognised clamd reply: {m}"),
            });
        }
        if self.dropped > 0 {
            self.report.errors.push(FileError {
                path: self.base.clone(),
                message: format!(
                    "{} more results ({} detections) were not kept; see clamd's own log",
                    self.dropped, self.dropped_hits
                ),
            });
        }
        Ok(self.report)
    }
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Result<&[u8], Error> {
    use std::os::unix::ffi::OsStrExt;
    Ok(path.as_os_str().as_bytes())
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Result<&[u8], Error> {
    path.to_str().map(str::as_bytes).ok_or(Error::InvalidPath)
}

/// Parse a `z`-mode scan reply: one NUL-terminated result per file, so file
/// names containing newlines cannot split a result. `base` is the scanned
/// path (or `stream`); it locates the `path: message` split in ERROR lines
/// whose message itself contains `: `.
///
/// Results naming a file get recorded. A reply with no per-file result fails:
/// an ERROR not tied to a file (e.g. size limit) as `Clamd`, anything else as
/// `Protocol`. Next to real results, such lines are kept as errors, so the
/// detections around them survive. Past `MAX_REPORT_LINES` results are counted
/// in one summary error. A scan with errors is never clean.
pub fn parse_scan(reply: &[u8], base: &str) -> Result<ScanReport, Error> {
    let mut p = Parser::new(base);
    p.feed(reply)?;
    p.finish()
}

/// Split `path: message` where the path starts with `base`.
fn split_path<'a>(line: &'a str, base: &str) -> Option<(&'a str, &'a str)> {
    if !line.starts_with(base) {
        return None;
    }
    let idx = line.get(base.len()..)?.find(": ")? + base.len();
    Some((&line[..idx], &line[idx + 2..]))
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
    fn parses_instream_results() {
        let clean = parse_scan(b"stream: OK\0", "stream").ok();
        assert_eq!(clean.map(|r| r.is_clean()), Some(true));
        let hit = parse_scan(b"stream: Eicar-Test-Signature FOUND\0", "stream").ok();
        assert_eq!(
            hit.map(|r| r.detections),
            Some(vec![Detection {
                path: "stream".into(),
                signature: "Eicar-Test-Signature".into()
            }])
        );
        assert!(matches!(
            parse_scan(b"INSTREAM size limit exceeded. ERROR\0", "stream"),
            Err(Error::Clamd(_))
        ));
        assert!(parse_scan(b"", "stream").is_err());
        assert!(parse_scan(b"something odd\0", "stream").is_err());
    }

    #[test]
    fn keeps_errors_alongside_detections() {
        let reply = b"/data/a.exe: Win.Trojan.X FOUND\0\
/data/b: lstat() failed: Permission denied. ERROR\0\
/data/big.mkv: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0";
        let r = parse_scan(reply, "/data").expect("parsed");
        assert_eq!(r.detections.len(), 2);
        assert!(r.detections[1].is_limit_exceeded());
        assert_eq!(
            r.errors,
            vec![FileError {
                path: "/data/b".into(),
                message: "lstat() failed: Permission denied.".into()
            }]
        );
        assert!(!r.is_clean());
    }

    #[test]
    fn errors_only_is_a_report_not_a_failure() {
        let reply = b"/data/x: Can't open file. ERROR\0/data/y: Can't open file. ERROR\0";
        let r = parse_scan(reply, "/data").expect("parsed");
        assert_eq!(r.errors.len(), 2);
        assert!(r.detections.is_empty());
    }

    #[test]
    fn huge_replies_keep_their_detections() {
        // Well past the 4 MB a whole reply used to be capped at.
        let mut reply = Vec::new();
        for i in 0..100_000 {
            reply.extend_from_slice(
                format!("/data/clean/{i:08}-a-long-file-name.bin: OK\0").as_bytes(),
            );
        }
        reply.extend_from_slice(b"/data/evil.exe: Win.Trojan.X FOUND\0");
        assert!(reply.len() > MAX_RESPONSE_BYTES);
        let mut p = Parser::new("/data");
        for chunk in reply.chunks(8192) {
            p.feed(chunk).expect("feed");
        }
        let r = p.finish().expect("parsed");
        assert_eq!(r.ok, 100_000);
        assert_eq!(r.detections.len(), 1);
    }

    #[test]
    fn odd_lines_next_to_hits_are_errors_not_failures() {
        let reply = b"/data/a.exe: Win.Trojan.X FOUND\0something new from clamd\0";
        let r = parse_scan(reply, "/data").expect("parsed");
        assert_eq!(r.detections.len(), 1);
        assert_eq!(r.errors.len(), 1);
        assert!(r.errors[0].message.contains("something new"));
    }

    #[test]
    fn results_past_the_cap_are_counted() {
        let mut reply = Vec::new();
        for i in 0..MAX_REPORT_LINES + 5 {
            reply.extend_from_slice(format!("/d/{i}: Eicar FOUND\0").as_bytes());
        }
        let r = parse_scan(&reply, "/d").expect("parsed");
        assert_eq!(r.detections.len(), MAX_REPORT_LINES);
        let last = r.errors.last().expect("summary");
        assert!(last.message.starts_with("5 more results (5 detections)"));
    }

    #[test]
    fn non_ascii_and_newline_names_survive() {
        let reply = "/data/Amélie/日本.mkv: Eicar-Test-Signature FOUND\0/data/odd\nname: OK\0";
        let r = parse_scan(reply.as_bytes(), "/data").expect("parsed");
        assert_eq!(r.detections[0].path, "/data/Amélie/日本.mkv");
        assert_eq!(r.ok, 1);
    }
}
