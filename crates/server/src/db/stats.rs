//! Aggregates for the dashboard and the Detections page.

use sqlx::Row;

use super::{Db, DbError, Kind};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bucket {
    pub start: i64,
    pub total: i64,
    pub detections: i64,
    pub errors: i64,
}

#[derive(Debug, Clone)]
pub struct DetectionRow {
    pub id: i64,
    pub job_id: String,
    pub found_at: i64,
    pub path: String,
    pub signature: String,
    pub kind: String,
    pub endpoint_id: Option<i64>,
    pub agent_id: Option<i64>,
}

/// Filters shared by the Detections page and its facet counts.
#[derive(Debug, Clone, Default)]
pub struct DetectionFilter {
    pub since: Option<i64>,
    pub until: Option<i64>,
    /// Substring of path or signature.
    pub text: Option<String>,
    pub not_text: Option<String>,
    pub signature: Option<String>,
    pub kind: Option<String>,
    pub endpoint_id: Option<i64>,
    pub agent_id: Option<i64>,
    pub path_prefix: Option<String>,
    /// Substring of the path only.
    pub path_text: Option<String>,
}

/// Escape LIKE wildcards; `!` is the escape character everywhere.
fn like(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('%');
    for c in s.chars() {
        if matches!(c, '%' | '_' | '!') {
            out.push('!');
        }
        out.push(c);
    }
    out.push('%');
    out
}

fn prefix(s: &str) -> String {
    let mut l = like(s);
    l.remove(0);
    l
}

macro_rules! filtered {
    ($head:literal, $tail:literal) => {
        concat!(
            $head,
            " WHERE (? IS NULL OR found_at >= ?) AND (? IS NULL OR found_at < ?) \
     AND (? IS NULL OR path LIKE ? ESCAPE '!' OR signature LIKE ? ESCAPE '!') \
     AND (? IS NULL OR (path NOT LIKE ? ESCAPE '!' AND signature NOT LIKE ? ESCAPE '!')) \
     AND (? IS NULL OR signature = ?) AND (? IS NULL OR kind = ?) \
     AND (? IS NULL OR endpoint_id = ?) AND (? IS NULL OR agent_id = ?) \
     AND (? IS NULL OR path LIKE ? ESCAPE '!') AND (? IS NULL OR path LIKE ? ESCAPE '!') ",
            $tail
        )
    };
}

macro_rules! bind_filter {
    ($q:expr, $f:expr) => {{
        let f = $f;
        let text = f.text.as_deref().map(like);
        let not_text = f.not_text.as_deref().map(like);
        let pre = f.path_prefix.as_deref().map(prefix);
        let pt = f.path_text.as_deref().map(like);
        $q.bind(f.since)
            .bind(f.since)
            .bind(f.until)
            .bind(f.until)
            .bind(text.clone())
            .bind(text.clone())
            .bind(text)
            .bind(not_text.clone())
            .bind(not_text.clone())
            .bind(not_text)
            .bind(f.signature.clone())
            .bind(f.signature.clone())
            .bind(f.kind.clone())
            .bind(f.kind.clone())
            .bind(f.endpoint_id)
            .bind(f.endpoint_id)
            .bind(f.agent_id)
            .bind(f.agent_id)
            .bind(pre.clone())
            .bind(pre)
            .bind(pt.clone())
            .bind(pt)
    }};
}

impl Db {
    /// Finished jobs per bucket since `since`. `offset_ms` shifts bucket edges to local time.
    pub async fn activity(
        &self,
        since: i64,
        bucket_ms: i64,
        offset_ms: i64,
    ) -> Result<Vec<Bucket>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT ((submitted_at + ?) - ((submitted_at + ?) % ?)) AS b, verdict, COUNT(*) AS n \
             FROM scan_jobs WHERE status = 'FINISHED' AND submitted_at >= ? GROUP BY b, verdict",
        ))
        .bind(offset_ms)
        .bind(offset_ms)
        .bind(bucket_ms)
        .bind(since)
        .fetch_all(self.pool())
        .await?;
        let mut out: Vec<Bucket> = Vec::new();
        for r in rows {
            let b: i64 = r.try_get("b")?;
            let v: Option<String> = r.try_get("verdict")?;
            let n: i64 = r.try_get("n")?;
            let start = b - offset_ms;
            let i = match out.iter().position(|x| x.start == start) {
                Some(i) => i,
                None => {
                    out.push(Bucket {
                        start,
                        ..Default::default()
                    });
                    out.len() - 1
                }
            };
            out[i].total += n;
            match v.as_deref() {
                Some(super::jobs::VIRUS_FOUND) => out[i].detections += n,
                Some(super::jobs::ERROR) => out[i].errors += n,
                _ => {}
            }
        }
        out.sort_by_key(|b| b.start);
        Ok(out)
    }

    pub async fn files_scanned_since(&self, since: i64) -> Result<i64, DbError> {
        let q = match self.kind() {
            Kind::Postgres => {
                "SELECT CAST(COALESCE(SUM(files_scanned), 0) AS BIGINT) FROM scan_jobs WHERE status = 'FINISHED' AND submitted_at >= ?"
            }
            Kind::MySql => {
                "SELECT CAST(COALESCE(SUM(files_scanned), 0) AS SIGNED) FROM scan_jobs WHERE status = 'FINISHED' AND submitted_at >= ?"
            }
            Kind::Sqlite => {
                "SELECT COALESCE(SUM(files_scanned), 0) FROM scan_jobs WHERE status = 'FINISHED' AND submitted_at >= ?"
            }
        };
        Ok(sqlx::query_scalar(self.sql(q))
            .bind(since)
            .fetch_one(self.pool())
            .await?)
    }

    /// Finished jobs per kind since `since`.
    pub async fn kinds_since(&self, since: i64) -> Result<Vec<(String, i64)>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT kind, COUNT(*) AS n FROM scan_jobs WHERE status = 'FINISHED' AND submitted_at >= ? GROUP BY kind ORDER BY n DESC",
        ))
        .bind(since)
        .fetch_all(self.pool())
        .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("kind")?, r.try_get("n")?)))
            .collect()
    }

    pub async fn count_detections(&self, f: &DetectionFilter) -> Result<i64, DbError> {
        let q = sqlx::query_scalar(self.sql(filtered!("SELECT COUNT(*) FROM detections", "")));
        Ok(bind_filter!(q, f).fetch_one(self.pool()).await?)
    }

    pub async fn list_detections(
        &self,
        f: &DetectionFilter,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<DetectionRow>, DbError> {
        let q = sqlx::query(self.sql(filtered!(
            "SELECT id, job_id, found_at, path, signature, kind, endpoint_id, agent_id FROM detections",
            "ORDER BY found_at DESC, id DESC LIMIT ? OFFSET ?"
        )));
        let rows = bind_filter!(q, f)
            .bind(limit)
            .bind(offset)
            .fetch_all(self.pool())
            .await?;
        rows.iter()
            .map(|r| {
                Ok(DetectionRow {
                    id: r.try_get("id")?,
                    job_id: r.try_get("job_id")?,
                    found_at: r.try_get("found_at")?,
                    path: r.try_get("path")?,
                    signature: r.try_get("signature")?,
                    kind: r.try_get("kind")?,
                    endpoint_id: r.try_get("endpoint_id")?,
                    agent_id: r.try_get("agent_id")?,
                })
            })
            .collect()
    }

    /// Counts per signature under `f`, most first.
    pub async fn detection_signatures(
        &self,
        f: &DetectionFilter,
        limit: i64,
    ) -> Result<Vec<(String, i64)>, DbError> {
        let q = sqlx::query(self.sql(filtered!(
            "SELECT signature AS k, COUNT(*) AS n FROM detections",
            "GROUP BY signature ORDER BY n DESC, signature LIMIT ?"
        )));
        let rows = bind_filter!(q, f)
            .bind(limit)
            .fetch_all(self.pool())
            .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("k")?, r.try_get("n")?)))
            .collect()
    }

    /// Counts per job kind under `f`.
    pub async fn detection_kinds(
        &self,
        f: &DetectionFilter,
    ) -> Result<Vec<(String, i64)>, DbError> {
        let q = sqlx::query(self.sql(filtered!(
            "SELECT kind AS k, COUNT(*) AS n FROM detections",
            "GROUP BY kind ORDER BY n DESC"
        )));
        let rows = bind_filter!(q, f).fetch_all(self.pool()).await?;
        rows.iter()
            .map(|r| Ok((r.try_get("k")?, r.try_get("n")?)))
            .collect()
    }

    /// Counts per (endpoint, agent) under `f`.
    pub async fn detection_sources(
        &self,
        f: &DetectionFilter,
    ) -> Result<Vec<(Option<i64>, Option<i64>, i64)>, DbError> {
        let q = sqlx::query(self.sql(filtered!(
            "SELECT endpoint_id, agent_id, COUNT(*) AS n FROM detections",
            "GROUP BY endpoint_id, agent_id ORDER BY n DESC"
        )));
        let rows = bind_filter!(q, f).fetch_all(self.pool()).await?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("endpoint_id")?,
                    r.try_get("agent_id")?,
                    r.try_get("n")?,
                ))
            })
            .collect()
    }

    /// Up to `limit` matching paths, newest first, for folder roll-ups.
    pub async fn detection_paths(
        &self,
        f: &DetectionFilter,
        limit: i64,
    ) -> Result<Vec<String>, DbError> {
        let q = sqlx::query_scalar(self.sql(filtered!(
            "SELECT path FROM detections",
            "ORDER BY found_at DESC LIMIT ?"
        )));
        Ok(bind_filter!(q, f)
            .bind(limit)
            .fetch_all(self.pool())
            .await?)
    }
}

/// Latest finished job of one kind on one host (`agent_id` None is this server).
#[derive(Debug, Clone)]
pub struct HostActivity {
    pub agent_id: Option<i64>,
    pub kind: String,
    pub last: i64,
}

impl Db {
    pub async fn host_activity(&self, since: i64) -> Result<Vec<HostActivity>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT agent_id, kind, MAX(submitted_at) AS last FROM scan_jobs \
             WHERE status = 'FINISHED' AND submitted_at >= ? GROUP BY agent_id, kind",
        ))
        .bind(since)
        .fetch_all(self.pool())
        .await?;
        rows.iter()
            .map(|r| {
                Ok(HostActivity {
                    agent_id: r.try_get("agent_id")?,
                    kind: r.try_get("kind")?,
                    last: r.try_get("last")?,
                })
            })
            .collect()
    }

    /// Recent EICAR control results, newest first: (host, verdict, at).
    pub async fn recent_controls(
        &self,
        since: i64,
    ) -> Result<Vec<(Option<i64>, String, i64)>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT agent_id, verdict, submitted_at FROM scan_jobs \
             WHERE kind = 'CONTROL' AND status = 'FINISHED' AND submitted_at >= ? \
             ORDER BY submitted_at DESC LIMIT 500",
        ))
        .bind(since)
        .fetch_all(self.pool())
        .await?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("agent_id")?,
                    r.try_get::<Option<String>, _>("verdict")?
                        .unwrap_or_default(),
                    r.try_get("submitted_at")?,
                ))
            })
            .collect()
    }
}
