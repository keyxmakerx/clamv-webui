//! Detections: every infected file found, with count-aware quick filters,
//! search and CSV export.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;

use super::admin::fmt_ts;
use super::scan::{Names, endpoint_names, parse_source, range_since};
use super::session::Auth;
use super::{Nav, error_page, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::db::stats::{DetectionFilter, DetectionRow};

const PAGE_SIZE: i64 = 50;
const CSV_MAX: i64 = 50_000;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/detections", get(page))
        .route("/detections.csv", get(csv))
}

#[derive(Deserialize, Default, Clone)]
pub struct DetQuery {
    page: Option<i64>,
    range: Option<String>,
    signature: Option<String>,
    kind: Option<String>,
    source: Option<String>,
    #[serde(default)]
    q: String,
}

pub struct Facet {
    pub label: String,
    pub count: i64,
    pub active: bool,
    pub href: String,
}

pub struct Row {
    at: String,
    path: String,
    signature: String,
    kind: String,
    host: String,
    job_id: String,
}

#[derive(Template)]
#[template(path = "detections.html")]
struct DetPage {
    nav: Nav,
    rows: Vec<Row>,
    total: i64,
    page: i64,
    pages: i64,
    q: String,
    range: String,
    sig_facets: Vec<Facet>,
    kind_facets: Vec<Facet>,
    host_facets: Vec<Facet>,
    folder_facets: Vec<Facet>,
    warnings: Vec<String>,
    active: Vec<(String, String)>,
    query_string: String,
}

impl DetPage {
    fn link(&self, page: i64) -> String {
        format!("/detections?{}&page={page}", self.query_string)
    }
}

fn enc(v: &str) -> String {
    url::form_urlencoded::byte_serialize(v.as_bytes()).collect()
}

struct Parsed {
    filter: DetectionFilter,
    warnings: Vec<String>,
    range: String,
    source: String,
}

fn parse(q: &DetQuery, names: &Names, now: i64, offset: i64) -> Parsed {
    let range = match q.range.as_deref() {
        Some(r @ ("1h" | "24h" | "7d" | "30d")) => r.to_owned(),
        _ => String::new(),
    };
    let source = q.source.clone().unwrap_or_default();
    let (endpoint_id, agent_id) = parse_source(&source);
    let mut f = DetectionFilter {
        since: range_since(&range, now),
        signature: q
            .signature
            .clone()
            .filter(|s| !s.is_empty())
            .map(|s| s.chars().take(255).collect()),
        kind: q
            .kind
            .clone()
            .filter(|k| super::scan::KINDS.contains(&k.as_str())),
        endpoint_id,
        agent_id,
        ..Default::default()
    };
    let terms = super::search::parse(&q.q);
    let (text, not_text) = super::search::free_text(&terms);
    f.text = text;
    f.not_text = not_text;
    let mut warnings = Vec::new();
    for t in terms.iter().filter(|t| t.field.is_some()) {
        let v = t.value.as_str();
        match (t.field.as_deref().unwrap_or_default(), t.exact, t.negate) {
            ("path" | "file", _, false) => f.path_text = Some(v.to_owned()),
            ("folder" | "dir", _, false) => {
                f.path_prefix = Some(format!("{}/", v.trim_end_matches('/')));
            }
            ("sig" | "signature", true, false) => f.signature = Some(v.to_owned()),
            ("sig" | "signature", false, false) => f.text = Some(v.to_owned()),
            ("path" | "file" | "sig" | "signature", _, true) => f.not_text = Some(v.to_owned()),
            ("kind" | "type", _, false) => {
                let up = v.to_ascii_uppercase();
                if super::scan::KINDS.contains(&up.as_str()) {
                    f.kind = Some(up);
                } else {
                    warnings.push(format!("Unknown type: {v}"));
                }
            }
            ("host" | "agent" | "endpoint", _, false) => match names.find(v) {
                Some((e, a)) => {
                    f.endpoint_id = e;
                    f.agent_id = a;
                }
                None => warnings.push(format!("No endpoint or agent named {v}")),
            },
            ("after" | "since", _, false) => match super::search::date(v, now, offset) {
                Some(d) => f.since = Some(d),
                None => warnings.push(format!("Not a date: {v}")),
            },
            ("before" | "until", _, false) => match super::search::date(v, now, offset) {
                Some(d) => f.until = Some(d),
                None => warnings.push(format!("Not a date: {v}")),
            },
            (other, _, _) => warnings.push(format!("Unknown or unsupported filter: {other}")),
        }
    }
    Parsed {
        filter: f,
        warnings,
        range,
        source,
    }
}

fn qs(q: &DetQuery, drop: &str) -> String {
    let mut parts = Vec::new();
    for (k, v) in [
        ("range", q.range.as_deref().unwrap_or_default()),
        ("signature", q.signature.as_deref().unwrap_or_default()),
        ("kind", q.kind.as_deref().unwrap_or_default()),
        ("source", q.source.as_deref().unwrap_or_default()),
        ("q", q.q.as_str()),
    ] {
        if k != drop && !v.is_empty() {
            parts.push(format!("{k}={}", enc(v)));
        }
    }
    parts.join("&")
}

fn facet_href(q: &DetQuery, key: &str, value: &str, active: bool) -> String {
    let base = qs(q, key);
    if active {
        format!("/detections?{base}")
    } else if base.is_empty() {
        format!("/detections?{key}={}", enc(value))
    } else {
        format!("/detections?{base}&{key}={}", enc(value))
    }
}

async fn page(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    headers: HeaderMap,
    Query(q): Query<DetQuery>,
) -> Response {
    let (s, u) = match auth.require(Role::Operator) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let names = endpoint_names(&st).await;
    let now = crate::db::now_ms();
    let p = parse(&q, &names, now, super::tz_offset_ms(&headers));
    let f = &p.filter;
    let page = q.page.unwrap_or(0).clamp(0, 100_000);
    let (Ok(total), Ok(list)) = (
        st.db.count_detections(f).await,
        st.db.list_detections(f, page * PAGE_SIZE, PAGE_SIZE).await,
    ) else {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    // Each facet counts under every other active filter, not its own.
    let sig_f = DetectionFilter {
        signature: None,
        ..f.clone()
    };
    let kind_f = DetectionFilter {
        kind: None,
        ..f.clone()
    };
    let host_f = DetectionFilter {
        endpoint_id: None,
        agent_id: None,
        ..f.clone()
    };
    let sig_facets = st
        .db
        .detection_signatures(&sig_f, 15)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(sig, n)| {
            let active = f.signature.as_deref() == Some(sig.as_str());
            Facet {
                href: facet_href(&q, "signature", &sig, active),
                label: sig,
                count: n,
                active,
            }
        })
        .collect();
    let kind_facets = st
        .db
        .detection_kinds(&kind_f)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(k, n)| {
            let active = f.kind.as_deref() == Some(k.as_str());
            Facet {
                href: facet_href(&q, "kind", &k, active),
                label: k,
                count: n,
                active,
            }
        })
        .collect();
    let host_facets = st
        .db
        .detection_sources(&host_f)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(e, a, n)| {
            let value = match (e, a) {
                (_, Some(a)) => format!("a:{a}"),
                (Some(e), None) => format!("e:{e}"),
                _ => String::new(),
            };
            let active = !value.is_empty() && p.source == value;
            Facet {
                href: facet_href(&q, "source", &value, active),
                label: names.label(e, a),
                count: n,
                active,
            }
        })
        .collect();
    let paths = st.db.detection_paths(f, 5000).await.unwrap_or_default();
    let folder_facets = super::folders(&paths, 10)
        .into_iter()
        .map(|(dir, n)| {
            let term = format!("folder:\"{dir}\"");
            let q2 = if q.q.is_empty() {
                term
            } else {
                format!("{} {term}", q.q)
            };
            let mut href = format!("/detections?q={}", enc(&q2));
            let rest = qs(&q, "q");
            if !rest.is_empty() {
                href = format!("{href}&{rest}");
            }
            Facet {
                label: dir,
                count: n,
                active: false,
                href,
            }
        })
        .collect();
    let mut active = Vec::new();
    if let Some(sig) = q.signature.as_deref().filter(|s| !s.is_empty()) {
        active.push((
            format!("Signature: {sig}"),
            format!("/detections?{}", qs(&q, "signature")),
        ));
    }
    if let Some(k) = q.kind.as_deref().filter(|k| !k.is_empty()) {
        active.push((
            format!("Type: {k}"),
            format!("/detections?{}", qs(&q, "kind")),
        ));
    }
    if !p.source.is_empty() {
        let (e, a) = parse_source(&p.source);
        active.push((
            format!("Host: {}", names.label(e, a)),
            format!("/detections?{}", qs(&q, "source")),
        ));
    }
    render(
        StatusCode::OK,
        &DetPage {
            nav: Nav::new("detections", &s, &u),
            rows: list.into_iter().map(|d| view(d, &names)).collect(),
            total,
            page,
            pages: (total + PAGE_SIZE - 1) / PAGE_SIZE,
            q: q.q.clone(),
            range: p.range.clone(),
            sig_facets,
            kind_facets,
            host_facets,
            folder_facets,
            warnings: p.warnings,
            active,
            query_string: qs(&q, ""),
        },
    )
}

fn view(d: DetectionRow, names: &Names) -> Row {
    Row {
        at: fmt_ts(d.found_at),
        host: names.label(d.endpoint_id, d.agent_id),
        path: d.path,
        signature: d.signature,
        kind: d.kind,
        job_id: d.job_id,
    }
}

/// Spreadsheet-safe CSV cell: quoted, and formulas neutralised.
fn cell(v: &str) -> String {
    let v = if v.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{v}")
    } else {
        v.to_owned()
    };
    format!("\"{}\"", v.replace('"', "\"\""))
}

async fn csv(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    headers: HeaderMap,
    Query(q): Query<DetQuery>,
) -> Response {
    let (_s, u) = match auth.require(Role::Operator) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let names = endpoint_names(&st).await;
    let p = parse(
        &q,
        &names,
        crate::db::now_ms(),
        super::tz_offset_ms(&headers),
    );
    let Ok(list) = st.db.list_detections(&p.filter, 0, CSV_MAX).await else {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    tracing::info!(event = "detections.exported", user = %u.username, rows = list.len(), "detections exported as CSV");
    let mut out = String::from("found_at,path,signature,type,host,job_id\n");
    for d in list {
        out.push_str(&format!(
            "{},{},{},{},{},{}\n",
            cell(&crate::timefmt::rfc3339(d.found_at)),
            cell(&d.path),
            cell(&d.signature),
            cell(&d.kind),
            cell(&names.label(d.endpoint_id, d.agent_id)),
            cell(&d.job_id)
        ));
    }
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"detections.csv\"",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        out,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    #[test]
    fn csv_cells_cannot_become_formulas() {
        assert_eq!(super::cell("=cmd()"), "\"'=cmd()\"");
        assert_eq!(super::cell("a\"b"), "\"a\"\"b\"");
    }
}
