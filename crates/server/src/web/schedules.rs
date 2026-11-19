//! Admin page for scheduled scans (F1) with the EICAR control (F2).

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use super::admin::{admin_post, audit, fmt_ts};
use super::scan::RunOn;
use super::session::Auth;
use super::{Nav, RequestInfo, error_page, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::cron::Cron;
use crate::db::endpoints::Endpoint;
use crate::db::schedules::{NewSchedule, Schedule};
use crate::db::sessions::Session;
use crate::db::users::User;
use crate::db::{jobs, now_ms};
use crate::scan;

const MAX_PATHS: usize = 50;

/// `HH:MM` → minute of the day.
fn parse_hhmm(v: &str) -> Result<Option<i64>, String> {
    let v = v.trim();
    if v.is_empty() {
        return Ok(None);
    }
    let bad = || format!("{v} is not a time like 22:00.");
    let (h, m) = v.split_once(':').ok_or_else(bad)?;
    let (h, m): (i64, i64) = (h.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?);
    if !(0..24).contains(&h) || !(0..60).contains(&m) {
        return Err(bad());
    }
    Ok(Some(h * 60 + m))
}

fn hhmm(m: i64) -> String {
    format!("{:02}:{:02}", m / 60, m % 60)
}

/// A time in `tz`, as `2026-11-20 02:00`.
fn fmt_in(tz: &jiff::tz::TimeZone, ms: i64) -> String {
    jiff::Timestamp::from_millisecond(ms)
        .map(|t| tz.to_datetime(t).strftime("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

/// What the form holds, kept when it is shown again (errors, preview).
#[derive(Default)]
pub struct Draft {
    name: String,
    cron: String,
    paths: String,
    endpoint: String,
    eicar: bool,
    time_zone: String,
    window_start: String,
    window_end: String,
    exclusions: String,
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/schedules", get(page).post(create))
        .route("/admin/schedules/{id}/run", post(run_now))
        .route("/admin/schedules/{id}/enabled", post(toggle))
        .route("/admin/schedules/{id}/delete", post(delete))
}

pub struct Row {
    id: String,
    name: String,
    cron: String,
    next: String,
    paths: Vec<String>,
    endpoint: String,
    enabled: bool,
    eicar: bool,
    control: &'static str,
    control_job: String,
    last_run: String,
    last_job: String,
    zone: String,
    window: String,
    exclusions: Vec<String>,
    upcoming: Vec<String>,
}

#[derive(Template)]
#[template(path = "admin_schedules.html")]
struct SchedulesPage {
    nav: Nav,
    rows: Vec<Row>,
    endpoints: Vec<Endpoint>,
    agents: Vec<super::scan::AgentChoice>,
    roots: Vec<String>,
    default_zone: String,
    draft: Draft,
    preview: Vec<String>,
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Admin) {
        Ok(x) => x,
        Err(r) => return r,
    };
    show(&st, Nav::new("schedules", &s, &u), fresh(), Vec::new()).await
}

fn fresh() -> Draft {
    Draft {
        eicar: true,
        ..Draft::default()
    }
}

async fn row(st: &AppState, s: Schedule, names: &super::scan::Names) -> Row {
    let (zone, tz) = crate::schedule::zone_of(&st.cfg, &s);
    let from = now_ms().max(s.last_run_at.unwrap_or(0));
    let runs = match s.cron.parse::<Cron>() {
        Ok(c) => crate::schedule::next_runs(&c, s.window, &tz, from, 3),
        Err(_) => Vec::new(),
    };
    let next = match s.cron.parse::<Cron>() {
        Ok(_) if s.enabled => runs.first().map_or_else(|| "never".into(), |t| fmt_ts(*t)),
        Ok(_) => "paused".into(),
        Err(_) => "invalid".into(),
    };
    let upcoming = runs.iter().map(|t| fmt_in(&tz, *t)).collect();
    let window = s
        .window
        .map(|(a, b)| format!("{}–{}", hhmm(a), hhmm(b)))
        .unwrap_or_default();
    let control = st.db.last_control_job(&s.id).await.ok().flatten();
    let (state, cj) = match &control {
        None => ("none", String::new()),
        Some(j) if j.verdict.as_deref() == Some(jobs::OK) => ("passed", j.id.clone()),
        Some(j) if j.status == jobs::FINISHED => ("failed", j.id.clone()),
        Some(j) => ("running", j.id.clone()),
    };
    Row {
        endpoint: names.label(s.endpoint_id, s.agent_id),
        next,
        control: state,
        control_job: cj,
        last_run: s.last_run_at.map_or_else(|| "never".into(), fmt_ts),
        last_job: s.last_job_id.clone().unwrap_or_default(),
        id: s.id,
        name: s.name,
        cron: s.cron,
        paths: s.paths,
        enabled: s.enabled,
        eicar: s.eicar_check,
        zone,
        window,
        exclusions: s.exclusions,
        upcoming,
    }
}

async fn show(st: &AppState, nav: Nav, draft: Draft, preview: Vec<String>) -> Response {
    let (Ok(list), Ok(endpoints)) = (st.db.list_schedules().await, st.db.list_endpoints().await)
    else {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    let names = super::scan::endpoint_names(st).await;
    let mut rows = Vec::with_capacity(list.len());
    for s in list {
        rows.push(row(st, s, &names).await);
    }
    let status = if nav.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    render(
        status,
        &SchedulesPage {
            nav,
            rows,
            endpoints: endpoints.into_iter().filter(|e| e.enabled).collect(),
            agents: super::scan::agent_choices(st).await,
            roots: st
                .cfg
                .scan_roots
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            default_zone: crate::schedule::default_zone(&st.cfg).0,
            draft,
            preview,
        },
    )
}

async fn result(
    st: &AppState,
    s: &Session,
    me: &User,
    error: Option<String>,
    success: Option<String>,
) -> Response {
    with_draft(st, s, me, error, success, fresh(), Vec::new()).await
}

async fn with_draft(
    st: &AppState,
    s: &Session,
    me: &User,
    error: Option<String>,
    success: Option<String>,
    draft: Draft,
    preview: Vec<String>,
) -> Response {
    let mut nav = Nav::new("schedules", s, me);
    nav.error = error;
    nav.success = success;
    show(st, nav, draft, preview).await
}

#[derive(Deserialize)]
struct CreateForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    cron: String,
    #[serde(default)]
    paths: String,
    endpoint: Option<String>,
    eicar: Option<String>,
    #[serde(default)]
    time_zone: String,
    #[serde(default)]
    window_start: String,
    #[serde(default)]
    window_end: String,
    #[serde(default)]
    exclusions: String,
    /// Show the next run times instead of saving.
    preview: Option<String>,
}

/// Check one exclusion line for where the schedule runs.
async fn exclusion(st: &AppState, run_on: &RunOn, line: &str) -> Result<String, String> {
    match run_on {
        RunOn::Agent(a) => match crate::agent::refuse(a, line) {
            None => Ok(line.trim_end_matches('/').to_owned()),
            Some(m) => Err(format!("{line}: {m}")),
        },
        RunOn::Endpoint(_) => match scan::resolve_path(&st.cfg.scan_roots, line).await {
            Ok(p) => p
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{line}: only UTF-8 paths can be excluded.")),
            Err(m) => Err(format!("{line}: {m}")),
        },
    }
}

async fn create(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<CreateForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let draft = || Draft {
        name: f.name.clone(),
        cron: f.cron.clone(),
        paths: f.paths.clone(),
        endpoint: f.endpoint.clone().unwrap_or_default(),
        eicar: f.eicar.is_some(),
        time_zone: f.time_zone.clone(),
        window_start: f.window_start.clone(),
        window_end: f.window_end.clone(),
        exclusions: f.exclusions.clone(),
    };
    let fail = |m: String| with_draft(&st, &s, &me, Some(m), None, draft(), Vec::new());
    let zone_name = f.time_zone.trim();
    let tz = match zone_name {
        "" => crate::schedule::default_zone(&st.cfg).1,
        z => match crate::cron::zone(z) {
            Ok(tz) => tz,
            Err(e) => return fail(format!("Time zone: {e}.")).await,
        },
    };
    let window = match (parse_hhmm(&f.window_start), parse_hhmm(&f.window_end)) {
        (Ok(None), Ok(None)) => None,
        (Ok(Some(a)), Ok(Some(b))) if a != b => Some((a, b)),
        (Err(e), _) | (_, Err(e)) => return fail(format!("Scan window: {e}")).await,
        _ => {
            return fail("Scan window: give a start and a different end, or neither.".into()).await;
        }
    };
    let name = f.name.trim();
    if f.preview.is_none()
        && (name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control))
    {
        return fail("Names are 1 to 100 characters.".into()).await;
    }
    let cron = f.cron.trim();
    let parsed = match cron.parse::<Cron>() {
        Ok(c) => c,
        Err(e) => return fail(format!("Schedule: {e}.")).await,
    };
    let upcoming = crate::schedule::next_runs(&parsed, window, &tz, now_ms(), 5);
    if f.preview.is_some() {
        let shown: Vec<String> = upcoming.iter().map(|t| fmt_in(&tz, *t)).collect();
        let msg = if shown.is_empty() {
            Some("That schedule never runs inside its window.".to_owned())
        } else {
            None
        };
        return with_draft(&st, &s, &me, msg, None, draft(), shown).await;
    }
    if upcoming.is_empty() {
        return fail("That schedule never runs inside its window.".into()).await;
    }
    let run_on = match super::scan::chosen_target(&st, f.endpoint.as_deref()).await {
        Ok(r) => r,
        Err(m) => return fail(m.into()).await,
    };
    let mut paths = Vec::new();
    for line in f.paths.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let p = match &run_on {
            // The agent checks each path again when it runs.
            RunOn::Agent(a) => match crate::agent::refuse(a, line) {
                None => line.to_owned(),
                Some(m) => return fail(format!("{line}: {m}")).await,
            },
            RunOn::Endpoint(_) => {
                if st.cfg.scan_roots.is_empty() {
                    return fail("Set SCAN_ROOTS before adding schedules.".into()).await;
                }
                match scan::resolve_path(&st.cfg.scan_roots, line).await {
                    Ok(p) => match p.to_str() {
                        Some(p) if st.excluded(p) => {
                            return fail(format!("{line}: {}", scan::PATH_EXCLUDED)).await;
                        }
                        Some(p) => p.to_owned(),
                        None => {
                            return fail(format!("{line}: only UTF-8 paths can be scheduled."))
                                .await;
                        }
                    },
                    Err(m) => return fail(format!("{line}: {m}")).await,
                }
            }
        };
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    if paths.is_empty() || paths.len() > MAX_PATHS {
        return fail(format!("Give 1 to {MAX_PATHS} paths, one per line.")).await;
    }
    let mut exclusions = Vec::new();
    for line in f
        .exclusions
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
    {
        match exclusion(&st, &run_on, line).await {
            Ok(p) if !exclusions.contains(&p) => exclusions.push(p),
            Ok(_) => {}
            Err(m) => return fail(m).await,
        }
    }
    if exclusions.len() > MAX_PATHS {
        return fail(format!("At most {MAX_PATHS} exclusions.")).await;
    }
    if let RunOn::Agent(_) = &run_on {
        // The agent's folders cannot be listed from here to scan around an inner exclusion.
        if let Some(e) = exclusions.iter().find(|e| {
            paths
                .iter()
                .any(|p| std::path::Path::new(e).starts_with(p) && e != &p)
        }) {
            return fail(format!(
                "{e}: on an agent, exclusions can only leave out whole paths; use ExcludePath in that host's clamd.conf for folders inside a path."
            ))
            .await;
        }
    } else if let Err(m) = crate::schedule::expand(&paths, &exclusions).await {
        return fail(m).await;
    }
    let (endpoint_id, agent_id) = match &run_on {
        RunOn::Agent(a) => (None, Some(a.id)),
        RunOn::Endpoint(e) => (*e, None),
    };
    match st
        .db
        .create_schedule(NewSchedule {
            name,
            cron,
            paths: &paths,
            endpoint_id,
            agent_id,
            eicar_check: f.eicar.is_some(),
            exclusions: &exclusions,
            window,
            time_zone: (!zone_name.is_empty()).then_some(zone_name),
        })
        .await
    {
        Ok(_) => {
            audit(
                &st,
                &me,
                &info,
                "SCHEDULE_CREATE",
                format!(
                    "{name} [{cron}{}] {}{}",
                    if zone_name.is_empty() {
                        String::new()
                    } else {
                        format!(" {zone_name}")
                    },
                    paths.join(", "),
                    if exclusions.is_empty() {
                        String::new()
                    } else {
                        format!(" excluding {}", exclusions.join(", "))
                    }
                ),
            )
            .await;
            result(&st, &s, &me, None, Some(format!("Added {name}."))).await
        }
        Err(_) => fail("That name is already taken.".into()).await,
    }
}

#[derive(Deserialize)]
struct CsrfForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    enabled: Option<String>,
}

async fn target(
    st: &AppState,
    auth: Auth,
    csrf: Option<&str>,
    id: &str,
) -> Result<(Session, User, Schedule), Response> {
    let (s, me) = admin_post(auth, csrf)?;
    match st.db.schedule(id).await {
        Ok(Some(x)) => Ok((s, me, x)),
        _ => Err(result(st, &s, &me, Some("No such schedule.".into()), None).await),
    }
}

async fn run_now(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let (s, me, sch) = match target(&st, auth, f.csrf.as_deref(), &id).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    match crate::schedule::run(&st, &sch, "manual").await {
        Ok(n) => {
            audit(&st, &me, &info, "SCHEDULE_RUN", sch.name.clone()).await;
            result(
                &st,
                &s,
                &me,
                None,
                Some(format!("Started {}: {n} job(s) queued.", sch.name)),
            )
            .await
        }
        Err(m) => result(&st, &s, &me, Some(m), None).await,
    }
}

async fn toggle(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let (s, me, sch) = match target(&st, auth, f.csrf.as_deref(), &id).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let enabled = f.enabled.is_some();
    if st.db.set_schedule_enabled(&sch.id, enabled).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    audit(
        &st,
        &me,
        &info,
        "SCHEDULE_UPDATE",
        format!("{} enabled={enabled}", sch.name),
    )
    .await;
    let word = if enabled { "resumed" } else { "paused" };
    result(&st, &s, &me, None, Some(format!("{} {word}.", sch.name))).await
}

async fn delete(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let (s, me, sch) = match target(&st, auth, f.csrf.as_deref(), &id).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if st.db.delete_schedule(&sch.id).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    audit(&st, &me, &info, "SCHEDULE_DELETE", sch.name.clone()).await;
    result(
        &st,
        &s,
        &me,
        None,
        Some(format!(
            "Deleted {}. Its past jobs stay in the job list.",
            sch.name
        )),
    )
    .await
}
