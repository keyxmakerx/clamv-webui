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

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/schedules", get(page).post(create))
        .route("/admin/schedules/{id}/run", post(run_now))
        .route("/admin/schedules/{id}/edit", post(edit))
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
    /// The "Run on" value for the edit form: "", an endpoint id, or `a:<id>`.
    run_on: String,
    enabled: bool,
    eicar: bool,
    control: &'static str,
    control_job: String,
    last_run: String,
    last_job: String,
}

#[derive(Template)]
#[template(path = "admin_schedules.html")]
struct SchedulesPage {
    nav: Nav,
    rows: Vec<Row>,
    endpoints: Vec<Endpoint>,
    agents: Vec<super::scan::AgentChoice>,
    roots: Vec<String>,
}

impl SchedulesPage {
    /// The "Run on" value an endpoint has in the form.
    fn endpoint_value(&self, e: &Endpoint) -> String {
        if e.is_default {
            String::new()
        } else {
            e.id.to_string()
        }
    }
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Admin) {
        Ok(x) => x,
        Err(r) => return r,
    };
    show(&st, Nav::new("schedules", &s, &u)).await
}

async fn row(st: &AppState, s: Schedule, names: &super::scan::Names) -> Row {
    let next = match s.cron.parse::<Cron>() {
        Ok(c) if s.enabled => c
            .next_after(now_ms().max(s.last_run_at.unwrap_or(0)))
            .map_or_else(|| "never".into(), fmt_ts),
        Ok(_) => "paused".into(),
        Err(_) => "invalid".into(),
    };
    let control = st.db.last_control_job(&s.id).await.ok().flatten();
    let (state, cj) = match &control {
        None => ("none", String::new()),
        Some(j) if j.verdict.as_deref() == Some(jobs::OK) => ("passed", j.id.clone()),
        Some(j) if j.status == jobs::FINISHED => ("failed", j.id.clone()),
        Some(j) => ("running", j.id.clone()),
    };
    Row {
        endpoint: names.label(s.endpoint_id, s.agent_id),
        run_on: match (s.agent_id, s.endpoint_id) {
            (Some(a), _) => format!("a:{a}"),
            (None, Some(e)) => e.to_string(),
            (None, None) => String::new(),
        },
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
    }
}

async fn show(st: &AppState, nav: Nav) -> Response {
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
        },
    )
}

async fn result(
    _st: &AppState,
    s: &Session,
    _me: &User,
    error: Option<String>,
    success: Option<String>,
) -> Response {
    super::ux::back(s, "/admin/schedules", error, success)
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
}

/// A checked schedule form.
struct Checked {
    name: String,
    cron: String,
    paths: Vec<String>,
    endpoint_id: Option<i64>,
    agent_id: Option<i64>,
    eicar: bool,
}

/// The same checks for a new schedule and an edited one.
async fn check(st: &AppState, f: &CreateForm) -> Result<Checked, String> {
    let name = f.name.trim();
    if name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
        return Err("Names are 1 to 100 characters.".into());
    }
    let cron = f.cron.trim();
    if let Err(e) = cron.parse::<Cron>() {
        return Err(format!("Schedule: {e}."));
    }
    let run_on = super::scan::chosen_target(st, f.endpoint.as_deref())
        .await
        .map_err(str::to_owned)?;
    let mut paths = Vec::new();
    for line in f.paths.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let p = match &run_on {
            // The agent checks each path again when it runs.
            RunOn::Agent(a) => match crate::agent::refuse(a, line) {
                None => line.to_owned(),
                Some(m) => return Err(format!("{line}: {m}")),
            },
            RunOn::Endpoint(_) => {
                if st.cfg.scan_roots.is_empty() {
                    return Err("Set SCAN_ROOTS before adding schedules.".into());
                }
                match scan::resolve_path(&st.cfg.scan_roots, line).await {
                    Ok(p) => match p.to_str() {
                        Some(p) if st.excluded(p) => {
                            return Err(format!("{line}: {}", scan::PATH_EXCLUDED));
                        }
                        Some(p) => p.to_owned(),
                        None => return Err(format!("{line}: only UTF-8 paths can be scheduled.")),
                    },
                    Err(m) => return Err(format!("{line}: {m}")),
                }
            }
        };
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    if paths.is_empty() || paths.len() > MAX_PATHS {
        return Err(format!("Give 1 to {MAX_PATHS} paths, one per line."));
    }
    let (endpoint_id, agent_id) = match &run_on {
        RunOn::Agent(a) => (None, Some(a.id)),
        RunOn::Endpoint(e) => (*e, None),
    };
    Ok(Checked {
        name: name.to_owned(),
        cron: cron.to_owned(),
        paths,
        endpoint_id,
        agent_id,
        eicar: f.eicar.is_some(),
    })
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
    let c = match check(&st, &f).await {
        Ok(c) => c,
        Err(m) => return result(&st, &s, &me, Some(m), None).await,
    };
    match st
        .db
        .create_schedule(NewSchedule {
            name: &c.name,
            cron: &c.cron,
            paths: &c.paths,
            endpoint_id: c.endpoint_id,
            agent_id: c.agent_id,
            eicar_check: c.eicar,
        })
        .await
    {
        Ok(_) => {
            audit(
                &st,
                &me,
                &info,
                "SCHEDULE_CREATE",
                format!("{} [{}] {}", c.name, c.cron, c.paths.join(", ")),
            )
            .await;
            result(&st, &s, &me, None, Some(format!("Added {}.", c.name))).await
        }
        Err(_) => {
            result(
                &st,
                &s,
                &me,
                Some("That name is already taken.".into()),
                None,
            )
            .await
        }
    }
}

async fn edit(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<CreateForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !matches!(st.db.schedule(&id).await, Ok(Some(_))) {
        return result(&st, &s, &me, Some("No such schedule.".into()), None).await;
    }
    let c = match check(&st, &f).await {
        Ok(c) => c,
        Err(m) => return result(&st, &s, &me, Some(m), None).await,
    };
    match st
        .db
        .update_schedule(
            &id,
            NewSchedule {
                name: &c.name,
                cron: &c.cron,
                paths: &c.paths,
                endpoint_id: c.endpoint_id,
                agent_id: c.agent_id,
                eicar_check: c.eicar,
            },
        )
        .await
    {
        Ok(_) => {
            audit(
                &st,
                &me,
                &info,
                "SCHEDULE_UPDATE",
                format!("{} [{}] {}", c.name, c.cron, c.paths.join(", ")),
            )
            .await;
            result(&st, &s, &me, None, Some(format!("Saved {}.", c.name))).await
        }
        Err(_) => {
            result(
                &st,
                &s,
                &me,
                Some("That name is already taken.".into()),
                None,
            )
            .await
        }
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
