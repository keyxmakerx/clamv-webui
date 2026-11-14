//! Firewall page: each host's rules with their owners (read-only), what
//! listens, and clamv's own plan, applied with a passkey.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use super::admin::{admin_post, audit, fmt_ts};
use super::session::Auth;
use super::{Nav, RequestInfo, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::db::sessions::Session;
use crate::db::users::User;
use crate::firewall::{Op, Proto, Rule};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/firewall", get(page))
        .route("/admin/firewall/rules", post(add_rule))
        .route("/admin/firewall/rules/delete", post(delete_rule))
        .route("/admin/firewall/refresh", post(refresh))
        .route("/admin/firewall/remove", post(remove))
}

/// How long the host waits for clamv to confirm (the apply script waits 90 s).
const CONFIRM_MS: i64 = 85_000;

pub struct HostChip {
    value: String,
    label: String,
    active: bool,
}

pub struct TableRow {
    family: String,
    name: String,
    owner: &'static str,
    chains: usize,
}

pub struct PortRow {
    proto: String,
    addr: String,
    port: u16,
    process: String,
    exposed: bool,
    plan: String,
}

pub struct RuleRow {
    port: u16,
    proto: &'static str,
    allow: String,
}

#[derive(Template)]
#[template(path = "firewall.html")]
struct FirewallPage {
    nav: Nav,
    host: String,
    host_name: String,
    chips: Vec<HostChip>,
    has_snapshot: bool,
    read: String,
    nft: bool,
    owners: Vec<&'static str>,
    ufw: String,
    firewalld: String,
    selinux: String,
    legacy_rules: usize,
    status: String,
    status_at: String,
    status_ok: bool,
    tables: Vec<TableRow>,
    ports: Vec<PortRow>,
    rules: Vec<RuleRow>,
    preview: String,
    pending: bool,
    dir: String,
}

#[derive(Deserialize, Default)]
pub struct HostQ {
    #[serde(default)]
    host: String,
}

async fn host_name(st: &AppState, host: Option<i64>) -> String {
    match host {
        None => crate::canary::hostname(),
        Some(id) => st
            .db
            .agent(id)
            .await
            .ok()
            .flatten()
            .map_or_else(|| format!("agent {id}"), |a| a.name),
    }
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth, Query(q): Query<HostQ>) -> Response {
    let (s, u) = match auth.require(Role::Admin) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let mut nav = Nav::new("firewall", &s, &u);
    let host = super::integrity::parse_host(&st, &q.host)
        .await
        .unwrap_or(None);
    // A fresh request from the admin, once the host waits, proves they still reach this server.
    let mut closing = false;
    if host.is_none() {
        let pending = st.firewalls.pending.lock().ok().and_then(|g| g.clone());
        if let Some((hash, user, at)) = pending
            && user == u.id
        {
            let dir = crate::firewall::dir(&st);
            let live = crate::db::now_ms() - at < CONFIRM_MS;
            if live && crate::firewall::waiting(&dir, &hash) {
                crate::firewall::confirm(&dir, &hash);
                tracing::info!(event = "firewall.confirmed", user = %u.username, hash = %hash, "firewall plan confirmed from the browser");
                nav.success = Some("Plan confirmed: you can still reach this server.".into());
                clear_pending(&st);
            } else if live {
                closing = true;
            } else {
                clear_pending(&st);
            }
        }
    }
    let mut r = show(&st, nav, host).await;
    if closing {
        // Each check must come over a new connection; an open one passes any rules.
        r.headers_mut().insert(
            axum::http::header::CONNECTION,
            axum::http::HeaderValue::from_static("close"),
        );
    }
    r
}

fn clear_pending(st: &Arc<AppState>) {
    if let Ok(mut g) = st.firewalls.pending.lock() {
        *g = None;
    }
    let st = st.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let _ = crate::firewall::refresh_here(&st).await;
    });
}

async fn show(st: &AppState, nav: Nav, host: Option<i64>) -> Response {
    let agents = st.db.list_agents().await.unwrap_or_default();
    let mut chips = vec![HostChip {
        value: String::new(),
        label: format!("{} (this server)", crate::canary::hostname()),
        active: host.is_none(),
    }];
    chips.extend(agents.iter().filter(|a| a.enabled).map(|a| HostChip {
        value: a.id.to_string(),
        label: a.name.clone(),
        active: host == Some(a.id),
    }));
    let plan = st.db.firewall_plan(host).await.unwrap_or_default();
    let snap = st.firewalls.get(host);
    let now = crate::db::now_ms();
    let (s, at) = snap.clone().unwrap_or_default();
    let mut owners: Vec<&'static str> = s
        .tables
        .iter()
        .map(|t| t.owner)
        .filter(|o| *o != "host" && *o != "clamv")
        .collect();
    owners.sort_unstable();
    owners.dedup();
    let plan_for = |port: u16, proto: &str| {
        plan.rules
            .iter()
            .find(|r| r.port == port && r.proto.as_str() == proto)
            .map_or_else(
                || "open to all".to_owned(),
                |r| {
                    if r.allow.is_empty() {
                        "closed".to_owned()
                    } else {
                        format!("only {}", r.allow.join(", "))
                    }
                },
            )
    };
    let ports = s
        .listening
        .iter()
        .map(|l| PortRow {
            plan: if crate::firewall::exposed(l) {
                plan_for(l.port, &l.proto)
            } else {
                "local only".into()
            },
            exposed: crate::firewall::exposed(l),
            proto: l.proto.clone(),
            addr: l.addr.clone(),
            port: l.port,
            process: l.process.clone(),
        })
        .collect();
    let (status, status_at, status_ok) = match &s.status {
        Some(a) => (
            a.state.replace('_', " "),
            fmt_ts(a.at),
            matches!(a.state.as_str(), "applied" | "removed"),
        ),
        None => (String::new(), String::new(), true),
    };
    let pending = host.is_none()
        && st
            .firewalls
            .pending
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .is_some_and(|(_, _, t)| now - t < CONFIRM_MS);
    let code = if nav.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    render(
        code,
        &FirewallPage {
            host: host.map(|h| h.to_string()).unwrap_or_default(),
            host_name: host_name(st, host).await,
            chips,
            has_snapshot: snap.is_some(),
            read: if at > 0 {
                super::crowdsec::span(now - at)
            } else {
                String::new()
            },
            nft: s.nft,
            owners,
            ufw: s.ufw.clone(),
            firewalld: s.firewalld.clone(),
            selinux: s.selinux.clone(),
            legacy_rules: s.legacy_rules,
            status,
            status_at,
            status_ok,
            tables: s
                .tables
                .iter()
                .map(|t| TableRow {
                    family: t.family.clone(),
                    name: t.name.clone(),
                    owner: t.owner,
                    chains: t.chains.len(),
                })
                .collect(),
            ports,
            rules: plan
                .rules
                .iter()
                .map(|r| RuleRow {
                    port: r.port,
                    proto: r.proto.as_str(),
                    allow: if r.allow.is_empty() {
                        "nobody (closed)".into()
                    } else {
                        r.allow.join(", ")
                    },
                })
                .collect(),
            preview: format!(
                "table inet clamv {{\n{}}}",
                crate::firewall::body(&plan.rules)
            ),
            pending,
            dir: st.cfg.firewall_dir.display().to_string(),
            nav,
        },
    )
}

async fn result(
    st: &AppState,
    s: &Session,
    me: &User,
    host: Option<i64>,
    r: Result<String, String>,
) -> Response {
    let mut nav = Nav::new("firewall", s, me);
    match r {
        Ok(m) => nav.success = Some(m),
        Err(m) => nav.error = Some(m),
    }
    show(st, nav, host).await
}

#[derive(Deserialize)]
struct RuleForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: String,
    #[serde(default)]
    proto: String,
    #[serde(default)]
    allow: String,
}

fn proto(s: &str) -> Proto {
    if s == "udp" { Proto::Udp } else { Proto::Tcp }
}

async fn add_rule(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<RuleForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let host = match super::integrity::parse_host(&st, &f.host).await {
        Ok(h) => h,
        Err(m) => return result(&st, &s, &me, None, Err(m)).await,
    };
    let Ok(port) = f.port.trim().parse::<u16>() else {
        return result(&st, &s, &me, host, Err("Port must be 1 to 65535.".into())).await;
    };
    let mut rules = st.db.firewall_plan(host).await.unwrap_or_default().rules;
    let p = proto(&f.proto);
    rules.retain(|r| !(r.port == port && r.proto == p));
    rules.push(Rule {
        port,
        proto: p,
        allow: f
            .allow
            .split([',', ' ', '\n'])
            .filter(|x| !x.trim().is_empty())
            .map(str::to_owned)
            .collect(),
    });
    let rules = match crate::firewall::check(rules) {
        Ok(r) => r,
        Err(m) => return result(&st, &s, &me, host, Err(m)).await,
    };
    if st
        .db
        .set_firewall_plan(host, &rules, &me.username)
        .await
        .is_err()
    {
        return result(&st, &s, &me, host, Err("Service unavailable.".into())).await;
    }
    let name = host_name(&st, host).await;
    audit(
        &st,
        &me,
        &info,
        "FIREWALL_PLAN",
        format!("{name}: {port}/{} only {}", p.as_str(), f.allow.trim()),
    )
    .await;
    result(
        &st,
        &s,
        &me,
        host,
        Ok(format!(
            "Added {port}/{} to the plan for {name}. Nothing changes on the host until you apply.",
            p.as_str()
        )),
    )
    .await
}

async fn delete_rule(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<RuleForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let host = match super::integrity::parse_host(&st, &f.host).await {
        Ok(h) => h,
        Err(m) => return result(&st, &s, &me, None, Err(m)).await,
    };
    let port: u16 = f.port.trim().parse().unwrap_or(0);
    let p = proto(&f.proto);
    let mut rules = st.db.firewall_plan(host).await.unwrap_or_default().rules;
    rules.retain(|r| !(r.port == port && r.proto == p));
    if st
        .db
        .set_firewall_plan(host, &rules, &me.username)
        .await
        .is_err()
    {
        return result(&st, &s, &me, host, Err("Service unavailable.".into())).await;
    }
    let name = host_name(&st, host).await;
    audit(
        &st,
        &me,
        &info,
        "FIREWALL_PLAN",
        format!("{name}: removed {port}/{}", p.as_str()),
    )
    .await;
    result(
        &st,
        &s,
        &me,
        host,
        Ok(format!("Removed {port}/{} from the plan.", p.as_str())),
    )
    .await
}

#[derive(Deserialize)]
struct HostForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    host: String,
}

async fn queue(st: &AppState, host: i64, op: &Op, by: &str) -> Result<(), String> {
    let target = serde_json::to_string(op).map_err(|_| "Service unavailable.".to_owned())?;
    st.db
        .create_job(crate::db::jobs::NewJob {
            kind: crate::firewall::KIND,
            target: &target,
            endpoint_id: None,
            schedule_id: None,
            agent_id: Some(host),
            submitted_by: Some(by),
            transport: "UI",
            running: false,
        })
        .await
        .map_err(|_| "Service unavailable.".to_owned())?;
    st.agents.poke();
    Ok(())
}

async fn refresh(State(st): State<Arc<AppState>>, auth: Auth, Form(f): Form<HostForm>) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let host = match super::integrity::parse_host(&st, &f.host).await {
        Ok(h) => h,
        Err(m) => return result(&st, &s, &me, None, Err(m)).await,
    };
    let r = match host {
        None => crate::firewall::refresh_here(&st)
            .await
            .map(|()| "Read this server's firewall.".to_owned())
            .map_err(|e| format!("{} ({})", crate::hostchecks::message(e.code), e.message)),
        Some(id) => queue(&st, id, &Op::Snapshot, &me.username)
            .await
            .map(|()| "Asked the agent to read its firewall; reload in a few seconds.".to_owned()),
    };
    result(&st, &s, &me, host, r).await
}

async fn remove(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<HostForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let host = match super::integrity::parse_host(&st, &f.host).await {
        Ok(h) => h,
        Err(m) => return result(&st, &s, &me, None, Err(m)).await,
    };
    let name = host_name(&st, host).await;
    let r = match host {
        None => crate::firewall::remove()
            .await
            .map_err(|e| crate::hostchecks::message(e.code).to_owned()),
        Some(id) => queue(&st, id, &Op::Remove, &me.username).await,
    };
    if r.is_ok() {
        tracing::warn!(event = "firewall.removed", user = %me.username, host = %name, "clamv's firewall table removed");
        audit(&st, &me, &info, "FIREWALL_REMOVE", name.clone()).await;
    }
    result(
        &st,
        &s,
        &me,
        host,
        r.map(|()| {
            format!(
                "Removing clamv's table on {name}. Rules owned by anything else stay as they are."
            )
        }),
    )
    .await
}

/// Refuse plans that would plainly lock the admin out.
fn lockout(
    st: &AppState,
    host: Option<i64>,
    rules: &[Rule],
    me: std::net::IpAddr,
) -> Result<(), String> {
    let allows_me = |r: &Rule| {
        r.allow
            .iter()
            .any(|a| crate::webhook::Cidr::parse(a).is_ok_and(|c| c.contains(me)))
    };
    if let Some(r) = rules
        .iter()
        .find(|r| r.port == 22 && r.proto == Proto::Tcp && r.allow.is_empty())
    {
        let _ = r;
        return Err(
            "That plan closes SSH (22/tcp) to everyone. Allow your admin network instead.".into(),
        );
    }
    if host.is_none() {
        let port = st.cfg.listen.port();
        if let Some(r) = rules
            .iter()
            .find(|r| r.port == port && r.proto == Proto::Tcp)
            && !allows_me(r)
        {
            return Err(format!(
                "That plan blocks clamv's own port {port} for your address {me}; you would lose this page."
            ));
        }
    }
    Ok(())
}

/// Apply a host's saved plan; called after a passkey confirmation.
pub(super) async fn apply_plan(
    st: &Arc<AppState>,
    me: &User,
    info: &RequestInfo,
    host: Option<i64>,
) -> Result<String, String> {
    let rules = st
        .db
        .firewall_plan(host)
        .await
        .map_err(|_| "Service unavailable.".to_owned())?
        .rules;
    let rules = crate::firewall::check(rules)?;
    lockout(st, host, &rules, info.ip)?;
    let name = host_name(st, host).await;
    let hash = crate::firewall::hash(&crate::firewall::body(&rules));
    let n = rules.len();
    let msg = match host {
        None => {
            let h = crate::firewall::apply(&crate::firewall::dir(st), rules)
                .await
                .map_err(|e| format!("{} ({})", crate::hostchecks::message(e.code), e.message))?;
            if let Ok(mut g) = st.firewalls.pending.lock() {
                *g = Some((h, me.id.clone(), crate::db::now_ms()));
            }
            "Loading on this server. This page reloads to confirm you can still reach it; without that, the host rolls back in 90 s.".to_owned()
        }
        Some(id) => {
            queue(st, id, &Op::Apply { rules }, &me.username).await?;
            format!(
                "Sent to {name}. The host rolls back in 90 s unless the agent confirms it still reaches this server."
            )
        }
    };
    tracing::warn!(event = "firewall.apply", user = %me.username, host = %name, rules = n, hash = %hash, "firewall plan applied with a passkey");
    audit(
        st,
        me,
        info,
        "FIREWALL_APPLY",
        format!("{name}: {n} rule(s), {}", &hash[..12]),
    )
    .await;
    Ok(msg)
}
