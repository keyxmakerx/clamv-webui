//! Admin pages: users and audit log. Every route requires ADMIN.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use super::session::Auth;
use super::{Nav, RequestInfo, csrf, error_page, render};
use crate::app::AppState;
use crate::auth::{Role, password};
use crate::db::audit::AuditEntry;
use crate::db::sessions::Session;
use crate::db::users::User;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/users", get(users_page).post(create_user))
        .route("/admin/users/{id}/role", post(update_user))
        .route("/admin/users/{id}/password", post(reset_password))
        .route("/admin/users/{id}/delete", post(delete_user))
        .route("/admin/audit", get(audit_page))
}

/// Admin + valid CSRF token, or an error response.
pub(super) fn admin_post(auth: Auth, token: Option<&str>) -> Result<(Session, User), Response> {
    let (s, u) = auth.require(Role::Admin)?;
    if !csrf::token_ok(&s.csrf_token, token) {
        return Err(error_page(
            StatusCode::FORBIDDEN,
            "Your session form expired. Reload and try again.",
        ));
    }
    Ok((s, u))
}

pub fn fmt_ts(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

// ---- users ----

struct UserView {
    id: String,
    username: String,
    role: Role,
    enabled: bool,
    must_change: bool,
    last_login: String,
    is_self: bool,
}

#[derive(Template)]
#[template(path = "admin_users.html")]
struct UsersPage {
    nav: Nav,
    users: Vec<UserView>,
    roles: [Role; 3],
}

async fn users_page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Admin) {
        Ok(x) => x,
        Err(r) => return r,
    };
    show_users(&st, Nav::new("users", &s, &u), &u).await
}

async fn show_users(st: &AppState, nav: Nav, me: &User) -> Response {
    let list = match st.db.list_users().await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "list users failed");
            return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
        }
    };
    let users = list
        .into_iter()
        .map(|x| UserView {
            is_self: x.id == me.id,
            id: x.id,
            username: x.username,
            role: x.role,
            enabled: x.enabled,
            must_change: x.must_change_password,
            last_login: x.last_login_at.map_or_else(|| "never".to_owned(), fmt_ts),
        })
        .collect();
    let status = if nav.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    render(
        status,
        &UsersPage {
            nav,
            users,
            roles: [Role::Viewer, Role::Operator, Role::Admin],
        },
    )
}

async fn users_result(
    st: &AppState,
    s: &Session,
    me: &User,
    error: Option<String>,
    success: Option<String>,
) -> Response {
    let mut nav = Nav::new("users", s, me);
    nav.error = error;
    nav.success = success;
    show_users(st, nav, me).await
}

fn valid_username(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
}

#[derive(Deserialize)]
struct CreateForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    username: String,
    role: String,
    password: String,
}

async fn create_user(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<CreateForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let name = f.username.trim();
    if !valid_username(name) {
        return users_result(
            &st,
            &s,
            &me,
            Some("Usernames are 1 to 64 letters, digits, '.', '_', '-' or '@'.".into()),
            None,
        )
        .await;
    }
    let Ok(role) = f.role.parse::<Role>() else {
        return users_result(&st, &s, &me, Some("Unknown role.".into()), None).await;
    };
    let hash = match password::hash(&f.password) {
        Ok(h) => h,
        Err(e) => return users_result(&st, &s, &me, Some(e.to_string()), None).await,
    };
    match st.db.create_user(name, &hash, role, true).await {
        Ok(_) => {
            audit(&st, &me, &info, "USER_CREATE", format!("{name} as {role}")).await;
            users_result(
                &st,
                &s,
                &me,
                None,
                Some(format!(
                    "Created {name}. They must change the password at first login."
                )),
            )
            .await
        }
        Err(_) => {
            users_result(
                &st,
                &s,
                &me,
                Some("That username is already taken.".into()),
                None,
            )
            .await
        }
    }
}

#[derive(Deserialize)]
struct RoleForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    role: String,
    enabled: Option<String>,
}

async fn update_user(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<RoleForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Ok(role) = f.role.parse::<Role>() else {
        return users_result(&st, &s, &me, Some("Unknown role.".into()), None).await;
    };
    let enabled = f.enabled.is_some();
    let Ok(Some(target)) = st.db.user_by_id(&id).await else {
        return users_result(&st, &s, &me, Some("No such user.".into()), None).await;
    };
    if let Err(msg) = keeps_an_admin(&st, &target, role, enabled).await {
        return users_result(&st, &s, &me, Some(msg), None).await;
    }
    if st.db.set_role_enabled(&id, role, enabled).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    audit(
        &st,
        &me,
        &info,
        "USER_UPDATE",
        format!("{} role={role} enabled={enabled}", target.username),
    )
    .await;
    if target.id == me.id {
        // Own sessions just ended.
        return Redirect::to("/login").into_response();
    }
    users_result(
        &st,
        &s,
        &me,
        None,
        Some(format!(
            "Updated {}; their sessions were ended.",
            target.username
        )),
    )
    .await
}

/// Refuse a change that would leave no enabled admin.
async fn keeps_an_admin(
    st: &AppState,
    target: &User,
    role: Role,
    enabled: bool,
) -> Result<(), String> {
    let was_admin = target.enabled && target.role == Role::Admin;
    let stays_admin = enabled && role == Role::Admin;
    if was_admin && !stays_admin && st.db.count_enabled_admins().await.unwrap_or(0) <= 1 {
        return Err("At least one enabled admin must remain.".into());
    }
    Ok(())
}

#[derive(Deserialize)]
struct ResetForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    password: String,
}

async fn reset_password(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<ResetForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Ok(Some(target)) = st.db.user_by_id(&id).await else {
        return users_result(&st, &s, &me, Some("No such user.".into()), None).await;
    };
    let hash = match password::hash(&f.password) {
        Ok(h) => h,
        Err(e) => return users_result(&st, &s, &me, Some(e.to_string()), None).await,
    };
    if st.db.set_password(&id, &hash, true, true).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    audit(
        &st,
        &me,
        &info,
        "USER_PASSWORD_RESET",
        target.username.clone(),
    )
    .await;
    if target.id == me.id {
        return Redirect::to("/login").into_response();
    }
    users_result(
        &st,
        &s,
        &me,
        None,
        Some(format!(
            "Password reset for {}. They must change it at next login.",
            target.username
        )),
    )
    .await
}

#[derive(Deserialize)]
struct CsrfForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

async fn delete_user(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if id == me.id {
        return users_result(
            &st,
            &s,
            &me,
            Some("You cannot delete your own account.".into()),
            None,
        )
        .await;
    }
    let Ok(Some(target)) = st.db.user_by_id(&id).await else {
        return users_result(&st, &s, &me, Some("No such user.".into()), None).await;
    };
    if let Err(msg) = keeps_an_admin(&st, &target, Role::Viewer, false).await {
        return users_result(&st, &s, &me, Some(msg), None).await;
    }
    if st.db.delete_user(&id).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    audit(&st, &me, &info, "USER_DELETE", target.username.clone()).await;
    users_result(
        &st,
        &s,
        &me,
        None,
        Some(format!("Deleted {}.", target.username)),
    )
    .await
}

pub(super) async fn audit(
    st: &AppState,
    me: &User,
    info: &RequestInfo,
    action: &'static str,
    details: String,
) {
    st.db
        .audit(AuditEntry {
            username: Some(me.username.clone()),
            action,
            outcome: "OK",
            details: Some(details),
            transport: Some("UI"),
            ip: Some(info.ip.to_string()),
            user_agent: info.user_agent.clone(),
            ..Default::default()
        })
        .await;
}

// ---- audit log ----

struct AuditView {
    at: String,
    user: String,
    action: String,
    outcome: String,
    details: String,
    ip: String,
}

#[derive(Template)]
#[template(path = "admin_audit.html")]
struct AuditPage {
    nav: Nav,
    rows: Vec<AuditView>,
}

async fn audit_page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Admin) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let rows = match st.db.recent_audit(200).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "audit list failed");
            return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
        }
    };
    let rows = rows
        .into_iter()
        .map(|r| AuditView {
            at: fmt_ts(r.at),
            user: r.username.unwrap_or_default(),
            action: r.action,
            outcome: r.outcome.unwrap_or_default(),
            details: [r.details, r.job_id.map(|j| format!("job {j}"))]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" · "),
            ip: r.ip.unwrap_or_default(),
        })
        .collect();
    render(
        StatusCode::OK,
        &AuditPage {
            nav: Nav::new("audit", &s, &u),
            rows,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_timestamps() {
        assert_eq!(fmt_ts(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(fmt_ts(1_794_536_660_000), "2026-11-13 02:24:20 UTC");
        assert_eq!(fmt_ts(951_782_400_000), "2000-02-29 00:00:00 UTC");
    }

    #[test]
    fn username_rules() {
        assert!(valid_username("jane.doe@nas"));
        assert!(!valid_username(""));
        assert!(!valid_username("a b"));
        assert!(!valid_username("<script>"));
    }
}
