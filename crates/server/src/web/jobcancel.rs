//! The job page's Cancel button.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::post;
use serde::Deserialize;

use super::session::Auth;
use super::{RequestInfo, csrf, error_page};
use crate::app::AppState;
use crate::auth::Role;
use crate::db::audit::AuditEntry;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/jobs/{id}/cancel", post(cancel))
}

#[derive(Deserialize)]
struct CancelForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

async fn cancel(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<CancelForm>,
) -> Response {
    let (s, u) = match auth.require(Role::Operator) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !csrf::token_ok(&s.csrf_token, f.csrf.as_deref()) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Your session form expired. Reload and try again.",
        );
    }
    let job = match st.db.job(&id).await {
        Ok(Some(j)) => j,
        Ok(None) => return error_page(StatusCode::NOT_FOUND, "No such job."),
        Err(_) => return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    };
    let r = crate::cancel::cancel(&st, &job, &u.username).await;
    st.db
        .audit(AuditEntry {
            username: Some(u.username.clone()),
            action: "CANCEL_JOB",
            outcome: if r.is_ok() { "OK" } else { "REFUSED" },
            details: Some(job.target.clone()),
            job_id: Some(job.id.clone()),
            transport: Some("UI"),
            endpoint_id: job.endpoint_id,
            ip: Some(info.ip.to_string()),
            user_agent: info.user_agent.clone(),
        })
        .await;
    match r {
        Ok(()) => Redirect::to(&format!("/jobs/{}", job.id)).into_response(),
        Err(m) => error_page(StatusCode::CONFLICT, m),
    }
}
