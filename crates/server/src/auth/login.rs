//! The one password check every path goes through: form login and HTTP Basic (S2).

use std::net::IpAddr;

use super::lockout::LockScope;
use super::password::{self, Verified};
use crate::app::AppState;
use crate::db::audit::AuditEntry;
use crate::db::users::User;

#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    Locked,
    Bad,
    Unavailable,
}

/// Throttled, constant-work password check. Logs and audits failures.
pub async fn authenticate(
    st: &AppState,
    username: &str,
    password: &str,
    ip: IpAddr,
    user_agent: Option<&str>,
    transport: &'static str,
) -> Result<User, Failure> {
    if st.lockout.check(username, ip).is_err() {
        tracing::warn!(event = "auth.locked", user = %username, ip = %ip, transport, "sign-in refused while locked");
        return Err(Failure::Locked);
    }
    let user = st.db.user_by_username(username).await.map_err(|e| {
        tracing::error!(error = %e, "user lookup failed");
        Failure::Unavailable
    })?;
    let stored = user
        .as_ref()
        .filter(|u| u.enabled)
        .map(|u| u.password_hash.clone());
    let pw = password.to_owned();
    // Argon2 is CPU-heavy; keep it off the async workers.
    let verdict = tokio::task::spawn_blocking(move || match stored {
        Some(h) => password::verify(&pw, &h),
        None => {
            password::verify_dummy(&pw);
            Verified::No
        }
    })
    .await
    .unwrap_or(Verified::No);
    let Some(user) = user.filter(|_| verdict != Verified::No) else {
        tracing::warn!(event = "auth.failed", user = %username, ip = %ip, transport, "sign-in failed");
        if let Some(scope) = st.lockout.fail(username, ip) {
            let scope = match scope {
                LockScope::AccountFromIp => "account+ip",
                LockScope::Account => "account",
                LockScope::Ip => "ip",
            };
            tracing::warn!(event = "auth.locked", user = %username, ip = %ip, scope, transport, "sign-in locked");
        }
        st.db
            .audit(AuditEntry {
                username: Some(username.to_owned()),
                action: "LOGIN",
                outcome: "FAILED",
                transport: Some(transport),
                ip: Some(ip.to_string()),
                user_agent: user_agent.map(str::to_owned),
                ..Default::default()
            })
            .await;
        return Err(Failure::Bad);
    };
    st.lockout.success(username, ip);
    if verdict == Verified::YesRehash {
        let pw = password.to_owned();
        if let Ok(Ok(h)) = tokio::task::spawn_blocking(move || password::hash(&pw)).await {
            let _ = st
                .db
                .set_password(&user.id, &h, user.must_change_password, false)
                .await;
        }
    }
    Ok(user)
}
