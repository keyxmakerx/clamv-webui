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
    /// Too many password checks already running; try again shortly.
    Busy,
    Unavailable,
}

/// Password checks that may run at once (each holds 19 MiB of argon2 memory).
pub const HASH_SLOTS: usize = 4;
/// How long a check waits for a free slot before giving up.
const HASH_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Throttled, constant-work password check. Logs and audits failures.
pub async fn authenticate(
    st: &AppState,
    username: &str,
    password: &str,
    ip: IpAddr,
    user_agent: Option<&str>,
    transport: &'static str,
) -> Result<User, Failure> {
    // Count the failure before hashing, so a burst cannot all get through (sa3).
    let reservation = match st.lockout.reserve(username, ip) {
        Ok(r) => r,
        Err(_) => {
            tracing::warn!(event = "auth.locked", user = %username, ip = %ip, transport, "sign-in refused while locked");
            return Err(Failure::Locked);
        }
    };
    let locked_scope = reservation.scope();
    let user = match st.db.user_by_username(username).await {
        Ok(u) => u,
        Err(e) => {
            st.lockout.refund(username, ip, reservation);
            tracing::error!(error = %e, "user lookup failed");
            return Err(Failure::Unavailable);
        }
    };
    let stored = user
        .as_ref()
        .filter(|u| u.enabled)
        .map(|u| u.password_hash.clone());
    let pw = password.to_owned();
    // Each check holds 19 MiB; only a few run at once, the rest wait briefly.
    let Ok(Ok(slot)) = tokio::time::timeout(HASH_WAIT, st.hash_slots.clone().acquire_owned()).await
    else {
        st.lockout.refund(username, ip, reservation);
        tracing::warn!(event = "auth.busy", user = %username, ip = %ip, transport, "too many password checks at once");
        return Err(Failure::Busy);
    };
    // Argon2 is CPU-heavy; keep it off the async workers.
    // The slot moves into the task, so it stays held even if this request is dropped.
    let verdict = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        match stored {
            Some(h) => password::verify(&pw, &h),
            None => {
                password::verify_dummy(&pw);
                Verified::No
            }
        }
    })
    .await
    .unwrap_or(Verified::No);
    let Some(user) = user.filter(|_| verdict != Verified::No) else {
        tracing::warn!(event = "auth.failed", user = %username, ip = %ip, transport, "sign-in failed");
        if let Some(scope) = locked_scope {
            let scope = match scope {
                LockScope::AccountFromIp => "account+ip",
                LockScope::Account => "account",
                LockScope::Ip => "ip",
            };
            tracing::warn!(event = "auth.locked", user = %username, ip = %ip, scope, transport, "sign-in locked; restart the server to clear it early");
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
    st.lockout.release(username, ip, reservation);
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

#[derive(Debug, PartialEq, Eq)]
pub enum DirectoryFailure {
    Locked,
    Bad,
    Denied,
    Disabled,
    Unavailable,
}

/// Directory sign-in with the same lockout and audit as local sign-in.
pub async fn authenticate_ldap(
    st: &AppState,
    username: &str,
    password: &str,
    ip: IpAddr,
    user_agent: Option<&str>,
) -> Result<User, DirectoryFailure> {
    use super::external::{ProvisionError, provision};
    use super::ldap::LdapError;
    let Some(dir) = &st.ldap else {
        return Err(DirectoryFailure::Unavailable);
    };
    let key = format!("ldap:{}", username.to_lowercase());
    let Ok(reservation) = st.lockout.reserve(&key, ip) else {
        tracing::warn!(event = "auth.locked", user = %username, ip = %ip, transport = "LDAP", "sign-in refused while locked");
        return Err(DirectoryFailure::Locked);
    };
    let audit = |outcome: &'static str, details: Option<String>| {
        st.db.audit(AuditEntry {
            username: Some(username.to_owned()),
            action: "LOGIN",
            outcome,
            transport: Some("LDAP"),
            ip: Some(ip.to_string()),
            user_agent: user_agent.map(str::to_owned),
            details,
            ..Default::default()
        })
    };
    let id = match dir.authenticate(username, password).await {
        Ok(id) => id,
        Err(LdapError::Bad) => {
            tracing::warn!(event = "auth.failed", user = %username, ip = %ip, transport = "LDAP", "sign-in failed");
            audit("FAILED", None).await;
            return Err(DirectoryFailure::Bad);
        }
        Err(LdapError::Unavailable(e)) => {
            // Not the user's fault: hand the reserved failure back.
            st.lockout.refund(&key, ip, reservation);
            tracing::error!(event = "ldap.unavailable", error = %e, "directory sign-in failed");
            return Err(DirectoryFailure::Unavailable);
        }
    };
    st.lockout.release(&key, ip, reservation);
    let Some(role) = dir.role_for(&id.groups) else {
        tracing::warn!(event = "auth.ldap_denied", user = %username, ip = %ip, "directory user has no matching group");
        audit("DENIED", Some("no matching group".into())).await;
        return Err(DirectoryFailure::Denied);
    };
    match provision(st, &id, role).await {
        Ok(u) => Ok(u),
        Err(ProvisionError::Disabled) => {
            audit("DENIED", Some("account disabled".into())).await;
            Err(DirectoryFailure::Disabled)
        }
        Err(ProvisionError::Unavailable) => Err(DirectoryFailure::Unavailable),
    }
}
