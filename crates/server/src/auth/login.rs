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
    if st.lockout.check(&key, ip).is_err() {
        tracing::warn!(event = "auth.locked", user = %username, ip = %ip, transport = "LDAP", "sign-in refused while locked");
        return Err(DirectoryFailure::Locked);
    }
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
            let _ = st.lockout.fail(&key, ip);
            audit("FAILED", None).await;
            return Err(DirectoryFailure::Bad);
        }
        Err(LdapError::Unavailable(e)) => {
            tracing::error!(event = "ldap.unavailable", error = %e, "directory sign-in failed");
            return Err(DirectoryFailure::Unavailable);
        }
    };
    st.lockout.success(&key, ip);
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
