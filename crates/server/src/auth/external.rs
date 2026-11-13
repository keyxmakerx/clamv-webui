//! Local accounts for external identities (OIDC, LDAP). Keyed on the
//! provider's immutable id, never on a username or email (deny by default).

use sha2::{Digest, Sha256};

use super::Role;
use crate::app::AppState;
use crate::db::users::{NO_PASSWORD, User};

/// A verified identity from an external provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// "OIDC" or "LDAP".
    pub source: &'static str,
    pub issuer: String,
    pub subject: String,
    pub name: String,
    pub groups: Vec<String>,
}

impl Identity {
    /// Stable local key derived from source, issuer and subject.
    pub fn principal(&self) -> String {
        let d = Sha256::digest(format!("{}\0{}", self.issuer, self.subject));
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        format!("{}:{}", self.source.to_ascii_lowercase(), &hex[..48])
    }
}

/// Lowercased, trimmed, non-empty group names from config.
pub fn groups_list(v: &[String]) -> Vec<String> {
    v.iter()
        .map(|g| g.trim().to_lowercase())
        .filter(|g| !g.is_empty())
        .collect()
}

/// The highest role any membership grants.
pub fn role_for(
    have: &[String],
    admin: &[String],
    operator: &[String],
    viewer: &[String],
) -> Option<Role> {
    let have: Vec<String> = have.iter().map(|g| g.trim().to_lowercase()).collect();
    let hit = |want: &[String]| want.iter().any(|w| have.contains(w));
    if hit(admin) {
        Some(Role::Admin)
    } else if hit(operator) {
        Some(Role::Operator)
    } else if hit(viewer) {
        Some(Role::Viewer)
    } else {
        None
    }
}

/// A free local name: prefix plus the provider's name, made unique.
async fn free_username(st: &AppState, prefix: &str, name: &str) -> Option<String> {
    let base: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
        .take(48)
        .collect();
    let base = if base.is_empty() {
        "user".to_owned()
    } else {
        base
    };
    for i in 1..100 {
        let candidate = if i == 1 {
            format!("{prefix}:{base}")
        } else {
            format!("{prefix}:{base}-{i}")
        };
        if matches!(st.db.user_by_username(&candidate).await, Ok(None)) {
            return Some(candidate);
        }
    }
    None
}

pub enum ProvisionError {
    Disabled,
    Unavailable,
}

/// Find or create the local user for an identity; the role follows groups at every sign-in.
pub async fn provision(st: &AppState, id: &Identity, role: Role) -> Result<User, ProvisionError> {
    use ProvisionError::{Disabled, Unavailable};
    let principal = id.principal();
    if let Some(uid) = st
        .db
        .identity_user(&principal)
        .await
        .map_err(|_| Unavailable)?
    {
        let u = st
            .db
            .user_by_id(&uid)
            .await
            .map_err(|_| Unavailable)?
            .ok_or(Unavailable)?;
        if !u.enabled {
            return Err(Disabled);
        }
        if u.role != role {
            // Also ends the user's other sessions (N7).
            st.db
                .set_role_enabled(&u.id, role, true)
                .await
                .map_err(|_| Unavailable)?;
            tracing::info!(event = "auth.role_changed", user = %u.username, role = %role, source = id.source, "role updated from groups");
            return st
                .db
                .user_by_id(&uid)
                .await
                .map_err(|_| Unavailable)?
                .ok_or(Unavailable);
        }
        return Ok(u);
    }
    let prefix = if id.source == "LDAP" { "ldap" } else { "sso" };
    let name = free_username(st, prefix, &id.name)
        .await
        .ok_or(Unavailable)?;
    let u = st
        .db
        .create_user(&name, NO_PASSWORD, role, false)
        .await
        .map_err(|_| Unavailable)?;
    st.db
        .link_identity(&principal, &u.id, id.source, &id.issuer, &id.subject)
        .await
        .map_err(|_| Unavailable)?;
    tracing::info!(event = "auth.user_provisioned", user = %u.username, role = %role, source = id.source, "external user created");
    Ok(u)
}
