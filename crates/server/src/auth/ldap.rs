//! Directory sign-in over LDAPS or StartTLS. A service account finds the
//! user, the user's own bind checks the password, and roles come only from
//! configured groups. Never falls back to local accounts.

use std::sync::Arc;
use std::time::Duration;

use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry, ldap_escape};

use super::Role;
use super::external::{Identity, groups_list, role_for};
use crate::config::Config;

const TIMEOUT: Duration = Duration::from_secs(10);

pub struct Ldap {
    url: String,
    starttls: bool,
    bind_dn: String,
    bind_password: String,
    base: String,
    filter: String,
    group_attr: String,
    admin: Vec<String>,
    operator: Vec<String>,
    viewer: Vec<String>,
    tls: Arc<rustls::ClientConfig>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LdapError {
    /// Unknown user, wrong password or ambiguous match.
    Bad,
    /// The directory could not be reached or searched.
    Unavailable(String),
}

/// Group values as written, plus the first RDN value of a DN (cn=admins,ou=x -> admins).
pub fn group_names(values: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for v in values {
        let v = v.trim();
        out.push(v.to_lowercase());
        if let Some((_, rest)) = v.split_once('=') {
            let first = rest.split(',').next().unwrap_or("").trim();
            if !first.is_empty() {
                out.push(first.to_lowercase());
            }
        }
    }
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Ldap {
    pub fn from_config(cfg: &Config) -> anyhow::Result<Option<Self>> {
        let url = cfg.ldap_url.clone().unwrap_or_default().trim().to_owned();
        if url.is_empty() {
            return Ok(None);
        }
        let lower = url.to_ascii_lowercase();
        if lower.starts_with("ldap://") {
            if !cfg.ldap_starttls {
                anyhow::bail!("LDAP_URL ldap:// needs LDAP_STARTTLS=true; use ldaps:// otherwise");
            }
        } else if !lower.starts_with("ldaps://") {
            anyhow::bail!("LDAP_URL must start with ldaps:// or ldap://");
        }
        let bind_dn = cfg
            .ldap_bind_dn
            .clone()
            .unwrap_or_default()
            .trim()
            .to_owned();
        let bind_password = match &cfg.ldap_bind_password_file {
            Some(p) => std::fs::read_to_string(p).map_err(|e| {
                anyhow::anyhow!("cannot read LDAP_BIND_PASSWORD_FILE {}: {e}", p.display())
            })?,
            None => cfg.ldap_bind_password.clone().unwrap_or_default(),
        }
        .trim_end_matches(['\r', '\n'])
        .to_owned();
        let base = cfg
            .ldap_user_base
            .clone()
            .unwrap_or_default()
            .trim()
            .to_owned();
        if bind_dn.is_empty() || bind_password.is_empty() || base.is_empty() {
            anyhow::bail!("LDAP_URL needs LDAP_BIND_DN, LDAP_BIND_PASSWORD and LDAP_USER_BASE");
        }
        if !cfg.ldap_user_filter.contains("{username}") {
            anyhow::bail!("LDAP_USER_FILTER must contain {{username}}");
        }
        let admin = groups_list(&cfg.ldap_admin_groups);
        let operator = groups_list(&cfg.ldap_operator_groups);
        let viewer = groups_list(&cfg.ldap_viewer_groups);
        if admin.is_empty() && operator.is_empty() && viewer.is_empty() {
            anyhow::bail!(
                "set LDAP_ADMIN_GROUPS, LDAP_OPERATOR_GROUPS or LDAP_VIEWER_GROUPS; nobody could sign in"
            );
        }
        let tls = Arc::new(crate::webhook::client_tls(cfg.ldap_ca_file.as_deref())?);
        Ok(Some(Self {
            url,
            starttls: cfg.ldap_starttls,
            bind_dn,
            bind_password,
            base,
            filter: cfg.ldap_user_filter.clone(),
            group_attr: cfg.ldap_group_attribute.clone(),
            admin,
            operator,
            viewer,
            tls,
        }))
    }

    pub fn role_for(&self, groups: &[String]) -> Option<Role> {
        role_for(
            &group_names(groups),
            &self.admin,
            &self.operator,
            &self.viewer,
        )
    }

    /// Check a username and password against the directory.
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Identity, LdapError> {
        // An empty password would be an unauthenticated bind, which many servers accept.
        if username.trim().is_empty()
            || password.is_empty()
            || username.len() > 128
            || username.chars().any(char::is_control)
        {
            return Err(LdapError::Bad);
        }
        tokio::time::timeout(TIMEOUT, self.run(username.trim(), password))
            .await
            .map_err(|_| LdapError::Unavailable("directory timed out".into()))?
    }

    async fn run(&self, username: &str, password: &str) -> Result<Identity, LdapError> {
        let down = |e: ldap3::LdapError| LdapError::Unavailable(e.to_string());
        let settings = LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(5))
            .set_starttls(self.starttls)
            .set_config(self.tls.clone());
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.url)
            .await
            .map_err(down)?;
        ldap3::drive!(conn);
        ldap.simple_bind(&self.bind_dn, &self.bind_password)
            .await
            .map_err(down)?
            .success()
            .map_err(|_| LdapError::Unavailable("service account bind failed".into()))?;
        let filter = self.filter.replace("{username}", &ldap_escape(username));
        let attrs = vec![
            self.group_attr.as_str(),
            "entryUUID",
            "objectGUID",
            "uid",
            "sAMAccountName",
        ];
        let (entries, _) = ldap
            .search(&self.base, Scope::Subtree, &filter, attrs)
            .await
            .map_err(down)?
            .success()
            .map_err(down)?;
        // Exactly one match, or nobody: ambiguity is a failure, not a guess.
        let [entry] = entries.as_slice() else {
            let _ = ldap.unbind().await;
            return Err(LdapError::Bad);
        };
        let e = SearchEntry::construct(entry.clone());
        let ok = ldap
            .simple_bind(&e.dn, password)
            .await
            .map_err(down)?
            .success()
            .is_ok();
        let _ = ldap.unbind().await;
        if !ok {
            return Err(LdapError::Bad);
        }
        let first = |k: &str| e.attrs.get(k).and_then(|v| v.first()).cloned();
        let subject = first("entryUUID")
            .or_else(|| {
                e.bin_attrs
                    .get("objectGUID")
                    .and_then(|v| v.first())
                    .map(|b| hex(b))
            })
            .unwrap_or_else(|| e.dn.to_lowercase());
        let name = first("uid")
            .or_else(|| first("sAMAccountName"))
            .unwrap_or_else(|| username.to_owned());
        let groups = e
            .attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&self.group_attr))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        Ok(Identity {
            source: "LDAP",
            issuer: self.url.clone(),
            subject,
            name,
            groups,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_match_by_dn_or_name() {
        let g = group_names(&["CN=ClamAV Admins,OU=Groups,DC=lan".into(), "staff".into()]);
        assert!(g.contains(&"clamav admins".to_owned()));
        assert!(g.contains(&"cn=clamav admins,ou=groups,dc=lan".to_owned()));
        assert!(g.contains(&"staff".to_owned()));
    }

    #[test]
    fn config_requires_tls_and_groups() {
        use clap::Parser;
        let parse = |extra: &[&str]| {
            let mut a = vec![
                "x",
                "--ldap-bind-dn",
                "cn=svc",
                "--ldap-bind-password",
                "p",
                "--ldap-user-base",
                "dc=lan",
            ];
            a.extend_from_slice(extra);
            Ldap::from_config(&crate::config::Cli::parse_from(a).config)
        };
        assert!(parse(&[]).expect("off").is_none());
        assert!(parse(&["--ldap-url", "ldap://dir", "--ldap-admin-groups", "a"]).is_err());
        assert!(parse(&["--ldap-url", "ldaps://dir"]).is_err(), "no groups");
        assert!(
            parse(&[
                "--ldap-url",
                "ldaps://dir",
                "--ldap-admin-groups",
                "a",
                "--ldap-user-filter",
                "(uid=x)"
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "--ldap-url",
                "ldap://dir",
                "--ldap-starttls",
                "--ldap-admin-groups",
                "a"
            ])
            .expect("ok")
            .is_some()
        );
    }

    #[tokio::test]
    async fn empty_password_never_binds() {
        use clap::Parser;
        let cfg = crate::config::Cli::parse_from([
            "x",
            "--ldap-url",
            "ldaps://127.0.0.1:1",
            "--ldap-bind-dn",
            "cn=svc",
            "--ldap-bind-password",
            "p",
            "--ldap-user-base",
            "dc=lan",
            "--ldap-admin-groups",
            "a",
        ])
        .config;
        let l = Ldap::from_config(&cfg).expect("cfg").expect("on");
        assert_eq!(l.authenticate("alice", "").await, Err(LdapError::Bad));
        assert_eq!(l.authenticate("", "pw").await, Err(LdapError::Bad));
        assert!(matches!(
            l.authenticate("alice", "pw").await,
            Err(LdapError::Unavailable(_))
        ));
    }
}
