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

    /// A connection already bound as the service account.
    async fn service(&self) -> Result<ldap3::Ldap, LdapError> {
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
        Ok(ldap)
    }

    fn attrs(&self) -> Vec<&str> {
        vec![
            self.group_attr.as_str(),
            "entryUUID",
            "objectGUID",
            "uid",
            "sAMAccountName",
            "userAccountControl",
        ]
    }

    /// The entries the configured user filter finds for a name.
    async fn find(
        &self,
        ldap: &mut ldap3::Ldap,
        username: &str,
    ) -> Result<Vec<SearchEntry>, LdapError> {
        let down = |e: ldap3::LdapError| LdapError::Unavailable(e.to_string());
        let filter = self.filter.replace("{username}", &ldap_escape(username));
        let (entries, _) = ldap
            .search(&self.base, Scope::Subtree, &filter, self.attrs())
            .await
            .map_err(down)?
            .success()
            .map_err(down)?;
        Ok(entries.into_iter().map(SearchEntry::construct).collect())
    }

    fn identity(&self, e: &SearchEntry, username: &str) -> Identity {
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
        Identity {
            source: "LDAP",
            issuer: self.url.clone(),
            subject,
            name,
            groups,
        }
    }

    async fn run(&self, username: &str, password: &str) -> Result<Identity, LdapError> {
        let down = |e: ldap3::LdapError| LdapError::Unavailable(e.to_string());
        let mut ldap = self.service().await?;
        let entries = self.find(&mut ldap, username).await?;
        // Exactly one match, or nobody: ambiguity is a failure, not a guess.
        let [e] = entries.as_slice() else {
            let _ = ldap.unbind().await;
            return Err(LdapError::Bad);
        };
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
        Ok(self.identity(e, username))
    }

    /// Look an already linked user up again without their password, for a
    /// passkey sign-in: found by the stored subject, then through the
    /// configured user filter, so a removed, filtered-out or (Active
    /// Directory) disabled account is `Ok(None)`.
    pub async fn lookup(&self, issuer: &str, subject: &str) -> Result<Option<Identity>, LdapError> {
        if issuer != self.url || subject.is_empty() || subject.len() > 512 {
            return Ok(None);
        }
        tokio::time::timeout(TIMEOUT, self.run_lookup(subject))
            .await
            .map_err(|_| LdapError::Unavailable("directory timed out".into()))?
    }

    async fn run_lookup(&self, subject: &str) -> Result<Option<Identity>, LdapError> {
        let down = |e: ldap3::LdapError| LdapError::Unavailable(e.to_string());
        let mut ldap = self.service().await?;
        let (base, scope, filter) = subject_search(&self.base, subject);
        let found = match ldap.search(&base, scope, &filter, self.attrs()).await {
            Ok(r) => match r.success() {
                Ok((entries, _)) => entries,
                // 32: no such object (a DN subject that is gone).
                Err(ldap3::LdapError::LdapResult { result }) if result.rc == 32 => Vec::new(),
                Err(e) => return Err(down(e)),
            },
            Err(e) => return Err(down(e)),
        };
        let [entry] = found.as_slice() else {
            let _ = ldap.unbind().await;
            return Ok(None);
        };
        let e = SearchEntry::construct(entry.clone());
        let id = self.identity(&e, "");
        // The same filter as a password sign-in must still match this entry, and only it.
        let again = if id.name.is_empty() {
            Vec::new()
        } else {
            self.find(&mut ldap, &id.name).await?
        };
        let _ = ldap.unbind().await;
        let [same] = again.as_slice() else {
            return Ok(None);
        };
        if !same.dn.eq_ignore_ascii_case(&e.dn) || ad_disabled(same) {
            return Ok(None);
        }
        Ok(Some(self.identity(same, &id.name)))
    }
}

/// Where to find a stored subject: entryUUID, hex objectGUID, or a DN.
fn subject_search(base: &str, subject: &str) -> (String, Scope, String) {
    let is_hex = |s: &str| s.chars().all(|c| c.is_ascii_hexdigit());
    if subject.len() == 32 && is_hex(subject) {
        let bytes: String = subject
            .as_bytes()
            .chunks(2)
            .map(|p| format!("\\{}", String::from_utf8_lossy(p)))
            .collect();
        (
            base.to_owned(),
            Scope::Subtree,
            format!("(objectGUID={bytes})"),
        )
    } else if subject.contains('=') {
        (
            subject.to_owned(),
            Scope::Base,
            "(objectClass=*)".to_owned(),
        )
    } else {
        (
            base.to_owned(),
            Scope::Subtree,
            format!("(entryUUID={})", ldap_escape(subject)),
        )
    }
}

/// Active Directory's "account disabled" bit.
fn ad_disabled(e: &SearchEntry) -> bool {
    e.attrs
        .get("userAccountControl")
        .and_then(|v| v.first())
        .and_then(|v| v.trim().parse::<i64>().ok())
        .is_some_and(|f| f & 2 != 0)
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
    fn subjects_are_searched_safely() {
        let (b, _, f) = subject_search("dc=lan", "0a1b2c3d4e5f60718293a4b5c6d7e8f9");
        assert_eq!(b, "dc=lan");
        assert!(f.starts_with("(objectGUID=\\0a\\1b"));
        let (b, s, _) = subject_search("dc=lan", "uid=alice,ou=people,dc=lan");
        assert_eq!((b.as_str(), s), ("uid=alice,ou=people,dc=lan", Scope::Base));
        let (_, _, f) = subject_search("dc=lan", "x)(uid=*");
        assert!(!f.contains(")(uid=*"), "{f}");
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
}
