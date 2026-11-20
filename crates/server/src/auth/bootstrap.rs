//! First start: create the `admin` account if there are no users.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::auth::{Role, password, token};
use crate::db::Db;

/// Name of the file that holds a generated one-time admin password.
pub const FILE_NAME: &str = "bootstrap-admin-password";

/// Where a generated one-time admin password is written.
pub fn file(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

/// Remove the one-time password file once admin has chosen their own password,
/// so a stale secret does not sit on disk. The file only ever holds a password
/// that no longer works at this point.
pub fn forget(data_dir: &Path) {
    let f = file(data_dir);
    match std::fs::remove_file(&f) {
        Ok(()) => {
            tracing::info!(event = "auth.bootstrap_file_removed", file = %f.display(), "one-time admin password file removed")
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(event = "auth.bootstrap_file_kept", file = %f.display(), error = %e, "could not remove the one-time admin password file; delete it by hand")
        }
    }
}

pub async fn ensure_admin(db: &Db, data_dir: &Path, supplied: Option<&str>) -> anyhow::Result<()> {
    if db.count_users().await? > 0 {
        return Ok(());
    }
    let (pw, generated) = match supplied {
        Some(p) => {
            password::validate(p).map_err(|e| anyhow::anyhow!("BOOTSTRAP_ADMIN_PASSWORD: {e}"))?;
            (p.to_owned(), false)
        }
        None => (token::random_secret(), true),
    };
    let hash = password::hash(&pw)?;
    // A generated password must be replaced; one the operator chose need not be.
    db.create_user("admin", &hash, Role::Admin, generated)
        .await?;
    if generated {
        let file = file(data_dir);
        write_private(&file, &pw)?;
        // The password itself is never logged.
        tracing::warn!(
            event = "auth.bootstrap",
            file = %file.display(),
            "created user admin; read its one-time password from the file, then delete the file"
        );
    } else {
        tracing::warn!(
            event = "auth.bootstrap",
            "created user admin with BOOTSTRAP_ADMIN_PASSWORD"
        );
    }
    Ok(())
}

/// Recovery: give `admin` a new one-time password (written to the data dir,
/// never printed), make it an enabled admin again, end its sessions, and
/// remove its second factors (a lost phone is a common reason to reset).
pub async fn reset_admin(db: &Db, data_dir: &Path) -> anyhow::Result<std::path::PathBuf> {
    let pw = token::random_secret();
    let hash = password::hash(&pw)?;
    match db.user_by_username("admin").await? {
        Some(u) => {
            db.set_role_enabled(&u.id, Role::Admin, true).await?;
            db.set_password(&u.id, &hash, true, true).await?;
            db.clear_mfa(&u.id).await?;
        }
        None => {
            db.create_user("admin", &hash, Role::Admin, true).await?;
        }
    }
    let file = file(data_dir);
    write_private(&file, &pw)?;
    tracing::warn!(event = "auth.admin_reset", file = %file.display(), "admin password reset; read it from the file, then delete the file");
    db.audit(crate::db::audit::AuditEntry {
        username: Some("admin".into()),
        action: "USER_PASSWORD_RESET",
        outcome: "OK",
        transport: Some("CLI"),
        details: Some("reset-admin".into()),
        ..Default::default()
    })
    .await;
    Ok(file)
}

fn write_private(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(content.as_bytes())?;
    f.write_all(b"\n")
}
