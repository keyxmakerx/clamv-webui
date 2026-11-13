//! First start: create the `admin` account if there are no users.

use std::io::Write;
use std::path::Path;

use crate::auth::{Role, password, token};
use crate::db::Db;

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
    db.create_user("admin", &hash, Role::Admin, true).await?;
    if generated {
        let file = data_dir.join("bootstrap-admin-password");
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
