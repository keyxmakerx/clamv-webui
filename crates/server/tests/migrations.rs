//! Schema rules: released migrations never change, and a database made by an
//! older image upgrades in place with its data intact.

use std::path::{Path, PathBuf};

use clamv_webui::db::{Db, new_id};
use sha2::{Digest, Sha256};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Every migration file must be listed in `migrations.sha256` with its hash.
/// A new migration adds a line; an existing line must never change (CI also
/// refuses any edit to a migration that is already on main).
#[test]
fn migrations_match_the_frozen_list() {
    let list = std::fs::read_to_string(root().join("migrations.sha256")).expect("list");
    let frozen: Vec<(&str, &str)> = list
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split_once("  ").expect("sha256sum format"))
        .collect();
    let mut seen = 0;
    for backend in ["sqlite", "postgres", "mysql"] {
        let dir = root().join("migrations").join(backend);
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .expect("dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for name in names {
            let rel = format!("{backend}/{name}");
            let bytes = std::fs::read(dir.join(&name)).expect("read");
            let hash = format!("{:x}", Sha256::digest(&bytes));
            match frozen.iter().find(|(_, p)| *p == rel) {
                Some((h, _)) => assert_eq!(
                    *h, hash,
                    "{rel} changed after release; add a new numbered migration instead"
                ),
                None => panic!(
                    "{rel} is not in migrations.sha256; run `sha256sum */*.sql` in crates/server/migrations"
                ),
            }
            seen += 1;
        }
    }
    assert_eq!(
        seen,
        frozen.len(),
        "migrations.sha256 lists a file that is gone"
    );
}

/// Build a database with only 0001 (what the first :latest image made), add
/// rows, then open it with this build and check nothing was lost.
#[tokio::test]
async fn upgrades_a_first_release_database() {
    let dir = std::env::temp_dir().join(format!("clamv-upgrade-{}", new_id()));
    let only_first = dir.join("m");
    std::fs::create_dir_all(&only_first).expect("dir");
    std::fs::copy(
        root().join("migrations/sqlite/0001_initial.sql"),
        only_first.join("0001_initial.sql"),
    )
    .expect("copy");
    let url = format!("sqlite://{}?mode=rwc", dir.join("old.db").display());

    let old = Db::connect(&url, 1).await.expect("connect");
    let first = sqlx::migrate::Migrator::new(only_first.as_path())
        .await
        .expect("migrator");
    first.run(old.pool()).await.expect("0001");
    sqlx::query(
        "INSERT INTO scan_schedules (id, name, cron, paths_json, exclusions_json, enabled, max_streams, eicar_check, created_at, updated_at) \
         VALUES ('s1', 'Nightly', '0 2 * * *', '[\"/data\"]', '[]', 1, 1, 1, 1, 1)",
    )
    .execute(old.pool())
    .await
    .expect("old schedule");
    sqlx::query(
        "INSERT INTO scan_jobs (id, kind, status, verdict, target, submitted_at, files_scanned, detections_json) \
         VALUES ('j1', 'PATH', 'FINISHED', 'VIRUS_FOUND', '/data', 1, 3, '{\"/data/x\":[\"Eicar\"]}')",
    )
    .execute(old.pool())
    .await
    .expect("old job");
    old.close().await;

    // This build: applies 0002 onward, refuses nothing.
    let db = Db::open(&url, 1).await.expect("upgrade");
    let job = db.job("j1").await.expect("q").expect("job kept");
    assert_eq!(job.files_scanned, 3);
    assert_eq!(job.detections.len(), 1);
    assert_eq!(job.results_omitted, 0);
    let s = db.schedule("s1").await.expect("q").expect("schedule kept");
    assert_eq!(s.paths, vec!["/data".to_owned()]);
    db.migrate().await.expect("second run is a no-op");
    db.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}
