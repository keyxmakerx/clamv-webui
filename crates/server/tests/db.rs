//! Runs against SQLite always, plus every URL in `TEST_DATABASE_URLS`
//! (comma-separated; CI sets PostgreSQL, MySQL and MariaDB).

use clamv_webui::db::{Db, new_id, now_ms};

/// Tests share the external databases; open them one at a time.
static OPEN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn databases() -> Vec<Db> {
    let _guard = OPEN.lock().await;
    let dir = std::env::temp_dir().join(format!("clamv-webui-test-{}", new_id()));
    std::fs::create_dir_all(&dir).expect("tmp dir");
    let mut urls = vec![format!("sqlite://{}", dir.join("t.db").display())];
    if let Ok(extra) = std::env::var("TEST_DATABASE_URLS") {
        urls.extend(
            extra
                .split(',')
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .map(String::from),
        );
    }
    let mut out = Vec::new();
    for url in urls {
        let db = Db::open(&url, 4)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", clamv_webui::db::redact_url(&url)));
        out.push(db);
    }
    out
}

#[tokio::test]
async fn migrations_are_idempotent_and_settings_upsert() {
    for db in databases().await {
        let kind = db.kind();
        db.migrate().await.expect("second migrate is a no-op");
        let key = format!("test.{}", new_id());
        assert_eq!(db.setting(&key).await.expect("get"), None, "{kind:?}");
        db.set_setting(&key, "a", Some("tester"))
            .await
            .expect("insert");
        db.set_setting(&key, "b", None).await.expect("update");
        assert_eq!(
            db.setting(&key).await.expect("get").as_deref(),
            Some("b"),
            "{kind:?}"
        );
        // Non-ASCII survives the round trip on every backend.
        db.set_setting(&key, "Überprüfung ✓ 日本", None)
            .await
            .expect("utf8");
        assert_eq!(
            db.setting(&key).await.expect("get").as_deref(),
            Some("Überprüfung ✓ 日本"),
            "{kind:?}"
        );
        assert!(db.delete_setting(&key).await.expect("delete"));
        db.close().await;
    }
}

#[tokio::test]
async fn portable_types_decode_everywhere() {
    for db in databases().await {
        let kind = db.kind();
        let id = new_id();
        let now = now_ms();
        sqlx::query(db.sql(
            "INSERT INTO endpoints (id, name, address, enabled, is_default, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        ))
        .bind(&id)
        .bind(format!("ep-{id}"))
        .bind("tcp://clamav:3310")
        .bind(1_i64)
        .bind(0_i64)
        .bind(now)
        .execute(db.pool())
        .await
        .expect("insert");
        let (enabled, created): (i64, i64) =
            sqlx::query_as(db.sql("SELECT enabled, created_at FROM endpoints WHERE id = ?"))
                .bind(&id)
                .fetch_one(db.pool())
                .await
                .unwrap_or_else(|e| panic!("{kind:?}: {e}"));
        assert_eq!((enabled, created), (1, now), "{kind:?}");
        // Foreign keys are enforced (SQLite needs the pragma).
        let bad = sqlx::query(db.sql(
            "INSERT INTO watched_directories (id, path, endpoint_id, enabled, created_at) VALUES (?, ?, ?, 1, ?)",
        ))
        .bind(new_id())
        .bind("/data")
        .bind("missing")
        .bind(now)
        .execute(db.pool())
        .await;
        assert!(bad.is_err(), "{kind:?}: foreign key not enforced");
        db.close().await;
    }
}
