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
        let now = now_ms();
        let id = now;
        sqlx::query(db.sql(
            "INSERT INTO endpoints (id, name, address, enabled, is_default, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        ))
        .bind(id)
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
                .bind(id)
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

#[tokio::test]
async fn users_and_sessions() {
    use clamv_webui::auth::Role;
    for db in databases().await {
        let kind = db.kind();
        let name = format!("u-{}", &new_id()[..8]);
        let u = db
            .create_user(&name, "$argon2id$x", Role::Operator, true)
            .await
            .expect("create");
        let dup = db
            .create_user(&name, "$argon2id$y", Role::Viewer, false)
            .await;
        assert!(dup.is_err(), "{kind:?}: duplicate username accepted");
        let got = db
            .user_by_username(&name)
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(
            (got.role, got.enabled, got.must_change_password),
            (Role::Operator, true, true),
            "{kind:?}"
        );

        let (raw, s) = db
            .create_session(&u.id, 3_600_000, Some("10.0.0.1"), Some("test"))
            .await
            .expect("session");
        assert_ne!(raw, s.id_hash);
        let (s2, u2) = db
            .session_user(&raw, 600_000)
            .await
            .expect("lookup")
            .expect("valid");
        assert_eq!(
            (s2.csrf_token, u2.id.clone()),
            (s.csrf_token, u.id.clone()),
            "{kind:?}"
        );
        assert!(
            db.session_user("not-a-session", 600_000)
                .await
                .expect("lookup")
                .is_none()
        );

        // Password change ends sessions (N7).
        db.set_password(&u.id, "$argon2id$z", false, true)
            .await
            .expect("pw");
        assert!(
            db.session_user(&raw, 600_000)
                .await
                .expect("lookup")
                .is_none(),
            "{kind:?}"
        );

        // Disabling ends sessions.
        let (raw2, _) = db
            .create_session(&u.id, 3_600_000, None, None)
            .await
            .expect("session");
        db.set_role_enabled(&u.id, Role::Viewer, false)
            .await
            .expect("disable");
        assert!(
            db.session_user(&raw2, 600_000)
                .await
                .expect("lookup")
                .is_none(),
            "{kind:?}"
        );

        // Deleting a user cascades to sessions.
        let (raw3, _) = db
            .create_session(&u.id, 3_600_000, None, None)
            .await
            .expect("session");
        assert!(db.delete_user(&u.id).await.expect("delete"));
        assert!(
            db.session_user(&raw3, 600_000)
                .await
                .expect("lookup")
                .is_none(),
            "{kind:?}"
        );
        db.close().await;
    }
}

#[tokio::test]
async fn audit_round_trip() {
    use clamv_webui::db::audit::AuditEntry;
    for db in databases().await {
        let kind = db.kind();
        let marker = new_id();
        db.audit(AuditEntry {
            username: Some("admin".into()),
            action: "TEST",
            outcome: "OK",
            details: Some(marker.clone()),
            ..Default::default()
        })
        .await;
        let rows = db.recent_audit(50).await.expect("list");
        assert!(
            rows.iter()
                .any(|r| r.details.as_deref() == Some(marker.as_str())),
            "{kind:?}"
        );
        db.close().await;
    }
}

#[tokio::test]
async fn endpoints_keep_one_default() {
    for db in databases().await {
        let kind = db.kind();
        sqlx::query(db.sql("DELETE FROM endpoints"))
            .execute(db.pool())
            .await
            .expect("clear");
        let a = db
            .create_endpoint(&format!("a-{}", &new_id()[..8]), "tcp://a:3310", false)
            .await
            .expect("a");
        assert!(a.is_default, "{kind:?}: first endpoint becomes default");
        let b = db
            .create_endpoint(&format!("b-{}", &new_id()[..8]), "tcp://b:3310", true)
            .await
            .expect("b");
        assert!(b.is_default);
        let list = db.list_endpoints().await.expect("list");
        assert_eq!(list.iter().filter(|e| e.is_default).count(), 1, "{kind:?}");
        assert!(
            !db.delete_endpoint(b.id).await.expect("del default"),
            "{kind:?}: default deleted"
        );
        db.set_default_endpoint(a.id).await.expect("set");
        assert_eq!(
            db.default_endpoint().await.expect("q").map(|e| e.id),
            Some(a.id),
            "{kind:?}"
        );
        assert!(db.delete_endpoint(b.id).await.expect("del"));
        db.close().await;
    }
}

#[tokio::test]
async fn jobs_claim_filter_and_prune() {
    use clamv_webui::db::jobs::{JobFilter, NewJob, Outcome};
    for db in databases().await {
        let kind = db.kind();
        sqlx::query(db.sql("DELETE FROM scan_jobs"))
            .execute(db.pool())
            .await
            .expect("clear");
        let target = format!("/data/ünïcode-{}", new_id());
        let j = db
            .create_job(NewJob {
                kind: "PATH",
                target: &target,
                endpoint_id: None,
                schedule_id: None,
                submitted_by: Some("admin"),
                transport: "UI",
                running: false,
            })
            .await
            .expect("create");
        assert_eq!(j.target, target, "{kind:?}");
        assert_eq!(
            db.queued_jobs(10).await.expect("queued"),
            vec![j.id.clone()]
        );
        assert!(db.claim_job(&j.id).await.expect("claim"), "{kind:?}");
        assert!(
            !db.claim_job(&j.id).await.expect("claim"),
            "{kind:?}: double claim"
        );
        let mut o = Outcome {
            verdict: "VIRUS_FOUND",
            files_scanned: 3,
            ..Outcome::default()
        };
        o.detections
            .insert(format!("{target}/x"), vec!["Eicar-Test-Signature".into()]);
        db.finish_job(&j.id, &o).await.expect("finish");
        let f = JobFilter {
            verdict: Some("VIRUS_FOUND".into()),
            ..JobFilter::default()
        };
        let (rows, total) = db.list_jobs(&f, 0, 10).await.expect("list");
        assert_eq!((rows.len(), total), (1, 1), "{kind:?}");
        assert_eq!(
            rows[0].signatures(),
            vec!["Eicar-Test-Signature".to_owned()]
        );
        let (_, none) = db
            .list_jobs(
                &JobFilter {
                    status: Some("QUEUED".into()),
                    ..JobFilter::default()
                },
                0,
                10,
            )
            .await
            .expect("list");
        assert_eq!(none, 0, "{kind:?}");
        let r = db
            .create_job(NewJob {
                kind: "UPLOAD",
                target: "f",
                endpoint_id: None,
                schedule_id: None,
                submitted_by: None,
                transport: "UI",
                running: true,
            })
            .await
            .expect("create");
        assert_eq!(db.interrupt_running_jobs().await.expect("interrupt"), 1);
        let r = db.job(&r.id).await.expect("q").expect("job");
        assert_eq!(r.error_code.as_deref(), Some("SCAN_FAILED"), "{kind:?}");
        assert_eq!(
            db.prune_jobs(now_ms() + 1).await.expect("prune"),
            2,
            "{kind:?}"
        );
        db.close().await;
    }
}
