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
                agent_id: None,
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
                agent_id: None,
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
            db.prune_jobs(now_ms() + 1, i64::MIN).await.expect("prune"),
            1,
            "{kind:?}: the detection is kept longer"
        );
        assert_eq!(
            db.prune_jobs(now_ms() + 1, now_ms() + 1)
                .await
                .expect("prune"),
            1,
            "{kind:?}"
        );
        db.close().await;
    }
}

#[tokio::test]
async fn tokens_and_audit_pages() {
    use clamv_webui::db::audit::AuditEntry;
    use clamv_webui::db::tokens::NewToken;
    for db in databases().await {
        let kind = db.kind();
        let scopes = vec!["jobs:read".to_owned(), "bogus".to_owned()];
        let (secret, t) = db
            .create_token(NewToken {
                label: "ci",
                scopes: &scopes,
                endpoint_ids: Some(&[7, 8]),
                path_roots: Some(&["/data/tv".to_owned()]),
                created_by: "admin",
                expires_at: None,
            })
            .await
            .expect("create");
        assert_eq!(
            t.scopes,
            vec!["jobs:read".to_owned()],
            "{kind:?}: unknown scope dropped"
        );
        assert_eq!(t.endpoint_ids, Some(vec![7, 8]));
        let found = db
            .token_by_secret(&secret)
            .await
            .expect("q")
            .expect("found");
        assert_eq!(found.id, t.id, "{kind:?}");
        assert!(db.token_by_secret("cvw_nope").await.expect("q").is_none());
        assert!(db.revoke_token(t.id).await.expect("revoke"));
        assert!(!db.revoke_token(t.id).await.expect("revoke twice"));
        assert!(
            db.token_by_secret(&secret).await.expect("q").is_none(),
            "{kind:?}"
        );
        for _ in 0..3 {
            db.audit(AuditEntry {
                action: "TEST",
                outcome: "OK",
                endpoint_id: Some(1),
                ..Default::default()
            })
            .await;
        }
        let (rows, total) = db.audit_page(0, 2).await.expect("page");
        assert_eq!(rows.len(), 2, "{kind:?}");
        assert!(total >= 3);
        assert!(rows[0].id > rows[1].id, "{kind:?}: newest first");
        db.close().await;
    }
}

#[tokio::test]
async fn schedules_claim_once() {
    use clamv_webui::db::schedules::NewSchedule;
    for db in databases().await {
        let kind = db.kind();
        let name = format!("s-{}", &new_id()[..8]);
        let s = db
            .create_schedule(NewSchedule {
                name: &name,
                cron: "@daily",
                paths: &["/data/ü".to_owned()],
                endpoint_id: None,
                agent_id: None,
                eicar_check: true,
            })
            .await
            .expect("create");
        assert_eq!(s.paths, vec!["/data/ü".to_owned()], "{kind:?}");
        assert!(
            db.claim_schedule_run(&s.id, None, 10).await.expect("claim"),
            "{kind:?}"
        );
        assert!(
            !db.claim_schedule_run(&s.id, None, 11).await.expect("claim"),
            "{kind:?}: twice"
        );
        assert!(
            db.claim_schedule_run(&s.id, Some(10), 20)
                .await
                .expect("claim")
        );
        assert_eq!(db.schedule_active_jobs(&s.id).await.expect("active"), 0);
        db.set_schedule_enabled(&s.id, false).await.expect("pause");
        assert!(!db.schedule(&s.id).await.expect("q").expect("s").enabled);
        assert!(db.delete_schedule(&s.id).await.expect("delete"));
        db.close().await;
    }
}

#[tokio::test]
async fn identities_link_and_cascade() {
    use clamv_webui::auth::Role;
    for db in databases().await {
        let kind = db.kind();
        let name = format!("sso:t-{}", &new_id()[..8]);
        let u = db
            .create_user(
                &name,
                clamv_webui::db::users::NO_PASSWORD,
                Role::Viewer,
                false,
            )
            .await
            .expect("user");
        let principal = format!("oidc:{}", &new_id().replace('-', "")[..24]);
        assert_eq!(
            db.identity_user(&principal).await.expect("q"),
            None,
            "{kind:?}"
        );
        db.link_identity(&principal, &u.id, "OIDC", "https://idp", "sub-1")
            .await
            .expect("link");
        assert_eq!(
            db.identity_user(&principal).await.expect("q"),
            Some(u.id.clone())
        );
        assert!(db.is_external_user(&u.id).await.expect("q"));
        assert!(db.delete_user(&u.id).await.expect("delete"));
        assert_eq!(
            db.identity_user(&principal).await.expect("q"),
            None,
            "{kind:?} cascade"
        );
    }
}

#[tokio::test]
async fn processed_files_are_forgotten_by_folder() {
    for db in databases().await {
        let kind = db.kind();
        let root = format!("/w/{}_a%b!", &new_id()[..8]);
        let inside = format!("{root}/x.bin");
        let deep = format!("{root}/sub/y.bin");
        let sibling = format!("{root}x/z.bin");
        let lookalike = format!("{}/q.bin", root.replace('_', "Z"));
        for p in [&inside, &deep, &sibling, &lookalike] {
            db.record_processed(p, 1, 2, "OK").await.expect("record");
        }
        assert_eq!(
            db.forget_processed_under(&root).await.expect("forget"),
            2,
            "{kind:?}"
        );
        assert!(db.processed(&inside).await.expect("q").is_none());
        assert!(
            db.processed(&sibling).await.expect("q").is_some(),
            "{kind:?} sibling kept"
        );
        assert!(
            db.processed(&lookalike).await.expect("q").is_some(),
            "{kind:?} _ is literal"
        );
        let _ = db.forget_processed_under(&format!("{root}x")).await;
        let _ = db.forget_processed_under(&root.replace('_', "Z")).await;
    }
}

#[tokio::test]
async fn agents_claim_heartbeat_and_delete() {
    use clamv_webui::db::agents::Heartbeat;
    use clamv_webui::db::jobs::{NewJob, Outcome};
    for db in databases().await {
        let kind = db.kind();
        let name = format!("ag-{}", &new_id()[..8]);
        let (a, secret) = db.create_agent(&name, "admin").await.expect("create");
        assert!(
            db.create_agent(&name, "admin").await.is_err(),
            "{kind:?}: unique name"
        );
        assert_eq!(
            db.agent_by_secret(&secret).await.expect("q").map(|x| x.id),
            Some(a.id),
            "{kind:?}"
        );
        assert!(
            db.agent_by_secret("clamv_agent_x")
                .await
                .expect("q")
                .is_none()
        );
        db.heartbeat_agent(
            a.id,
            &Heartbeat {
                ip: "100.82.0.9",
                version: "1.0",
                clamd_version: Some("ClamAV 1.4"),
                roots: &["/data/ü".to_owned()],
                slots: 2,
            },
        )
        .await
        .expect("hb");
        assert!(db.set_agent_online(a.id, true).await.expect("on"));
        assert!(
            !db.set_agent_online(a.id, true).await.expect("on"),
            "{kind:?}: once"
        );
        let got = db.agent(a.id).await.expect("q").expect("a");
        assert_eq!(got.roots, vec!["/data/ü".to_owned()], "{kind:?}");
        assert_eq!((got.slots, got.online), (2, true));

        let mk = |t: &'static str| NewJob {
            kind: "PATH",
            target: t,
            endpoint_id: None,
            schedule_id: None,
            agent_id: Some(a.id),
            submitted_by: None,
            transport: "UI",
            running: false,
        };
        let j1 = db.create_job(mk("/data/1")).await.expect("j1");
        let j2 = db.create_job(mk("/data/2")).await.expect("j2");
        assert!(
            !db.queued_jobs(1000).await.expect("q").contains(&j1.id),
            "{kind:?}: local dispatcher skips agent jobs"
        );
        let claimed = db.claim_agent_jobs(a.id, 1).await.expect("claim");
        assert_eq!(claimed.len(), 1, "{kind:?}");
        let o = Outcome {
            verdict: "OK",
            ..Outcome::default()
        };
        assert!(
            db.finish_job_if(&claimed[0].id, "RUNNING", &o)
                .await
                .expect("fin")
        );
        assert!(
            !db.finish_job_if(&claimed[0].id, "RUNNING", &o)
                .await
                .expect("fin"),
            "{kind:?}: once"
        );
        let rotated = db
            .rotate_agent_secret(a.id)
            .await
            .expect("rot")
            .expect("some");
        assert!(
            db.agent_by_secret(&secret).await.expect("q").is_none(),
            "{kind:?}"
        );
        assert!(db.agent_by_secret(&rotated).await.expect("q").is_some());
        assert!(db.delete_agent(a.id).await.expect("del"));
        let left = if claimed[0].id == j1.id { &j2 } else { &j1 };
        let j = db.job(&left.id).await.expect("q").expect("j");
        assert_eq!(j.status, "FINISHED", "{kind:?}: removed agent's jobs fail");
        db.close().await;
    }
}

#[tokio::test]
async fn second_factors_everywhere() {
    use clamv_webui::auth::Role;
    for db in databases().await {
        let kind = db.kind();
        let name = format!("mfa-{}", &new_id()[..8]);
        let u = db
            .create_user(&name, "x", Role::Viewer, false)
            .await
            .expect("user");
        assert_eq!(
            db.mfa_methods(&u.id).await.expect("q"),
            (false, 0),
            "{kind:?}"
        );
        let hashes = vec!["a".repeat(64), "b".repeat(64)];
        db.enable_totp(&u.id, "v1:sealed", 100, &hashes)
            .await
            .expect("enable");
        assert_eq!(db.mfa_methods(&u.id).await.expect("q"), (true, 0));
        assert!(
            !db.use_totp_step(&u.id, 100).await.expect("q"),
            "{kind:?} no replay"
        );
        assert!(db.use_totp_step(&u.id, 101).await.expect("q"));
        assert!(db.use_recovery_code(&u.id, &hashes[0]).await.expect("q"));
        assert!(
            !db.use_recovery_code(&u.id, &hashes[0]).await.expect("q"),
            "{kind:?} once"
        );
        assert_eq!(db.recovery_codes_left(&u.id).await.expect("q"), 1);

        let raw = db.create_mfa_pending(&u.id, "UI").await.expect("pending");
        let p = db.mfa_pending(&raw).await.expect("q").expect("found");
        for _ in 0..clamv_webui::db::mfa::PENDING_MAX_ATTEMPTS {
            assert!(db.count_mfa_attempt(&p.id_hash).await.expect("q"));
        }
        assert!(
            !db.count_mfa_attempt(&p.id_hash).await.expect("q"),
            "{kind:?} capped"
        );

        db.add_passkey(&u.id, "cred-1", "Laptop", "key", 0)
            .await
            .expect("add");
        assert!(
            db.add_passkey(&u.id, "cred-1", "Dup", "key", 0)
                .await
                .is_err(),
            "{kind:?} unique"
        );
        let k = db.passkey_by_cred("cred-1").await.expect("q").expect("k");
        assert!(
            db.use_passkey(&k.id, 0, 0).await.expect("q"),
            "zero counters allowed"
        );
        assert!(db.use_passkey(&k.id, 0, 5).await.expect("q"));
        assert!(
            !db.use_passkey(&k.id, 5, 5).await.expect("q"),
            "{kind:?} counter must grow"
        );
        let (h, c) = db.create_challenge("login", None).await.expect("ch");
        let got = db.take_challenge(&h).await.expect("q").expect("once");
        assert_eq!(got.challenge, c);
        assert!(
            db.take_challenge(&h).await.expect("q").is_none(),
            "{kind:?} single use"
        );

        db.clear_mfa(&u.id).await.expect("clear");
        assert_eq!(
            db.mfa_methods(&u.id).await.expect("q"),
            (false, 0),
            "{kind:?}"
        );
        assert!(db.delete_user(&u.id).await.expect("delete"));
    }
}

#[tokio::test]
async fn dashboard_and_detection_queries_everywhere() {
    use clamv_webui::db::jobs::{JobFilter, NewJob, Outcome};
    use clamv_webui::db::stats::DetectionFilter;
    for db in databases().await {
        let kind = db.kind();
        let tag = new_id()[..8].to_owned();
        let target = format!("/data/{tag}/x 100%_done");
        let j = db
            .create_job(NewJob {
                kind: "WATCH",
                target: &target,
                endpoint_id: None,
                schedule_id: None,
                agent_id: None,
                submitted_by: Some("watcher"),
                transport: "WATCH",
                running: true,
            })
            .await
            .expect("create");
        let mut det = std::collections::BTreeMap::new();
        det.insert(
            target.clone(),
            vec![format!("Sig-{tag}"), format!("Other-{tag}")],
        );
        let o = Outcome {
            verdict: "VIRUS_FOUND",
            files_scanned: 7,
            detections: det,
            errors: Vec::new(),
            error_code: None,
            error_message: None,
            sha256: None,
            size_bytes: None,
        };
        assert!(
            db.finish_job_if(&j.id, "RUNNING", &o)
                .await
                .expect("finish")
        );
        let since = now_ms() - 60_000;
        let f = DetectionFilter {
            text: Some(tag.clone()),
            ..Default::default()
        };
        assert_eq!(db.count_detections(&f).await.expect("count"), 2, "{kind:?}");
        let sigs = db.detection_signatures(&f, 10).await.expect("sigs");
        assert_eq!(sigs.len(), 2, "{kind:?}");
        assert_eq!(
            db.detection_kinds(&f).await.expect("kinds"),
            vec![("WATCH".to_owned(), 2)]
        );
        assert_eq!(
            db.detection_sources(&f).await.expect("src"),
            vec![(None, None, 2)]
        );
        assert_eq!(db.detection_paths(&f, 10).await.expect("paths").len(), 2);
        let exact = DetectionFilter {
            signature: Some(format!("Sig-{tag}")),
            ..Default::default()
        };
        assert_eq!(
            db.list_detections(&exact, 0, 10).await.expect("list").len(),
            1,
            "{kind:?}"
        );
        // LIKE wildcards are literal.
        let pct = DetectionFilter {
            path_text: Some("100%_done".into()),
            text: Some(tag.clone()),
            ..Default::default()
        };
        assert_eq!(
            db.count_detections(&pct).await.expect("count"),
            2,
            "{kind:?} literal %"
        );
        let none = DetectionFilter {
            path_text: Some("100%Xdone".into()),
            text: Some(tag.clone()),
            ..Default::default()
        };
        assert_eq!(
            db.count_detections(&none).await.expect("count"),
            0,
            "{kind:?} % is not a wildcard"
        );
        let pre = DetectionFilter {
            path_prefix: Some(format!("/data/{tag}/")),
            ..Default::default()
        };
        assert_eq!(db.count_detections(&pre).await.expect("count"), 2);
        let b = db
            .activity(since, 3_600_000, -6 * 3_600_000)
            .await
            .expect("activity");
        assert!(b.iter().map(|x| x.detections).sum::<i64>() >= 1, "{kind:?}");
        assert!(
            db.files_scanned_since(since).await.expect("sum") >= 7,
            "{kind:?}"
        );
        assert!(
            db.kinds_since(since)
                .await
                .expect("kinds")
                .iter()
                .any(|(k, _)| k == "WATCH")
        );
        let jf = JobFilter {
            text: Some(tag.clone()),
            kind: Some("WATCH".into()),
            since: Some(since),
            ..Default::default()
        };
        assert_eq!(
            db.list_jobs(&jf, 0, 10).await.expect("jobs").1,
            1,
            "{kind:?}"
        );
        let nf = JobFilter {
            text: Some(tag.clone()),
            not_text: Some("watcher".into()),
            ..Default::default()
        };
        assert_eq!(
            db.list_jobs(&nf, 0, 10).await.expect("jobs").1,
            0,
            "{kind:?} negation"
        );
    }
}

#[tokio::test]
async fn canaries_everywhere() {
    for db in databases().await {
        let kind = db.kind();
        let (agent, _) = db
            .create_agent(&format!("can-{}", &new_id()[..8]), "admin")
            .await
            .expect("agent");
        let p = format!("/srv/{}/keys.txt", &new_id()[..8]);
        let central = db.add_canary(None, &p, true, "admin").await.expect("add");
        db.add_canary(Some(agent.id), &p, false, "admin")
            .await
            .expect("add");
        db.set_canary_armed(Some(agent.id), &p, true)
            .await
            .expect("arm");
        db.canary_tripped(None, &p).await.expect("trip");
        let mine = db.host_canaries(None).await.expect("q");
        let c = mine.iter().find(|c| c.path == p).expect("central");
        assert!(
            c.create_file && c.armed.is_none() && c.last_tripped_at.is_some(),
            "{kind:?}"
        );
        let theirs = db.host_canaries(Some(agent.id)).await.expect("q");
        assert_eq!(theirs.len(), 1, "{kind:?}");
        assert_eq!(theirs[0].armed, Some(true));
        assert!(theirs[0].last_tripped_at.is_none());
        assert!(db.delete_canary(&central).await.expect("del"));
        assert!(db.delete_agent(agent.id).await.expect("del agent"));
        assert!(
            db.host_canaries(Some(agent.id))
                .await
                .expect("q")
                .is_empty(),
            "{kind:?} cascade"
        );
        db.host_activity(0).await.expect("activity query");
        db.recent_controls(0).await.expect("controls query");
    }
}
