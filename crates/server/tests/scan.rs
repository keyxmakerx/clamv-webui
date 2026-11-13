//! Upload and path scans end to end against a fake clamd.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use clamv_webui::app::{AppState, router};
use clamv_webui::config::Cli;
use clamv_webui::db::Db;
use clamv_webui::db::jobs::JobFilter;
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::ServiceExt;

const EICAR: &[u8] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const BOUNDARY: &str = "XtestBOUNDARYx";

/// PING, VERSION, INSTREAM (FOUND on EICAR) and MULTISCAN (a hit, an error and a limit hit).
async fn fake_clamd() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut cmd = Vec::new();
                let mut b = [0u8; 1];
                while s.read_exact(&mut b).await.is_ok() && b[0] != 0 {
                    cmd.push(b[0]);
                }
                let reply: Vec<u8> = match cmd.as_slice() {
                    b"zPING" => b"PONG\0".to_vec(),
                    b"zVERSION" => b"ClamAV 1.4.0/27000/Thu Nov 12 09:00:00 2026\0".to_vec(),
                    b"zINSTREAM" => {
                        let mut data = Vec::new();
                        loop {
                            let mut len = [0u8; 4];
                            if s.read_exact(&mut len).await.is_err() {
                                return;
                            }
                            let n = u32::from_be_bytes(len) as usize;
                            if n == 0 {
                                break;
                            }
                            let mut chunk = vec![0u8; n];
                            if s.read_exact(&mut chunk).await.is_err() {
                                return;
                            }
                            data.extend_from_slice(&chunk);
                        }
                        if data.windows(EICAR.len()).any(|w| w == EICAR) {
                            b"stream: Eicar-Test-Signature FOUND\0".to_vec()
                        } else {
                            b"stream: OK\0".to_vec()
                        }
                    }
                    c if c.starts_with(b"zMULTISCAN ") => {
                        let p = String::from_utf8_lossy(&c[11..]).into_owned();
                        format!(
                            "{p}/eicar.com: Eicar-Test-Signature FOUND\0{p}/locked: Can't open file or directory ERROR\0{p}/huge.iso: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0"
                        )
                        .into_bytes()
                    }
                    _ => b"UNKNOWN COMMAND\0".to_vec(),
                };
                let _ = s.write_all(&reply).await;
            });
        }
    });
    port
}

async fn app(extra: &[&str]) -> (Router, Arc<AppState>, String, String) {
    let port = fake_clamd().await;
    let ep = format!("tcp://127.0.0.1:{port}");
    let mut args = vec!["clamv-webui", "--clamd-endpoint", ep.as_str()];
    args.extend_from_slice(extra);
    let cli = Cli::parse_from(args);
    let db = Db::open("sqlite::memory:", 1).await.expect("db");
    let pw = clamv_webui::auth::token::random_secret();
    clamv_webui::auth::bootstrap::ensure_admin(&db, &std::env::temp_dir(), Some(&pw))
        .await
        .expect("bootstrap");
    clamv_webui::app::seed_endpoint(&db, &cli.config)
        .await
        .expect("seed");
    let st = Arc::new(AppState::new(cli.config.clone(), db));
    let admin = st
        .db
        .user_by_username("admin")
        .await
        .expect("q")
        .expect("admin");
    st.db
        .set_password(&admin.id, &admin.password_hash, false, false)
        .await
        .expect("clear");
    let (raw, s) = st
        .db
        .create_session(&admin.id, 3_600_000, None, None)
        .await
        .expect("session");
    (
        router(st.clone(), &cli.config),
        st,
        format!("clamv_session={raw}"),
        s.csrf_token,
    )
}

fn multipart(csrf: Option<&str>, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = Vec::new();
    if let Some(t) = csrf {
        b.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"_csrf\"\r\n\r\n{t}\r\n"
            )
            .as_bytes(),
        );
    }
    for (name, data) in files {
        b.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        b.extend_from_slice(data);
        b.extend_from_slice(b"\r\n");
    }
    b.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    b
}

fn upload(cookie: &str, body: Vec<u8>) -> Request<Body> {
    Request::post("/scan/upload")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .header(header::COOKIE, cookie)
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body))
        .expect("req")
}

#[tokio::test]
async fn uploads_stream_to_clamd() {
    let (app, st, c, t) = app(&[]).await;
    let res = app
        .clone()
        .oneshot(upload(
            &c,
            multipart(
                Some(&t),
                &[("eicar.com", EICAR), ("../notes.txt", b"hello")],
            ),
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let (jobs, total) = st
        .db
        .list_jobs(&JobFilter::default(), 0, 10)
        .await
        .expect("list");
    assert_eq!(total, 2);
    let bad = jobs
        .iter()
        .find(|j| j.target == "eicar.com")
        .expect("eicar job");
    assert_eq!(bad.verdict.as_deref(), Some("VIRUS_FOUND"));
    assert_eq!(bad.signatures(), vec!["Eicar-Test-Signature".to_owned()]);
    assert_eq!(bad.size_bytes, Some(EICAR.len() as i64));
    assert_eq!(bad.sha256.as_deref().map(str::len), Some(64));
    let ok = jobs
        .iter()
        .find(|j| j.target == "notes.txt")
        .expect("basename only");
    assert_eq!(ok.verdict.as_deref(), Some("OK"));
}

#[tokio::test]
async fn upload_needs_csrf_first() {
    let (app, st, c, _) = app(&[]).await;
    let res = app
        .clone()
        .oneshot(upload(&c, multipart(None, &[("eicar.com", EICAR)])))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let (_, total) = st
        .db
        .list_jobs(&JobFilter::default(), 0, 10)
        .await
        .expect("list");
    assert_eq!(total, 0, "nothing scanned for a forged request");
}

#[tokio::test]
async fn oversized_upload_is_a_limit_error() {
    let (app, st, c, t) = app(&["--clamd-max-stream-mb", "1"]).await;
    let big = vec![b'a'; 1024 * 1024 + 10];
    let res = app
        .clone()
        .oneshot(upload(&c, multipart(Some(&t), &[("big.bin", &big)])))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let (jobs, _) = st
        .db
        .list_jobs(&JobFilter::default(), 0, 10)
        .await
        .expect("list");
    assert_eq!(jobs[0].verdict.as_deref(), Some("ERROR"));
    assert_eq!(jobs[0].error_code.as_deref(), Some("LIMIT_EXCEEDED"));
}

#[tokio::test]
async fn path_scans_keep_every_result() {
    let base = std::env::temp_dir().join(format!("clamv-scan-{}", clamv_webui::db::new_id()));
    let root = base.join("media");
    std::fs::create_dir_all(root.join("tv")).expect("mkdir");
    let roots = root.to_str().expect("utf8").to_owned();
    let (app, st, c, t) = app(&["--scan-roots", &roots]).await;
    clamv_webui::scan::start(st.clone()).await;

    let outside = format!("_csrf={t}&path={}", base.display());
    let res = app
        .clone()
        .oneshot(form("/scan/path", &outside, &c))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let inside = format!("_csrf={t}&path={}/tv", root.display());
    let res = app
        .clone()
        .oneshot(form("/scan/path", &inside, &c))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let loc = res.headers()[header::LOCATION]
        .to_str()
        .expect("loc")
        .to_owned();
    let id = loc.trim_start_matches("/jobs/");
    let mut job = None;
    for _ in 0..50 {
        let j = st.db.job(id).await.expect("q").expect("job");
        if j.status == "FINISHED" {
            job = Some(j);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let job = job.expect("job finished");
    assert_eq!(job.verdict.as_deref(), Some("VIRUS_FOUND"));
    assert_eq!(job.detections.len(), 1);
    assert_eq!(job.errors.len(), 2, "error and limit hit kept (N3)");
    let res = app
        .clone()
        .oneshot(
            Request::get(&loc)
                .header(header::COOKIE, &c)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let _ = std::fs::remove_dir_all(&base);
}

fn form(uri: &str, body: &str, cookie: &str) -> Request<Body> {
    Request::post(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body.to_owned()))
        .expect("req")
}

async fn wait_finished(st: &AppState, id: &str) -> clamv_webui::db::jobs::Job {
    for _ in 0..50 {
        let j = st.db.job(id).await.expect("q").expect("job");
        if j.status == "FINISHED" {
            return j;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("job {id} did not finish");
}

#[tokio::test]
async fn schedules_run_with_eicar_control() {
    let base = std::env::temp_dir().join(format!("clamv-sched-{}", clamv_webui::db::new_id()));
    let root = base.join("media");
    std::fs::create_dir_all(root.join("movies")).expect("mkdir");
    let roots = root.to_str().expect("utf8").to_owned();
    let (app, st, c, t) = app(&["--scan-roots", &roots]).await;
    clamv_webui::scan::start(st.clone()).await;
    let bad = format!(
        "_csrf={t}&name=n&cron=99+*+*+*+*&paths={}/movies&eicar=1",
        root.display()
    );
    let res = app
        .clone()
        .oneshot(form("/admin/schedules", &bad, &c))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "bad cron");
    let outside = format!("_csrf={t}&name=n&cron=%40daily&paths=/etc&eicar=1");
    let res = app
        .clone()
        .oneshot(form("/admin/schedules", &outside, &c))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "path outside roots");
    let good = format!(
        "_csrf={t}&name=nightly&cron=30+2+*+*+*&paths={}/movies&eicar=1",
        root.display()
    );
    let res = app
        .clone()
        .oneshot(form("/admin/schedules", &good, &c))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let sch = st.db.list_schedules().await.expect("list").remove(0);
    assert!(sch.eicar_check);
    let res = app
        .clone()
        .oneshot(form(
            &format!("/admin/schedules/{}/run", sch.id),
            &format!("_csrf={t}"),
            &c,
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let control = st
        .db
        .last_control_job(&sch.id)
        .await
        .expect("q")
        .expect("control job");
    assert_eq!(
        control.verdict.as_deref(),
        Some("OK"),
        "fake clamd flags EICAR"
    );
    let sch = st.db.schedule(&sch.id).await.expect("q").expect("s");
    let job = wait_finished(&st, sch.last_job_id.as_deref().expect("job")).await;
    assert_eq!(job.schedule_id.as_deref(), Some(sch.id.as_str()));
    assert_eq!(job.verdict.as_deref(), Some("VIRUS_FOUND"));
    let page = app
        .clone()
        .oneshot(
            Request::get("/admin/schedules")
                .header(header::COOKIE, &c)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("res");
    let html = String::from_utf8_lossy(
        &http_body_util::BodyExt::collect(page.into_body())
            .await
            .expect("b")
            .to_bytes(),
    )
    .into_owned();
    assert!(html.contains("passed") && html.contains("nightly"));
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test]
async fn eicar_control_failure_is_recorded() {
    let base = std::env::temp_dir().join(format!("clamv-ctl-{}", clamv_webui::db::new_id()));
    std::fs::create_dir_all(&base).expect("mkdir");
    let roots = base.to_str().expect("utf8").to_owned();
    let (_app, st, _c, _t) = app(&["--scan-roots", &roots]).await;
    // Point the default endpoint at a closed port.
    let dead = st
        .db
        .create_endpoint("dead", "tcp://127.0.0.1:1", true)
        .await
        .expect("ep");
    let sch = st
        .db
        .create_schedule(clamv_webui::db::schedules::NewSchedule {
            name: "s",
            cron: "@daily",
            paths: std::slice::from_ref(&roots),
            endpoint_id: Some(dead.id),
            eicar_check: true,
        })
        .await
        .expect("schedule");
    let ok = clamv_webui::schedule::control(&st, &sch, &dead).await;
    assert!(!ok);
    let j = st
        .db
        .last_control_job(&sch.id)
        .await
        .expect("q")
        .expect("job");
    assert_eq!(j.verdict.as_deref(), Some("ERROR"));
    assert_eq!(j.error_code.as_deref(), Some("SCAN_FAILED"));
    let _ = std::fs::remove_dir_all(&base);
}
