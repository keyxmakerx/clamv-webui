//! Upload and path scans end to end against a fake clamd.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use clap::Parser;
use palisade::app::{AppState, router};
use palisade::config::Cli;
use palisade::db::Db;
use palisade::db::jobs::JobFilter;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::ServiceExt;

mod common;
use common::{EICAR, fake_clamd, silent_clamd};
const BOUNDARY: &str = "XtestBOUNDARYx";

async fn app(extra: &[&str]) -> (Router, Arc<AppState>, String, String) {
    app_on(fake_clamd().await, extra).await
}

async fn app_on(port: u16, extra: &[&str]) -> (Router, Arc<AppState>, String, String) {
    let ep = format!("tcp://127.0.0.1:{port}");
    let mut args = vec!["palisade", "--clamd-endpoint", ep.as_str()];
    args.extend_from_slice(extra);
    let cli = Cli::parse_from(args);
    let db = Db::open("sqlite::memory:", 1).await.expect("db");
    let pw = palisade::auth::token::random_secret();
    palisade::auth::bootstrap::ensure_admin(&db, &std::env::temp_dir(), Some(&pw))
        .await
        .expect("bootstrap");
    palisade::app::seed_endpoint(&db, &cli.config)
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
        format!("palisade_session={raw}"),
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
    let base = std::env::temp_dir().join(format!("palisade-scan-{}", palisade::db::new_id()));
    let root = base.join("media");
    std::fs::create_dir_all(root.join("tv")).expect("mkdir");
    let roots = root.to_str().expect("utf8").to_owned();
    let (app, st, c, t) = app(&["--scan-roots", &roots]).await;
    palisade::scan::start(st.clone()).await;

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

#[tokio::test]
async fn dropped_upload_does_not_stay_running() {
    let (app, st, c, t) = app_on(silent_clamd().await, &[]).await;
    let req = upload(&c, multipart(Some(&t), &[("slow.bin", b"hello")]));
    let task = tokio::spawn(async move { app.oneshot(req).await });
    let mut id = None;
    for _ in 0..50 {
        let (jobs, _) = st
            .db
            .list_jobs(&JobFilter::default(), 0, 10)
            .await
            .expect("list");
        if let Some(j) = jobs.first() {
            id = Some(j.id.clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let id = id.expect("job created");
    // The browser goes away while clamd is still scanning.
    task.abort();
    let job = wait_finished(&st, &id).await;
    assert_eq!(job.verdict.as_deref(), Some("ERROR"));
    assert_eq!(
        job.error_message.as_deref(),
        Some("The upload was interrupted.")
    );
}

#[tokio::test]
async fn huge_results_are_capped_when_stored() {
    let base = std::env::temp_dir().join(format!("palisade-many-{}", palisade::db::new_id()));
    let root = base.join("media");
    std::fs::create_dir_all(root.join("many")).expect("mkdir");
    let roots = root.to_str().expect("utf8").to_owned();
    let (app, st, c, t) = app(&["--scan-roots", &roots]).await;
    palisade::scan::start(st.clone()).await;
    let res = app
        .clone()
        .oneshot(form(
            "/scan/path",
            &format!("_csrf={t}&path={}/many", root.display()),
            &c,
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let loc = res.headers()[header::LOCATION].to_str().expect("loc");
    let job = wait_finished(&st, loc.trim_start_matches("/jobs/")).await;
    assert_eq!(job.verdict.as_deref(), Some("VIRUS_FOUND"));
    assert_eq!(job.detections.len(), palisade::db::jobs::MAX_STORED_LINES);
    assert_eq!(job.results_omitted, 500);
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test]
async fn quarantine_leftovers_are_settled_at_start() {
    use palisade::db::quarantine as q;
    let base = std::env::temp_dir().join(format!("palisade-qs-{}", palisade::db::new_id()));
    let (root, qdir) = (base.join("root"), base.join("q"));
    std::fs::create_dir_all(&root).expect("root");
    std::fs::create_dir_all(&qdir).expect("q");
    let (_app, st, _c, _t) = app(&[
        "--scan-roots",
        root.to_str().expect("utf8"),
        "--quarantine-dir",
        qdir.to_str().expect("utf8"),
    ])
    .await;
    // Finished before the restart: copy held, original gone.
    let done = root.join("done.exe");
    let a = st
        .db
        .create_quarantine(None, done.to_str().expect("utf8"), "Eicar", "admin")
        .await
        .expect("q")
        .expect("item");
    std::fs::write(qdir.join(format!("{}.quarantined", a.id)), b"X5O").expect("held");
    // Cut off mid-copy: original still there, partial copy present.
    let half = root.join("half.exe");
    std::fs::write(&half, b"X5O!P").expect("orig");
    let b = st
        .db
        .create_quarantine(None, half.to_str().expect("utf8"), "Eicar", "admin")
        .await
        .expect("q")
        .expect("item");
    std::fs::write(qdir.join(format!("{}.quarantined", b.id)), b"X5").expect("partial");

    palisade::quarantine::settle(&st, true).await;
    let a = st.db.quarantine_item(&a.id).await.expect("q").expect("a");
    assert_eq!(a.state, q::HELD);
    assert_eq!(a.size_bytes, Some(3));
    let b2 = st.db.quarantine_item(&b.id).await.expect("q").expect("b");
    assert_eq!(b2.state, q::FAILED);
    assert!(!qdir.join(format!("{}.quarantined", b.id)).exists());
    assert!(half.exists(), "original left in place");
    // The file can be tried again.
    assert!(
        st.db
            .create_quarantine(None, half.to_str().expect("utf8"), "Eicar", "admin")
            .await
            .expect("q")
            .is_some()
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test]
async fn lost_agent_quarantine_jobs_release_the_entry() {
    use palisade::db::jobs::NewJob;
    use palisade::db::quarantine as q;
    let (_app, st, _c, _t) = app(&[]).await;
    let (agent, _) = st.db.create_agent("nas", "admin").await.expect("agent");
    let item = st
        .db
        .create_quarantine(Some(agent.id), "/data/x.exe", "Eicar", "admin")
        .await
        .expect("q")
        .expect("item");
    let job = st
        .db
        .create_job(NewJob {
            kind: "QUARANTINE",
            target: "{}",
            endpoint_id: None,
            schedule_id: None,
            agent_id: Some(agent.id),
            submitted_by: Some("admin"),
            transport: "UI",
            running: true,
        })
        .await
        .expect("job");
    st.db
        .set_quarantine_job(&item.id, &job.id)
        .await
        .expect("link");
    // Still running on the agent: left alone.
    palisade::quarantine::settle(&st, false).await;
    let i = st
        .db
        .quarantine_item(&item.id)
        .await
        .expect("q")
        .expect("i");
    assert_eq!(i.state, q::PENDING);
    // The server gives up on the job (agent lost) without a result.
    let o = palisade::scan::failure(palisade::scan::SCAN_FAILED, "lost");
    st.db.finish_job(&job.id, &o).await.expect("finish");
    palisade::quarantine::settle(&st, false).await;
    let i = st
        .db
        .quarantine_item(&item.id)
        .await
        .expect("q")
        .expect("i");
    assert_eq!(i.state, q::FAILED);
}

fn form(uri: &str, body: &str, cookie: &str) -> Request<Body> {
    Request::post(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body.to_owned()))
        .expect("req")
}

/// Send a form and load the page its 303 points to, as a browser does (u03).
async fn send(
    app: Router,
    req: Request<Body>,
) -> Result<axum::response::Response, std::convert::Infallible> {
    let cookie = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_default();
    let res = app.clone().oneshot(req).await?;
    if res.status() != StatusCode::SEE_OTHER {
        return Ok(res);
    }
    let to = res.headers()[header::LOCATION]
        .to_str()
        .expect("location")
        .to_owned();
    if to.starts_with("/login") || to.starts_with("/jobs/") {
        return Ok(res);
    }
    app.oneshot(page_get(&to, &cookie)).await
}

async fn wait_finished(st: &AppState, id: &str) -> palisade::db::jobs::Job {
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
    let base = std::env::temp_dir().join(format!("palisade-sched-{}", palisade::db::new_id()));
    let root = base.join("media");
    std::fs::create_dir_all(root.join("movies")).expect("mkdir");
    let roots = root.to_str().expect("utf8").to_owned();
    let (app, st, c, t) = app(&["--scan-roots", &roots]).await;
    palisade::scan::start(st.clone()).await;
    let bad = format!(
        "_csrf={t}&name=n&cron=99+*+*+*+*&paths={}/movies&eicar=1",
        root.display()
    );
    let res = send(app.clone(), form("/admin/schedules", &bad, &c))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "bad cron");
    let outside = format!("_csrf={t}&name=n&cron=%40daily&paths=/etc&eicar=1");
    let res = send(app.clone(), form("/admin/schedules", &outside, &c))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "path outside roots");
    let good = format!(
        "_csrf={t}&name=nightly&cron=30+2+*+*+*&paths={}/movies&eicar=1",
        root.display()
    );
    let res = send(app.clone(), form("/admin/schedules", &good, &c))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let sch = st.db.list_schedules().await.expect("list").remove(0);
    assert!(sch.eicar_check);
    let res = send(
        app.clone(),
        form(
            &format!("/admin/schedules/{}/run", sch.id),
            &format!("_csrf={t}"),
            &c,
        ),
    )
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
    let base = std::env::temp_dir().join(format!("palisade-ctl-{}", palisade::db::new_id()));
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
        .create_schedule(palisade::db::schedules::NewSchedule {
            name: "s",
            cron: "@daily",
            paths: std::slice::from_ref(&roots),
            endpoint_id: Some(dead.id),
            agent_id: None,
            eicar_check: true,
            exclusions: &[],
            window: None,
            time_zone: None,
        })
        .await
        .expect("schedule");
    let ok = palisade::schedule::control(&st, &sch, &dead).await;
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

#[tokio::test]
async fn schedules_take_zone_window_and_exclusions() {
    let base = std::env::temp_dir().join(format!("palisade-sx-{}", palisade::db::new_id()));
    let media = base.join("media");
    for d in ["tv/Downloads/x", "tv/Shows", "movies"] {
        std::fs::create_dir_all(media.join(d)).expect("mkdir");
    }
    std::fs::write(media.join("tv/notes.txt"), b"n").expect("file");
    let media = std::fs::canonicalize(&media).expect("real");
    let roots = media.to_str().expect("utf8").to_owned();
    let (app, st, c, t) = app(&["--scan-roots", &roots]).await;
    let enc = |v: &str| {
        v.replace('/', "%2F")
            .replace(' ', "+")
            .replace('\n', "%0A")
            .replace(':', "%3A")
    };
    let fields = |extra: &str| {
        format!(
            "_csrf={t}&name=Night&cron={}&paths={}&exclusions={}&time_zone=Europe%2FBerlin&window_start=22%3A00&window_end=06%3A00{extra}",
            enc("30 23 * * *"),
            enc(&roots),
            enc(&format!("{roots}/tv/Downloads")),
        )
    };
    // Preview: next runs in Berlin, nothing saved.
    let res = app
        .clone()
        .oneshot(form("/admin/schedules", &fields("&preview=1"), &c))
        .await
        .expect("res");
    let html = body(res).await;
    assert!(html.contains("Next runs"), "preview shown");
    assert!(html.contains(" 23:30</li>"));
    assert!(st.db.list_schedules().await.expect("q").is_empty());
    // A window that never meets the cron is refused.
    let never = fields("")
        .replace("window_start=22%3A00", "window_start=01%3A00")
        .replace("window_end=06%3A00", "window_end=02%3A00");
    let res = app
        .clone()
        .oneshot(form("/admin/schedules", &never, &c))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // Saved.
    let res = app
        .clone()
        .oneshot(form("/admin/schedules", &fields(""), &c))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let s = st.db.list_schedules().await.expect("q").remove(0);
    assert_eq!(s.time_zone.as_deref(), Some("Europe/Berlin"));
    assert_eq!(s.window, Some((22 * 60, 6 * 60)));
    // A run scans around the exclusion: movies, tv/Shows and tv/notes.txt, not tv/Downloads.
    let n = palisade::schedule::run(&st, &s, "manual")
        .await
        .expect("run");
    let (jobs, _) = st
        .db
        .list_jobs(&JobFilter::default(), 0, 50)
        .await
        .expect("list");
    let mut targets: Vec<String> = jobs
        .iter()
        .filter(|j| j.kind == "PATH")
        .map(|j| j.target.trim_start_matches(&roots).to_owned())
        .collect();
    targets.sort();
    assert_eq!(targets, ["/movies", "/tv/Shows", "/tv/notes.txt"]);
    assert_eq!(n, 3);
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test]
async fn closed_windows_drop_queued_paths() {
    let base = std::env::temp_dir().join(format!("palisade-sw-{}", palisade::db::new_id()));
    std::fs::create_dir_all(&base).expect("mkdir");
    let roots = base.to_str().expect("utf8").to_owned();
    let (_app, st, _c, _t) = app(&["--scan-roots", &roots]).await;
    let now_min = (palisade::db::now_ms() / 60_000).rem_euclid(1440);
    // A window that closed a minute ago (UTC), opened two hours before.
    let window = Some(((now_min + 1440 - 120) % 1440, (now_min + 1440 - 1) % 1440));
    let s = st
        .db
        .create_schedule(palisade::db::schedules::NewSchedule {
            name: "w",
            cron: "0 0 1 1 *",
            paths: std::slice::from_ref(&roots),
            endpoint_id: None,
            agent_id: None,
            eicar_check: false,
            exclusions: &[],
            window,
            time_zone: Some("UTC"),
        })
        .await
        .expect("schedule");
    let job = st
        .db
        .create_job(palisade::db::jobs::NewJob {
            kind: "PATH",
            target: &roots,
            endpoint_id: None,
            schedule_id: Some(&s.id),
            agent_id: None,
            submitted_by: Some("schedule:w"),
            transport: "SCHEDULER",
            running: false,
        })
        .await
        .expect("job");
    // Queued inside the window.
    sqlx::query(
        st.db
            .sql("UPDATE scan_jobs SET submitted_at = ? WHERE id = ?"),
    )
    .bind(palisade::db::now_ms() - 30 * 60_000)
    .bind(&job.id)
    .execute(st.db.pool())
    .await
    .expect("backdate");
    palisade::schedule::tick(&st).await.expect("tick");
    let j = st.db.job(&job.id).await.expect("q").expect("job");
    assert_eq!(j.status, "FINISHED");
    assert_eq!(j.error_code.as_deref(), Some("WINDOW_CLOSED"));
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test]
async fn watcher_queues_new_files_once() {
    let base = std::env::temp_dir().join(format!("palisade-watch-{}", palisade::db::new_id()));
    let dir = base.join("downloads");
    std::fs::create_dir_all(dir.join("sub")).expect("mkdir");
    let old = dir.join("old.bin");
    std::fs::write(&old, b"old").expect("write");
    let roots = base.to_str().expect("utf8").to_owned();
    let (app, st, c, t) = app(&["--scan-roots", &roots]).await;
    // Baseline: existing files are recorded, not scanned.
    let body = format!("_csrf={t}&path={}", dir.display());
    let res = send(app.clone(), form("/admin/watch", &body, &c))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let real_old = std::fs::canonicalize(&old).expect("real");
    assert_eq!(
        st.db
            .processed(real_old.to_str().expect("utf8"))
            .await
            .expect("q")
            .map(|p| p.verdict),
        Some("BASELINE".to_owned())
    );
    // A new file that has settled (mtime pushed back) is queued; a fresh one waits.
    let new = dir.join("sub").join("new.bin");
    std::fs::write(&new, b"new").expect("write");
    let past = std::time::SystemTime::now() - Duration::from_secs(120);
    std::fs::File::options()
        .write(true)
        .open(&new)
        .expect("open")
        .set_modified(past)
        .expect("mtime");
    std::fs::write(dir.join("fresh.bin"), b"still copying").expect("write");
    assert_eq!(palisade::watch::pass(&st).await, 1);
    assert_eq!(
        palisade::watch::pass(&st).await,
        0,
        "not queued twice while pending"
    );
    palisade::scan::start(st.clone()).await;
    let (jobs, _) = st
        .db
        .list_jobs(&JobFilter::default(), 0, 10)
        .await
        .expect("list");
    let job = wait_finished(&st, &jobs[0].id).await;
    assert_eq!(job.kind, "WATCH");
    let real_new = std::fs::canonicalize(&new).expect("real");
    let rec = st
        .db
        .processed(real_new.to_str().expect("utf8"))
        .await
        .expect("q")
        .expect("recorded");
    assert_eq!(rec.verdict, "VIRUS_FOUND", "recorded after the scan (N6)");
    assert_eq!(
        palisade::watch::pass(&st).await,
        0,
        "unchanged files are not rescanned"
    );
    // A name that is not UTF-8 is still scanned, by streaming the file.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bad = dir.join(std::ffi::OsStr::from_bytes(b"eicar\xff.com"));
        std::fs::write(&bad, EICAR).expect("write");
        std::fs::File::options()
            .write(true)
            .open(&bad)
            .expect("open")
            .set_modified(past)
            .expect("mtime");
        assert_eq!(palisade::watch::pass(&st).await, 1);
        st.runner.poke();
        let (jobs, _) = st
            .db
            .list_jobs(&JobFilter::default(), 0, 10)
            .await
            .expect("list");
        let job = wait_finished(&st, &jobs[0].id).await;
        assert!(job.target.contains("//raw:"), "{}", job.target);
        assert_eq!(job.verdict.as_deref(), Some("VIRUS_FOUND"));
        assert!(job.detections.contains_key(&job.target));
        assert_eq!(palisade::watch::pass(&st).await, 0, "recorded once scanned");
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// A tiny HTTP server that hands every request body to the test.
async fn hook_receiver() -> (u16, tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut b = [0u8; 1024];
                let (head_end, len) = loop {
                    let Ok(n) = s.read(&mut b).await else { return };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&b[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (i + 4, len);
                    }
                };
                while buf.len() < head_end + len {
                    let Ok(n) = s.read(&mut b).await else { return };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&b[..n]);
                }
                let _ = tx.send(
                    serde_json::from_slice(&buf[head_end..head_end + len]).unwrap_or_default(),
                );
                let _ = s
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            });
        }
    });
    (port, rx)
}

#[tokio::test]
async fn webhook_reports_alerts_only() {
    let (port, mut rx) = hook_receiver().await;
    let url = format!("http://127.0.0.1:{port}/hook");
    let (app, st, c, t) = app(&[
        "--webhook-url",
        &url,
        "--webhook-allowed-cidrs",
        "127.0.0.1/32",
    ])
    .await;
    palisade::webhook::spawn(st.clone());
    let res = app
        .clone()
        .oneshot(upload(
            &c,
            multipart(Some(&t), &[("clean.txt", b"hello"), ("eicar.com", EICAR)]),
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let body = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("delivered")
        .expect("body");
    assert_eq!(body["event"], "scan.finished");
    assert_eq!(body["verdict"], "VIRUS_FOUND");
    assert_eq!(body["target"], "eicar.com");
    assert_eq!(body["foundViruses"][0], "Eicar-Test-Signature");
    assert!(
        tokio::time::timeout(Duration::from_millis(700), rx.recv())
            .await
            .is_err(),
        "clean scans are not sent in alerts mode"
    );
    st.notifier.test().await.expect("test delivered");
    let body = rx.recv().await.expect("test body");
    assert_eq!(body["event"], "test");
    assert!(st.notifier.last().is_some_and(|d| d.ok));
}

#[tokio::test]
async fn alerts_reach_every_destination() {
    let (port, mut rx) = hook_receiver().await;
    let urls = format!("http://127.0.0.1:{port}/hook,ntfy+http://127.0.0.1:{port}/palisade");
    let (_app, st, _, _) = app(&[
        "--webhook-url",
        &urls,
        "--webhook-allowed-cidrs",
        "127.0.0.1/32",
    ])
    .await;
    assert_eq!(st.notifier.targets().len(), 2);
    st.notifier.test().await.expect("both delivered");
    let a = rx.recv().await.expect("json");
    let b = rx.recv().await.expect("ntfy");
    assert_eq!(a["event"], "test");
    assert_eq!(b["topic"], "palisade");
    assert_eq!(b["title"], "Test from palisade");
    assert!(
        st.notifier
            .last_each()
            .iter()
            .all(|d| d.as_ref().is_some_and(|d| d.ok))
    );
}

#[tokio::test]
async fn webhook_refuses_private_addresses() {
    let (port, _rx) = hook_receiver().await;
    let url = format!("http://localhost:{port}/hook");
    let (_app, st, _, _) = app(&["--webhook-url", &url]).await;
    let err = st.notifier.test().await.expect_err("blocked");
    assert!(err.contains("not allowed"), "{err}");
    assert!(!err.contains("/hook"), "URL is not echoed");
    let bad = Cli::try_parse_from(["palisade", "--webhook-url", "ftp://x/y"]).expect("parse");
    assert!(palisade::webhook::Target::from_config(&bad.config).is_err());
    let creds = Cli::try_parse_from(["palisade", "--webhook-url", "https://u:p@example.com/"])
        .expect("parse");
    assert!(palisade::webhook::Target::from_config(&creds.config).is_err());
}

#[tokio::test]
async fn metrics_need_the_token_and_count_scans() {
    let (app, st, c, t) = app(&["--metrics-token", "0123456789abcdef-test"]).await;
    palisade::metrics::spawn(st.clone());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let scrape = |auth: Option<&str>| {
        let mut b = Request::get("/metrics");
        if let Some(a) = auth {
            b = b.header(header::AUTHORIZATION, a);
        }
        b.body(Body::empty()).expect("req")
    };
    let res = app.clone().oneshot(scrape(None)).await.expect("res");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = app
        .clone()
        .oneshot(scrape(Some("Bearer wrong")))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = app
        .clone()
        .oneshot(upload(&c, multipart(Some(&t), &[("eicar.com", EICAR)])))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let res = app
        .clone()
        .oneshot(scrape(Some("Bearer 0123456789abcdef-test")))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let b = http_body_util::BodyExt::collect(res.into_body())
        .await
        .expect("body")
        .to_bytes();
    let text = String::from_utf8_lossy(&b);
    for want in [
        "clamav_scans_total{type=\"upload\",verdict=\"virus_found\"} 1",
        "clamav_scans_total{type=\"path\",verdict=\"ok\"} 0",
        "clamav_viruses_detected_total{signature=\"Eicar-Test-Signature\"} 1",
        "clamav_scan_detections_total 1",
        "clamav_scan_jobs_pending 0",
        "clamav_scan_duration_seconds_count{type=\"upload\"} 1",
        "clamav_threads_live{slot=\"0\"} 3",
        "clamav_threads_busy{slot=\"0\"} 2",
        "clamav_pools_used_bytes{slot=\"0\"} 1048576",
        "clamav_clamd_endpoint_available{slot=\"0\"} 1",
        "clamav_clamd_version_minor{slot=\"0\"} 4",
        "clamav_database_version{slot=\"0\"} 27000",
        "clamav_clamd_endpoint_info{slot=\"0\",endpoint=\"default\"} 1",
    ] {
        assert!(text.contains(want), "missing {want}\n{text}");
    }
    // Off unless a token is configured.
    let (plain, _, _, _) = self::app(&[]).await;
    let res = plain.oneshot(scrape(Some("Bearer x"))).await.expect("res");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn clamd_conf_excludes_and_is_shown() {
    let base = std::env::temp_dir().join(format!("palisade-conf-{}", palisade::db::new_id()));
    let dir = base.join("data");
    std::fs::create_dir_all(dir.join("cache")).expect("mkdir");
    let dir = std::fs::canonicalize(&dir).expect("real");
    let conf = base.join("clamd.conf");
    std::fs::write(
        &conf,
        format!(
            "StreamMaxLength 100M\nExcludePath ^{}/cache/\n",
            dir.display()
        ),
    )
    .expect("conf");
    let roots = dir.to_str().expect("utf8").to_owned();
    let (app, st, c, t) = app(&[
        "--scan-roots",
        &roots,
        "--clamd-conf-file",
        conf.to_str().expect("utf8"),
    ])
    .await;
    let skipped = dir.join("cache").join("x.bin");
    std::fs::write(&skipped, b"x").expect("write");
    let res = app
        .clone()
        .oneshot(form(
            "/scan/path",
            &format!("_csrf={t}&path={}", skipped.display()),
            &c,
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(body(res).await.contains("excluded by ExcludePath"));
    // The watcher skips it too.
    let past = std::time::SystemTime::now() - Duration::from_secs(120);
    std::fs::File::options()
        .write(true)
        .open(&skipped)
        .expect("open")
        .set_modified(past)
        .expect("mtime");
    st.db.create_watch(&roots, None).await.expect("watch");
    assert_eq!(palisade::watch::pass(&st).await, 0);
    let res = app
        .clone()
        .oneshot(
            Request::get("/admin/clamd-config")
                .header(header::COOKIE, &c)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("res");
    let html = body(res).await;
    assert!(html.contains("Raise StreamMaxLength to 1024M"), "{html}");
    assert!(html.contains("/cache/"));
    let _ = std::fs::remove_dir_all(&base);
}

async fn body(res: axum::response::Response) -> String {
    String::from_utf8_lossy(
        &http_body_util::BodyExt::collect(res.into_body())
            .await
            .expect("b")
            .to_bytes(),
    )
    .into_owned()
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn realtime_scans_files_as_they_are_written() {
    let base = std::env::temp_dir().join(format!("palisade-rt-{}", palisade::db::new_id()));
    let dir = base.join("incoming");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let roots = base.to_str().expect("utf8").to_owned();
    let (app, st, c, t) = app(&["--scan-roots", &roots]).await;
    let body = format!("_csrf={t}&path={}", dir.display());
    let res = send(app.clone(), form("/admin/watch", &body, &c))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    palisade::scan::start(st.clone()).await;
    palisade::watch::spawn_realtime(st.clone());
    tokio::time::sleep(Duration::from_millis(500)).await;
    // Fresh files (no settle time) are scanned without a polling pass.
    std::fs::write(dir.join("payload.com"), EICAR).expect("write");
    let mut found = None;
    for _ in 0..200 {
        let (jobs, _) = st
            .db
            .list_jobs(&JobFilter::default(), 0, 10)
            .await
            .expect("list");
        if let Some(j) = jobs.into_iter().find(|j| j.kind == "WATCH") {
            found = Some(j);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let job = wait_finished(&st, &found.expect("queued in real time").id).await;
    assert!(
        job.target.ends_with("/incoming/payload.com"),
        "{}",
        job.target
    );
    assert_eq!(job.verdict.as_deref(), Some("VIRUS_FOUND"));
    assert_eq!(
        palisade::watch::pass(&st).await,
        0,
        "recorded, not rescanned"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn touching_a_canary_alerts() {
    let (port, mut rx) = hook_receiver().await;
    let url = format!("http://127.0.0.1:{port}/hook");
    let dir = std::env::temp_dir().join(format!("palisade-canary-{}", palisade::db::new_id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let decoy = dir.join("passwords.kdbx");
    std::fs::write(&decoy, b"decoy").expect("write");
    let decoy_s = decoy.to_str().expect("utf8").to_owned();
    let (_app, st, _c, _t) = app(&[
        "--webhook-url",
        &url,
        "--webhook-allowed-cidrs",
        "127.0.0.1/32",
        "--canary-files",
        &decoy_s,
    ])
    .await;
    palisade::webhook::spawn(st.clone());
    palisade::canary::spawn(st.clone());
    let _ = std::fs::read(&decoy).expect("read");
    let body = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("delivered")
        .expect("body");
    assert_eq!(body["event"], "canary.tripped");
    assert_eq!(body["target"], decoy_s.as_str());
    assert_eq!(body["error"], "opened");
    let audit = st.db.audit_page(0, 10).await.expect("audit");
    assert!(audit.0.iter().any(|a| a.action == "CANARY_TRIPPED"));
    let _ = std::fs::remove_dir_all(&dir);
}

fn page_get(uri: &str, cookie: &str) -> Request<Body> {
    Request::get(uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .expect("req")
}

#[tokio::test]
async fn detections_dashboard_and_search() {
    let base = std::env::temp_dir().join(format!("palisade-det-{}", palisade::db::new_id()));
    let root = base.join("media");
    std::fs::create_dir_all(root.join("tv")).expect("mkdir");
    let roots = root.to_str().expect("utf8").to_owned();
    let (app, st, c, t) = app(&["--scan-roots", &roots]).await;
    palisade::scan::start(st.clone()).await;
    let res = app
        .clone()
        .oneshot(form(
            "/scan/path",
            &format!("_csrf={t}&path={}/tv", root.display()),
            &c,
        ))
        .await
        .expect("res");
    let id = res.headers()[header::LOCATION]
        .to_str()
        .expect("loc")
        .trim_start_matches("/jobs/")
        .to_owned();
    wait_finished(&st, &id).await;

    // One detection row per hit.
    let rows = st
        .db
        .list_detections(&Default::default(), 0, 10)
        .await
        .expect("list");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].signature, "Eicar-Test-Signature");
    assert_eq!(rows[0].job_id, id);

    // Dashboard: chart, KPIs and top lists that link to filtered views.
    for range in ["24h", "7d", "30d"] {
        let page = body(
            app.clone()
                .oneshot(page_get(&format!("/dashboard?range={range}"), &c))
                .await
                .expect("res"),
        )
        .await;
        assert!(page.contains("<svg class=\"chart"), "{range}");
        assert!(page.contains("Eicar-Test-Signature"));
        assert!(
            page.contains("/detections?range=") && page.contains("signature=Eicar-Test-Signature")
        );
        assert!(!page.contains("style="), "CSP: no inline styles");
    }

    // Detections page: facets, search and exact signature.
    let page = body(
        app.clone()
            .oneshot(page_get("/detections", &c))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("1 infected file(s)"));
    assert!(page.contains("class=\"facet\"") && page.contains("/tv"));
    let page = body(
        app.clone()
            .oneshot(page_get("/detections?q=sig%3DNope", &c))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("0 infected file(s)"));
    let page = body(
        app.clone()
            .oneshot(page_get("/detections?q=-eicar", &c))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("0 infected file(s)"), "negation");
    let page = body(
        app.clone()
            .oneshot(page_get(
                &format!("/detections?q=folder%3A{}", root.join("tv").display()),
                &c,
            ))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("1 infected file(s)"), "folder prefix");
    let page = body(
        app.clone()
            .oneshot(page_get("/detections?q=bogus%3Ax", &c))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("Unknown or unsupported filter: bogus"));
    // Wildcards in search are literal.
    let page = body(
        app.clone()
            .oneshot(page_get("/detections?q=%25", &c))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("0 infected file(s)"));

    // CSV export is spreadsheet-safe and filtered the same way.
    let res = app
        .clone()
        .oneshot(page_get(
            "/detections.csv?signature=Eicar-Test-Signature",
            &c,
        ))
        .await
        .expect("res");
    assert_eq!(
        res.headers()[header::CONTENT_TYPE],
        "text/csv; charset=utf-8"
    );
    let csv = body(res).await;
    assert_eq!(csv.lines().count(), 2);
    assert!(csv.contains("\"Eicar-Test-Signature\""));

    // Jobs search and filters.
    let page = body(
        app.clone()
            .oneshot(page_get("/jobs?q=verdict%3DVIRUS_FOUND+kind%3DPATH", &c))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("1 job(s)"));
    let page = body(
        app.clone()
            .oneshot(page_get("/jobs?q=before%3A2000-01-01", &c))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("0 job(s)"));
    let page = body(
        app.clone()
            .oneshot(page_get("/jobs?q=after%3Asoon", &c))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("Not a date: soon"));

    // Deleting the job removes its detections.
    assert_eq!(
        st.db.prune_jobs(i64::MAX, i64::MAX).await.expect("prune"),
        1
    );
    assert_eq!(
        st.db
            .count_detections(&Default::default())
            .await
            .expect("count"),
        0
    );
    let _ = std::fs::remove_dir_all(&base);
}

async fn text(res: axum::response::Response) -> String {
    String::from_utf8_lossy(
        &http_body_util::BodyExt::collect(res.into_body())
            .await
            .expect("b")
            .to_bytes(),
    )
    .into_owned()
}

#[tokio::test]
async fn schedules_offer_presets_and_prefill_the_roots() {
    let base = std::env::temp_dir().join(format!("palisade-preset-{}", palisade::db::new_id()));
    std::fs::create_dir_all(base.join("media")).expect("mkdir");
    let root = std::fs::canonicalize(base.join("media")).expect("real");
    let roots = root.to_str().expect("utf8").to_owned();
    let (app, st, c, t) = app(&["--scan-roots", &roots]).await;
    let html = text(
        app.clone()
            .oneshot(page_get("/admin/schedules", &c))
            .await
            .expect("res"),
    )
    .await;
    assert!(html.contains("Nightly at 02:00") && html.contains(&format!(">{roots}</textarea>")));
    // A preset with an empty cron field is used as is.
    let weekly = format!("_csrf={t}&name=weekly&preset=0+3+*+*+0&cron=&paths={roots}");
    let html = text(
        send(app.clone(), form("/admin/schedules", &weekly, &c))
            .await
            .expect("res"),
    )
    .await;
    assert!(html.contains("Added weekly."), "{html}");
    assert!(html.contains("Weekly, Sunday at 03:00"));
    // A typed cron line wins over the preset.
    let typed = format!("_csrf={t}&name=typed&preset=0+2+*+*+*&cron=15+4+*+*+*&paths={roots}");
    send(app.clone(), form("/admin/schedules", &typed, &c))
        .await
        .expect("res");
    let crons: Vec<String> = st
        .db
        .list_schedules()
        .await
        .expect("list")
        .into_iter()
        .map(|s| s.cron)
        .collect();
    assert!(crons.contains(&"0 3 * * 0".to_owned()) && crons.contains(&"15 4 * * *".to_owned()));
    // Custom with nothing typed says what to do.
    let empty = format!("_csrf={t}&name=e&preset=custom&cron=&paths={roots}");
    let res = send(app.clone(), form("/admin/schedules", &empty, &c))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(text(res).await.contains("Pick how often it runs"));
    let bad = format!("_csrf={t}&name=b&preset=custom&cron=99+*+*+*+*&paths={roots}");
    let res = send(app.clone(), form("/admin/schedules", &bad, &c))
        .await
        .expect("res");
    assert!(
        text(res)
            .await
            .contains("Pick a preset, or write five fields")
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test]
async fn watched_folders_scan_now_and_forget_deleted_files() {
    let base = std::env::temp_dir().join(format!("palisade-wnow-{}", palisade::db::new_id()));
    let dir = base.join("in");
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(dir.join("a.bin"), b"a").expect("write");
    std::fs::write(dir.join("b.bin"), b"b").expect("write");
    let roots = base.to_str().expect("utf8").to_owned();
    let (app, st, c, t) = app(&["--scan-roots", &roots]).await;
    let res = send(
        app.clone(),
        form(
            "/admin/watch",
            &format!("_csrf={t}&path={}", dir.display()),
            &c,
        ),
    )
    .await
    .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let w = st.db.list_watches().await.expect("list").remove(0);
    let html = text(
        app.clone()
            .oneshot(page_get("/admin/watch", &c))
            .await
            .expect("res"),
    )
    .await;
    assert!(html.contains(&format!("/admin/watch/{}/scan", w.id)));

    // Scan now queues one path scan of the whole folder and shows its job.
    let res = app
        .clone()
        .oneshot(form(
            &format!("/admin/watch/{}/scan", w.id),
            &format!("_csrf={t}"),
            &c,
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let to = res.headers()[header::LOCATION]
        .to_str()
        .expect("loc")
        .to_owned();
    let job = st
        .db
        .job(to.trim_start_matches("/jobs/"))
        .await
        .expect("q")
        .expect("job");
    assert_eq!(
        (job.kind.as_str(), job.target.as_str()),
        ("PATH", w.path.as_str())
    );

    // Records of deleted files are dropped by the daily sweep; present ones stay.
    let real = std::fs::canonicalize(&dir).expect("real");
    let a = real.join("a.bin").to_str().expect("utf8").to_owned();
    let b = real.join("b.bin").to_str().expect("utf8").to_owned();
    assert!(st.db.processed(&a).await.expect("q").is_some());
    std::fs::remove_file(dir.join("a.bin")).expect("rm");
    tokio::time::sleep(Duration::from_millis(5)).await;
    st.watcher.sweep_soon();
    palisade::watch::pass(&st).await;
    assert!(
        st.db.processed(&a).await.expect("q").is_none(),
        "deleted file forgotten"
    );
    assert!(
        st.db.processed(&b).await.expect("q").is_some(),
        "present file kept"
    );
    assert_eq!(st.watcher.known_len(), 1, "memory follows the disk");
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test]
async fn endpoint_test_checks_eicar_detection() {
    let (app, st, c, t) = app(&[]).await;
    let ep = st.db.list_endpoints().await.expect("list").remove(0);
    let res = send(
        app.clone(),
        form(
            &format!("/admin/endpoints/{}/test", ep.id),
            &format!("_csrf={t}"),
            &c,
        ),
    )
    .await
    .expect("res");
    let html = text(res).await;
    assert!(
        html.contains("flagged the EICAR test file (Eicar-Test-Signature)"),
        "{html}"
    );
}
