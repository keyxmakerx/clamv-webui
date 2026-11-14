//! Managed AIDE and rkhunter. Each host installs fixed, sandboxed systemd
//! units once (examples/host-checks); clamv, running unprivileged, may only
//! start those units and switch their timers, which a polkit rule enforces.
//! Results still arrive by reading the reports (see `integrity`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::app::AppState;

pub const KIND: &str = "HOSTCHECK";
pub const NO_BUS: &str = "HOSTCHECK_NO_BUS";
pub const DENIED: &str = "HOSTCHECK_DENIED";
pub const NOT_INSTALLED: &str = "HOSTCHECK_NOT_INSTALLED";
pub const FAILED: &str = "HOSTCHECK_FAILED";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Action {
    pub name: &'static str,
    pub unit: &'static str,
    /// Stop the unit instead of starting it.
    pub stop: bool,
    /// Changes a baseline, so the admin confirms with a passkey.
    pub passkey: bool,
    pub label: &'static str,
}

pub const ACTIONS: [Action; 12] = [
    Action {
        name: "aide.check",
        unit: "clamv-aide-check.service",
        stop: false,
        passkey: false,
        label: "Run AIDE now",
    },
    Action {
        name: "rkhunter.check",
        unit: "clamv-rkhunter-check.service",
        stop: false,
        passkey: false,
        label: "Run rkhunter now",
    },
    Action {
        name: "aide.accept",
        unit: "clamv-aide-accept.service",
        stop: false,
        passkey: true,
        label: "Accept AIDE baseline",
    },
    Action {
        name: "rkhunter.propupd",
        unit: "clamv-rkhunter-propupd.service",
        stop: false,
        passkey: true,
        label: "Update rkhunter properties",
    },
    Action {
        name: "aide.timer.on",
        unit: "clamv-aide-check.timer",
        stop: false,
        passkey: false,
        label: "Daily AIDE on",
    },
    Action {
        name: "aide.timer.off",
        unit: "clamv-aide-check.timer",
        stop: true,
        passkey: false,
        label: "Daily AIDE off",
    },
    Action {
        name: "rkhunter.timer.on",
        unit: "clamv-rkhunter-check.timer",
        stop: false,
        passkey: false,
        label: "Daily rkhunter on",
    },
    Action {
        name: "rkhunter.timer.off",
        unit: "clamv-rkhunter-check.timer",
        stop: true,
        passkey: false,
        label: "Daily rkhunter off",
    },
    // Started only through `set_time`, which writes the time first.
    Action {
        name: "timers.set",
        unit: "clamv-timer-set.service",
        stop: false,
        passkey: false,
        label: "Set timer times",
    },
    // Firewall units are started only by the firewall code, never from a host-check job.
    Action {
        name: "firewall.snapshot",
        unit: "clamv-firewall-snapshot.service",
        stop: false,
        passkey: false,
        label: "Read firewall",
    },
    Action {
        name: "firewall.apply",
        unit: "clamv-firewall-apply.service",
        stop: false,
        passkey: true,
        label: "Apply firewall plan",
    },
    Action {
        name: "firewall.remove",
        unit: "clamv-firewall-remove.service",
        stop: false,
        passkey: true,
        label: "Remove clamv's firewall table",
    },
];

/// An action a host-check job or the Host Checks page may ask for.
pub fn check_action(name: &str) -> Option<&'static Action> {
    action(name).filter(|a| !a.name.starts_with("firewall.") && a.name != "timers.set")
}

/// Shared with the host's timer-set unit, which uses this fixed path too.
pub const TIMER_DIR: &str = "/var/lib/clamv/timers";

/// A daily time, `HH:MM`, or `random` for systemd's own randomised daily run.
pub fn valid_time(t: &str) -> bool {
    if t == "random" {
        return true;
    }
    let b = t.as_bytes();
    b.len() == 5
        && b[2] == b':'
        && t[..2].parse::<u8>().is_ok_and(|h| h < 24)
        && t[3..].parse::<u8>().is_ok_and(|m| m < 60)
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 2 || c.is_ascii_digit())
}

/// The job target that sets a tool's daily time, e.g. `aide.timer.at 03:30`.
pub fn timer_target(tool: &str, time: &str) -> String {
    format!("{tool}.timer.at {time}")
}

pub fn parse_timer_target(t: &str) -> Option<(&'static str, String)> {
    let (head, time) = t.split_once(' ')?;
    let tool = match head {
        "aide.timer.at" => "aide",
        "rkhunter.timer.at" => "rkhunter",
        _ => return None,
    };
    valid_time(time).then(|| (tool, time.to_owned()))
}

/// Ask the host's timer-set unit for a new daily time.
pub async fn set_time(tool: &str, time: &str) -> Result<(), RunError> {
    if !valid_time(time) || !matches!(tool, "aide" | "rkhunter") {
        return Err(RunError {
            code: FAILED,
            message: "not a time".into(),
        });
    }
    let dir = std::path::Path::new(TIMER_DIR);
    let io = |e: std::io::Error| RunError {
        code: NOT_INSTALLED,
        message: format!("cannot write to {TIMER_DIR}: {e}"),
    };
    let tmp = dir.join(format!(".{tool}.want.tmp"));
    std::fs::write(&tmp, format!("{time}\n")).map_err(io)?;
    std::fs::rename(&tmp, dir.join(format!("{tool}.want"))).map_err(io)?;
    let a = action("timers.set").ok_or_else(|| RunError {
        code: FAILED,
        message: "no timer unit".into(),
    })?;
    run(a).await
}

/// The time the host last applied for a tool, if clamv ever set one.
fn applied_time(tool: &str) -> Option<String> {
    use std::io::Read;
    let f = std::fs::File::open(std::path::Path::new(TIMER_DIR).join(format!("{tool}.applied")))
        .ok()?;
    let mut s = String::new();
    f.take(16).read_to_string(&mut s).ok()?;
    let t = s.trim();
    valid_time(t).then(|| t.to_owned())
}

pub fn action(name: &str) -> Option<&'static Action> {
    ACTIONS.iter().find(|a| a.name == name)
}

/// What a host's systemd says about clamv's units.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitStates {
    #[serde(default)]
    pub aide: bool,
    #[serde(default)]
    pub rkhunter: bool,
    /// None when the timer is not installed.
    #[serde(default)]
    pub aide_timer: Option<bool>,
    #[serde(default)]
    pub rkhunter_timer: Option<bool>,
    /// The daily time clamv set (`HH:MM` or `random`); None when it never set one.
    #[serde(default)]
    pub aide_at: Option<String>,
    #[serde(default)]
    pub rkhunter_at: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

impl UnitStates {
    pub fn installed(&self) -> bool {
        self.aide || self.rkhunter
    }

    /// Bounded, since an agent sends it.
    pub fn cleaned(mut self) -> Self {
        self.error = self.error.map(|e| crate::agent::proto::clean(&e, 200));
        self.aide_at = self.aide_at.filter(|t| valid_time(t));
        self.rkhunter_at = self.rkhunter_at.filter(|t| valid_time(t));
        self
    }
}

/// Last known unit states per host (None is this server), with when they were read.
#[derive(Default)]
pub struct States(Mutex<HashMap<Option<i64>, (UnitStates, i64)>>);

impl States {
    pub fn set(&self, host: Option<i64>, s: UnitStates) {
        if let Ok(mut g) = self.0.lock() {
            g.insert(host, (s, crate::db::now_ms()));
        }
    }

    pub fn get(&self, host: Option<i64>) -> Option<(UnitStates, i64)> {
        self.0.lock().ok()?.get(&host).cloned()
    }
}

/// Why an action could not run, as a job error code and a sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunError {
    pub code: &'static str,
    pub message: String,
}

pub fn message(code: &str) -> &'static str {
    match code {
        NO_BUS => "No system D-Bus here; mount /run/dbus/system_bus_socket into the container.",
        DENIED => {
            "systemd refused; run host-setup on the host and run clamv as the clamv user (uid 10001)."
        }
        NOT_INSTALLED => {
            "The clamv host units are not installed; run the image with host-setup on the host."
        }
        _ => "systemd could not start the unit; see the host's journal.",
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{Action, DENIED, FAILED, NO_BUS, NOT_INSTALLED, RunError, UnitStates};
    use zbus::{OwnedObjectPath, OwnedVariant};

    const DEST: &str = "org.freedesktop.systemd1";
    const PATH: &str = "/org/freedesktop/systemd1";
    const MANAGER: &str = "org.freedesktop.systemd1.Manager";

    fn classify(e: &zbus::Error) -> RunError {
        let text = e.to_string();
        let code = match e {
            zbus::Error::MethodError(name, _, _) => match name.as_str() {
                "org.freedesktop.DBus.Error.AccessDenied"
                | "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired" => DENIED,
                "org.freedesktop.systemd1.NoSuchUnit" => NOT_INSTALLED,
                _ => FAILED,
            },
            _ => FAILED,
        };
        RunError {
            code,
            message: crate::agent::proto::clean(&text, 200),
        }
    }

    async fn bus() -> Result<zbus::Connection, RunError> {
        zbus::Connection::system().await.map_err(|e| RunError {
            code: NO_BUS,
            message: crate::agent::proto::clean(&e.to_string(), 200),
        })
    }

    pub async fn run(a: &Action) -> Result<(), RunError> {
        let c = bus().await?;
        let method = if a.stop { "StopUnit" } else { "StartUnit" };
        c.call_method(
            Some(DEST),
            PATH,
            Some(MANAGER),
            method,
            &(a.unit, "replace"),
        )
        .await
        .map_err(|e| classify(&e))?;
        Ok(())
    }

    async fn prop(c: &zbus::Connection, unit: &str, name: &str) -> Option<String> {
        let reply = c
            .call_method(Some(DEST), PATH, Some(MANAGER), "LoadUnit", &(unit,))
            .await
            .ok()?;
        let path: OwnedObjectPath = reply.body().deserialize().ok()?;
        let reply = c
            .call_method(
                Some(DEST),
                path.as_str(),
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("org.freedesktop.systemd1.Unit", name),
            )
            .await
            .ok()?;
        let v: OwnedVariant = reply.body().deserialize().ok()?;
        String::try_from(v).ok()
    }

    pub async fn probe() -> UnitStates {
        let c = match bus().await {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(error = %e.message, "no system bus for host checks");
                return UnitStates {
                    error: Some(super::message(e.code).to_owned()),
                    ..UnitStates::default()
                };
            }
        };
        let loaded = |s: Option<String>| s.as_deref() == Some("loaded");
        let timer = |load: Option<String>, active: Option<String>| {
            loaded(load).then(|| active.as_deref() == Some("active"))
        };
        UnitStates {
            aide: loaded(prop(&c, "clamv-aide-check.service", "LoadState").await),
            rkhunter: loaded(prop(&c, "clamv-rkhunter-check.service", "LoadState").await),
            aide_timer: timer(
                prop(&c, "clamv-aide-check.timer", "LoadState").await,
                prop(&c, "clamv-aide-check.timer", "ActiveState").await,
            ),
            rkhunter_timer: timer(
                prop(&c, "clamv-rkhunter-check.timer", "LoadState").await,
                prop(&c, "clamv-rkhunter-check.timer", "ActiveState").await,
            ),
            aide_at: None,
            rkhunter_at: None,
            error: None,
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::{Action, NO_BUS, RunError, UnitStates};

    pub async fn run(_: &Action) -> Result<(), RunError> {
        Err(RunError {
            code: NO_BUS,
            message: "systemd is Linux only".into(),
        })
    }

    pub async fn probe() -> UnitStates {
        UnitStates {
            error: Some("systemd is Linux only".into()),
            ..UnitStates::default()
        }
    }
}

/// Start or stop one allow-listed unit on this host.
pub async fn run(a: &Action) -> Result<(), RunError> {
    imp::run(a).await
}

/// Read which units exist and whether their timers run.
pub async fn probe() -> UnitStates {
    match tokio::time::timeout(Duration::from_secs(10), imp::probe()).await {
        Ok(s) => UnitStates {
            aide_at: applied_time("aide"),
            rkhunter_at: applied_time("rkhunter"),
            ..s
        },
        Err(_) => UnitStates {
            error: Some("systemd did not answer in 10 s".into()),
            ..UnitStates::default()
        },
    }
}

/// Run an action on this server as a job, so it shows in Jobs and the audit trail.
pub async fn run_here(st: &Arc<AppState>, a: &'static Action, by: &str) -> anyhow::Result<String> {
    let job = st
        .db
        .create_job(crate::db::jobs::NewJob {
            kind: KIND,
            target: a.name,
            endpoint_id: None,
            schedule_id: None,
            agent_id: None,
            submitted_by: Some(by),
            transport: "UI",
            running: true,
        })
        .await?;
    let id = job.id.clone();
    let st = st.clone();
    tokio::spawn(async move {
        let host = crate::canary::hostname();
        let o = match run(a).await {
            Ok(()) => {
                tracing::info!(event = "hostcheck.started", host = %host, action = a.name, unit = a.unit, "host check started");
                crate::db::jobs::Outcome {
                    verdict: crate::db::jobs::OK,
                    ..Default::default()
                }
            }
            Err(e) => {
                tracing::warn!(event = "hostcheck.failed", host = %host, action = a.name, unit = a.unit, code = e.code, error = %e.message, "host check could not start");
                crate::scan::failure(e.code, message(e.code))
            }
        };
        crate::scan::finish(&st, &job, &host, o).await;
        st.host_units.set(None, probe().await);
    });
    Ok(id)
}

/// Keep this server's unit states fresh.
pub fn spawn(st: Arc<AppState>) {
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(300));
        loop {
            t.tick().await;
            st.host_units.set(None, probe().await);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allow_list_is_fixed() {
        assert_eq!(
            action("aide.check").map(|a| a.unit),
            Some("clamv-aide-check.service")
        );
        assert!(action("aide.accept").is_some_and(|a| a.passkey));
        assert!(action("rkhunter.timer.off").is_some_and(|a| a.stop && !a.passkey));
        assert!(action("../../etc").is_none());
        assert!(check_action("timers.set").is_none());
        for (t, ok) in [
            ("03:30", true),
            ("23:59", true),
            ("24:00", false),
            ("3:30", false),
            ("03:3a", false),
            ("random", true),
            ("03:30\nx", false),
        ] {
            assert_eq!(valid_time(t), ok, "{t}");
        }
        assert_eq!(
            parse_timer_target("aide.timer.at 03:30"),
            Some(("aide", "03:30".into()))
        );
        assert_eq!(parse_timer_target("aide.timer.at 99:99"), None);
        assert_eq!(parse_timer_target("sshd.timer.at 03:30"), None);
        let rules = include_str!("../../../examples/host-checks/50-clamv-host-checks.rules");
        for a in ACTIONS {
            assert!(a.unit.starts_with("clamv-"));
            assert!(
                rules.contains(a.unit),
                "{} missing from the polkit rule",
                a.unit
            );
        }
    }
}
