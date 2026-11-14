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

pub const ACTIONS: [Action; 8] = [
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
];

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
            "systemd refused; install the polkit rule from examples/host-checks and run clamv as the clamv user."
        }
        NOT_INSTALLED => {
            "The clamv host-check units are not installed; run examples/host-checks/install.sh."
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
        Ok(s) => s,
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
