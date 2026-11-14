//! `host-setup`: install the fixed host-check and firewall units from inside the image,
//! so a host needs no checkout. It runs once as root with the host's / mounted; the
//! clamv containers themselves stay unprivileged.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

use crate::config::HostSetup;

const LIBEXEC: &str = "usr/local/libexec/clamv";
const UNITS: &str = "etc/systemd/system";
const POLKIT: &str = "etc/polkit-1/rules.d/50-clamv-host-checks.rules";
const SYSUSERS: &str = "etc/sysusers.d/clamv.conf";
const FIREWALL_DIR: &str = "var/lib/clamv/firewall";

macro_rules! ex {
    ($name:literal) => {
        (
            $name,
            include_str!(concat!("../../../examples/host-checks/", $name)),
        )
    };
}

const SCRIPTS: [(&str, &str); 4] = [
    ex!("aide-accept"),
    ex!("firewall-snapshot"),
    ex!("firewall-apply"),
    ex!("firewall-remove"),
];

const UNIT_FILES: [(&str, &str); 9] = [
    ex!("clamv-aide-check.service"),
    ex!("clamv-aide-check.timer"),
    ex!("clamv-aide-accept.service"),
    ex!("clamv-rkhunter-check.service"),
    ex!("clamv-rkhunter-check.timer"),
    ex!("clamv-rkhunter-propupd.service"),
    ex!("clamv-firewall-snapshot.service"),
    ex!("clamv-firewall-apply.service"),
    ex!("clamv-firewall-remove.service"),
];

const RULES: &str = include_str!("../../../examples/host-checks/50-clamv-host-checks.rules");

/// Every file this installs, relative to the host's /, with its mode.
fn files(uid: u32) -> Vec<(PathBuf, String, u32)> {
    let mut v: Vec<(PathBuf, String, u32)> = SCRIPTS
        .iter()
        .map(|(n, c)| (Path::new(LIBEXEC).join(n), (*c).to_owned(), 0o755))
        .collect();
    for (n, c) in UNIT_FILES {
        v.push((Path::new(UNITS).join(n), c.to_owned(), 0o644));
    }
    v.push((PathBuf::from(POLKIT), RULES.to_owned(), 0o644));
    v.push((
        PathBuf::from(SYSUSERS),
        format!("# clamv-webui's containers run as this uid; its polkit rule names this user.\nu clamv {uid} \"clamv-webui\" - /usr/sbin/nologin\n"),
        0o644,
    ));
    v
}

/// Who holds a name or uid in the host's passwd.
fn passwd(root: &Path, uid: u32) -> (Option<u32>, Option<String>) {
    let text = std::fs::read_to_string(root.join("etc/passwd")).unwrap_or_default();
    let mut clamv = None;
    let mut holder = None;
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 3 {
            continue;
        }
        let Ok(u) = f[2].parse::<u32>() else {
            continue;
        };
        if f[0] == "clamv" {
            clamv = Some(u);
        }
        if u == uid {
            holder = Some(f[0].to_owned());
        }
    }
    (clamv, holder)
}

fn write(root: &Path, rel: &Path, body: &str, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dest = root.join(rel);
    let parent = dest.parent().context("no parent")?;
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let tmp = parent.join(format!(
        ".{}.clamv-tmp",
        rel.file_name().and_then(|n| n.to_str()).unwrap_or("f")
    ));
    std::fs::write(&tmp, body).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, &dest).with_context(|| format!("install {}", dest.display()))?;
    println!("  /{}", rel.display());
    Ok(())
}

fn check_root(h: &HostSetup) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(u32::MAX)
        != 0
    {
        bail!("run as root: docker run --rm --user 0 -v /:/host … host-setup");
    }
    if !h.root.join("etc/os-release").is_file() || !h.root.join("run/systemd/system").is_dir() {
        bail!(
            "{} is not a systemd host's /; mount it with -v /:{}",
            h.root.display(),
            h.root.display()
        );
    }
    if h.uid == 0 {
        bail!("--uid must not be 0");
    }
    Ok(())
}

pub async fn run(h: &HostSetup) -> anyhow::Result<()> {
    check_root(h)?;
    let bus = format!(
        "unix:path={}",
        h.root.join("run/dbus/system_bus_socket").display()
    );
    if h.remove {
        return remove(h, &bus).await;
    }
    let (clamv, holder) = passwd(&h.root, h.uid);
    match (clamv, holder.as_deref()) {
        (Some(u), _) if u != h.uid => bail!(
            "the host already has a clamv user with uid {u}; pass --uid {u} and run clamv's containers with --user {u}"
        ),
        (None, Some(other)) => bail!(
            "uid {} belongs to {other} on this host; pick another with --uid and run clamv's containers as that uid",
            h.uid
        ),
        _ => {}
    }
    println!("Installing into {}:", h.root.display());
    for (rel, body, mode) in files(h.uid) {
        write(&h.root, &rel, &body, mode)?;
    }
    std::fs::create_dir_all(h.root.join("var/log/aide"))?;
    let fw = h.root.join(FIREWALL_DIR);
    std::fs::create_dir_all(&fw)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::os::unix::fs::chown(&fw, Some(h.uid), Some(0))?;
        std::fs::set_permissions(&fw, std::fs::Permissions::from_mode(0o750))?;
    }
    println!("  /{FIREWALL_DIR} (owned by clamv, 0750)");
    imp::reload(&bus, clamv.is_none().then_some(h.root.as_path())).await?;
    if passwd(&h.root, h.uid).0 != Some(h.uid) {
        bail!(
            "systemd-sysusers did not add the clamv user; add it by hand with uid {}",
            h.uid
        );
    }
    println!(
        "Done. Mount /run/dbus/system_bus_socket (read-only) and /{FIREWALL_DIR} (read-write) into clamv and its agents."
    );
    Ok(())
}

async fn remove(h: &HostSetup, bus: &str) -> anyhow::Result<()> {
    imp::stop(bus).await;
    println!("Removing from {}:", h.root.display());
    for (rel, _, _) in files(h.uid) {
        match std::fs::remove_file(h.root.join(&rel)) {
            Ok(()) => println!("  /{}", rel.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("remove /{}", rel.display())),
        }
    }
    imp::reload(bus, None).await?;
    println!(
        "Done. The clamv user, /var/lib/clamv and the AIDE and rkhunter packages stay; remove them by hand if you want."
    );
    Ok(())
}

#[cfg(target_os = "linux")]
mod imp {
    const DEST: &str = "org.freedesktop.systemd1";
    const PATH: &str = "/org/freedesktop/systemd1";
    const MANAGER: &str = "org.freedesktop.systemd1.Manager";

    async fn connect(bus: &str) -> anyhow::Result<zbus::Connection> {
        Ok(zbus::connection::Builder::address(bus).build().await?)
    }

    /// Reload systemd; with a root, also run systemd-sysusers and wait for the user.
    pub async fn reload(bus: &str, sysusers: Option<&std::path::Path>) -> anyhow::Result<()> {
        let c = connect(bus).await?;
        c.call_method(Some(DEST), PATH, Some(MANAGER), "Reload", &())
            .await?;
        println!("Reloaded systemd.");
        if let Some(root) = sysusers {
            c.call_method(
                Some(DEST),
                PATH,
                Some(MANAGER),
                "RestartUnit",
                &("systemd-sysusers.service", "replace"),
            )
            .await?;
            // RestartUnit returns once queued; give the oneshot a moment.
            for _ in 0..20 {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                if std::fs::read_to_string(root.join("etc/passwd"))
                    .is_ok_and(|p| p.lines().any(|l| l.starts_with("clamv:")))
                {
                    break;
                }
            }
            println!("Ran systemd-sysusers.");
        }
        Ok(())
    }

    /// Stop the timers and take clamv's firewall table away before the units go.
    pub async fn stop(bus: &str) {
        let Ok(c) = connect(bus).await else {
            return;
        };
        for (m, u) in [
            ("StopUnit", "clamv-aide-check.timer"),
            ("StopUnit", "clamv-rkhunter-check.timer"),
            ("StartUnit", "clamv-firewall-remove.service"),
        ] {
            let _ = c
                .call_method(Some(DEST), PATH, Some(MANAGER), m, &(u, "replace"))
                .await;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    pub async fn reload(_: &str, _: Option<&std::path::Path>) -> anyhow::Result<()> {
        anyhow::bail!("host-setup is Linux only")
    }

    pub async fn stop(_: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_every_unit_the_allow_list_names() {
        let f = files(10001);
        for a in crate::hostchecks::ACTIONS {
            assert!(
                f.iter().any(|(p, _, _)| p.ends_with(a.unit)),
                "{} is not installed",
                a.unit
            );
        }
        assert!(
            f.iter()
                .any(|(p, b, _)| p.ends_with("clamv.conf") && b.contains("u clamv 10001 "))
        );
    }

    #[test]
    fn reads_passwd_holders() {
        let d = std::env::temp_dir().join(format!("clamv-passwd-{}", std::process::id()));
        std::fs::create_dir_all(d.join("etc")).expect("etc");
        std::fs::write(
            d.join("etc/passwd"),
            "root:x:0:0::/root:/bin/sh\nbob:x:10001:10001::/home/bob:/bin/sh\n",
        )
        .expect("passwd");
        assert_eq!(passwd(&d, 10001), (None, Some("bob".into())));
        assert_eq!(passwd(&d, 10002), (None, None));
        let _ = std::fs::remove_dir_all(&d);
    }
}
