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
const TIMER_DIR: &str = "var/lib/clamv/timers";

macro_rules! ex {
    ($name:literal) => {
        (
            $name,
            include_str!(concat!("../../../examples/host-checks/", $name)),
        )
    };
}

const SCRIPTS: [(&str, &str); 6] = [
    ex!("aide-accept"),
    ex!("firewall-lib"),
    ex!("timer-set"),
    ex!("firewall-snapshot"),
    ex!("firewall-apply"),
    ex!("firewall-remove"),
];

const UNIT_FILES: [(&str, &str); 10] = [
    ex!("clamv-timer-set.service"),
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
    if let Err(why) = polkit_ok(&h.root) {
        bail!(
            "{why}. Managed units need polkit 0.106 or newer (JavaScript rules), so nothing was installed. \
             clamv still reads AIDE and rkhunter reports you mount into it."
        );
    }
    println!("Installing into {}:", h.root.display());
    for (rel, body, mode) in files(h.uid) {
        write(&h.root, &rel, &body, mode)?;
    }
    std::fs::create_dir_all(h.root.join("var/log/aide"))?;
    for d in [FIREWALL_DIR, TIMER_DIR] {
        use std::os::unix::fs::PermissionsExt;
        let p = h.root.join(d);
        std::fs::create_dir_all(&p)?;
        std::os::unix::fs::chown(&p, Some(h.uid), Some(0))?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750))?;
        println!("  /{d} (owned by clamv, 0750)");
    }
    for t in ["aide", "rkhunter"] {
        std::fs::create_dir_all(h.root.join(UNITS).join(format!("clamv-{t}-check.timer.d")))?;
    }
    imp::reload(&bus, clamv.is_none().then_some(h.root.as_path())).await?;
    if passwd(&h.root, h.uid).0 != Some(h.uid) {
        bail!(
            "systemd-sysusers did not add the clamv user; add it by hand with uid {}",
            h.uid
        );
    }
    println!(
        "Done. Mount /run/dbus/system_bus_socket (read-only), /{FIREWALL_DIR} and /{TIMER_DIR} (read-write) into clamv and its agents (the commented volume lines in the compose files), then recreate the container."
    );
    for n in notes(&h.root) {
        println!("Note: {n}");
    }
    Ok(())
}

/// polkit's version from dpkg where there is one, else whether rules.d exists.
fn polkit_ok(root: &Path) -> Result<(), String> {
    if let Ok(status) = std::fs::read_to_string(root.join("var/lib/dpkg/status")) {
        let mut found = None;
        for stanza in status.split("\n\n") {
            let field = |k: &str| {
                stanza
                    .lines()
                    .find_map(|l| l.strip_prefix(k))
                    .map(str::trim)
            };
            if matches!(field("Package:"), Some("polkitd" | "policykit-1"))
                && field("Status:").is_some_and(|s| s.ends_with(" installed"))
                && let Some(v) = field("Version:")
            {
                found = Some(v.to_owned());
                if field("Package:") == Some("polkitd") {
                    break;
                }
            }
        }
        if let Some(v) = found {
            return if polkit_version_ok(&v) {
                Ok(())
            } else {
                Err(format!("this host has polkit {v}"))
            };
        }
    }
    if root.join("usr/share/polkit-1/rules.d").is_dir()
        || root.join("etc/polkit-1/rules.d").is_dir()
    {
        Ok(())
    } else {
        Err("polkit with rules.d support was not found on this host".into())
    }
}

/// True for 0.106 and later, including the newer single-number versions (121, 122, ...).
fn polkit_version_ok(v: &str) -> bool {
    let v = v.split(':').next_back().unwrap_or(v);
    let mut parts = v.split(['.', '-', '+', '~']);
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    major > 0 || minor >= 106
}

/// What the host still lacks for the units to be of use. Paths are checked without
/// following links, since the host's absolute symlinks point outside its mount here.
fn notes(root: &Path) -> Vec<String> {
    let has = |rel: &[&str]| rel.iter().any(|r| root.join(r).symlink_metadata().is_ok());
    let mut v = Vec::new();
    if !has(&["usr/bin/aide"]) {
        v.push("/usr/bin/aide is missing; install AIDE and initialise its database to use the AIDE units.".to_owned());
    }
    if !has(&["usr/bin/rkhunter"]) {
        v.push(
            "/usr/bin/rkhunter is missing; install rkhunter to use the rkhunter units.".to_owned(),
        );
    }
    if !has(&["usr/sbin/nft", "usr/bin/nft", "sbin/nft"]) {
        v.push(
            "nft is missing; install nftables for the Firewall page to read and apply rules."
                .to_owned(),
        );
    }
    v
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
    for t in ["aide", "rkhunter"] {
        let _ = std::fs::remove_file(
            h.root
                .join(UNITS)
                .join(format!("clamv-{t}-check.timer.d/clamv-time.conf")),
        );
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
    fn notes_name_what_the_host_lacks() {
        let d = std::env::temp_dir().join(format!("clamv-notes-{}", std::process::id()));
        std::fs::create_dir_all(d.join("usr/bin")).expect("usr/bin");
        assert_eq!(notes(&d).len(), 3);
        std::fs::create_dir_all(d.join("usr/sbin")).expect("usr/sbin");
        for f in ["usr/bin/aide", "usr/bin/rkhunter", "usr/sbin/nft"] {
            std::fs::write(d.join(f), "").expect("tool");
        }
        assert!(notes(&d).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn polkit_must_take_javascript_rules() {
        for (v, ok) in [
            ("0.105-31+deb11u1", false),
            ("0.106-1", true),
            ("0.120-3", true),
            ("122-3", true),
            ("1:0.105-1", false),
        ] {
            assert_eq!(polkit_version_ok(v), ok, "{v}");
        }
        let d = std::env::temp_dir().join(format!("clamv-polkit-{}", std::process::id()));
        std::fs::create_dir_all(d.join("var/lib/dpkg")).expect("dpkg");
        assert!(polkit_ok(&d).is_err());
        std::fs::write(
            d.join("var/lib/dpkg/status"),
            "Package: bash\nStatus: install ok installed\nVersion: 5.2\n\nPackage: policykit-1\nStatus: install ok installed\nVersion: 0.105-31\n",
        )
        .expect("status");
        assert!(polkit_ok(&d).expect_err("old").contains("0.105"));
        std::fs::write(
            d.join("var/lib/dpkg/status"),
            "Package: polkitd\nStatus: install ok installed\nVersion: 122-3\n",
        )
        .expect("status");
        assert!(polkit_ok(&d).is_ok());
        let _ = std::fs::remove_dir_all(&d);
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
