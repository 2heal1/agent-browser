use std::env;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const HOME_ENV: &str = "AGENT_BROWSER_HOME";
static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Root directory for agent-browser-owned state, configuration, downloads,
/// and temporary artifacts.
///
/// `AGENT_BROWSER_HOME` is intentionally independent from the operating
/// system's `HOME`: sandboxed callers can relocate agent-browser without
/// changing how unrelated tools resolve their own files.
pub fn agent_browser_home() -> PathBuf {
    let explicit = env::var_os(HOME_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    resolve_agent_browser_home(
        explicit,
        dirs::home_dir().map(|home| home.join(".agent-browser")),
        fallback_home(),
    )
}

fn resolve_agent_browser_home(
    explicit: Option<PathBuf>,
    default_home: Option<PathBuf>,
    fallback: PathBuf,
) -> PathBuf {
    if let Some(path) = explicit {
        return path;
    }

    match default_home {
        Some(path) if directory_is_writable(&path) => path,
        _ => fallback,
    }
}

/// Short, per-user fallback for Unix-domain socket compatibility and to avoid
/// sharing state across users of the same host.
fn fallback_home() -> PathBuf {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::geteuid() };
        for suffix in 0..100 {
            let name = if suffix == 0 {
                format!("agent-browser-{uid}")
            } else {
                format!("agent-browser-{uid}-{suffix}")
            };
            let path = PathBuf::from("/tmp").join(name);
            if prepare_private_directory(&path, uid) {
                return path;
            }
        }

        env::temp_dir().join(format!("agent-browser-{uid}-{}", std::process::id()))
    }

    #[cfg(not(unix))]
    {
        env::temp_dir().join(format!("agent-browser-{}", std::process::id()))
    }
}

#[cfg(unix)]
fn prepare_private_directory(path: &Path, uid: u32) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return false,
    }

    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() || metadata.uid() != uid
    {
        return false;
    }

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).is_ok()
}

fn directory_is_writable(path: &Path) -> bool {
    if fs::create_dir_all(path).is_err() {
        return false;
    }

    let probe = path.join(format!(
        ".write-probe-{}-{}",
        std::process::id(),
        PROBE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let writable = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .is_ok();
    if writable {
        let _ = fs::remove_file(probe);
    }
    writable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_home_wins_without_being_probed() {
        let explicit = PathBuf::from("/explicit/agent-browser-home");
        let result = resolve_agent_browser_home(
            Some(explicit.clone()),
            Some(PathBuf::from("/default/home")),
            PathBuf::from("/fallback"),
        );
        assert_eq!(result, explicit);
    }

    #[test]
    fn unwritable_default_uses_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let not_a_directory = temp.path().join("file");
        fs::write(&not_a_directory, "x").unwrap();
        let fallback = temp.path().join("fallback");

        assert_eq!(
            resolve_agent_browser_home(None, Some(not_a_directory), fallback.clone()),
            fallback
        );
    }

    #[test]
    fn writable_default_is_preserved() {
        let temp = tempfile::tempdir().unwrap();
        let default = temp.path().join("state");
        assert_eq!(
            resolve_agent_browser_home(None, Some(default.clone()), temp.path().join("fallback")),
            default
        );
    }
}
