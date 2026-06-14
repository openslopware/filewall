use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::Ordering;

pub fn spawn_watcher(config_path: &Path, rules_path: &Path) {
    let config_dir = match config_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(d) => d.to_path_buf(),
        None => {
            eprintln!("[filewalld] watcher: no parent dir for config, file watching disabled");
            return;
        }
    };
    let config_name: OsString = match config_path.file_name() {
        Some(n) => n.to_os_string(),
        None => {
            eprintln!("[filewalld] watcher: no filename for config, file watching disabled");
            return;
        }
    };
    let rules_dir = match rules_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(d) => d.to_path_buf(),
        None => {
            eprintln!("[filewalld] watcher: no parent dir for rules, file watching disabled");
            return;
        }
    };
    let rules_name: OsString = match rules_path.file_name() {
        Some(n) => n.to_os_string(),
        None => {
            eprintln!("[filewalld] watcher: no filename for rules, file watching disabled");
            return;
        }
    };

    let inotify = match Inotify::init(InitFlags::IN_CLOEXEC) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("[filewalld] watcher: inotify init failed ({e}), file watching disabled");
            return;
        }
    };

    let mask = AddWatchFlags::IN_CLOSE_WRITE | AddWatchFlags::IN_MOVED_TO;
    if let Err(e) = inotify.add_watch(&config_dir, mask) {
        eprintln!(
            "[filewalld] watcher: cannot watch {}: {e}, file watching disabled",
            config_dir.display()
        );
        return;
    }
    if rules_dir != config_dir {
        if let Err(e) = inotify.add_watch(&rules_dir, mask) {
            eprintln!(
                "[filewalld] watcher: cannot watch {}: {e}, file watching disabled",
                rules_dir.display()
            );
            return;
        }
    }
    eprintln!("[filewalld] watcher: watching for config/rules changes");

    std::thread::spawn(move || loop {
        let events = match inotify.read_events() {
            Ok(evs) => evs,
            Err(e) => {
                eprintln!("[filewalld] watcher: read error ({e}), file watching disabled");
                break;
            }
        };
        for ev in &events {
            if ev.name.as_deref() == Some(&*config_name)
                || ev.name.as_deref() == Some(&*rules_name)
            {
                crate::RELOAD.store(true, Ordering::SeqCst);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RELOAD;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "filewall-watcher-{}-{}-{}-{}",
            tag,
            std::process::id(),
            ts.as_secs(),
            ts.subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn wait_for_reload(timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if RELOAD.load(Ordering::SeqCst) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn config_close_write_triggers_reload() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmp_dir("cfg");
        let config_path = dir.join("config.toml");
        let rules_path = dir.join("rules.toml");
        std::fs::write(&config_path, b"").unwrap();
        std::fs::write(&rules_path, b"").unwrap();

        spawn_watcher(&config_path, &rules_path);
        std::thread::sleep(Duration::from_millis(50)); // let watcher thread settle

        RELOAD.store(false, Ordering::SeqCst);
        std::fs::write(&config_path, b"default_action = \"prompt\"").unwrap();

        assert!(wait_for_reload(Duration::from_millis(500)), "RELOAD not set after config write");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
