use hotpan_core::LeaseId;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A private per-lease directory. Purged explicitly at end of lease, and on
/// drop if that never happened.
#[derive(Debug)]
pub struct Workspace {
    lease: LeaseId,
    dir: PathBuf,
    purged: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PurgeReceipt {
    pub lease_id: LeaseId,
    pub files_removed: u64,
    pub bytes_removed: u64,
}

const PREFIX: &str = "hotpan-lease-";

impl Workspace {
    pub fn create(workroot: &Path, lease: LeaseId) -> std::io::Result<Self> {
        std::fs::create_dir_all(workroot)?;
        let dir = workroot.join(format!("{PREFIX}{lease}"));
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(&dir)?;
        Ok(Self { lease, dir, purged: false })
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    pub fn lease(&self) -> LeaseId {
        self.lease
    }

    pub fn purge(mut self) -> std::io::Result<PurgeReceipt> {
        self.purge_inner()
    }

    fn purge_inner(&mut self) -> std::io::Result<PurgeReceipt> {
        let (files, bytes) = tally(&self.dir);
        if self.dir.exists() {
            make_writable(&self.dir);
            std::fs::remove_dir_all(&self.dir)?;
        }
        self.purged = true;
        Ok(PurgeReceipt { lease_id: self.lease, files_removed: files, bytes_removed: bytes })
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        if !self.purged {
            let _ = self.purge_inner();
        }
    }
}

fn tally(dir: &Path) -> (u64, u64) {
    let mut files = 0;
    let mut bytes = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let Ok(m) = e.path().symlink_metadata() else { continue };
            if m.is_dir() {
                stack.push(e.path());
            } else {
                files += 1;
                bytes += m.len();
            }
        }
    }
    (files, bytes)
}

/// A task may chmod its own files read-only; make sure purge still succeeds.
fn make_writable(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                if e.path().symlink_metadata().map(|m| m.is_dir()).unwrap_or(false) {
                    stack.push(e.path());
                }
            }
        }
    }
}

/// Remove leftovers from a previous crashed session. A node never resumes
/// old work: no node persistence is assumed.
pub fn purge_stale(workroot: &Path) -> usize {
    let Ok(rd) = std::fs::read_dir(workroot) else { return 0 };
    let mut n = 0;
    for e in rd.flatten() {
        if e.file_name().to_string_lossy().starts_with(PREFIX) {
            make_writable(&e.path());
            if std::fs::remove_dir_all(e.path()).is_ok() {
                n += 1;
            }
        }
    }
    n
}
