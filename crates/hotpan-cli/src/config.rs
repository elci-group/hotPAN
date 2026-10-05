//! File formats: job specs (TOML or JSON) and node configuration (TOML).

use anyhow::{Context, Result};
use hotpan_core::*;
use hotpan_probe::Overrides;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub fn load_job(path: &Path) -> Result<JobSpec> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let job: JobSpec = if path.extension().is_some_and(|e| e == "json") {
        serde_json::from_str(&text)?
    } else {
        toml::from_str(&text)?
    };
    job.validate()?;
    Ok(job)
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeFile {
    pub label: Option<String>,
    pub max_leases: Option<u32>,
    /// Absolute paths `exec` tasks may run. Empty means builtins only.
    #[serde(default)]
    pub allowed_programs: BTreeSet<String>,
    pub workroot: Option<PathBuf>,
    /// The most any single lease may take on this device.
    pub max: Option<ResourceCeiling>,
    #[serde(default)]
    pub protection: Option<hotpan_heuristic::Protection>,
    #[serde(default)]
    pub device: Overrides,
}

pub fn load_node(path: Option<&Path>) -> Result<NodeFile> {
    let Some(path) = path else { return Ok(NodeFile::default()) };
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let f: NodeFile = toml::from_str(&text)?;
    for p in &f.allowed_programs {
        anyhow::ensure!(p.starts_with('/'), "allowed program `{p}` must be an absolute path");
    }
    Ok(f)
}

pub fn default_workroot() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir)
        .join("hotpan")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn examples() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples")
    }

    #[test]
    fn shipped_examples_parse() {
        let job = load_job(&examples().join("photo-pipeline.toml")).unwrap();
        assert!(job.fragments.len() >= 4);
        let capture = job.fragments.iter().find(|f| f.id == "capture").unwrap();
        assert!(capture.requires.contains(&Capability::Camera));
        let locate = job.fragments.iter().find(|f| f.id == "geotag").unwrap();
        assert_eq!(locate.privacy, Privacy::MustStayOn("location-history".into()));
        let node = load_node(Some(&examples().join("node.toml"))).unwrap();
        assert!(node.device.capabilities.contains(&Capability::LocalData("location-history".into())));
        assert!(node.allowed_programs.iter().all(|p| p.starts_with('/')));
    }

    #[test]
    fn json_jobs_too() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.json");
        std::fs::write(
            &p,
            r#"{"name":"j","fragments":[{"id":"a","task":{"type":"builtin","op":"echo","payload":"hi"}}]}"#,
        )
        .unwrap();
        let j = load_job(&p).unwrap();
        assert_eq!(j.max_attempts, 3);
        assert_eq!(j.fragments[0].task, TaskSpec::Builtin(BuiltinTask::Echo { payload: "hi".into() }));
    }
}
