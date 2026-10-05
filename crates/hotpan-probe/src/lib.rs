//! Capability probing: how a device learns its own capability vector.
//!
//! [`SysProbe`] reads Linux sysfs/procfs (which covers Android when readable)
//! and, on Termux, discovers sensors via the `termux-*` API binaries.
//! Anything a probe cannot observe it reports conservatively (unknown user
//! activity, modest thermal headroom) rather than optimistically.
//! [`ScriptedProbe`] lets simulations and tests drive a vector by hand.

#![forbid(unsafe_code)]

use hotpan_core::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub trait Probe: Send + Sync {
    fn sample(&self) -> CapabilityVector;
    fn device_class(&self) -> DeviceClass;
}

/// Operator-declared facts a probe cannot discover (site, local data,
/// authenticated sessions) and corrections for ones it gets wrong.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Overrides {
    pub device_class: Option<DeviceClass>,
    #[serde(default)]
    pub capabilities: BTreeSet<Capability>,
    pub site: Option<String>,
    pub lan: Option<String>,
    pub user_activity: Option<UserActivity>,
    pub relative_perf: Option<f32>,
    pub cost: Option<f32>,
    pub metered: Option<bool>,
}

pub struct SysProbe {
    root: PathBuf,
    overrides: Overrides,
    /// Look for termux-* binaries on PATH (disabled in tests).
    termux: bool,
}

impl SysProbe {
    pub fn new(overrides: Overrides) -> Self {
        Self { root: PathBuf::from("/"), overrides, termux: true }
    }

    /// Probe a fake filesystem tree rooted at `root` (for tests).
    pub fn with_root(root: impl Into<PathBuf>, overrides: Overrides) -> Self {
        Self { root: root.into(), overrides, termux: false }
    }

    fn p(&self, rel: &str) -> PathBuf {
        self.root.join(rel.trim_start_matches('/'))
    }

    fn is_android(&self) -> bool {
        self.p("/system/build.prop").exists() || (self.termux && std::env::var_os("TERMUX_VERSION").is_some())
    }

    fn power(&self) -> (PowerState, bool) {
        let mut battery: Option<f32> = None;
        let mut charging = false;
        let mut mains_online = false;
        for dir in list(&self.p("/sys/class/power_supply")) {
            match read(&dir.join("type")).as_deref() {
                Some("Battery") => {
                    if let Some(c) = read(&dir.join("capacity")).and_then(|s| s.parse::<f32>().ok()) {
                        battery = Some(battery.map_or(c, |b: f32| b.min(c)));
                    }
                    if matches!(read(&dir.join("status")).as_deref(), Some("Charging" | "Full")) {
                        charging = true;
                    }
                }
                Some(_) if read(&dir.join("online")).as_deref() == Some("1") => mains_online = true,
                _ => {}
            }
        }
        if battery.is_none() && self.termux && self.is_android() {
            if let Some((pct, chg)) = termux_battery() {
                return (PowerState::battery(pct, chg), true);
            }
        }
        match battery {
            Some(pct) => (PowerState::battery(pct, charging || mains_online), true),
            None => (PowerState::mains(), false),
        }
    }

    fn thermal(&self) -> f32 {
        const AMBIENT: f32 = 35.0;
        let mut headroom: Option<f32> = None;
        for zone in list(&self.p("/sys/class/thermal")) {
            if !zone.file_name().is_some_and(|n| n.to_string_lossy().starts_with("thermal_zone")) {
                continue;
            }
            let Some(t) = read(&zone.join("temp")).and_then(|s| s.parse::<f32>().ok()).map(|m| m / 1000.0) else {
                continue;
            };
            // Disabled or bogus sensors report <= 0.
            if t <= 0.0 || t > 150.0 {
                continue;
            }
            let mut crit = 95.0_f32;
            for i in 0..16 {
                let ty = read(&zone.join(format!("trip_point_{i}_type")));
                let Some(ty) = ty else { break };
                if ty == "critical" || ty == "hot" {
                    if let Some(c) =
                        read(&zone.join(format!("trip_point_{i}_temp"))).and_then(|s| s.parse::<f32>().ok())
                    {
                        let c = c / 1000.0;
                        if c > AMBIENT {
                            crit = crit.min(c);
                        }
                    }
                }
            }
            let h = ((crit - t) / (crit - AMBIENT)).clamp(0.0, 1.0);
            headroom = Some(headroom.map_or(h, |x| x.min(h)));
        }
        // Unknown thermal state is reported as moderate, not as cold.
        headroom.unwrap_or(0.7)
    }

    fn memory(&self) -> MemoryState {
        let text = read(&self.p("/proc/meminfo")).unwrap_or_default();
        let field = |name: &str| -> u64 {
            text.lines()
                .find(|l| l.starts_with(name))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
                .map(|kb| kb / 1024)
                .unwrap_or(0)
        };
        MemoryState { total_mb: field("MemTotal:"), available_mb: field("MemAvailable:") }
    }

    fn compute(&self) -> ComputeState {
        let from_cpuinfo = read(&self.p("/proc/cpuinfo"))
            .map(|t| t.lines().filter(|l| l.starts_with("processor")).count() as u32)
            .filter(|&n| n > 0);
        let cpus =
            from_cpuinfo.or_else(|| std::thread::available_parallelism().ok().map(|n| n.get() as u32)).unwrap_or(1);
        let load = read(&self.p("/proc/loadavg"))
            .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse::<f32>().ok()))
            .unwrap_or(0.0);
        let default_perf = if self.is_android() { 0.5 } else { 1.0 };
        ComputeState {
            logical_cpus: cpus,
            busy: (load / cpus as f32).clamp(0.0, 1.0),
            relative_perf: self.overrides.relative_perf.unwrap_or(default_perf),
        }
    }

    fn network(&self, caps: &mut BTreeSet<Capability>) -> NetworkState {
        let mut best = NetworkKind::Offline;
        for dev in list(&self.p("/sys/class/net")) {
            let name = dev.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if name == "lo" || read(&dev.join("operstate")).as_deref() != Some("up") {
                continue;
            }
            let kind = if dev.join("wireless").exists() || name.starts_with("wl") {
                NetworkKind::Wifi
            } else if ["rmnet", "ccmni", "wwan", "ppp"].iter().any(|p| name.starts_with(p)) {
                caps.insert(Capability::Cellular);
                NetworkKind::Cellular
            } else if name.starts_with("eth") || name.starts_with("en") {
                NetworkKind::Ethernet
            } else {
                continue;
            };
            best = best.max(kind);
        }
        if matches!(best, NetworkKind::Wifi | NetworkKind::Ethernet) {
            caps.insert(Capability::LanPresence);
        }
        let metered = self.overrides.metered.unwrap_or(best == NetworkKind::Cellular);
        NetworkState { kind: best, metered, rtt_ms: None }
    }

    fn devices(&self, caps: &mut BTreeSet<Capability>) {
        let has_prefix = |dir: &str, prefix: &str| {
            list(&self.p(dir)).iter().any(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with(prefix)))
        };
        if has_prefix("/dev", "video") {
            caps.insert(Capability::Camera);
        }
        if has_prefix("/sys/class/bluetooth", "hci") {
            caps.insert(Capability::Bluetooth);
        }
        if has_prefix("/sys/class/sound", "pcmC")
            && list(&self.p("/sys/class/sound"))
                .iter()
                .any(|p| p.file_name().is_some_and(|n| n.to_string_lossy().ends_with('c')))
        {
            // A capture PCM device (pcmC*D*c) means a microphone path exists.
            caps.insert(Capability::Microphone);
        }
        if has_prefix("/dev/dri", "renderD") {
            caps.insert(Capability::Gpu);
        }
        if self.termux {
            for (bin, cap) in [
                ("termux-camera-photo", Capability::Camera),
                ("termux-microphone-record", Capability::Microphone),
                ("termux-location", Capability::Gps),
                ("termux-sensor", Capability::Accelerometer),
                ("termux-nfc", Capability::Nfc),
                ("termux-keystore", Capability::HardwareKeystore),
            ] {
                if on_path(bin) {
                    caps.insert(cap);
                }
            }
        }
    }
}

impl Probe for SysProbe {
    fn sample(&self) -> CapabilityVector {
        let mut caps = BTreeSet::new();
        let (power, _) = self.power();
        let network = self.network(&mut caps);
        self.devices(&mut caps);
        caps.extend(self.overrides.capabilities.iter().cloned());
        let cost = self.overrides.cost.unwrap_or(0.0) + if network.metered { 1.0 } else { 0.0 };
        CapabilityVector {
            power,
            thermal_headroom: self.thermal(),
            network,
            compute: self.compute(),
            memory: self.memory(),
            capabilities: caps,
            locality: Locality { site: self.overrides.site.clone(), lan: self.overrides.lan.clone() },
            user_activity: self.overrides.user_activity.unwrap_or_default(),
            cost,
            observed_at: now_millis(),
        }
    }

    fn device_class(&self) -> DeviceClass {
        if let Some(c) = self.overrides.device_class {
            return c;
        }
        if self.is_android() {
            DeviceClass::Phone
        } else if self.power().1 {
            DeviceClass::Laptop
        } else {
            DeviceClass::Desktop
        }
    }
}

fn read(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

fn list(p: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> =
        std::fs::read_dir(p).map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).collect()).unwrap_or_default();
    v.sort();
    v
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH").map(|paths| std::env::split_paths(&paths).any(|d| d.join(bin).is_file())).unwrap_or(false)
}

/// `termux-battery-status` blocks forever when the Termux:API app is missing,
/// so it gets a hard timeout.
fn termux_battery() -> Option<(f32, bool)> {
    if !on_path("termux-battery-status") {
        return None;
    }
    let mut child = std::process::Command::new("termux-battery-status")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut out = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take()?, &mut out).ok()?;
    parse_termux_battery(&out)
}

fn parse_termux_battery(json: &str) -> Option<(f32, bool)> {
    // Avoid a JSON dependency for two fields: "percentage": N, "status": "..."
    let num = json.split("\"percentage\"").nth(1)?.trim_start_matches([':', ' ']);
    let pct: f32 = num.split(|c: char| !c.is_ascii_digit() && c != '.').next()?.parse().ok()?;
    let status = json.split("\"status\"").nth(1).unwrap_or("");
    let charging = (status.contains("CHARGING") && !status.contains("DISCHARGING")) || status.contains("FULL");
    Some((pct, charging))
}

/// A probe whose vector is set by hand: simulations, tests, and fixed
/// "declared" nodes.
#[derive(Clone)]
pub struct ScriptedProbe {
    class: DeviceClass,
    vector: Arc<Mutex<CapabilityVector>>,
}

impl ScriptedProbe {
    pub fn new(class: DeviceClass, vector: CapabilityVector) -> Self {
        Self { class, vector: Arc::new(Mutex::new(vector)) }
    }
    pub fn update(&self, f: impl FnOnce(&mut CapabilityVector)) {
        f(&mut self.vector.lock().unwrap());
    }
}

impl Probe for ScriptedProbe {
    fn sample(&self) -> CapabilityVector {
        let mut v = self.vector.lock().unwrap().clone();
        v.observed_at = now_millis();
        v
    }
    fn device_class(&self) -> DeviceClass {
        self.class
    }
}

/// A reasonable starting vector for a scripted device of a given class.
pub fn template(class: DeviceClass) -> CapabilityVector {
    let (power, cpus, perf, mem, net) = match class {
        DeviceClass::Phone | DeviceClass::Tablet => (PowerState::battery(80.0, false), 8, 0.5, 6144, NetworkKind::Wifi),
        DeviceClass::Laptop => (PowerState::battery(80.0, true), 8, 0.9, 16384, NetworkKind::Wifi),
        _ => (PowerState::mains(), 8, 1.0, 16384, NetworkKind::Ethernet),
    };
    CapabilityVector {
        power,
        thermal_headroom: 0.8,
        network: NetworkState { kind: net, metered: false, rtt_ms: Some(20) },
        compute: ComputeState { logical_cpus: cpus, busy: 0.1, relative_perf: perf },
        memory: MemoryState { total_mb: mem, available_mb: mem / 2 },
        capabilities: BTreeSet::new(),
        locality: Locality::default(),
        user_activity: UserActivity::Idle,
        cost: 0.0,
        observed_at: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn put(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }

    fn phone_tree() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        put(r, "system/build.prop", "ro.product.model=Pixel\n");
        put(r, "sys/class/power_supply/battery/type", "Battery\n");
        put(r, "sys/class/power_supply/battery/capacity", "18\n");
        put(r, "sys/class/power_supply/battery/status", "Discharging\n");
        put(r, "sys/class/power_supply/usb/type", "USB\n");
        put(r, "sys/class/power_supply/usb/online", "0\n");
        put(r, "sys/class/thermal/thermal_zone0/temp", "65000\n");
        put(r, "sys/class/thermal/thermal_zone0/trip_point_0_type", "critical\n");
        put(r, "sys/class/thermal/thermal_zone0/trip_point_0_temp", "95000\n");
        put(r, "sys/class/thermal/thermal_zone1/temp", "-273000\n");
        put(r, "proc/meminfo", "MemTotal:  8000000 kB\nMemFree: 1 kB\nMemAvailable:  2048000 kB\n");
        put(r, "proc/cpuinfo", "processor\t: 0\nprocessor\t: 1\nprocessor\t: 2\nprocessor\t: 3\n");
        put(r, "proc/loadavg", "2.00 1.00 0.50 1/100 1\n");
        put(r, "sys/class/net/lo/operstate", "unknown\n");
        put(r, "sys/class/net/rmnet0/operstate", "up\n");
        put(r, "sys/class/net/wlan0/operstate", "down\n");
        put(r, "dev/video0", "");
        put(r, "sys/class/bluetooth/hci0/x", "");
        put(r, "sys/class/sound/pcmC0D0c/x", "");
        d
    }

    #[test]
    fn probes_a_phone_tree() {
        let d = phone_tree();
        let probe = SysProbe::with_root(
            d.path(),
            Overrides {
                capabilities: BTreeSet::from([Capability::LocalData("photos".into())]),
                site: Some("home".into()),
                ..Default::default()
            },
        );
        let v = probe.sample();
        assert_eq!(probe.device_class(), DeviceClass::Phone);
        assert_eq!(v.power, PowerState::battery(18.0, false));
        assert!((v.thermal_headroom - 0.5).abs() < 1e-3, "{}", v.thermal_headroom);
        assert_eq!(v.memory, MemoryState { total_mb: 7812, available_mb: 2000 });
        assert_eq!(v.compute.logical_cpus, 4);
        assert!((v.compute.busy - 0.5).abs() < 1e-6);
        assert_eq!(v.compute.relative_perf, 0.5);
        assert_eq!(v.network.kind, NetworkKind::Cellular);
        assert!(v.network.metered);
        assert_eq!(v.cost, 1.0);
        for c in [
            Capability::Camera,
            Capability::Bluetooth,
            Capability::Microphone,
            Capability::Cellular,
            Capability::LocalData("photos".into()),
        ] {
            assert!(v.has(&c), "missing {c}");
        }
        assert!(!v.has(&Capability::LanPresence));
        assert_eq!(v.locality.site.as_deref(), Some("home"));
        assert_eq!(v.user_activity, UserActivity::Unknown);
    }

    #[test]
    fn charger_online_counts_as_charging_and_wifi_beats_cellular() {
        let d = phone_tree();
        put(d.path(), "sys/class/power_supply/usb/online", "1\n");
        put(d.path(), "sys/class/net/wlan0/operstate", "up\n");
        let v = SysProbe::with_root(d.path(), Overrides::default()).sample();
        assert!(v.power.charging);
        assert_eq!(v.network.kind, NetworkKind::Wifi);
        assert!(!v.network.metered);
        assert!(v.has(&Capability::LanPresence));
    }

    #[test]
    fn empty_tree_is_conservative() {
        let d = tempfile::tempdir().unwrap();
        let p = SysProbe::with_root(d.path(), Overrides::default());
        let v = p.sample();
        assert_eq!(v.power, PowerState::mains());
        assert_eq!(v.thermal_headroom, 0.7);
        assert_eq!(v.network.kind, NetworkKind::Offline);
        assert_eq!(p.device_class(), DeviceClass::Desktop);
    }

    #[test]
    fn termux_battery_json() {
        let j = r#"{ "health": "GOOD", "percentage": 42, "plugged": "UNPLUGGED", "status": "DISCHARGING" }"#;
        assert_eq!(parse_termux_battery(j), Some((42.0, false)));
        let j = r#"{"percentage":97,"status":"CHARGING"}"#;
        assert_eq!(parse_termux_battery(j), Some((97.0, true)));
    }

    #[test]
    fn real_host_probe_does_not_panic() {
        let v = SysProbe::new(Overrides::default()).sample();
        assert!(v.compute.logical_cpus >= 1);
        assert!((0.0..=1.0).contains(&v.thermal_headroom));
    }
}
