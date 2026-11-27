//! Space that a folder walk can't see: other APFS volumes, local snapshots, swap.

use serde::Serialize;
use std::ffi::{CStr, CString};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct Volume {
    pub name: String,
    pub mount: String,
    pub device: String,
    pub fstype: String,
    pub used: u64,
    pub avail: u64,
    pub total: u64,
}

fn cstr(a: &[libc::c_char]) -> String {
    unsafe { CStr::from_ptr(a.as_ptr()) }.to_string_lossy().into_owned()
}

fn from_statfs(s: &libc::statfs) -> Volume {
    let bs = s.f_bsize as u64;
    Volume {
        name: String::new(),
        mount: cstr(&s.f_mntonname),
        device: cstr(&s.f_mntfromname),
        fstype: cstr(&s.f_fstypename),
        used: s.f_blocks.saturating_sub(s.f_bfree) * bs,
        avail: s.f_bavail * bs,
        total: s.f_blocks * bs,
    }
}

pub fn volume_of(path: &Path) -> Option<Volume> {
    let c = CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    Some(from_statfs(&s))
}

pub fn all_volumes() -> Vec<Volume> {
    let mut p: *mut libc::statfs = std::ptr::null_mut();
    let n = unsafe { libc::getmntinfo(&mut p, libc::MNT_NOWAIT) };
    if n <= 0 || p.is_null() {
        return vec![];
    }
    unsafe { std::slice::from_raw_parts(p, n as usize) }.iter().map(from_statfs).collect()
}

/// "/dev/disk3s5" -> "disk3"
pub fn container_of(device: &str) -> Option<String> {
    let rest = device.strip_prefix("/dev/disk")?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() { None } else { Some(format!("disk{digits}")) }
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemFacts {
    /// Other APFS volumes sharing the same disk (they compete for the same free space).
    pub sibling_volumes: Vec<Volume>,
    pub local_snapshots: Vec<String>,
    pub swap_used: Option<u64>,
    pub sleepimage: Option<u64>,
}

/// Per-volume usage from diskutil. statfs reports the whole container's usage for every
/// APFS volume, so it can't tell volumes apart.
fn apfs_volumes() -> Vec<(String, String, u64, String)> {
    let Ok(out) = Command::new("sh").args(["-c", "diskutil apfs list -plist | plutil -convert json -o - -"]).output() else {
        return vec![];
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else { return vec![] };
    let mut res = vec![];
    for c in v["Containers"].as_array().into_iter().flatten() {
        let cref = c["ContainerReference"].as_str().unwrap_or("").to_string();
        for vol in c["Volumes"].as_array().into_iter().flatten() {
            res.push((
                cref.clone(),
                vol["DeviceIdentifier"].as_str().unwrap_or("").to_string(),
                vol["CapacityInUse"].as_u64().unwrap_or(0),
                vol["Name"].as_str().unwrap_or("").to_string(),
            ));
        }
    }
    res
}

/// "/dev/disk3s1s1" (a sealed-system snapshot) belongs to volume "disk3s1".
fn same_dev(mnt_from: &str, dev: &str) -> bool {
    let m = mnt_from.trim_start_matches("/dev/");
    m == dev || m.starts_with(&format!("{dev}s"))
}

pub fn gather(scan_volume: &Volume) -> (SystemFacts, Option<u64>) {
    let container = container_of(&scan_volume.device);
    let mounts = all_volumes();
    let mut scan_used = None;
    let mut sibling_volumes = Vec::new();
    for (cref, dev, used, name) in apfs_volumes() {
        if Some(&cref) != container.as_ref() {
            continue;
        }
        if same_dev(&scan_volume.device, &dev) {
            scan_used = Some(used);
            continue;
        }
        if used < 500_000_000 {
            continue;
        }
        let mount = mounts.iter().find(|m| same_dev(&m.device, &dev)).map(|m| m.mount.clone()).unwrap_or_default();
        sibling_volumes.push(Volume { name, mount, device: dev, fstype: "apfs".into(), used, avail: 0, total: 0 });
    }
    sibling_volumes.sort_by(|a, b| b.used.cmp(&a.used));

    let local_snapshots = Command::new("tmutil")
        .args(["listlocalsnapshots", "/"])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| l.contains("com.apple"))
                .map(|l| l.trim().to_string())
                .collect()
        })
        .unwrap_or_default();

    // "total = 2048.00M  used = 1234.50M  free = ..."
    let swap_used = Command::new("sysctl").args(["-n", "vm.swapusage"]).output().ok().and_then(|o| {
        let s = String::from_utf8_lossy(&o.stdout).to_string();
        let i = s.find("used = ")?;
        let v = s[i + 7..].split_whitespace().next()?;
        let (num, unit) = v.split_at(v.len() - 1);
        let mult = match unit { "K" => 1e3, "M" => 1e6, "G" => 1e9, _ => 1.0 };
        num.parse::<f64>().ok().map(|n| (n * mult * 1.024f64.powi(match unit { "K" => 1, "M" => 2, "G" => 3, _ => 0 })) as u64)
    });

    let sleepimage = std::fs::metadata("/private/var/vm/sleepimage").ok().map(|m| {
        use std::os::unix::fs::MetadataExt;
        m.blocks() * 512
    });

    (SystemFacts { sibling_volumes, local_snapshots, swap_used, sleepimage }, scan_used)
}
