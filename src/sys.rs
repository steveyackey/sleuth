//! Space that a folder walk can't see.
//! macOS: other APFS volumes, local snapshots, swap.
//! Linux: deleted files still held open by running processes, swap.

use serde::Serialize;
use std::ffi::CString;
use std::path::Path;

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

#[derive(Debug, Clone, Serialize)]
pub struct SystemFacts {
    /// Other APFS volumes sharing the same disk (they compete for the same free space).
    pub sibling_volumes: Vec<Volume>,
    pub local_snapshots: Vec<String>,
    pub swap_used: Option<u64>,
    pub sleepimage: Option<u64>,
    /// Deleted files on the scanned filesystem that a process still holds open (Linux).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deleted_open: Vec<OpenDeleted>,
    /// False when some processes couldn't be inspected (not root).
    pub saw_all_processes: bool,
}

/// Space held by one process through files that were deleted but are still open.
#[derive(Debug, Clone, Serialize)]
pub struct OpenDeleted {
    pub pid: u32,
    pub process: String,
    pub bytes: u64,
    pub files: usize,
    pub example: String,
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::ffi::CStr;
    use std::process::Command;

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

        (SystemFacts { sibling_volumes, local_snapshots, swap_used, sleepimage, deleted_open: vec![], saw_all_processes: true }, scan_used)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::os::unix::fs::MetadataExt;

    /// One line of /proc/self/mountinfo: (mount point, source device, fs type).
    fn mounts() -> Vec<(String, String, String)> {
        let Ok(s) = std::fs::read_to_string("/proc/self/mountinfo") else { return vec![] };
        s.lines()
            .filter_map(|l| {
                let (pre, post) = l.split_once(" - ")?;
                let mount = unescape(pre.split(' ').nth(4)?);
                let mut post = post.split(' ');
                let fstype = post.next()?.to_string();
                let source = unescape(post.next().unwrap_or(""));
                Some((mount, source, fstype))
            })
            .collect()
    }

    /// mountinfo escapes space, tab, newline and backslash as \ooo octal.
    fn unescape(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
                out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
                i += 4;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    pub fn volume_of(path: &Path) -> Option<Volume> {
        let c = CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
        let mut s: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
            return None;
        }
        // f_blocks is in units of f_frsize (f_bsize is only the preferred I/O size).
        let bs = if s.f_frsize > 0 { s.f_frsize as u64 } else { s.f_bsize as u64 };
        // The mount holding path: the longest mount point it sits under (the last one wins on overmounts).
        let (mount, device, fstype) = mounts()
            .into_iter()
            .filter(|(m, _, _)| path.starts_with(m))
            .fold(None::<(String, String, String)>, |best, m| match &best {
                Some(b) if b.0.len() > m.0.len() => best,
                _ => Some(m),
            })
            .unwrap_or_default();
        Some(Volume {
            name: String::new(),
            mount,
            device,
            fstype,
            used: (s.f_blocks as u64).saturating_sub(s.f_bfree as u64) * bs,
            avail: s.f_bavail as u64 * bs,
            total: s.f_blocks as u64 * bs,
        })
    }

    /// Files that were deleted while a process had them open keep their space until the process
    /// closes them. A walk can't see them; /proc/<pid>/fd can.
    fn deleted_open(dev: u64) -> (Vec<OpenDeleted>, bool) {
        let mut seen: HashSet<u64> = HashSet::new();
        let mut by_pid: HashMap<u32, OpenDeleted> = HashMap::new();
        let mut saw_all = true;
        let Ok(procs) = std::fs::read_dir("/proc") else { return (vec![], false) };
        for p in procs.flatten() {
            let Some(pid) = p.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else {
                saw_all = false;
                continue;
            };
            for fd in fds.flatten() {
                let Ok(target) = std::fs::read_link(fd.path()) else { continue };
                let t = target.to_string_lossy();
                let Some(name) = t.strip_suffix(" (deleted)") else { continue };
                // metadata() follows the magic link to the open file itself.
                let Ok(md) = std::fs::metadata(fd.path()) else { continue };
                if md.dev() != dev || md.nlink() != 0 || !md.is_file() || !seen.insert(md.ino()) {
                    continue;
                }
                let bytes = md.blocks() * 512;
                if bytes == 0 {
                    continue;
                }
                let e = by_pid.entry(pid).or_insert_with(|| OpenDeleted {
                    pid,
                    process: std::fs::read_to_string(p.path().join("comm")).unwrap_or_default().trim().to_string(),
                    bytes: 0,
                    files: 0,
                    example: name.to_string(),
                });
                e.bytes += bytes;
                e.files += 1;
            }
        }
        let mut v: Vec<OpenDeleted> = by_pid.into_values().collect();
        v.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        (v, saw_all)
    }

    fn swap_used() -> Option<u64> {
        let s = std::fs::read_to_string("/proc/meminfo").ok()?;
        let kb = |k: &str| -> Option<u64> {
            s.lines().find_map(|l| l.strip_prefix(k)?.trim().strip_suffix("kB")?.trim().parse().ok())
        };
        Some(kb("SwapTotal:")?.saturating_sub(kb("SwapFree:")?) * 1024)
    }

    pub fn gather(scan_volume: &Volume) -> (SystemFacts, Option<u64>) {
        let dev = std::fs::metadata(&scan_volume.mount).map(|m| m.dev()).ok();
        let (deleted_open, saw_all_processes) = dev.map(deleted_open).unwrap_or((vec![], true));
        (
            SystemFacts {
                sibling_volumes: vec![],
                local_snapshots: vec![],
                swap_used: swap_used(),
                sleepimage: None,
                deleted_open,
                saw_all_processes,
            },
            None,
        )
    }
}

pub use imp::{gather, volume_of};
