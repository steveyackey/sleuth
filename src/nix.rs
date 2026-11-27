//! Nix store forensics: what keeps each store path alive, and what letting go would free.
//! Uses only read-only nix queries (--print-roots, --print-dead, -qR).

use crate::scan::Scanner;
use crate::util::*;
use serde::Serialize;
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum PinKind {
    OldGenerations,
    InUse,
    BuildResult,
    Direnv,
    Runtime,
    Other,
}

#[derive(Serialize, Clone, Debug)]
pub struct Pin {
    pub kind: PinKind,
    pub label: String,
    pub links: Vec<PathBuf>,
    /// Freed if this pin alone is removed (then GC'd).
    pub unique_bytes: u64,
    pub closure_bytes: u64,
    pub oldest: i64,
    pub newest: i64,
    pub command: String,
}

#[derive(Serialize, Debug)]
pub struct NixReport {
    pub store_bytes: u64,
    pub store_paths: usize,
    pub dead_bytes: u64,
    pub dead_paths: usize,
    pub pins: Vec<Pin>,
    /// Freed only if several removable pins all go (shared between them).
    pub shared_removable_bytes: u64,
    pub auto_optimise: Option<bool>,
    pub min_free: Option<u64>,
    pub gc_job: Option<String>,
    pub determinate: bool,
    /// Running NixOS: nix.conf is generated, so settings belong in configuration.nix.
    pub nixos: bool,
    /// Configuration suggestions (auto-optimise, automatic GC).
    pub tips: Vec<Tip>,
    pub seconds: f64,
    pub notes: Vec<String>,
}

fn bin(name: &str) -> String {
    for dir in ["/nix/var/nix/profiles/default/bin", "/run/current-system/sw/bin"] {
        let p = format!("{dir}/{name}");
        if Path::new(&p).exists() {
            return p;
        }
    }
    name.to_string()
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(bin(cmd)).args(args).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

fn base(store_path: &str) -> Option<&str> {
    store_path.strip_prefix("/nix/store/")?.split('/').next().filter(|s| !s.is_empty())
}

fn link_mtime(p: &Path) -> i64 {
    std::fs::symlink_metadata(p).map(|m| m.mtime()).unwrap_or(0)
}

/// "/a/b/system-12-link" -> Some(("/a/b/system", 12))
fn generation(link: &Path) -> Option<(PathBuf, u64)> {
    let name = link.file_name()?.to_str()?;
    let stem = name.strip_suffix("-link")?;
    let (prof, num) = stem.rsplit_once('-')?;
    let n = num.parse().ok()?;
    Some((link.with_file_name(prof), n))
}

#[derive(Serialize, Clone, Debug)]
pub struct Tip {
    pub id: &'static str,
    pub problem: String,
    /// First entry is the command to run now; the rest make it permanent.
    pub fix: Vec<String>,
}

fn make_tips(auto_optimise: Option<bool>, gc_job: &Option<String>, min_free: Option<u64>, determinate: bool, nixos: bool) -> Vec<Tip> {
    let conf = if determinate { "/etc/nix/nix.custom.conf" } else { "/etc/nix/nix.conf" };
    let mut tips = Vec::new();
    if auto_optimise == Some(false) {
        tips.push(Tip {
            id: "nix-auto-optimise",
            problem: "auto-optimise-store is off. Identical files are stored once per path; optimise hard-links them (nothing is removed)".into(),
            fix: vec![
                "nix store optimise".into(),
                if nixos {
                    "then in configuration.nix: nix.settings.auto-optimise-store = true; (or nix.optimise.automatic = true;)".into()
                } else {
                    format!("then add auto-optimise-store = true to {conf}")
                },
            ],
        });
    }
    if gc_job.is_none() && min_free.unwrap_or(0) == 0 {
        tips.push(Tip {
            id: "nix-auto-gc",
            problem: "nothing collects garbage automatically (no GC job, min-free = 0)".into(),
            fix: if nixos {
                vec![
                    "sudo nix-collect-garbage --delete-older-than 30d".into(),
                    "then in configuration.nix: nix.gc = { automatic = true; dates = \"weekly\"; options = \"--delete-older-than 30d\"; };".into(),
                    "and: nix.settings = { min-free = 5000000000; max-free = 20000000000; };  # GC when space is low".into(),
                ]
            } else {
                vec![
                    "nix-collect-garbage --delete-older-than 30d".into(),
                    format!("then add min-free = 5000000000 and max-free = 20000000000 to {conf} (GC kicks in when space is low)"),
                    "home-manager users: nix.gc.automatic = true; sets up a user timer".into(),
                ]
            },
        });
    }
    tips
}

/// Where an automatic GC job would be installed on this platform.
fn gc_job_dirs() -> Vec<PathBuf> {
    let home = home().unwrap_or_default();
    if cfg!(target_os = "macos") {
        vec![PathBuf::from("/Library/LaunchDaemons"), home.join("Library/LaunchAgents")]
    } else {
        vec![
            PathBuf::from("/etc/systemd/system"),
            PathBuf::from("/etc/systemd/system/timers.target.wants"),
            PathBuf::from("/run/systemd/system"),
            home.join(".config/systemd/user"),
            home.join(".config/systemd/user/timers.target.wants"),
        ]
    }
}

struct Group {
    kind: PinKind,
    label: String,
    key: String,
    links: Vec<PathBuf>,
    roots: Vec<String>,
    command: String,
}

pub fn analyze() -> Option<NixReport> {
    if !Path::new("/nix/store").is_dir() {
        return None;
    }
    let t = Instant::now();
    let mut notes = Vec::new();

    // 1. on-disk size of every store path (our own fast walker; /nix is its own volume)
    let store_scan = std::thread::spawn(|| {
        let mut s = Scanner::new(Path::new("/nix/store"), true, 1).ok()?;
        s.prune_min = 0;
        let r = s.run(Path::new("/nix/store"));
        let sizes: HashMap<String, u64> =
            r.root.children.iter().map(|c| (c.name.to_string_lossy().into_owned(), c.size)).collect();
        let count = std::fs::read_dir("/nix/store").map(|d| d.count()).unwrap_or(sizes.len());
        Some((r.root.size, sizes, count))
    });

    // 2. roots and garbage, straight from nix
    let roots_out = run("nix-store", &["--gc", "--print-roots"]);
    let dead_out = run("nix-store", &["--gc", "--print-dead"]);
    let config = run("nix", &["config", "show"]).unwrap_or_default();
    let version = run("nix", &["--version"]).unwrap_or_default();

    let cfg = |k: &str| {
        config.lines().find_map(|l| l.strip_prefix(&format!("{k} = ")).map(|v| v.trim().to_string()))
    };
    let auto_optimise = cfg("auto-optimise-store").map(|v| v == "true");
    let min_free = cfg("min-free").and_then(|v| v.parse().ok());
    let nixos = Path::new("/etc/NIXOS").exists();
    let determinate = version.contains("Determinate");
    let gc_job = gc_job_dirs()
        .iter()
        .flat_map(|d| std::fs::read_dir(d).into_iter().flatten().flatten())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| {
            let l = n.to_lowercase();
            l.contains("nix") && (l.contains("-gc") || l.contains(".gc") || l.contains("garbage"))
        });

    // 3. group roots
    let me = std::env::var("SUDO_USER").or_else(|_| std::env::var("USER")).unwrap_or_default();
    let mut groups: Vec<Group> = Vec::new();
    let mut add = |kind: PinKind, key: String, label: String, link: PathBuf, root: String, command: String| {
        if let Some(g) = groups.iter_mut().find(|g| g.key == key) {
            g.links.push(link);
            g.roots.push(root);
        } else {
            groups.push(Group { kind, label, key, links: vec![link], roots: vec![root], command });
        }
    };
    let Some(roots_out) = roots_out else {
        notes.push("couldn't run nix-store --gc --print-roots; showing sizes only".into());
        let (bytes, _sizes, count) = store_scan.join().ok()??;
        let tips = make_tips(auto_optimise, &gc_job, min_free, determinate, nixos);
        return Some(NixReport {
            store_bytes: bytes, store_paths: count, dead_bytes: 0, dead_paths: 0, pins: vec![],
            shared_removable_bytes: 0, auto_optimise, min_free, gc_job, determinate, nixos, tips,
            seconds: t.elapsed().as_secs_f64(), notes,
        });
    };
    for line in roots_out.lines() {
        let Some((link, target)) = line.split_once(" -> ") else { continue };
        // newer nix quotes the root path: "/Users/me/proj/result" -> /nix/store/…
        let link = link.trim();
        let link = link.strip_prefix('"').and_then(|l| l.strip_suffix('"')).unwrap_or(link);
        let target = target.trim().trim_matches('"');
        let Some(b) = base(target) else { continue };
        let root = b.to_string();
        let link_p = PathBuf::from(link);
        if link.starts_with('{') || link.starts_with("/proc") {
            add(PinKind::Runtime, "runtime".into(), "Running processes".into(), link_p, root,
                "# restart the programs or log out/in; they release these on exit".into());
            continue;
        }
        if let Some((profile, _n)) = generation(&link_p) {
            let current = std::fs::read_link(&profile).ok().and_then(|t| t.file_name().map(|f| f.to_owned()));
            let is_current = current.as_deref() == link_p.file_name();
            let pname = profile.file_name().unwrap_or_default().to_string_lossy().into_owned();
            if is_current {
                add(PinKind::InUse, "inuse".into(), "Current generations (in use)".into(), link_p, root, String::new());
            } else {
                let root_owned = profile.starts_with("/nix/var/nix/profiles") && !profile.starts_with(format!("/nix/var/nix/profiles/per-user/{me}"));
                let sudo = if root_owned { "sudo " } else { "" };
                let mut cmd = format!(
                    "{sudo}nix-env --profile {} --delete-generations old && {sudo}nix-store --gc",
                    shq(&profile)
                );
                // NixOS keeps a boot menu entry per system generation; refresh it so /boot shrinks too.
                if nixos && profile == Path::new("/nix/var/nix/profiles/system") {
                    cmd.push_str(" && sudo /run/current-system/bin/switch-to-configuration boot");
                }
                add(PinKind::OldGenerations, format!("gens:{}", profile.display()), format!("{pname}: old generations"), link_p, root, cmd);
            }
            continue;
        }
        if link == "/run/current-system" || link == "/run/booted-system" || link.contains("/gcroots/current-home") || link.ends_with("/current-system") {
            add(PinKind::InUse, "inuse".into(), "Current generations (in use)".into(), link_p, root, String::new());
            continue;
        }
        if let Some(i) = link.find("/.direnv/") {
            let proj = PathBuf::from(&link[..i]);
            let cmd = format!("rm -rf {} && nix-store --gc", shq(&proj.join(".direnv")));
            add(PinKind::Direnv, format!("direnv:{}", proj.display()), format!("direnv cache in {}", tilde(&proj)), link_p, root, cmd);
            continue;
        }
        let fname = link_p.file_name().unwrap_or_default().to_string_lossy();
        if fname.starts_with("result") {
            let cmd = format!("rm {} && nix-store --gc", shq(&link_p));
            add(PinKind::BuildResult, format!("result:{link}"), format!("build result {}", tilde(&link_p)), link_p.clone(), root, cmd);
            continue;
        }
        let cmd = if link_p.starts_with(home().unwrap_or_default()) { format!("rm {} && nix-store --gc", shq(&link_p)) } else { String::new() };
        add(PinKind::Other, format!("other:{link}"), format!("GC root {}", tilde(&link_p)), link_p, root, cmd);
    }

    // 4. closures (one nix-store -qR per distinct root; run in parallel)
    let mut distinct: Vec<String> = groups.iter().flat_map(|g| g.roots.iter().cloned()).collect();
    distinct.sort();
    distinct.dedup();
    let closures: HashMap<String, Vec<String>> = std::thread::scope(|s| {
        let chunk = (distinct.len() / 8).max(1);
        let handles: Vec<_> = distinct
            .chunks(chunk)
            .map(|c| {
                s.spawn(move || {
                    c.iter()
                        .map(|r| {
                            let out = run("nix-store", &["-qR", &format!("/nix/store/{r}")]).unwrap_or_default();
                            (r.clone(), out.lines().filter_map(base).map(String::from).collect::<Vec<_>>())
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    });

    let (store_bytes, sizes, store_count) = store_scan.join().ok()??;
    let size = |p: &str| sizes.get(p).copied().unwrap_or(0);

    // 5. who owns what: bitmask of groups reaching each path (groups beyond 127 share the last bit)
    let gbit = |i: usize| 1u128 << i.min(127);
    let mut owner: HashMap<&str, u128> = HashMap::new();
    for (i, g) in groups.iter().enumerate() {
        for r in &g.roots {
            for p in closures.get(r).into_iter().flatten() {
                *owner.entry(p.as_str()).or_insert(0) |= gbit(i);
            }
        }
    }
    let removable_mask: u128 = groups
        .iter()
        .enumerate()
        .filter(|(_, g)| !matches!(g.kind, PinKind::InUse | PinKind::Runtime))
        .fold(0, |m, (i, _)| m | gbit(i));
    let mut unique = vec![0u64; groups.len()];
    let mut closure = vec![0u64; groups.len()];
    let mut shared_removable = 0u64;
    for (p, mask) in &owner {
        let s = size(p);
        for (i, c) in closure.iter_mut().enumerate() {
            if mask & gbit(i) != 0 {
                *c += s;
            }
        }
        if mask.count_ones() == 1 {
            let i = mask.trailing_zeros() as usize;
            if i < 127 || groups.len() <= 128 {
                unique[i.min(groups.len() - 1)] += s;
            }
        } else if mask & !removable_mask == 0 {
            shared_removable += s;
        }
    }

    let dead: Vec<&str> = dead_out.as_deref().unwrap_or("").lines().filter_map(base).collect();
    let dead_bytes = dead.iter().map(|p| size(p)).sum();
    if dead_out.is_none() {
        notes.push("couldn't run nix-store --gc --print-dead".into());
    }

    let mut pins: Vec<Pin> = groups
        .into_iter()
        .enumerate()
        .map(|(i, g)| {
            let times: Vec<i64> = g.links.iter().map(|l| link_mtime(l)).filter(|&t| t > 0).collect();
            let label = if g.kind == PinKind::OldGenerations { format!("{} ({})", g.label, g.links.len()) } else { g.label };
            Pin {
                kind: g.kind,
                label,
                unique_bytes: unique[i],
                closure_bytes: closure[i],
                oldest: times.iter().copied().min().unwrap_or(0),
                newest: times.iter().copied().max().unwrap_or(0),
                links: g.links,
                command: g.command,
            }
        })
        .collect();
    pins.sort_by(|a, b| b.unique_bytes.cmp(&a.unique_bytes));

    Some(NixReport {
        store_bytes,
        store_paths: store_count,
        dead_bytes,
        dead_paths: dead.len(),
        pins,
        shared_removable_bytes: shared_removable,
        auto_optimise,
        min_free,
        tips: make_tips(auto_optimise, &gc_job, min_free, determinate, nixos),
        gc_job,
        determinate,
        nixos,
        seconds: t.elapsed().as_secs_f64(),
        notes,
    })
}
