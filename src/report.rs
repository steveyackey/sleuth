use crate::rules::{file_hint, home_rules, ArtifactKind, Safety, APP_DATA_DIRS, OPEN, SYSTEM_RULES, UNREADABLE_HINT, USERS_DIR};
use crate::nix::{NixReport, PinKind};
use crate::scan::{Node, ScanResult};
use crate::sys::{SystemFacts, Volume};
use crate::util::*;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Bumped whenever a field is renamed or removed (adding fields doesn't bump it).
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
pub struct Report {
    pub schema_version: u32,
    /// "macos" or "linux".
    pub platform: &'static str,
    /// ID from /etc/os-release on Linux ("fedora", "nixos", …); "macos" on a Mac.
    pub distro: String,
    pub is_root: bool,
    /// Every suggestion in one flat list, safest and biggest first. The easiest thing to act on.
    pub actions: Vec<Action>,
    pub root: PathBuf,
    pub stale_days: u64,
    pub scanned_bytes: u64,
    pub files: u64,
    pub dirs: u64,
    pub seconds: f64,
    pub unreadable_dirs: u64,
    pub unreadable_examples: Vec<PathBuf>,
    pub skipped_mounts: Vec<PathBuf>,
    pub volume: Option<Volume>,
    /// Used on the volume but not found under root.
    pub outside_scan: Option<u64>,
    pub tree: TreeNode,
    pub suspects: Vec<Suspect>,
    pub artifacts: Vec<ArtifactGroup>,
    pub largest_files: Vec<FileOut>,
    pub system: Option<SystemFacts>,
    pub nix: Option<NixReport>,
    pub reclaimable_safe: u64,
    pub reclaimable_review: u64,
}

/// One thing that could be done, with the command to do it. sleuth never runs these.
#[derive(Serialize)]
pub struct Action {
    /// Stable across runs for the same thing: "<kind>:<path or name>".
    pub id: String,
    /// "suspect" | "artifact" | "nix-garbage" | "nix-pin" | "nix-tip" | "large-file"
    pub kind: &'static str,
    pub label: String,
    pub path: Option<PathBuf>,
    /// Estimated bytes freed by running the command (not counting anything listed separately).
    pub bytes: u64,
    pub safety: Safety,
    pub command: String,
    /// The command needs root (it contains sudo, or touches root-owned paths).
    pub needs_sudo: bool,
    /// For artifacts: the owning project hasn't been touched for stale_days.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
}

#[derive(Serialize)]
pub struct TreeNode {
    pub name: String,
    /// Absolute path; pass it back to sleuth to drill in.
    pub path: PathBuf,
    pub size: u64,
    pub files: u64,
    pub newest: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<TreeNode>,
}

#[derive(Serialize, Clone)]
pub struct Suspect {
    pub label: String,
    pub path: PathBuf,
    pub size: u64,
    pub safety: Safety,
    pub command: String,
    pub note: String,
    /// Bytes inside this folder that are reported as separate suspects.
    pub nested_reported: u64,
    pub top_children: Vec<(String, u64)>,
}

#[derive(Serialize)]
pub struct ArtifactOut {
    pub path: PathBuf,
    pub size: u64,
    pub project_newest: i64,
    pub stale: bool,
    pub command: String,
}

#[derive(Serialize)]
pub struct ArtifactGroup {
    pub kind: ArtifactKind,
    pub label: String,
    pub safety: Safety,
    pub hint: String,
    pub total: u64,
    pub count: usize,
    pub stale_bytes: u64,
    pub stale_count: usize,
    pub items: Vec<ArtifactOut>,
}

#[derive(Serialize)]
pub struct FileOut {
    pub path: PathBuf,
    pub size: u64,
    pub mtime: i64,
    pub hint: Option<String>,
}

pub struct Opts {
    pub depth: usize,
    pub min_pct: f64,
    pub top: usize,
    pub stale_days: u64,
    pub min_suspect: u64,
}

fn tree(n: &Node, path: &Path, depth: usize, min: u64) -> TreeNode {
    TreeNode {
        name: n.name.to_string_lossy().into_owned(),
        path: pretty(path),
        size: n.size,
        files: n.files,
        newest: n.newest,
        children: if depth == 0 {
            vec![]
        } else {
            n.children.iter().filter(|c| c.size >= min).map(|c| tree(c, &path.join(&c.name), depth - 1, min)).collect()
        },
    }
}

/// Total size of a set of paths, counting nested paths only once.
fn union_size(mut items: Vec<(PathBuf, u64)>) -> u64 {
    items.sort();
    let mut total = 0;
    let mut last: Option<PathBuf> = None;
    for (p, s) in items {
        if let Some(l) = &last {
            if p.starts_with(l) {
                continue;
            }
        }
        total += s;
        last = Some(p);
    }
    total
}

fn top_children(n: &Node, min: u64, k: usize) -> Vec<(String, u64)> {
    n.children.iter().filter(|c| c.size >= min).take(k).map(|c| (c.name.to_string_lossy().into_owned(), c.size)).collect()
}

pub fn build(
    res: &ScanResult,
    root: &Path,
    stats: (u64, u64, f64, u64, Vec<PathBuf>, Vec<PathBuf>),
    volume: Option<Volume>,
    system: Option<SystemFacts>,
    nix: Option<NixReport>,
    o: &Opts,
) -> Report {
    let (files, dirs, seconds, unreadable, unreadable_examples, skipped_mounts) = stats;
    let total = res.root.size;
    let min_tree = ((total as f64) * o.min_pct / 100.0) as u64;
    let home = home().unwrap_or_default();

    // --- known locations
    let mut suspects: Vec<Suspect> = Vec::new();
    let home_rules = home_rules().map(|r| (home.join(r.rel), r));
    let sys_rules = SYSTEM_RULES.iter().map(|r| (PathBuf::from(r.rel), r));
    for (p, r) in home_rules.chain(sys_rules) {
        let p = in_scan_ns(root, &p);
        let Some(n) = res.root.find(root, &p) else { continue };
        if n.size < o.min_suspect {
            continue;
        }
        if suspects.iter().any(|s| s.path == p) {
            continue;
        }
        suspects.push(Suspect {
            label: r.label.into(),
            command: r.cmd.replace("{p}", &shq(&p)),
            path: p,
            size: n.size,
            safety: r.safety,
            note: r.note.into(),
            nested_reported: 0,
            top_children: top_children(n, (n.size / 20).max(50_000_000), 5),
        });
    }
    // --- big app data folders with no specific rule
    for &(rel, what) in APP_DATA_DIRS {
        let base = in_scan_ns(root, &home.join(rel));
        let Some(n) = res.root.find(root, &base) else { continue };
        for c in n.children.iter().filter(|c| c.size >= 2_000_000_000) {
            let p = base.join(&c.name);
            if suspects.iter().any(|s| s.path.starts_with(&p) || p.starts_with(&s.path)) {
                continue;
            }
            suspects.push(Suspect {
                label: format!("{what}: {}", c.name.to_string_lossy()),
                command: format!("{} {}", OPEN, shq(&p)),
                path: p,
                size: c.size,
                safety: Safety::Review,
                note: "Large app data. Often offline caches, VM images or old versions you can clear inside the app".into(),
                nested_reported: 0,
                top_children: top_children(c, (c.size / 20).max(50_000_000), 5),
            });
        }
    }
    // other people's home folders
    if let Some(users) = res.root.find(root, &in_scan_ns(root, Path::new(USERS_DIR))) {
        for c in users.children.iter().filter(|c| c.size >= 1_000_000_000) {
            let p = in_scan_ns(root, &Path::new(USERS_DIR).join(&c.name));
            if pretty(&p) == home || ["Shared", "linuxbrew", "lost+found"].iter().any(|n| c.name == *n) {
                continue;
            }
            suspects.push(Suspect {
                label: format!("Another user: {}", c.name.to_string_lossy()),
                command: String::new(),
                path: p,
                size: c.size,
                safety: Safety::Personal,
                note: "Someone else's home folder (or a leftover from a deleted account)".into(),
                nested_reported: 0,
                top_children: vec![],
            });
        }
    }
    // subtract nested suspects so nothing is double counted
    let paths: Vec<(PathBuf, u64)> = suspects.iter().map(|s| (s.path.clone(), s.size)).collect();
    for s in suspects.iter_mut() {
        let inner: Vec<(PathBuf, u64)> =
            paths.iter().filter(|(p, _)| p != &s.path && p.starts_with(&s.path)).cloned().collect();
        s.nested_reported = union_size(inner);
        let reported: Vec<String> = paths
            .iter()
            .filter(|(p, _)| p != &s.path && p.starts_with(&s.path))
            .filter_map(|(p, _)| p.strip_prefix(&s.path).ok()?.components().next().map(|c| c.as_os_str().to_string_lossy().into_owned()))
            .collect();
        s.top_children.retain(|(n, _)| !reported.contains(n));
    }
    suspects.sort_by(|a, b| (a.safety, std::cmp::Reverse(a.size - a.nested_reported)).cmp(&(b.safety, std::cmp::Reverse(b.size - b.nested_reported))));

    // --- project artifacts
    let stale_cutoff = now() - (o.stale_days as i64) * 86400;
    let mut groups: BTreeMap<ArtifactKind, Vec<ArtifactOut>> = BTreeMap::new();
    for a in &res.artifacts {
        if a.size < a.kind.min_size() || a.size < 1_000_000 {
            continue;
        }
        // Already covered by a suspect (e.g. venvs inside the uv cache, node_modules in ~/.npm/_npx).
        if suspects.iter().any(|s| a.path.starts_with(&s.path)) || a.path.starts_with(in_scan_ns(root, &home.join(".npm"))) {
            continue;
        }
        let parent = a.path.parent().unwrap_or(Path::new("/"));
        groups.entry(a.kind).or_default().push(ArtifactOut {
            path: a.path.clone(),
            size: a.size,
            project_newest: a.project_newest,
            stale: a.project_newest > 0 && a.project_newest < stale_cutoff,
            command: a.kind.cmd(&shq(&a.path), &shq(parent)),
        });
    }
    let mut artifacts: Vec<ArtifactGroup> = groups
        .into_iter()
        .map(|(kind, items)| ArtifactGroup {
            kind,
            label: kind.label().into(),
            safety: kind.safety(),
            hint: kind.hint().into(),
            total: items.iter().map(|i| i.size).sum(),
            count: items.len(),
            stale_bytes: items.iter().filter(|i| i.stale).map(|i| i.size).sum(),
            stale_count: items.iter().filter(|i| i.stale).count(),
            items,
        })
        .filter(|g| g.total >= o.min_suspect)
        .collect();
    artifacts.sort_by(|a, b| b.total.cmp(&a.total));

    // --- totals
    let mut safe: Vec<(PathBuf, u64)> = suspects.iter().filter(|s| s.safety == Safety::Safe).map(|s| (s.path.clone(), s.size)).collect();
    let mut review: Vec<(PathBuf, u64)> = suspects.iter().filter(|s| s.safety == Safety::Review).map(|s| (s.path.clone(), s.size)).collect();
    for g in &artifacts {
        let dst = if g.safety == Safety::Safe { &mut safe } else { &mut review };
        dst.extend(g.items.iter().map(|i| (i.path.clone(), i.size)));
    }
    let reclaimable_safe = union_size(safe.clone());
    let mut reclaimable_review = union_size(safe.into_iter().chain(review).collect()) - reclaimable_safe;
    let mut reclaimable_safe = reclaimable_safe;
    if let Some(n) = &nix {
        reclaimable_safe += n.dead_bytes;
        reclaimable_review += n.pins.iter().filter(|p| removable(p.kind)).map(|p| p.unique_bytes).sum::<u64>();
    }

    let largest_files: Vec<FileOut> = res
        .largest_files
        .iter()
        .take(o.top)
        .map(|f| FileOut {
            hint: file_hint(&f.path.file_name().unwrap_or_default().to_string_lossy()).map(String::from),
            path: f.path.clone(),
            size: f.size,
            mtime: f.mtime,
        })
        .collect();

    let outside_scan = volume.as_ref().map(|v| v.used.saturating_sub(total));

    let mut t = tree(&res.root, root, o.depth, min_tree);
    t.name = root.display().to_string();
    let actions = actions(&suspects, &artifacts, nix.as_ref(), &largest_files, o.min_suspect);
    Report {
        schema_version: SCHEMA_VERSION,
        platform: std::env::consts::OS,
        distro: distro(),
        is_root: unsafe { libc::geteuid() } == 0,
        actions,
        root: root.to_owned(),
        stale_days: o.stale_days,
        scanned_bytes: total,
        files,
        dirs,
        seconds,
        unreadable_dirs: unreadable,
        unreadable_examples,
        skipped_mounts,
        volume,
        outside_scan,
        tree: t,
        suspects,
        artifacts,
        largest_files,
        system,
        nix,
        reclaimable_safe,
        reclaimable_review,
    }
}

fn distro() -> String {
    if cfg!(target_os = "macos") {
        return "macos".into();
    }
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("ID=").map(|v| v.trim_matches('"').to_string())))
        .unwrap_or_else(|| "linux".into())
}

fn needs_sudo(cmd: &str) -> bool {
    cmd.split(|c: char| c.is_whitespace() || c == '&' || c == ';' || c == '|').any(|w| w == "sudo")
}

fn actions(suspects: &[Suspect], artifacts: &[ArtifactGroup], nix: Option<&NixReport>, files: &[FileOut], min: u64) -> Vec<Action> {
    let mut v = Vec::new();
    // Personal data never becomes an action, even with a command (those just open a folder).
    for s in suspects.iter().filter(|s| !s.command.is_empty() && s.safety != Safety::Personal) {
        v.push(Action {
            id: format!("suspect:{}", pretty(&s.path).display()),
            kind: "suspect",
            label: s.label.clone(),
            path: Some(pretty(&s.path)),
            bytes: s.size - s.nested_reported,
            safety: s.safety,
            needs_sudo: needs_sudo(&s.command),
            command: s.command.clone(),
            stale: false,
            note: s.note.clone(),
        });
    }
    for g in artifacts {
        for i in &g.items {
            v.push(Action {
                id: format!("artifact:{}", pretty(&i.path).display()),
                kind: "artifact",
                label: g.label.clone(),
                path: Some(pretty(&i.path)),
                bytes: i.size,
                safety: g.safety,
                needs_sudo: false,
                command: i.command.clone(),
                stale: i.stale,
                note: format!("project touched {}", age(i.project_newest)),
            });
        }
    }
    if let Some(n) = nix {
        if n.dead_bytes > 0 {
            v.push(Action {
                id: "nix-garbage".into(),
                kind: "nix-garbage",
                label: format!("Nix garbage ({} paths nothing references)", n.dead_paths),
                path: Some("/nix/store".into()),
                bytes: n.dead_bytes,
                safety: Safety::Safe,
                command: "nix-store --gc".into(),
                needs_sudo: false,
                stale: false,
                note: String::new(),
            });
        }
        for p in n.pins.iter().filter(|p| removable(p.kind) && !p.command.is_empty()) {
            v.push(Action {
                id: format!("nix-pin:{}", p.links.first().map(|l| l.display().to_string()).unwrap_or_default()),
                kind: "nix-pin",
                label: p.label.clone(),
                path: p.links.first().cloned(),
                bytes: p.unique_bytes,
                safety: Safety::Review,
                needs_sudo: needs_sudo(&p.command),
                command: p.command.clone(),
                stale: false,
                note: format!("{} GC root(s); bytes are what this frees on its own", p.links.len()),
            });
        }
        for t in &n.tips {
            v.push(Action {
                id: format!("nix-tip:{}", t.id),
                kind: "nix-tip",
                label: t.problem.clone(),
                path: None,
                bytes: 0,
                safety: Safety::Safe,
                needs_sudo: needs_sudo(&t.fix[0]),
                command: t.fix[0].clone(),
                stale: false,
                note: t.fix[1..].join("\n"),
            });
        }
    }
    for f in files.iter().filter(|f| f.size >= min) {
        v.push(Action {
            id: format!("large-file:{}", pretty(&f.path).display()),
            kind: "large-file",
            label: f.hint.clone().unwrap_or_else(|| "large file".into()),
            path: Some(pretty(&f.path)),
            bytes: f.size,
            safety: Safety::Review,
            command: format!("rm {}", shq(&f.path)),
            needs_sudo: false,
            stale: false,
            note: format!("modified {}", age(f.mtime)),
        });
    }
    v.sort_by(|a, b| (a.safety, std::cmp::Reverse(a.bytes)).cmp(&(b.safety, std::cmp::Reverse(b.bytes))));
    v
}

fn removable(k: PinKind) -> bool {
    !matches!(k, PinKind::InUse | PinKind::Runtime)
}

fn nix_section(o: &mut String, n: &NixReport) {
    section(o, "NIX STORE", &format!("({} on disk · {} store paths · what keeps them alive, analyzed in {:.1}s)", human(n.store_bytes), group(n.store_paths as u64), n.seconds));
    let pad = format!("  {:6} {:>8}  ", "", "");
    if n.dead_paths > 0 {
        let _ = writeln!(o, "  {} {:>8}  Garbage right now {}", safety_tag(Safety::Safe), bold(&human(n.dead_bytes)), dim(&format!("({} paths nothing references)", n.dead_paths)));
        let _ = writeln!(o, "{pad}{} nix-store --gc", cyan("→"));
    }
    for p in n.pins.iter().filter(|p| removable(p.kind) && p.unique_bytes >= 50_000_000) {
        let when = match p.kind {
            PinKind::OldGenerations => format!("made {} to {}. Deleting them removes those rollback points", age(p.oldest), age(p.newest)),
            PinKind::BuildResult => format!("built {}", age(p.newest)),
            PinKind::Direnv => format!("last refreshed {}", age(p.newest)),
            _ => format!("created {}", age(p.newest)),
        };
        let _ = writeln!(o, "  {} {:>8}  {}  {}", safety_tag(Safety::Review), bold(&human(p.unique_bytes)), p.label, dim(&when));
        if !p.command.is_empty() {
            let _ = writeln!(o, "{pad}{} {}", cyan("→"), p.command);
        }
    }
    if n.shared_removable_bytes >= 100_000_000 {
        let _ = writeln!(o, "{pad}{}", dim(&format!("+ {} more shared between the items above, freed only once all of them go", human(n.shared_removable_bytes))));
    }
    let small: Vec<&crate::nix::Pin> = n.pins.iter().filter(|p| removable(p.kind) && p.unique_bytes < 50_000_000).collect();
    if !small.is_empty() {
        let _ = writeln!(o, "{pad}{}", dim(&format!("{} more GC roots each pin < 50 MB on their own (see --json)", small.len())));
    }
    for p in n.pins.iter().filter(|p| p.kind == PinKind::Runtime && p.unique_bytes >= 50_000_000) {
        let _ = writeln!(o, "  {} {:>8}  held by running processes {}", safety_tag(Safety::Personal), human(p.unique_bytes), dim("(freed after they exit)"));
    }
    if let Some(p) = n.pins.iter().find(|p| p.kind == PinKind::InUse) {
        let _ = writeln!(o, "  {:6} {:>8}  {}", dim("IN USE"), dim(&human(p.closure_bytes)), dim("current system + home generations (not reclaimable)"));
    }
    for t in &n.tips {
        let _ = writeln!(o, "  {} {:>8}  {}", yellow("TIP   "), "", t.problem);
        for (i, f) in t.fix.iter().enumerate() {
            let _ = writeln!(o, "{pad}{} {}", cyan("→"), if i == 0 { f.clone() } else { dim(f) });
        }
    }
    for note in &n.notes {
        let _ = writeln!(o, "  {}", dim(note));
    }
}

fn safety_tag(s: Safety) -> String {
    let t = format!("{:<6}", s.label());
    match s {
        Safety::Safe => green(&t),
        Safety::Review => yellow(&t),
        Safety::Personal => blue(&t),
    }
}

fn section(out: &mut String, title: &str, sub: &str) {
    let _ = writeln!(out, "\n{} {}", bold(&cyan(title)), dim(sub));
}

fn print_tree(out: &mut String, n: &TreeNode, total: u64, prefix: &str, breadth: usize) {
    let shown: Vec<&TreeNode> = n.children.iter().take(breadth).collect();
    let rest: Vec<&TreeNode> = n.children.iter().skip(breadth).collect();
    for (i, c) in shown.iter().enumerate() {
        let last = i == shown.len() - 1 && rest.is_empty();
        let frac = c.size as f64 / total.max(1) as f64;
        let _ = writeln!(
            out,
            "  {:>8}  {} {:>4.0}%  {}{}{}",
            human(c.size),
            magenta(&bar(frac, 16)),
            frac * 100.0,
            dim(prefix),
            dim(if last { "└─ " } else { "├─ " }),
            if c.children.is_empty() { c.name.clone() } else { bold(&c.name) }
        );
        let np = format!("{prefix}{}", if last { "   " } else { "│  " });
        print_tree(out, c, total, &np, breadth);
    }
    if !rest.is_empty() {
        let sum: u64 = rest.iter().map(|c| c.size).sum();
        let _ = writeln!(out, "  {:>8}  {:16}        {}{}", dim(&human(sum)), "", dim(prefix), dim(&format!("└─ … {} more", rest.len())));
    }
}

pub fn text(r: &Report, top: usize) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{} {} {}",
        bold("🔎 sleuth"),
        bold(&tilde(&r.root)),
        dim(&format!(
            "· {} in {:.1}s · {} files · {} folders",
            human(r.scanned_bytes),
            r.seconds,
            group(r.files),
            group(r.dirs)
        ))
    );
    if let Some(v) = &r.volume {
        let used_frac = 1.0 - v.avail as f64 / v.total.max(1) as f64;
        let col = if used_frac > 0.9 { red(&bar(used_frac, 30)) } else if used_frac > 0.75 { yellow(&bar(used_frac, 30)) } else { green(&bar(used_frac, 30)) };
        let _ = writeln!(o, "   disk {} {} free of {}   {}", col, bold(&human(v.avail)), human(v.total), dim(&format!("(volume {} holds {})", v.mount, human(v.used))));
        if let Some(out) = r.outside_scan {
            if out > 1_000_000_000 {
                let where_ = if Path::new(&v.mount) == r.root.as_path() {
                    "not visible to the walk (snapshots, purgeable, unreadable folders)"
                } else {
                    "on this volume but outside this folder (apps, system data, other users, snapshots). Run sleuth / to see it"
                };
                let _ = writeln!(o, "   {} {}", bold(&human(out)), dim(where_));
            }
        }
    }

    section(&mut o, "WHERE IT IS", "(folders ≥ 1% of total; re-run on any path to drill in)");
    let _ = writeln!(o, "  {:>8}  {}", bold(&human(r.tree.size)), bold(&tilde(Path::new(&r.tree.name))));
    print_tree(&mut o, &r.tree, r.tree.size, "", 8);

    if !r.suspects.is_empty() {
        section(&mut o, "SUSPECTS", "(known space hogs. Commands are suggestions; sleuth never deletes)");
        for s in &r.suspects {
            let own = s.size - s.nested_reported;
            let extra = if s.nested_reported > 0 { dim(&format!(" (+{} listed separately)", human(s.nested_reported))) } else { String::new() };
            let _ = writeln!(o, "  {} {:>8}  {}  {}{}", safety_tag(s.safety), bold(&human(own)), s.label, dim(&tilde(&s.path)), extra);
            if !s.top_children.is_empty() {
                let parts: Vec<String> = s.top_children.iter().map(|(n, b)| format!("{n} {}", human(*b))).collect();
                let _ = writeln!(o, "  {:6} {:>8}  {}", "", "", dim(&format!("biggest: {}", parts.join(" · "))));
            }
            if !s.note.is_empty() {
                let _ = writeln!(o, "  {:6} {:>8}  {}", "", "", dim(&s.note));
            }
            if !s.command.is_empty() {
                let _ = writeln!(o, "  {:6} {:>8}  {} {}", "", "", cyan("→"), s.command);
            }
        }
    }

    if !r.artifacts.is_empty() {
        section(&mut o, "PROJECT LEFTOVERS", "(dependencies and build output that can be rebuilt)");
        for g in &r.artifacts {
            let stale = if g.stale_count > 0 {
                format!(" · {} in {} projects untouched {}+ days", yellow(&human(g.stale_bytes)), g.stale_count, r.stale_days)
            } else {
                String::new()
            };
            let _ = writeln!(o, "  {} {:>8}  {}  {}{}", safety_tag(g.safety), bold(&human(g.total)), bold(&g.label), dim(&format!("{} dirs", g.count)), stale);
            for i in g.items.iter().take(5) {
                let when = format!("project touched {}", age(i.project_newest));
                let _ = writeln!(o, "  {:6} {:>8}  {}  {}", "", human(i.size), tilde(&i.path), if i.stale { yellow(&when) } else { dim(&when) });
            }
            if g.items.len() > 5 {
                let _ = writeln!(o, "  {:6} {:>8}  {}", "", "", dim(&format!("… {} more (all of them are in --script / --json)", g.items.len() - 5)));
            }
            let _ = writeln!(o, "  {:6} {:>8}  {} {}", "", "", cyan("→"), dim(&g.hint));
        }
    }

    if !r.largest_files.is_empty() {
        section(&mut o, "LARGEST FILES", "");
        for f in r.largest_files.iter().take(top) {
            let hint = f.hint.as_deref().map(|h| dim(&format!("  {h}"))).unwrap_or_default();
            let _ = writeln!(o, "  {:>8}  {:<9} {}{}", bold(&human(f.size)), dim(&age(f.mtime)), tilde(&f.path), hint);
        }
    }

    // --- outside the walk
    let mut sys_lines = Vec::new();
    if let Some(s) = &r.system {
        if !s.local_snapshots.is_empty() {
            sys_lines.push(format!(
                "{} local Time Machine snapshot(s). They can hold deleted files' space; macOS frees it under pressure. {} tmutil listlocalsnapshots /",
                bold(&s.local_snapshots.len().to_string()),
                cyan("→")
            ));
        }
        let held: u64 = s.deleted_open.iter().map(|d| d.bytes).sum();
        if held >= 100_000_000 {
            let who: Vec<String> = s.deleted_open.iter().take(3).map(|d| format!("{} (pid {}) {}", d.process, d.pid, human(d.bytes))).collect();
            sys_lines.push(format!(
                "{} in deleted files still held open by running processes; freed when they close them or restart. {} {}",
                bold(&human(held)),
                dim(&who.join(" · ")),
                cyan("→ sudo lsof +L1"),
            ));
        }
        if !s.saw_all_processes && held < 100_000_000 && unsafe { libc::geteuid() } != 0 {
            sys_lines.push(dim("couldn't check other users' processes for deleted-but-open files (run with sudo)"));
        }
        for v in &s.sibling_volumes {
            let hint = match if v.mount.is_empty() { v.name.as_str() } else { v.mount.as_str() } {
                "/nix" if r.nix.is_some() => "see NIX STORE below".to_string(),
                "/nix" => format!("{} nix-collect-garbage -d && nix store optimise", cyan("→")),
                "/System/Volumes/VM" => "swap + sleep image; shrinks after a reboot".to_string(),
                "/" => "sealed macOS system; not reclaimable".to_string(),
                m if m.starts_with("/System/Volumes/") => "managed by macOS".to_string(),
                _ => "another volume sharing this disk's free space".to_string(),
            };
            let label = if v.mount.is_empty() { format!("{} (not mounted)", v.name) } else { format!("{} {}", v.name, dim(&format!("at {}", v.mount))) };
            sys_lines.push(format!("{:>8}  {}  {}", bold(&human(v.used)), label, dim(&hint)));
        }
    }
    if r.unreadable_dirs > 0 {
        sys_lines.push(format!(
            "{} folders were unreadable, so totals are low. {}{}",
            yellow(&group(r.unreadable_dirs)),
            UNREADABLE_HINT,
            r.unreadable_examples.first().map(|p| dim(&format!(" (e.g. {})", tilde(p)))).unwrap_or_default()
        ));
    }
    if !r.skipped_mounts.is_empty() {
        let names: Vec<String> = r.skipped_mounts.iter().take(4).map(|p| tilde(p)).collect();
        sys_lines.push(format!("skipped other filesystems: {} {}", names.join(", "), dim("(use --cross-mounts to include)")));
    }
    if !sys_lines.is_empty() {
        section(&mut o, "OUTSIDE THE WALK", "");
        for l in sys_lines {
            let _ = writeln!(o, "  {l}");
        }
    }

    if let Some(n) = &r.nix {
        nix_section(&mut o, n);
    }

    section(&mut o, "VERDICT", "");
    let _ = writeln!(o, "  {} reclaimable with little risk, plus {} worth a look.", bold(&green(&human(r.reclaimable_safe))), bold(&yellow(&human(r.reclaimable_review))));
    if let Some(c) = r.tree.children.first() {
        let p = Path::new(&r.tree.name).join(&c.name);
        let _ = writeln!(o, "  {} sleuth {}   {}", cyan("→"), shq(&p), dim("drill into the biggest folder"));
    }
    let _ = writeln!(o, "  {} sleuth {} --script cleanup.sh   {}", cyan("→"), shq(&r.root), dim("every suggestion as a commented-out script you review and edit"));
    o
}

fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// A cleanup script where every action is commented out. You uncomment what you want.
pub fn script(r: &Report) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "#!/usr/bin/env bash");
    let _ = writeln!(o, "# Generated by sleuth for {} ({} scanned)", r.root.display(), human(r.scanned_bytes));
    let _ = writeln!(o, "# Every action is COMMENTED OUT. Read each one, uncomment the lines you want, then run:");
    let _ = writeln!(o, "#   bash {}", "<this file>");
    let _ = writeln!(o, "# SAFE = regenerates automatically · REVIEW = look first · YOURS = personal data\n");
    let _ = writeln!(o, "set -euo pipefail\n");
    let _ = writeln!(o, "# ===== Suspects =====");
    for s in &r.suspects {
        if s.command.is_empty() {
            continue;
        }
        let _ = writeln!(o, "\n# [{}] {} · {}  ({})", s.safety.label(), human(s.size), s.label, s.path.display());
        if !s.note.is_empty() {
            let _ = writeln!(o, "#   {}", s.note);
        }
        let _ = writeln!(o, "# {}", s.command);
    }
    for g in &r.artifacts {
        let _ = writeln!(o, "\n# ===== [{}] {} · {} in {} dirs. {} =====", g.safety.label(), g.label, human(g.total), g.count, g.hint);
        for i in &g.items {
            let tag = if i.stale { "stale " } else { "" };
            let _ = writeln!(o, "# {}{:>8}  project touched {}", tag, human(i.size), age(i.project_newest));
            let _ = writeln!(o, "# {}", i.command);
        }
    }
    if let Some(n) = &r.nix {
        let _ = writeln!(o, "\n# ===== Nix store ({} on disk) =====", human(n.store_bytes));
        let _ = writeln!(o, "\n# [SAFE] {} · garbage nothing references", human(n.dead_bytes));
        let _ = writeln!(o, "# nix-store --gc");
        for p in n.pins.iter().filter(|p| removable(p.kind) && !p.command.is_empty()) {
            let _ = writeln!(o, "\n# [REVIEW] {} freed on its own · {}", human(p.unique_bytes), p.label);
            let _ = writeln!(o, "# {}", p.command);
        }
        for t in &n.tips {
            let _ = writeln!(o, "\n# [TIP] {}", t.problem);
            for f in &t.fix {
                let _ = writeln!(o, "# {f}");
            }
        }
    }
    let _ = writeln!(o, "\n# ===== Largest files =====");
    for f in &r.largest_files {
        let _ = writeln!(o, "# {:>8}  {}{}", human(f.size), age(f.mtime), f.hint.as_deref().map(|h| format!(" · {h}")).unwrap_or_default());
        let _ = writeln!(o, "# rm {}", shq(&f.path));
    }
    o
}
