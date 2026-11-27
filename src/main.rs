mod nix;
mod report;
mod rules;
mod scan;
mod sys;
mod util;

use clap::Parser;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

const EXAMPLES: &str = "\x1b[1;4mExamples:\x1b[0m
  sleuth                      Investigate your home folder
  sleuth /                    The whole Mac (apps, /Library, /private/var, other users)
  sleuth ~/code               Drill into one folder
  sleuth -d 5 --min-pct 0.5   Deeper, finer folder tree
  sleuth --script clean.sh    Every suggestion as a script, all lines commented out
  sleuth --json | jq '.suspects[] | {label, size}'
  sleuth --json | jq '.nix.pins[] | {label, unique_bytes}'";

const MORE: &str = "\x1b[1;4mReading the report:\x1b[0m
  WHERE IT IS         Folder tree, largest first. Sizes are on-disk bytes, like du (decimal GB, like Finder)
  SUSPECTS            Known space hogs (caches, Docker, Xcode, package managers, app data)
  PROJECT LEFTOVERS   node_modules, target/, bin/obj, venvs… flagged stale when the project is idle
  LARGEST FILES       Biggest single files, with what they probably are
  OUTSIDE THE WALK    Space a folder walk can't see: other volumes (swap, Preboot), snapshots, unreadable folders
  NIX STORE           If /nix exists: what keeps store paths alive (old generations, result links,
                      direnv caches, running processes) and how much each would free on its own

\x1b[1;4mSafety tags:\x1b[0m
  SAFE     Regenerates on its own (caches, build output). Clearing it costs a re-download or rebuild
  REVIEW   Probably reclaimable, but look first (Downloads, Docker images, VMs, old toolchains)
  YOURS    Your data. Shown so you know where the space is

\x1b[1;4mTips:\x1b[0m
  • sleuth never deletes. Commands it prints are suggestions you run yourself.
  • Seeing \"N folders were unreadable\"? Give your terminal Full Disk Access:
    System Settings › Privacy & Security › Full Disk Access
  • sudo sleuth / also counts root-only folders; ~ still means your home.
  • Re-run on any folder from the tree to drill in. It's fast enough to just ask again.";

/// Find out what's eating your Mac's disk, fast. Read-only: it never deletes anything.
///
/// sleuth walks a folder, shows where the space went, picks out the known space hogs,
/// rates how safe each is to reclaim, and prints the exact command to run if you choose to.
#[derive(Parser)]
#[command(
    name = "sleuth",
    version,
    after_help = format!("{EXAMPLES}\n\nMore detail: sleuth --help"),
    after_long_help = format!("{EXAMPLES}\n\n{MORE}"),
)]
struct Args {
    /// Folder to investigate [default: ~]. "/" scans the whole Mac
    #[arg(value_name = "PATH")]
    path: Option<PathBuf>,

    /// Folder tree depth to show
    #[arg(short, long, value_name = "N", default_value_t = 3, help_heading = "What to show")]
    depth: usize,

    /// Hide folders smaller than this % of the total
    #[arg(long, value_name = "PCT", default_value_t = 1.0, help_heading = "What to show")]
    min_pct: f64,

    /// How many of the largest files to list
    #[arg(short = 'n', long, value_name = "N", default_value_t = 15, help_heading = "What to show")]
    top: usize,

    /// Hide suspects and leftover groups smaller than this
    #[arg(long, value_name = "MB", default_value_t = 100, help_heading = "What to show")]
    min_mb: u64,

    /// Flag projects untouched for this long as stale
    #[arg(long, value_name = "DAYS", default_value_t = 90, help_heading = "What to show")]
    stale_days: u64,

    /// Write every suggestion to a shell script, with every action commented out
    #[arg(long, value_name = "FILE", help_heading = "Output")]
    script: Option<PathBuf>,

    /// Print the full report as JSON
    #[arg(long, help_heading = "Output")]
    json: bool,

    /// Plain text without colors (also honors NO_COLOR)
    #[arg(long, help_heading = "Output")]
    no_color: bool,

    /// Also descend into other mounted filesystems
    #[arg(long, help_heading = "Scanning")]
    cross_mounts: bool,

    /// Skip system checks (snapshots, other volumes, swap)
    #[arg(long, help_heading = "Scanning")]
    no_system: bool,

    /// Skip the Nix store analysis
    #[arg(long, help_heading = "Scanning")]
    no_nix: bool,

    /// Worker threads [default: 2 × CPU cores]
    #[arg(short = 'j', long, value_name = "N", help_heading = "Scanning")]
    threads: Option<usize>,
}

fn main() {
    let args = Args::parse();
    util::init_color(args.no_color);

    let mut root = args.path.clone().or_else(util::home).unwrap_or_else(|| PathBuf::from("."));
    root = std::fs::canonicalize(&root).unwrap_or_else(|e| {
        eprintln!("sleuth: {}: {e}", root.display());
        std::process::exit(2);
    });
    // On modern macOS user data lives on the Data volume; "/" is the sealed system snapshot.
    if root == PathBuf::from("/") && std::path::Path::new("/System/Volumes/Data").is_dir() {
        root = PathBuf::from("/System/Volumes/Data");
    }

    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
    let threads = args.threads.unwrap_or(cores * 2);
    rayon::ThreadPoolBuilder::new().num_threads(threads).stack_size(16 << 20).build_global().ok();

    let scanner = match scan::Scanner::new(&root, !args.cross_mounts, args.top.max(50)) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("sleuth: {}: {e}", root.display());
            std::process::exit(2);
        }
    };

    // Kick off the slow-ish system probes (tmutil, sysctl) while we walk.
    let mut volume = sys::volume_of(&root);
    let sys_handle = if args.no_system {
        None
    } else {
        volume.clone().map(|v| std::thread::spawn(move || sys::gather(&v)))
    };

    let nix_handle = if args.no_system || args.no_nix { None } else { Some(std::thread::spawn(nix::analyze)) };

    let done = Arc::new(AtomicBool::new(false));
    let progress = if !args.json && std::io::stderr().is_terminal() {
        let (s, d) = (scanner.clone(), done.clone());
        Some(std::thread::spawn(move || {
            let t = Instant::now();
            while !d.load(Relaxed) {
                std::thread::sleep(Duration::from_millis(100));
                eprint!(
                    "\r\x1b[2K  scanning… {} files · {} · {:.1}s",
                    s.files.load(Relaxed),
                    util::human(s.bytes.load(Relaxed)),
                    t.elapsed().as_secs_f64()
                );
                let _ = std::io::stderr().flush();
            }
            eprint!("\r\x1b[2K");
        }))
    } else {
        None
    };

    let start = Instant::now();
    let res = scanner.run(&root);
    let secs = start.elapsed().as_secs_f64();
    done.store(true, Relaxed);
    if let Some(p) = progress {
        let _ = p.join();
    }
    let nix_report = nix_handle.and_then(|h| h.join().ok()).flatten();
    let system = sys_handle.and_then(|h| h.join().ok()).map(|(facts, used)| {
        if let (Some(v), Some(u)) = (volume.as_mut(), used) {
            v.used = u;
        }
        facts
    });

    let stats = (
        scanner.files.load(Relaxed),
        scanner.dirs.load(Relaxed),
        secs,
        scanner.denied.load(Relaxed),
        scanner.denied_paths.lock().unwrap().clone(),
        scanner.skipped_mounts.lock().unwrap().clone(),
    );
    let opts = report::Opts {
        depth: args.depth,
        min_pct: args.min_pct,
        top: args.top,
        stale_days: args.stale_days,
        min_suspect: args.min_mb * 1_000_000,
    };
    let rep = report::build(&res, &root, stats, volume, system, nix_report, &opts);

    if let Some(path) = &args.script {
        if let Err(e) = std::fs::write(path, report::script(&rep)) {
            eprintln!("sleuth: could not write {}: {e}", path.display());
            std::process::exit(1);
        }
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&rep).unwrap());
    } else {
        print!("{}", report::text(&rep, args.top));
        if let Some(path) = &args.script {
            println!("\n  📝 wrote {} (every action commented out; nothing was deleted)", path.display());
        }
    }
}
