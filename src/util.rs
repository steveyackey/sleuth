use std::io::IsTerminal;
use std::path::Path;
use std::sync::OnceLock;

static COLOR: OnceLock<bool> = OnceLock::new();

pub fn init_color(disabled: bool) {
    let on = !disabled && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
    let _ = COLOR.set(on);
}

fn paint(code: &str, s: &str) -> String {
    if *COLOR.get().unwrap_or(&false) {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}
pub fn bold(s: &str) -> String { paint("1", s) }
pub fn dim(s: &str) -> String { paint("2", s) }
pub fn red(s: &str) -> String { paint("31", s) }
pub fn green(s: &str) -> String { paint("32", s) }
pub fn yellow(s: &str) -> String { paint("33", s) }
pub fn blue(s: &str) -> String { paint("34", s) }
pub fn cyan(s: &str) -> String { paint("36", s) }
pub fn magenta(s: &str) -> String { paint("35", s) }

/// Decimal units, matching Finder and "About This Mac".
pub fn human(b: u64) -> String {
    const U: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 { format!("{b} B") } else if v >= 100.0 { format!("{v:.0} {}", U[i]) } else { format!("{v:.1} {}", U[i]) }
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn age(mtime: i64) -> String {
    if mtime <= 0 {
        return "?".into();
    }
    let d = (now() - mtime).max(0) / 86400;
    match d {
        0 => "today".into(),
        1..=30 => format!("{d}d ago"),
        31..=364 => format!("{}mo ago", d / 30),
        _ => format!("{:.1}y ago", d as f64 / 365.0),
    }
}

/// The invoking user's home, even under sudo.
pub fn home() -> Option<std::path::PathBuf> {
    static H: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();
    H.get_or_init(|| {
        if unsafe { libc::geteuid() } == 0 {
            if let Some(user) = std::env::var_os("SUDO_USER") {
                let c = std::ffi::CString::new(user.into_encoded_bytes()).ok()?;
                let pw = unsafe { libc::getpwnam(c.as_ptr()) };
                if !pw.is_null() {
                    let dir = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) };
                    return Some(std::path::PathBuf::from(dir.to_string_lossy().into_owned()));
                }
            }
        }
        std::env::var_os("HOME").map(Into::into)
    })
    .clone()
}

pub const DATA_VOL: &str = "/System/Volumes/Data";

/// "/System/Volumes/Data/Users/x" -> "/Users/x" (macOS firmlinks make these the same place).
pub fn pretty(p: &Path) -> std::path::PathBuf {
    match p.strip_prefix(DATA_VOL) {
        Ok(rest) if !rest.as_os_str().is_empty() => Path::new("/").join(rest),
        _ => p.to_path_buf(),
    }
}

/// The inverse: a normal path expressed inside the data volume when scanning it.
pub fn in_scan_ns(root: &Path, p: &Path) -> std::path::PathBuf {
    if root.starts_with(DATA_VOL) && !p.starts_with(DATA_VOL) {
        Path::new(DATA_VOL).join(p.strip_prefix("/").unwrap_or(p))
    } else {
        p.to_path_buf()
    }
}

/// Path for display: ~/… when under $HOME.
pub fn tilde(p: &Path) -> String {
    let p = &pretty(p);
    if let Some(h) = home() {
        if let Ok(rest) = p.strip_prefix(&h) {
            return if rest.as_os_str().is_empty() { "~".into() } else { format!("~/{}", rest.display()) };
        }
    }
    p.display().to_string()
}

/// Shell-safe double-quoted path, using "$HOME/…" for readability.
pub fn shq(p: &Path) -> String {
    fn esc(s: &str) -> String {
        s.chars().flat_map(|c| match c { '"' | '\\' | '$' | '\x60' => vec!['\\', c], _ => vec![c] }).collect()
    }
    let p = &pretty(p);
    if let Some(h) = home() {
        if let Ok(rest) = p.strip_prefix(&h) {
            if rest.as_os_str().is_empty() { return "\"$HOME\"".into(); }
            return format!("\"$HOME/{}\"", esc(&rest.to_string_lossy()));
        }
    }
    format!("\"{}\"", esc(&p.to_string_lossy()))
}

pub fn bar(frac: f64, width: usize) -> String {
    let cells = (frac.clamp(0.0, 1.0) * width as f64 * 8.0).round() as usize;
    let full = cells / 8;
    let part = cells % 8;
    const P: [&str; 8] = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];
    let mut s = "█".repeat(full);
    if full < width {
        s.push_str(P[part]);
    }
    let len = full + usize::from(part > 0 && full < width);
    s.push_str(&" ".repeat(width.saturating_sub(len)));
    s
}
