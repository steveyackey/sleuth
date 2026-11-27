//! Parallel, read-only directory scanner.
//!
//! macOS: getattrlistbulk(2), one syscall returns name/type/alloc-size/inode/mtime for a
//! whole batch of directory entries, instead of readdir + one lstat per file.
//! Linux: getdents64(2) into a reusable buffer, then fstatat(2) relative to the open
//! directory for non-directories only (d_type already tells us what's a folder).

use rayon::prelude::*;
use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::ffi::{CString, OsString};
#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;

use crate::rules::ArtifactKind;

thread_local! {
    static BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 256 * 1024]);
}

#[derive(Debug)]
pub struct Node {
    pub name: OsString,
    /// Bytes actually allocated on disk (like du), hard links counted once.
    pub size: u64,
    pub files: u64,
    /// Newest file mtime anywhere below (unix seconds).
    pub newest: i64,
    pub children: Vec<Node>,
    is_venv: bool,
}

#[derive(Debug, Clone)]
pub struct BigFile {
    pub path: PathBuf,
    pub size: u64,
    pub mtime: i64,
}

#[derive(Debug, Clone)]
pub struct Artifact {
    pub kind: ArtifactKind,
    pub path: PathBuf,
    pub size: u64,
    /// Newest mtime in the owning project, ignoring build/dependency folders.
    pub project_newest: i64,
}

enum Kind {
    Dir,
    File,
}

struct Entry {
    name: OsString,
    kind: Kind,
    alloc: u64,
    ino: u64,
    nlink: u32,
    mtime: i64,
}

#[derive(Default)]
struct Flags {
    package_json: bool,
    cargo: bool,
    gradle: bool,
    dotnet: bool,
    podfile: bool,
    pyvenv_cfg: bool,
}

impl Flags {
    fn observe(&mut self, name: &[u8]) {
        match name {
            b"package.json" => self.package_json = true,
            b"Cargo.toml" => self.cargo = true,
            b"build.gradle" | b"build.gradle.kts" | b"settings.gradle" | b"settings.gradle.kts" => {
                self.gradle = true
            }
            b"Podfile" => self.podfile = true,
            b"pyvenv.cfg" => self.pyvenv_cfg = true,
            n if n.ends_with(b".csproj") || n.ends_with(b".fsproj") || n.ends_with(b".vbproj") => {
                self.dotnet = true
            }
            _ => {}
        }
    }
}

fn classify(name: &[u8], f: &Flags) -> Option<ArtifactKind> {
    use ArtifactKind::*;
    Some(match name {
        b"node_modules" => NodeModules,
        b"target" if f.cargo => RustTarget,
        b"build" | b".gradle" if f.gradle => GradleBuild,
        b"bin" | b"obj" if f.dotnet => DotnetBuild,
        b"Pods" if f.podfile => CocoaPods,
        b".next" | b".nuxt" | b".turbo" | b".svelte-kit" | b".parcel-cache" | b".angular" | b".expo" => JsBuildCache,
        b".terraform" => Terraform,
        b".git" => GitRepo,
        _ => return None,
    })
}

struct TopFiles {
    cap: usize,
    min: AtomicU64,
    heap: Mutex<BinaryHeap<Reverse<(u64, PathBuf, i64)>>>,
}

impl TopFiles {
    fn offer(&self, size: u64, path: impl FnOnce() -> PathBuf, mtime: i64) {
        if size <= self.min.load(Relaxed) {
            return;
        }
        let mut h = self.heap.lock().unwrap();
        h.push(Reverse((size, path(), mtime)));
        if h.len() > self.cap {
            h.pop();
        }
        if h.len() == self.cap {
            self.min.store(h.peek().unwrap().0 .0, Relaxed);
        }
    }
}

pub struct Scanner {
    root_dev: u64,
    one_fs: bool,
    pub prune_min: u64,
    pub files: AtomicU64,
    pub dirs: AtomicU64,
    pub bytes: AtomicU64,
    pub denied: AtomicU64,
    pub errors: AtomicU64,
    pub skipped_mounts: Mutex<Vec<PathBuf>>,
    pub denied_paths: Mutex<Vec<PathBuf>>,
    top: TopFiles,
    links: Vec<Mutex<HashSet<(u64, u64)>>>,
    /// Linux: real mount points. A different st_dev that isn't one of these is a btrfs
    /// subvolume of the same filesystem, which we walk into.
    #[cfg(target_os = "linux")]
    mounts: HashMap<PathBuf, u32>,
    pub artifacts: Mutex<Vec<Artifact>>,
}

pub struct ScanResult {
    pub root: Node,
    pub largest_files: Vec<BigFile>,
    pub artifacts: Vec<Artifact>,
}

impl Scanner {
    pub fn new(root: &Path, one_fs: bool, top_files: usize) -> io::Result<Self> {
        let md = std::fs::metadata(root)?;
        if !md.is_dir() {
            return Err(io::Error::new(io::ErrorKind::Other, "not a directory"));
        }
        Ok(Scanner {
            root_dev: md.dev() as u64,
            one_fs,
            prune_min: 1_000_000,
            files: AtomicU64::new(0),
            dirs: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            denied: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            skipped_mounts: Mutex::new(Vec::new()),
            denied_paths: Mutex::new(Vec::new()),
            top: TopFiles { cap: top_files.max(1), min: AtomicU64::new(0), heap: Mutex::new(BinaryHeap::new()) },
            links: (0..64).map(|_| Mutex::new(HashSet::new())).collect(),
            artifacts: Mutex::new(Vec::new()),
            #[cfg(target_os = "linux")]
            mounts: linux::mounts(),
        })
    }

    pub fn run(&self, root: &Path) -> ScanResult {
        raise_fd_limit();
        let root_node = self.scan_dir(None, root, root.as_os_str().to_owned(), false);
        let mut largest: Vec<BigFile> = std::mem::take(&mut *self.top.heap.lock().unwrap())
            .into_iter()
            .map(|Reverse((size, path, mtime))| BigFile { path, size, mtime })
            .collect();
        largest.sort_by(|a, b| b.size.cmp(&a.size));
        let mut artifacts = std::mem::take(&mut *self.artifacts.lock().unwrap());
        artifacts.sort_by(|a, b| b.size.cmp(&a.size));
        ScanResult { root: root_node, largest_files: largest, artifacts }
    }

    /// True the first time an inode with several hard links is seen.
    fn first_link(&self, dev: u64, ino: u64) -> bool {
        self.links[(ino % 64) as usize].lock().unwrap().insert((dev, ino))
    }

    fn scan_dir(&self, parent: Option<libc::c_int>, path: &Path, name: OsString, in_artifact: bool) -> Node {
        let mut node = Node { name, size: 0, files: 0, newest: 0, children: Vec::new(), is_venv: false };
        let mut entries = Vec::new();
        let fd = match self.open_dir(parent, path, &node.name) {
            Ok(fd) => fd,
            Err(e) => {
                self.record_err(&e, path);
                return node;
            }
        };
        let dev = match self.list(fd.0, path, &mut entries) {
            Ok(Listed::Ok(dev)) => dev,
            Ok(Listed::OtherFs) => {
                self.skipped_mounts.lock().unwrap().push(path.to_owned());
                return node;
            }
            Ok(Listed::Ignored) => return node,
            Err(e) => {
                self.record_err(&e, path);
                return node;
            }
        };
        self.dirs.fetch_add(1, Relaxed);
        // Keep this directory open while children are scanned so they can openat() it,
        // which avoids re-resolving the full path (and contending on shared ancestors).
        // If we're close to the fd limit, children fall back to absolute paths.
        let pfd = if OPEN_FDS.load(Relaxed) < FD_BUDGET.load(Relaxed) { Some(fd.0) } else { None };
        let fd = if pfd.is_some() { Some(fd) } else { drop(fd); None };

        let mut flags = Flags::default();
        let mut subdirs = Vec::new();
        let mut own_newest = 0i64;
        for e in entries {
            match e.kind {
                Kind::Dir => subdirs.push(e.name),
                Kind::File => {
                    node.files += 1;
                    flags.observe(e.name.as_bytes());
                    let mut sz = e.alloc;
                    if e.nlink > 1 && !self.first_link(dev, e.ino) {
                        sz = 0;
                    }
                    node.size += sz;
                    own_newest = own_newest.max(e.mtime);
                    if sz > 0 {
                        self.top.offer(sz, || path.join(&e.name), e.mtime);
                    }
                }
            }
        }
        self.files.fetch_add(node.files, Relaxed);
        self.bytes.fetch_add(node.size, Relaxed);
        node.is_venv = flags.pyvenv_cfg;
        let child_in = in_artifact || node.is_venv;

        let children: Vec<(Node, Option<ArtifactKind>)> = subdirs
            .into_par_iter()
            .map(|n| {
                let kind = if child_in { None } else { classify(n.as_bytes(), &flags) };
                let p = path.join(&n);
                let c = self.scan_dir(pfd, &p, n, child_in || kind.is_some());
                (c, kind)
            })
            .collect();

        drop(fd);
        let mut project_newest = own_newest;
        for (c, k) in &children {
            if k.is_none() && !c.is_venv {
                project_newest = project_newest.max(c.newest);
            }
        }
        if !child_in {
            let mut found = Vec::new();
            for (c, k) in &children {
                let kind = k.or(if c.is_venv { Some(ArtifactKind::PythonVenv) } else { None });
                if let Some(kind) = kind {
                    if c.size > 0 {
                        found.push(Artifact { kind, path: path.join(&c.name), size: c.size, project_newest });
                    }
                }
            }
            if !found.is_empty() {
                self.artifacts.lock().unwrap().extend(found);
            }
        }

        node.newest = own_newest;
        let mut kept = Vec::new();
        for (c, _) in children {
            node.size += c.size;
            node.files += c.files;
            node.newest = node.newest.max(c.newest);
            if c.size >= self.prune_min {
                kept.push(c);
            }
        }
        kept.sort_unstable_by(|a, b| b.size.cmp(&a.size));
        kept.shrink_to_fit();
        node.children = kept;
        node
    }

    fn record_err(&self, e: &io::Error, path: &Path) {
        match e.raw_os_error() {
            Some(libc::EACCES) | Some(libc::EPERM) => {
                self.denied.fetch_add(1, Relaxed);
                let mut d = self.denied_paths.lock().unwrap();
                if d.len() < 200 {
                    d.push(path.to_owned());
                }
            }
            _ => {
                self.errors.fetch_add(1, Relaxed);
            }
        }
    }

    fn open_dir(&self, parent: Option<libc::c_int>, path: &Path, name: &OsString) -> io::Result<Fd> {
        const FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let fd = match parent {
            Some(pfd) => {
                let c = CString::new(name.as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
                unsafe { libc::openat(pfd, c.as_ptr(), FLAGS) }
            }
            None => {
                let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
                unsafe { libc::open(c.as_ptr(), FLAGS) }
            }
        };
        if fd < 0 {
            let e = io::Error::last_os_error();
            // Out of descriptors: retry once by absolute path after others close.
            if matches!(e.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE)) && parent.is_some() {
                std::thread::yield_now();
                return self.open_dir(None, path, name);
            }
            return Err(e);
        }
        OPEN_FDS.fetch_add(1, Relaxed);
        Ok(Fd(fd))
    }

    fn list(&self, fd: libc::c_int, path: &Path, out: &mut Vec<Entry>) -> io::Result<Listed> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let dev = if unsafe { libc::fstat(fd, &mut st) } == 0 { st.st_dev as u64 } else { 0 };
        if dev != self.root_dev && dev != 0 {
            #[cfg(target_os = "linux")]
            match linux::other_fs(fd, path, &self.mounts) {
                linux::Other::Pseudo => return Ok(Listed::Ignored),
                linux::Other::Ram if self.one_fs => return Ok(Listed::Ignored),
                linux::Other::Subvolume => {}
                _ if self.one_fs => return Ok(Listed::OtherFs),
                _ => {}
            }
            #[cfg(not(target_os = "linux"))]
            if self.one_fs {
                return Ok(Listed::OtherFs);
            }
        }
        match bulk_list(fd, out) {
            Ok(()) => Ok(Listed::Ok(dev)),
            Err(e) if out.is_empty() && matches!(e.raw_os_error(), Some(libc::ENOTSUP) | Some(libc::EINVAL)) => {
                slow_list(path, out)?;
                Ok(Listed::Ok(dev))
            }
            Err(e) if out.is_empty() => Err(e),
            Err(_) => {
                self.errors.fetch_add(1, Relaxed);
                Ok(Listed::Ok(dev))
            }
        }
    }
}

enum Listed {
    /// Listed; the directory's st_dev.
    Ok(u64),
    /// On another filesystem; skipped and reported.
    OtherFs,
    /// Kernel/virtual filesystem (/proc, /sys, snap squashfs…) or RAM: skipped silently.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Ignored,
}

static OPEN_FDS: AtomicU64 = AtomicU64::new(0);
static FD_BUDGET: AtomicU64 = AtomicU64::new(200);

struct Fd(libc::c_int);
impl Drop for Fd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
        OPEN_FDS.fetch_sub(1, Relaxed);
    }
}

fn raise_fd_limit() {
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } != 0 {
        return;
    }
    for want in [65_536u64, 24_576, 10_240, 4_096] {
        let want = want.min(rl.rlim_max as u64);
        if want <= rl.rlim_cur as u64 {
            break;
        }
        let new = libc::rlimit { rlim_cur: want as libc::rlim_t, rlim_max: rl.rlim_max };
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new) } == 0 {
            rl.rlim_cur = new.rlim_cur;
            break;
        }
    }
    // Leave headroom for the fds of directories being opened right now and for stdio.
    FD_BUDGET.store((rl.rlim_cur as u64).saturating_sub(256).max(32), Relaxed);
}

#[inline]
unsafe fn rd<T: Copy>(p: *const u8, off: usize) -> T {
    std::ptr::read_unaligned(p.add(off) as *const T)
}

#[cfg(target_os = "macos")]
use mac::bulk_list;
#[cfg(target_os = "linux")]
use linux::bulk_list;

#[cfg(target_os = "macos")]
mod mac {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    // <sys/attr.h>
    const ATTR_BIT_MAP_COUNT: u16 = 5;
    const ATTR_CMN_NAME: u32 = 0x0000_0001;
    const ATTR_CMN_OBJTYPE: u32 = 0x0000_0008;
    const ATTR_CMN_MODTIME: u32 = 0x0000_0400;
    const ATTR_CMN_FILEID: u32 = 0x0200_0000;
    const ATTR_CMN_ERROR: u32 = 0x2000_0000;
    const ATTR_CMN_RETURNED_ATTRS: u32 = 0x8000_0000;
    const ATTR_FILE_LINKCOUNT: u32 = 0x0000_0001;
    const ATTR_FILE_ALLOCSIZE: u32 = 0x0000_0004;
    const VDIR: u32 = 2;

    #[repr(C)]
    struct AttrList {
        bitmapcount: u16,
        reserved: u16,
        commonattr: u32,
        volattr: u32,
        dirattr: u32,
        fileattr: u32,
        forkattr: u32,
    }

    extern "C" {
        fn getattrlistbulk(
            dirfd: libc::c_int,
            alist: *mut libc::c_void,
            attribute_buffer: *mut libc::c_void,
            buffer_size: libc::size_t,
            options: u64,
        ) -> libc::c_int;
    }

    pub fn bulk_list(fd: libc::c_int, out: &mut Vec<Entry>) -> io::Result<()> {
        let mut al = AttrList {
            bitmapcount: ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME | ATTR_CMN_ERROR | ATTR_CMN_OBJTYPE | ATTR_CMN_MODTIME | ATTR_CMN_FILEID,
            volattr: 0,
            dirattr: 0,
            fileattr: ATTR_FILE_LINKCOUNT | ATTR_FILE_ALLOCSIZE,
            forkattr: 0,
        };
        BUF.with(|b| {
            let mut buf = b.borrow_mut();
            loop {
                let n = unsafe {
                    getattrlistbulk(fd, &mut al as *mut _ as *mut libc::c_void, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(e);
                }
                if n == 0 {
                    return Ok(());
                }
                let mut p = buf.as_ptr();
                for _ in 0..n {
                    unsafe {
                        let len: u32 = rd(p, 0);
                        let ret_cmn: u32 = rd(p, 4);
                        let ret_file: u32 = rd(p, 4 + 12);
                        let mut off = 4 + 20;
                        let mut err = 0u32;
                        if ret_cmn & ATTR_CMN_ERROR != 0 {
                            err = rd(p, off);
                            off += 4;
                        }
                        let mut name = OsString::new();
                        if ret_cmn & ATTR_CMN_NAME != 0 {
                            let noff: i32 = rd(p, off);
                            let nlen: u32 = rd(p, off + 4);
                            let np = p.add(off).offset(noff as isize);
                            let bytes = std::slice::from_raw_parts(np, (nlen as usize).saturating_sub(1));
                            name = OsString::from_vec(bytes.to_vec());
                            off += 8;
                        }
                        let mut objtype = 0u32;
                        if ret_cmn & ATTR_CMN_OBJTYPE != 0 {
                            objtype = rd(p, off);
                            off += 4;
                        }
                        let mut mtime = 0i64;
                        if ret_cmn & ATTR_CMN_MODTIME != 0 {
                            mtime = rd(p, off);
                            off += 16;
                        }
                        let mut ino = 0u64;
                        if ret_cmn & ATTR_CMN_FILEID != 0 {
                            ino = rd(p, off);
                            off += 8;
                        }
                        let mut nlink = 1u32;
                        if ret_file & ATTR_FILE_LINKCOUNT != 0 {
                            nlink = rd(p, off);
                            off += 4;
                        }
                        let mut alloc = 0u64;
                        if ret_file & ATTR_FILE_ALLOCSIZE != 0 {
                            alloc = rd(p, off);
                        }
                        p = p.add(len as usize);
                        if err != 0 || name.is_empty() {
                            continue;
                        }
                        let kind = if objtype == VDIR { Kind::Dir } else { Kind::File };
                        out.push(Entry { name, kind, alloc, ino, nlink, mtime });
                    }
                }
            }
        })
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CStr;

    /// Real mount points from /proc/self/mountinfo (mount ID as value, unused but handy).
    pub fn mounts() -> HashMap<PathBuf, u32> {
        let s = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        s.lines()
            .filter_map(|l| {
                let mut f = l.split(' ');
                let id = f.next()?.parse().ok()?;
                let mp = f.nth(3)?;
                Some((PathBuf::from(unescape(mp)), id))
            })
            .collect()
    }

    fn unescape(s: &str) -> OsString {
        use std::os::unix::ffi::OsStringExt;
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
        OsString::from_vec(out)
    }

    pub enum Other {
        /// /proc, /sys, cgroups, snap squashfs, overlay mounts…: never worth walking.
        Pseudo,
        /// tmpfs/ramfs: memory, not disk.
        Ram,
        /// A btrfs subvolume of the same filesystem (different st_dev, but not a mount).
        Subvolume,
        Disk,
    }

    pub fn other_fs(fd: libc::c_int, path: &Path, mounts: &HashMap<PathBuf, u32>) -> Other {
        let mut s: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(fd, &mut s) } != 0 {
            return Other::Disk;
        }
        const BTRFS: u32 = 0x9123_683e;
        const TMPFS: u32 = 0x0102_1994;
        const RAMFS: u32 = 0x8584_58f6;
        const PSEUDO: &[u32] = &[
            0x9fa0,      // proc
            0x6265_6572, // sysfs
            0x1cd1,      // devpts
            0x0027_e0eb, // cgroup
            0x6367_7270, // cgroup2
            0x6462_6720, // debugfs
            0x7472_6163, // tracefs
            0x7363_6673, // securityfs
            0x6165_676c, // pstore
            0xcafe_4a11, // bpf
            0xde5e_81e4, // efivarfs
            0x6265_6570, // configfs
            0x6573_5543, // fusectl
            0x1980_0202, // mqueue
            0x9584_58f6, // hugetlbfs
            0x4249_4e4d, // binfmt_misc
            0x0187,      // autofs
            0x6e73_6673, // nsfs
            0x7371_7368, // squashfs (snaps, AppImages: their image files are counted where they live)
            0x794c_7630, // overlayfs (container rootfs views of data counted elsewhere)
        ];
        let t = s.f_type as u32;
        if PSEUDO.contains(&t) {
            Other::Pseudo
        } else if t == TMPFS || t == RAMFS {
            Other::Ram
        } else if t == BTRFS && !mounts.contains_key(path) {
            Other::Subvolume
        } else {
            Other::Disk
        }
    }

    pub fn bulk_list(fd: libc::c_int, out: &mut Vec<Entry>) -> io::Result<()> {
        BUF.with(|b| {
            let mut buf = b.borrow_mut();
            loop {
                let n = unsafe { libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(e);
                }
                if n == 0 {
                    return Ok(());
                }
                let p = buf.as_ptr();
                let mut off = 0usize;
                while off < n as usize {
                    // struct linux_dirent64 { u64 d_ino; i64 d_off; u16 d_reclen; u8 d_type; char d_name[]; }
                    let (ino, reclen, dtype, name) = unsafe {
                        let ino: u64 = rd(p, off);
                        let reclen: u16 = rd(p, off + 16);
                        let dtype: u8 = *p.add(off + 18);
                        (ino, reclen, dtype, CStr::from_ptr(p.add(off + 19) as *const libc::c_char))
                    };
                    off += reclen as usize;
                    let nb = name.to_bytes();
                    if nb == b"." || nb == b".." || nb.is_empty() {
                        continue;
                    }
                    if dtype == libc::DT_DIR {
                        out.push(Entry { name: OsString::from_vec(nb.to_vec()), kind: Kind::Dir, alloc: 0, ino, nlink: 1, mtime: 0 });
                        continue;
                    }
                    let mut st: libc::stat = unsafe { std::mem::zeroed() };
                    if unsafe { libc::fstatat(fd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
                        continue;
                    }
                    let is_dir = st.st_mode & libc::S_IFMT == libc::S_IFDIR;
                    out.push(Entry {
                        name: OsString::from_vec(nb.to_vec()),
                        kind: if is_dir { Kind::Dir } else { Kind::File },
                        alloc: st.st_blocks as u64 * 512,
                        ino: st.st_ino as u64,
                        nlink: st.st_nlink as u32,
                        mtime: st.st_mtime as i64,
                    });
                }
            }
        })
    }
    use std::os::unix::ffi::OsStringExt;
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn bulk_list(_fd: libc::c_int, _out: &mut Vec<Entry>) -> io::Result<()> {
    Err(io::Error::from_raw_os_error(libc::ENOTSUP))
}

fn slow_list(path: &Path, out: &mut Vec<Entry>) -> io::Result<()> {
    for de in std::fs::read_dir(path)? {
        let Ok(de) = de else { continue };
        let Ok(md) = de.path().symlink_metadata() else { continue };
        out.push(Entry {
            name: de.file_name(),
            kind: if md.is_dir() { Kind::Dir } else { Kind::File },
            alloc: md.blocks() * 512,
            ino: md.ino(),
            nlink: md.nlink() as u32,
            mtime: md.mtime(),
        });
    }
    Ok(())
}

impl Node {
    /// Find the node for an absolute path below this (root) node.
    pub fn find(&self, root_path: &Path, target: &Path) -> Option<&Node> {
        let rel = target.strip_prefix(root_path).ok()?;
        let mut cur = self;
        for comp in rel.components() {
            cur = cur.children.iter().find(|c| c.name.as_os_str() == comp.as_os_str())?;
        }
        Some(cur)
    }
}
