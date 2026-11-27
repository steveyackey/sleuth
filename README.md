# sleuth

A fast, read-only detective for "where did my Mac's disk space go?".

It **never deletes anything**. It finds the space, explains what it is, rates how safe it is to reclaim,
and gives you the exact command. You decide what to run.

## Install

```sh
cargo install --path .
```

## Use

```sh
sleuth                    # investigate your home folder
sleuth /                  # the whole data volume: apps, /Library, /private/var, other users
sudo sleuth /             # also counts root-only folders (Spotlight index, etc.); ~ still means your home
sleuth ~/code             # drill into any folder
sleuth --script clean.sh  # write every suggestion to a script, all lines commented out
sleuth --json | jq        # machine-readable
sleuth -d 5 --min-pct 0.5 # deeper and finer folder tree
```

For complete results, give your terminal **Full Disk Access**
(System Settings › Privacy & Security). Without it, macOS hides folders like `~/.Trash` and Mail.

## What it reports

- **WHERE IT IS**: the folder tree, largest first, sized like `du` (allocated blocks, hard links counted once).
- **SUSPECTS**: about 80 known macOS space hogs (Xcode, Docker, simulators, npm/pnpm/uv/NuGet/Gradle/Go/Cargo
  caches, iOS backups, ML models, …), plus any app-data folder over 2 GB. Each is tagged:
  - `SAFE`: regenerates on its own
  - `REVIEW`: probably reclaimable, look first
  - `YOURS`: your data, shown so you know where it is
- **PROJECT LEFTOVERS**: `node_modules`, Rust `target/`, .NET `bin/obj`, Gradle builds, venvs, Pods, `.next`,
  `.terraform`, and huge `.git` folders. Each is flagged **stale** when the project itself (not its build output)
  hasn't changed in 90+ days.
- **LARGEST FILES**, with hints (installer, VM disk, disk image, archive, …).
- **NIX STORE** (when `/nix` exists): sleuth asks Nix what keeps each store path alive (read-only queries only) and
  works out how much each thing would free **on its own**:
  - garbage nothing references (`nix-store --gc`)
  - old generations per profile (nix-darwin system, home-manager, user profiles)
  - `result` symlinks from `nix build`, and direnv caches in your projects
  - paths held by running processes, and the current system (shown, not reclaimable)
  - space shared between several removable roots, freed only when all of them go
  - checks for `auto-optimise-store` and automatic GC, and suggests settings (Determinate Nix aware)
- **OUTSIDE THE WALK**: space a folder walk can't see: other APFS volumes on the same disk (Nix store, VM/swap,
  Preboot), local Time Machine snapshots, and folders it couldn't read.

## Why it's fast

- Lists directories with macOS `getattrlistbulk(2)`: one syscall returns name, type, allocated size, inode
  and mtime for a whole batch of entries, instead of `readdir` plus one `lstat` per file.
- Folders are scanned in parallel with work stealing (rayon), opened with `openat` relative to their parent.
- Only folders ≥ 1 MB are kept in memory.

On a ~510k-file cache folder it ran in 6.3s, against 13.4s for `du -sk` and 4.6s for `fd` just listing names.
In practice the filesystem is the limit.
