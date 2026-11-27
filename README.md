# sleuth

A fast, read-only detective for "where did my disk space go?" on macOS and Linux (x86_64 and arm64).

It **never deletes anything**. It finds the space, explains what it is, rates how safe it is to reclaim,
and gives you the exact command. You decide what to run.

## Install

```sh
nix run github:steveyackey/sleuth            # try it (Linux x86_64/arm64, Apple silicon)
nix profile install github:steveyackey/sleuth
cargo install --git https://github.com/steveyackey/sleuth
```

Prebuilt binaries for `x86_64`/`aarch64` Linux and macOS are attached to every
[GitHub release](https://github.com/steveyackey/sleuth/releases). The Linux ones are static (musl), so they run on any
distro, NixOS included. Intel Macs: use the release binary or `cargo install` (Nix has dropped x86_64-darwin).

On NixOS or with nix-darwin/home-manager, add the flake as an input and use `inputs.sleuth.packages.${system}.default`
(or `overlays.default`, which adds `pkgs.sleuth`).

## Use

```sh
sleuth                    # investigate your home folder
sleuth /                  # the whole data volume: apps, /Library, /private/var, other users
sudo sleuth /             # also counts root-only folders (Spotlight index, /var/lib/docker…); ~ still means your home
sleuth ~/code             # drill into any folder
sleuth --script clean.sh  # write every suggestion to a script, all lines commented out
sleuth --json | jq        # machine-readable
sleuth --actions          # one JSON suggestion per line, ranked (for agents and scripts; see AGENTS.md)
sleuth -d 5 --min-pct 0.5 # deeper and finer folder tree
sleuth ~ --bench          # find the fastest thread count here; then export SLEUTH_THREADS=N
```

For complete results on macOS, give your terminal **Full Disk Access**
(System Settings › Privacy & Security). Without it, macOS hides folders like `~/.Trash` and Mail.
On Linux, `sudo` lets sleuth read root-only folders and check every process for deleted-but-open files.

## What it reports

- **WHERE IT IS**: the folder tree, largest first, sized like `du` (allocated blocks, hard links counted once).
- **SUSPECTS**: known space hogs (npm/pnpm/uv/NuGet/Gradle/Go/Cargo caches, ML models, containers, VMs, …), plus any
  app-data folder over 2 GB. macOS adds Xcode, simulators, iOS backups and the like. Linux adds `~/.cache`, Trash,
  Flatpak/Snap, Docker/Podman, dnf/apt/pacman caches, the systemd journal, core dumps, old kernels and rpm-ostree
  deployments. Each is tagged:
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
  - checks for `auto-optimise-store` and automatic GC (launchd or systemd timers), and suggests settings. It knows
    about Determinate Nix, and on NixOS it gives `configuration.nix` options rather than nix.conf edits. Deleting old
    NixOS system generations also refreshes the boot menu
- **OUTSIDE THE WALK**: space a folder walk can't see. On macOS: other APFS volumes on the same disk (Nix store,
  VM/swap, Preboot) and local Time Machine snapshots. On Linux: deleted files still held open by running processes,
  and other mounts it skipped. Both list folders it couldn't read.

## Why it's fast

- macOS: lists directories with `getattrlistbulk(2)`. One syscall returns name, type, allocated size, inode
  and mtime for a whole batch of entries, instead of `readdir` plus one `lstat` per file.
- Linux: `getdents64(2)` into a reused buffer, then `fstatat(2)` relative to the open directory, only for
  non-directories (`d_type` already identifies folders). It skips pseudo filesystems and walks btrfs subvolumes.
- Folders are scanned in parallel with work stealing (rayon), opened with `openat` relative to their parent.
- Only folders ≥ 1 MB are kept in memory.

On a ~510k-file cache folder it ran in 6.3s, against 13.4s for `du -sk` and 4.6s for `fd` just listing names.
In practice the filesystem is the limit.

## Contributing

Commits follow [Conventional Commits](https://www.conventionalcommits.org) (enforced in CI; `nix develop` installs a
local hook). [release-plz](https://release-plz.dev) turns them into the changelog and releases: merge its release PR
and the tag, GitHub release and binaries follow. See [AGENTS.md](AGENTS.md).

## License

[MIT](LICENSE)
