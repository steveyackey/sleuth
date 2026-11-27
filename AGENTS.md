# sleuth for agents

sleuth is a **read-only** disk-space detective for macOS and Linux (x86_64 and arm64).
It never deletes anything. Every command it prints is a suggestion for you, or your user, to run.

## Using sleuth

```sh
sleuth --actions            # ~ : one JSON object per line, safest and biggest first
sleuth / --actions          # whole root filesystem (sudo sleuth / sees root-only folders too)
sleuth <dir> --json         # full report: tree, suspects, leftovers, nix, system, actions
sleuth <dir> --json -d 1    # shallower tree = smaller output
```

Prefer `--actions`. It's compact, line-oriented and already ranked. Each line looks like this:

```json
{"id":"suspect:/home/u/.cache/go-build","kind":"suspect","label":"Go build cache",
 "path":"/home/u/.cache/go-build","bytes":12056514560,"safety":"safe",
 "command":"go clean -cache","needs_sudo":false}
```

| field | meaning |
|---|---|
| `id` | stable across runs: `<kind>:<path or name>` |
| `kind` | `suspect` (known location), `artifact` (node_modules, target/, venv…), `nix-garbage`, `nix-pin` (GC root), `nix-tip` (config advice), `large-file` |
| `bytes` | estimated space freed, not counting anything listed as its own action |
| `safety` | `safe`: regenerates by itself. `review`: look first. Personal data never shows up as an action |
| `command` | shell command; paths are double-quoted and use `$HOME` |
| `needs_sudo` | the command runs sudo |
| `stale` | artifacts only: the owning project has been idle for `--stale-days` (90) |
| `note` | context, such as how a tip becomes permanent (NixOS: configuration.nix lines) |

Rules for agents:
- **Don't run `review` commands without the user's go-ahead.** `safe` ones only cost a re-download or a rebuild,
  but still say what you're about to clear and how big it is.
- Drill in with `sleuth <tree node .path>`. Every node in `--json` `.tree` has an absolute `path`.
- Speed: `sleuth <big dir> --bench --json` times several thread counts and returns `recommended_threads`.
  `-j N` or `SLEUTH_THREADS=N` applies it. Defaults are 4 on macOS and at least 16 on Linux.
- `--min-mb N` (default 100) hides smaller items, `-n N` limits the largest-files list, and `--no-nix` / `--no-system`
  skip slower probes.
- Errors: with `--json` or `--actions`, stderr gets `{"error": "...", "path": "...", "exit_code": N}`.
  Exit codes: `0` ok, `1` couldn't write `--script`, `2` bad path or arguments.
- `--json` has `schema_version` (currently 1), which changes only when a field is renamed or removed. It also
  reports `platform` (`macos`/`linux`), `distro` (`fedora`, `nixos`, …) and `is_root`.
- Output has no colour and no progress line when it isn't going to a terminal.

Linux specifics: pseudo filesystems (/proc, /sys, cgroups, snap squashfs, overlay) and tmpfs are skipped silently.
Other mounts (a separate /home or /boot) are skipped and listed unless you pass `--cross-mounts`. btrfs subvolumes
of the same filesystem (Fedora's layout) are walked. `system.deleted_open` lists deleted files that running
processes still hold open; you need sudo to see other users' processes.

## Working on sleuth

- `nix develop` gives you the toolchain and enables the commit hook. Or use rustup and run `git config core.hooksPath .githooks`.
- `cargo build --release && ./target/release/sleuth ~ --actions` is the fastest end-to-end check.
  Compare totals with `du -sk --one-file-system <dir>`; sleuth should come out a little lower, because it doesn't count directory blocks.
- Platform code is split with `#[cfg(target_os = ...)]`: `scan.rs` (getattrlistbulk on macOS, getdents64+fstatat on
  Linux), `sys.rs` (APFS/tmutil on macOS, /proc on Linux), and `rules.rs` (shared, macOS and Linux rule tables).
  Check the other OS still compiles: `cargo check --target aarch64-apple-darwin` and `--target x86_64-unknown-linux-gnu`.
- **Commits must be [Conventional Commits](https://www.conventionalcommits.org)** (`feat:`, `fix:`, `docs:`, `ci:`,
  `chore:`, …; `!` for breaking changes). CI enforces this on every PR commit and on the PR title.
- Releases are automatic. On each push to `main`, release-plz opens or updates a release PR (version bump +
  CHANGELOG). Merging it tags `vX.Y.Z`, creates the GitHub release and attaches static binaries for
  x86_64/aarch64 Linux (musl) and macOS. Don't bump versions or edit CHANGELOG.md by hand.
