//! The detective's casebook: known space hogs on macOS and how to deal with them.
//! Nothing here deletes anything — commands are suggestions for the human.

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Safety {
    /// Regenerates automatically / re-downloads on demand.
    Safe,
    /// Probably reclaimable, but look first.
    Review,
    /// Your own data. Shown so you know where the space is.
    Personal,
}

impl Safety {
    pub fn label(self) -> &'static str {
        match self {
            Safety::Safe => "SAFE",
            Safety::Review => "REVIEW",
            Safety::Personal => "YOURS",
        }
    }
}

pub struct Rule {
    /// Path relative to $HOME.
    pub rel: &'static str,
    pub label: &'static str,
    pub safety: Safety,
    /// Suggested command; {p} becomes the quoted path.
    pub cmd: &'static str,
    pub note: &'static str,
}

macro_rules! r {
    ($rel:expr, $label:expr, $s:ident, $cmd:expr, $note:expr) => {
        Rule { rel: $rel, label: $label, safety: Safety::$s, cmd: $cmd, note: $note }
    };
}

pub const RULES: &[Rule] = &[
    // --- macOS / apps
    r!(".Trash", "Trash", Safe, "osascript -e 'tell app \"Finder\" to empty trash'", "Already thrown away, just not emptied"),
    r!("Library/Caches", "App caches", Safe, "rm -rf {p}/*", "Apps rebuild these. Quit big apps first; the largest are listed below"),
    r!("Library/Logs", "Logs", Safe, "rm -rf {p}/*", "Diagnostic logs"),
    r!("Library/Containers/com.apple.mail/Data/Library/Mail Downloads", "Mail attachment copies", Safe, "rm -rf {p}/*", "Copies of attachments you opened"),
    r!("Library/Application Support/Code/Cache", "VS Code cache", Safe, "rm -rf {p}", ""),
    r!("Library/Application Support/Code/CachedData", "VS Code cached data", Safe, "rm -rf {p}", ""),
    r!("Library/Application Support/Code/CachedExtensionVSIXs", "VS Code extension installers", Safe, "rm -rf {p}", ""),
    r!("Library/Application Support/Code/User/workspaceStorage", "VS Code workspace storage", Review, "rm -rf {p}/*", "Per-workspace state, including old projects"),
    r!("Library/Application Support/Slack/Service Worker/CacheStorage", "Slack cache", Safe, "rm -rf {p}", "Quit Slack first"),
    r!("Library/Application Support/MobileSync/Backup", "iPhone/iPad backups", Review, "open 'x-apple.systempreferences:com.apple.settings.Storage'", "Old device backups. Manage them in Finder or Storage settings"),
    r!("Library/Messages/Attachments", "Messages attachments", Personal, "open 'x-apple.systempreferences:com.apple.settings.Storage'", "System Settings › General › Storage › Messages"),
    r!("Library/Mail", "Mail database", Personal, "", "Mail › Settings › Accounts. Consider not downloading all attachments"),
    r!("Downloads", "Downloads", Review, "open {p}", "Installers and one-offs pile up here (see largest files)"),
    r!("Movies", "Movies", Personal, "", ""),
    r!("Pictures/Photos Library.photoslibrary", "Photos library", Personal, "", "Photos › Settings › iCloud › Optimize Mac Storage"),
    r!("Music", "Music", Personal, "", ""),
    r!("Library/Containers/com.apple.Safari/Data/Library/Caches", "Safari cache", Safe, "rm -rf {p}/*", ""),
    // --- Xcode / Apple dev
    r!("Library/Developer/Xcode/DerivedData", "Xcode DerivedData", Safe, "rm -rf {p}/*", "Build intermediates; Xcode regenerates"),
    r!("Library/Developer/Xcode/iOS DeviceSupport", "Xcode iOS DeviceSupport", Safe, "rm -rf {p}/*", "Debug symbols, re-copied when a device connects"),
    r!("Library/Developer/Xcode/watchOS DeviceSupport", "Xcode watchOS DeviceSupport", Safe, "rm -rf {p}/*", ""),
    r!("Library/Developer/Xcode/Archives", "Xcode Archives", Review, "open {p}", "Holds dSYMs for shipped builds. Keep the ones you might need to symbolicate"),
    r!("Library/Developer/CoreSimulator/Devices", "iOS Simulator devices", Review, "xcrun simctl delete unavailable", "Removes sims for runtimes you no longer have"),
    r!("Library/Developer/CoreSimulator/Caches", "iOS Simulator caches", Safe, "rm -rf {p}/*", ""),
    // --- containers / VMs
    r!("Library/Containers/com.docker.docker", "Docker Desktop disk", Review, "docker system df && docker system prune -a --volumes", "The VM disk file only shrinks after pruning (and sometimes needs Docker › Settings › Resources to reclaim)"),
    r!(".orbstack", "OrbStack data", Review, "orb prune  # or: docker system prune -a", ""),
    r!(".colima", "Colima VMs", Review, "colima list && colima delete <profile>", ""),
    r!(".local/share/containers", "Podman storage", Review, "podman system prune -a", ""),
    r!(".vagrant.d/boxes", "Vagrant boxes", Review, "vagrant box prune", ""),
    r!(".minikube", "minikube", Review, "minikube delete --all", ""),
    r!("Library/Containers/com.utmapp.UTM", "UTM virtual machines", Review, "", "Delete VMs you don't use from UTM"),
    r!("Parallels", "Parallels VMs", Review, "", "Delete or compact VMs from Parallels Control Center"),
    r!(".android/avd", "Android emulators", Review, "emulator -list-avds", "Delete from Android Studio › Device Manager"),
    r!("Library/Android/sdk", "Android SDK", Review, "", "Uninstall old platforms and system images in SDK Manager"),
    // --- package managers & toolchains
    r!("Library/Caches/Homebrew", "Homebrew downloads", Safe, "brew cleanup --prune=all", ""),
    r!(".npm/_cacache", "npm cache", Safe, "npm cache clean --force", ""),
    r!("Library/Caches/Yarn", "Yarn cache", Safe, "yarn cache clean", ""),
    r!(".yarn/berry/cache", "Yarn Berry cache", Safe, "yarn cache clean --all", ""),
    r!("Library/pnpm/store", "pnpm store", Safe, "pnpm store prune", ""),
    r!(".bun/install/cache", "Bun cache", Safe, "bun pm cache rm", ""),
    r!("Library/Caches/ms-playwright", "Playwright browsers", Safe, "npx playwright uninstall --all", "Re-installed by npx playwright install"),
    r!("Library/Caches/Cypress", "Cypress binaries", Safe, "npx cypress cache prune", ""),
    r!(".cache/puppeteer", "Puppeteer browsers", Safe, "rm -rf {p}", ""),
    r!(".nvm/versions/node", "nvm Node versions", Review, "nvm ls  # then: nvm uninstall <version>", ""),
    r!("Library/Application Support/fnm/node-versions", "fnm Node versions", Review, "fnm list  # then: fnm uninstall <version>", ""),
    r!(".volta/tools/image", "Volta toolchains", Review, "volta list all", ""),
    r!(".cargo/registry", "Cargo registry", Safe, "cargo install cargo-cache && cargo cache --autoclean", "Crates re-download on demand"),
    r!(".rustup/toolchains", "Rust toolchains", Review, "rustup toolchain list  # then: rustup toolchain uninstall <name>", ""),
    r!("go/pkg/mod", "Go module cache", Safe, "go clean -modcache", ""),
    r!("Library/Caches/go-build", "Go build cache", Safe, "go clean -cache", ""),
    r!(".gradle/caches", "Gradle caches", Safe, "rm -rf {p}", ""),
    r!(".gradle/wrapper/dists", "Gradle distributions", Safe, "rm -rf {p}", ""),
    r!(".m2/repository", "Maven repository", Safe, "rm -rf {p}", "Re-downloads on next build"),
    r!(".nuget/packages", "NuGet packages", Safe, "dotnet nuget locals all --clear", ""),
    r!("Library/Caches/pip", "pip cache", Safe, "pip cache purge", ""),
    r!(".cache/pip", "pip cache", Safe, "pip cache purge", ""),
    r!(".cache/uv", "uv cache", Safe, "uv cache clean", ""),
    r!("Library/Caches/pypoetry", "Poetry cache", Safe, "poetry cache clear --all .", ""),
    r!(".pyenv/versions", "pyenv Pythons", Review, "pyenv versions  # then: pyenv uninstall <version>", ""),
    r!("miniconda3/pkgs", "Conda package cache", Safe, "conda clean --all", ""),
    r!("anaconda3/pkgs", "Conda package cache", Safe, "conda clean --all", ""),
    r!(".conda/pkgs", "Conda package cache", Safe, "conda clean --all", ""),
    r!(".cocoapods/repos", "CocoaPods specs", Safe, "pod repo remove trunk", ""),
    r!("Library/Caches/CocoaPods", "CocoaPods cache", Safe, "pod cache clean --all", ""),
    r!(".terraform.d/plugin-cache", "Terraform plugin cache", Safe, "rm -rf {p}/*", ""),
    r!(".cache/pre-commit", "pre-commit envs", Safe, "pre-commit clean", ""),
    r!("Library/Caches/JetBrains", "JetBrains caches", Safe, "rm -rf {p}/*", "Old IDE version caches pile up"),
    r!("Library/Application Support/JetBrains", "JetBrains IDE data", Review, "open {p}", "Folders for old IDE versions are safe to remove"),
    // --- AI / ML
    r!(".cache/huggingface", "Hugging Face models", Review, "hf cache scan  # then: hf cache delete", ""),
    r!(".ollama/models", "Ollama models", Review, "ollama list  # then: ollama rm <model>", ""),
    r!(".lmstudio/models", "LM Studio models", Review, "", "Delete models in LM Studio › My Models"),
    r!(".cache/lm-studio", "LM Studio models", Review, "", "Delete models in LM Studio › My Models"),
    r!(".cache/torch", "PyTorch hub cache", Safe, "rm -rf {p}", ""),
    // --- games
    r!("Library/Application Support/Steam/steamapps", "Steam games", Personal, "", "Uninstall games from Steam"),
];

/// Absolute, outside-home locations (seen when scanning / or a system folder).
pub const SYSTEM_RULES: &[Rule] = &[
    r!("/Applications", "Applications", Personal, "open /Applications", "Uninstall apps you no longer use (check for Xcode betas, old Office/Adobe)"),
    r!("/Applications/Xcode.app", "Xcode", Review, "", "Needed for iOS/macOS development; xcode-select --install gets just the CLI tools"),
    r!("/Library/Caches", "System-wide caches", Review, "sudo rm -rf /Library/Caches/*", ""),
    r!("/Library/Logs", "System-wide logs", Review, "sudo rm -rf /Library/Logs/DiagnosticReports/*", ""),
    r!("/Library/Developer/CoreSimulator", "iOS Simulator runtimes", Review, "xcrun simctl runtime list  # then: xcrun simctl runtime delete <id>", "Old iOS runtimes are several GB each"),
    r!("/Library/Application Support/com.apple.idleassetsd", "Aerial screensaver videos", Safe, "", "System Settings › Wallpaper: switch off the downloaded aerials"),
    r!("/Library/Updates", "Downloaded macOS updates", Review, "softwareupdate --list", ""),
    r!("/opt/homebrew", "Homebrew (Apple silicon)", Review, "brew autoremove && brew cleanup --prune=all", "Also: brew leaves  # to spot formulae you never use"),
    r!("/usr/local", "Homebrew (Intel) / /usr/local", Review, "brew autoremove && brew cleanup --prune=all", ""),
    r!("/private/var/folders", "Per-user temp & caches", Review, "", "Owned by macOS; most of it is cleared by a reboot"),
    r!("/private/var/log", "System logs", Review, "sudo log erase --all  # unified logs; or look in /private/var/log", ""),
    r!("/private/var/db/diagnostics", "Unified log store", Review, "sudo log erase --all", "macOS caps and rotates this itself"),
    r!("/private/var/vm", "Swap & sleep image", Review, "", "Shrinks after a reboot"),
    r!("/Users/Shared", "Shared user folder", Personal, "open /Users/Shared", "Some installers leave large content here"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum ArtifactKind {
    NodeModules,
    RustTarget,
    PythonVenv,
    GradleBuild,
    DotnetBuild,
    CocoaPods,
    JsBuildCache,
    Terraform,
    GitRepo,
}

impl ArtifactKind {
    pub fn label(self) -> &'static str {
        use ArtifactKind::*;
        match self {
            NodeModules => "node_modules",
            RustTarget => "Rust target/ dirs",
            PythonVenv => "Python virtualenvs",
            GradleBuild => "Gradle build output",
            DotnetBuild => ".NET bin/obj",
            CocoaPods => "CocoaPods Pods/",
            JsBuildCache => "JS framework caches (.next, .turbo…)",
            Terraform => ".terraform provider dirs",
            GitRepo => "Large .git histories",
        }
    }
    pub fn safety(self) -> Safety {
        match self {
            ArtifactKind::PythonVenv | ArtifactKind::GitRepo => Safety::Review,
            _ => Safety::Safe,
        }
    }
    pub fn hint(self) -> &'static str {
        use ArtifactKind::*;
        match self {
            NodeModules => "reinstall with npm/pnpm/yarn install. Tip: npx npkill to pick interactively",
            RustTarget => "cargo clean, or cargo install cargo-sweep && cargo sweep -r -t 30 ~",
            PythonVenv => "recreate from requirements/pyproject when you need it again",
            GradleBuild => "./gradlew clean",
            DotnetBuild => "dotnet clean, or remove bin/ and obj/",
            CocoaPods => "pod install restores it",
            JsBuildCache => "rebuilt on the next dev/build run",
            Terraform => "terraform init restores it",
            GitRepo => "git gc, or look for large files/LFS objects in history",
        }
    }
    /// Command for one specific artifact path (already quoted).
    pub fn cmd(self, quoted: &str, parent_quoted: &str) -> String {
        use ArtifactKind::*;
        match self {
            RustTarget => format!("cargo clean --manifest-path {parent_quoted}/Cargo.toml"),
            GitRepo => format!("git -C {parent_quoted} gc --prune=now"),
            _ => format!("rm -rf {quoted}"),
        }
    }
    /// Only report a GitRepo when it is genuinely large.
    pub fn min_size(self) -> u64 {
        match self {
            ArtifactKind::GitRepo => 1_000_000_000,
            _ => 0,
        }
    }
}

/// Hints for individual large files by extension.
pub fn file_hint(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    Some(match ext {
        "dmg" | "pkg" | "mpkg" | "xip" => "installer, usually not needed once installed",
        "ipsw" => "iOS/macOS firmware image",
        "iso" | "img" => "disk image",
        "zip" | "tar" | "gz" | "tgz" | "7z" | "rar" | "xz" | "zst" => "archive; is it already extracted?",
        "raw" | "qcow2" | "vmdk" | "vdi" | "vhdx" | "hdd" | "utm" => "virtual machine disk",
        "mov" | "mp4" | "mkv" | "avi" | "m4v" => "video",
        "gguf" | "safetensors" | "ckpt" | "pt" | "bin" if lower.contains("model") || ext != "bin" => "ML model weights",
        "log" => "log file",
        "core" => "crash dump",
        "sparseimage" | "sparsebundle" => "disk image",
        _ => return None,
    })
}
