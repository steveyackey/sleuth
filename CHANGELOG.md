# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/steveyackey/sleuth/compare/v0.1.0...v0.1.1) - 2026-11-27

### Other

- release v0.1.0 ([#2](https://github.com/steveyackey/sleuth/pull/2))

## [0.1.0](https://github.com/steveyackey/sleuth/releases/tag/v0.1.0) - 2026-11-27

### Added

- add --bench to find the fastest thread count
- support Linux (Fedora, NixOS) and agent-friendly output

### Other

- add MIT license
- *(macos)* default to 4 worker threads
- default to at least 16 worker threads
- *(nix)* [**breaking**] drop x86_64-darwin from the flake
- pin Nix 2.35 on Intel macOS runners
- enforce conventional commits and release with release-plz
- *(nix)* add flake for x86_64/aarch64 Linux and macOS
- Initial commit: sleuth, a read-only disk-space detective for macOS
