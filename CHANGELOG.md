# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.3](https://github.com/SecurityRonin/safe-read/compare/safe-read-v0.2.2...safe-read-v0.2.3) - 2026-08-20

### Fixed

- *(gitignore)* unanchor the target rule so nested cargo projects are ignored

## [0.2.2](https://github.com/SecurityRonin/safe-read/compare/safe-read-v0.2.1...safe-read-v0.2.2) - 2026-08-05

### Added

- *(read)* add signed readers and try_bytes window

### Documentation

- *(read)* widen README install caret 0.1 -> 0.3

## [0.2.1](https://github.com/SecurityRonin/safe-read/compare/safe-read-v0.2.0...safe-read-v0.2.1) - 2026-07-25

### Documentation

- *(readme)* align robustness wording with fleet standard (fuzzed + panic-free-by-lint pairing)

### Fixed

- *(vet)* declare own crates first-party so version bumps don't break supply-chain audit

## [0.2.0](https://github.com/SecurityRonin/safe-read/compare/v0.1.0...v0.2.0) - 2026-07-17

### Added

- add u8 + try_* (Option-returning) readers; bump 0.2.0
