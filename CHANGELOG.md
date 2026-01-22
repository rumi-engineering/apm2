# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial project structure with workspace layout
- Core library (`apm2-core`) with:
  - Process management types (`ProcessSpec`, `ProcessState`, `ProcessHandle`)
  - Credential management with keyring integration
  - Hot-swap support for runtime credential switching
  - OAuth token refresh management
  - Restart policies with backoff strategies
  - Health check framework
  - Log management with rotation support
  - Graceful shutdown coordination
  - State persistence for recovery
  - IPC protocol over Unix sockets
  - Supervisor for process lifecycle management
- Daemon binary (`apm2-daemon`) with:
  - Daemonization support
  - Signal handling
  - Configuration loading
- CLI client (`apm2-cli`) with:
  - Process management commands (start, stop, restart, reload)
  - Credential management commands
  - Log tailing
- CI/CD infrastructure:
  - GitHub Actions workflows for CI, release, fuzzing, benchmarks
  - release-plz integration for automated releases
  - cargo-deny for security and license checks
- Documentation and configuration files
