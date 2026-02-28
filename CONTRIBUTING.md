# Contributing to HermitShell

## Getting Started

1. Fork and clone the repo
2. Install Rust (stable) and the musl target:
   ```bash
   rustup target add x86_64-unknown-linux-musl
   ```
3. Build:
   ```bash
   cargo build --workspace
   ```
4. Run integration tests (requires Vagrant and VirtualBox):
   ```bash
   cd tests
   sudo -E vagrant up
   sudo -E ./run.sh
   ```

See [docs/INSTALL.md](docs/INSTALL.md) for full build details including cross-compilation and packaging.

## Project Structure

```
hermitshell-agent/       Router daemon (nftables, DHCP, DNS, WireGuard, WiFi, logging)
  src/socket/            Unix socket API handlers, split by domain
  src/wifi/              WiFi provider implementations (UniFi, TP-Link EAP)
hermitshell/             Web UI (Leptos 0.8 + Axum 0.8, SSR-only)
hermitshell-common/      Shared wire types between agent and UI
hermitshell-dhcp/        DHCP server (DHCPv4 + DHCPv6)
tests/cases/             Integration tests (shell scripts)
```

## Code Conventions

These are enforced — PRs that don't follow them will be asked to revise.

**No `sleep` calls.** Use polling, retries with conditions, or event-driven alternatives.

**Validate user input before interpolation.** Anything that reaches nftables, shell commands, or device configuration must be validated first — `nftables::validate_*` for firewall rules, `wifi::validate_*` for AP names and SSIDs. This includes bulk paths like `import_config`.

**Secrets use zeroize.** Secrets read from the DB (password hashes, private keys, API tokens) must be wrapped in `zeroize::Zeroizing<String>` so they are zeroed on drop. New secrets must be added to `BLOCKED_CONFIG_KEYS` in `socket/mod.rs`.

**Wire types go in hermitshell-common.** Structs shared between agent and UI live in `hermitshell-common/src/lib.rs`. Don't duplicate definitions in `db.rs` or `client.rs`.

**Document security compromises.** If your change introduces a security trade-off, add an entry to [docs/SECURITY.md](docs/SECURITY.md) with What, Why, Risk, and Proper fix.

**Tests exercise real network paths.** Integration tests should use the LAN VM as a client (e.g., curl from the LAN VM, not localhost on the router). Tests must be idempotent — passing on both a fresh VM and a dirty one from a prior run.

**Commit messages: ten words or fewer.**

## Making Changes

1. Create a branch from `main`
2. Make your changes
3. Run `cargo build --workspace` to verify it compiles
4. Run the integration tests if your change affects networking, DHCP, DNS, firewall, or the socket API:
   ```bash
   cd tests && sudo -E ./run.sh
   ```
   For targeted testing, run individual test files:
   ```bash
   bash tests/cases/04-agent-socket.sh
   ```
5. Open a PR against `main`

## What Makes a Good Contribution

**Bug fixes** — always welcome. Include a test case or describe how to reproduce.

**New WiFi AP vendors** — the `WifiProvider` and `WifiDevice` traits in `wifi/mod.rs` define the interface. Implement both traits, add the provider type to the `connect()` match, and add the option to the UI dropdown in `wifi.rs`.

**New integration tests** — especially for edge cases or regressions. Follow the existing pattern in `tests/cases/`.

**Documentation improvements** — if something confused you, it'll confuse others. Fix it.

**Feature requests** — open an issue first to discuss. Check [docs/ROADMAP.md](docs/ROADMAP.md) for planned work.

## What to Avoid

- Don't add features without discussion. Open an issue first.
- Don't refactor working code unless it's blocking a fix or feature.
- Don't add dependencies without justification. The agent runs on resource-constrained hardware.
- Don't add `unsafe` code. If you think you need it, explain why in the PR.

## Releases

Releases ship when ready, not on a fixed schedule. The version follows semver (`0.x.y` — `x` for features, `y` for fixes). Security fixes are fast-tracked as patch releases.

A release happens when there's a meaningful set of changes worth shipping. During active development this might be every few weeks; during stable periods it might be months apart. Routers should be boring and stable — frequent churn is worse than patience.

The release process:
1. Update the version in `hermitshell-agent/Cargo.toml`
2. Tag the commit: `git tag v0.x.y`
3. Push the tag: `git push origin v0.x.y`
4. CI builds tarballs, .deb packages, and Docker images automatically
5. The APT repository updates after the release workflow completes

Users with auto-update enabled will receive the new version within 24 hours. Others can update via `apt upgrade`, `docker pull`, the web UI's one-click update, or `install.sh --upgrade`.

## Reporting Issues

Open an issue on GitHub. Include:
- What you expected vs. what happened
- HermitShell version (`Settings > Update` in the web UI, or check `hermitshell-agent --version`)
- How you installed (APT, Docker, install script, source)
- Relevant log output: `sudo journalctl -u hermitshell-agent -n 50 --no-pager`

## Security Issues

If you find a security vulnerability, please report it privately rather than opening a public issue. Email security@hermitshell.dev or use GitHub's private vulnerability reporting.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
