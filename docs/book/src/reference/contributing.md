# Contributing

## Building from Source

Requires Rust (stable) and the musl target:

```bash
rustup target add x86_64-unknown-linux-musl   # or aarch64-unknown-linux-musl
./scripts/build-agent.sh
```

The build script compiles all three components (agent, DHCP server, web UI) as static musl binaries, then packages them:

| Output | Location | Notes |
|---|---|---|
| Static binaries | `target/release/hermitshell-agent`, `hermitshell-dhcp`, `hermitshell` | Portable across any Linux distro |
| Install tarball | `target/release/hermitshell-local.tar.gz` | For use with `install.sh --local` |
| Docker image | `target/release/hermitshell-container.tar` | Built if Docker is available |
| .deb package | `target/release/hermitshell_*.deb` | Built if `cargo-deb` is installed |

For development builds without musl or packaging:

```bash
cargo build --workspace
```

## Cross-Compiling for aarch64

The CI uses [cross](https://github.com/cross-rs/cross) for aarch64 builds. To cross-compile locally:

```bash
cargo install cross --git https://github.com/cross-rs/cross
LEPTOS_OUTPUT_NAME=hermitshell cross build --release \
  -p hermitshell-agent -p hermitshell-dhcp -p hermitshell \
  --target aarch64-unknown-linux-musl
```

## Testing

Integration tests use Vagrant to spin up a 3-VM test network (router, LAN client, WAN upstream). Tests run on the host and exercise real network paths.

```bash
cd tests
sudo -E vagrant up          # start VMs
sudo -E ./run.sh            # run all tests
bash tests/cases/04-agent-socket.sh   # run a single test
sudo -E vagrant destroy -f  # tear down
```

## Code Conventions

- **No `sleep` calls.** Use polling, retries with conditions, or event-driven alternatives.
- **Validate user input before interpolation.** Anything reaching nftables, shell commands, or device configuration must be validated first.
- **Secrets use `zeroize`.** Secrets from the DB must be wrapped in `zeroize::Zeroizing<String>`. New secrets must be added to `BLOCKED_CONFIG_KEYS` in `socket/mod.rs`.
- **Wire types go in `hermitshell-common`.** Shared structs live in `hermitshell-common/src/lib.rs`.
- **Document security compromises.** Add an entry to `docs/SECURITY.md` with What, Why, Risk, and Proper fix.
- **Tests exercise real network paths.** Use the LAN VM as a client, not localhost. Tests must be idempotent.
- **Commit messages: ten words or fewer.**

## Making Changes

1. Fork and clone the repo
2. Create a branch from `main`
3. Build: `cargo build --workspace`
4. Run integration tests if your change affects networking, DHCP, DNS, firewall, or the socket API
5. Open a PR against `main`

## Good Contributions

- **Bug fixes** -- always welcome. Include a test case or describe how to reproduce.
- **New WiFi AP vendors** -- implement the `WifiProvider` and `WifiDevice` traits in `wifi/mod.rs`.
- **New integration tests** -- especially for edge cases or regressions. Follow the existing pattern in `tests/cases/`.
- **Documentation improvements** -- if something confused you, fix it.
- **Feature requests** -- open an issue first. Check `docs/ROADMAP.md` for planned work.

## What to Avoid

- Don't add features without discussion. Open an issue first.
- Don't refactor working code unless it's blocking a fix or feature.
- Don't add dependencies without justification. The agent runs on resource-constrained hardware.
- Don't add `unsafe` code. If you think you need it, explain why in the PR.

## Reporting Issues

Open an issue on GitHub with:
- What you expected vs. what happened
- HermitShell version (`Settings > Update` in the web UI, or `hermitshell-agent --version`)
- Install method (APT, Docker, install script, source)
- Relevant log output: `sudo journalctl -u hermitshell-agent -n 50 --no-pager`

## Security Issues

Report security vulnerabilities privately -- email security@hermitshell.org or use GitHub's private vulnerability reporting. Do not open a public issue.

## License

MIT. By contributing, you agree that your contributions will be licensed under the MIT License.
