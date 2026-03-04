# hermitctl

Declarative configuration tool for HermitShell. Manages router configuration via TOML files.

## Global Options

| Flag | Default | Description |
|------|---------|-------------|
| `--socket <PATH>` | `/run/hermitshell/agent.sock` | Path to agent socket |

## Commands

### apply

Apply configuration from a TOML file. Validates first, then sends to the running agent.

```
hermitctl apply --config /etc/hermitshell/hermitshell.toml
hermitctl apply --config hermitshell.toml --secrets hermitshell.secrets.toml
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config <PATH>` | `/etc/hermitshell/hermitshell.toml` | Config file |
| `--secrets <PATH>` | `/etc/hermitshell/hermitshell.secrets.toml` | Secrets file (optional) |

Exits with code 1 on validation or apply error.

### diff

Show what would change without applying. Compares the config file against the running configuration.

```
hermitctl diff --config hermitshell.toml
```

Output uses `-`/`+` prefixes for removed/added lines. Prints "No changes." if configs match.

| Flag | Default | Description |
|------|---------|-------------|
| `--config <PATH>` | `/etc/hermitshell/hermitshell.toml` | Config file to compare |

### export

Export the running configuration as TOML to stdout.

```
hermitctl export > current-config.toml
```

### validate

Check a config file for errors without contacting the agent. Does not require the agent to be running.

```
hermitctl validate --config hermitshell.toml
```

Prints "Config is valid." on success. Prints errors to stderr and exits with code 1 on failure.

### status

Show runtime status -- uptime, device count, ad blocking state, WAN info.

```
hermitctl status
```

Output is formatted JSON.

## Typical Workflow

1. Export the current config: `hermitctl export > hermitshell.toml`
2. Edit the TOML file
3. Validate: `hermitctl validate --config hermitshell.toml`
4. Preview changes: `hermitctl diff --config hermitshell.toml`
5. Apply: `hermitctl apply --config hermitshell.toml`

## File Locations

| File | Default Path | Description |
|------|-------------|-------------|
| Config | `/etc/hermitshell/hermitshell.toml` | Main configuration |
| Secrets | `/etc/hermitshell/hermitshell.secrets.toml` | Sensitive values (passwords, keys) |
| Socket | `/run/hermitshell/agent.sock` | Agent communication socket |
