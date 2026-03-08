# CLAUDE.md

## Build & Lint

Before pushing, always run clippy to match CI:

```
cargo clippy --workspace -- -D warnings
```

CI runs against `x86_64-unknown-linux-musl` but clippy checks are architecture-independent.

## Test

Full integration test suite (requires Vagrant VMs):

```
bash tests/run.sh
```

Individual test:

```
bash tests/cases/XX-name.sh
```

## Commit Style

- Ten words or fewer
- Don't mention Claude
