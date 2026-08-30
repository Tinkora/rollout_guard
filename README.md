# rollout_guard

[中文](README.zh-CN.md) · [Ko-fi](https://ko-fi.com/tinkora)

Privacy-first, offline inspection of explicitly selected JSONL rollout artifacts. It helps find oversized or malformed records, embedded `data:*;base64` payload growth, duplicate records/content, and repeated top-level instruction fields before an agent rollout artifact is shared or archived.

## Safety boundary

- Reads only the file or directory you name; a directory scan is non-recursive and includes only immediate `*.jsonl` files.
- Streams records and retains at most `--max-line-bytes + 1` bytes per line. Oversized lines are drained without parsing.
- Never uploads, deletes, rewrites, redacts, or exports input data.
- Reports basenames, counts, and hashes used only in memory. It never prints record content, secret values, or full local paths.
- Detects embedded bytes only for syntactically explicit `data:...;base64,...` strings. It does not guess whether ordinary strings are base64.
- Repeated instructions are counted only for identical top-level string fields named `instruction`, `system_instruction`, or `prompt`.

This is a bounded JSONL inspector, not a universal agent-log validator or secret scanner.

## Install and use

```console
cargo install --path . --locked
rollout_guard ./run.jsonl
rollout_guard ./artifacts --format json
rollout_guard ./run.jsonl --format sarif > rollout_guard.sarif
```

Exit codes: `0` clean, `1` findings exceeded configured thresholds, `2` invalid input or I/O failure.

Rules: `RG001` malformed JSONL, `RG002` oversized line, `RG003` embedded payload ratio, `RG004` exact duplicate record, `RG005` duplicate `content`, `RG006` repeated explicit instruction, `RG007` data URL skipped because its encoded value exceeded the inspection bound, `RG008` duplicate-hash tracking reached its 250,000-entry-per-category bound.

## Development

```console
cargo fmt --all -- --check
cargo test --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

See [product specification](docs/PRODUCT_SPEC.md), [contributing guide](CONTRIBUTING.md), and [security policy](SECURITY.md).
