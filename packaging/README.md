# codeassure: standalone binaries

Single-file executables (PyInstaller, no Python needed on the target). Binaries are **not committed to git**:
they are built with `packaging/build-binaries.sh` into `dist/release/` (git-ignored) and attached to a release.

| Platform | File | Notes |
|---|---|---|
| Linux x86_64 | `codeassure-linux-amd64` | needs glibc >= 2.31 (Debian 11+, Ubuntu 20.04+, RHEL 9, Amazon Linux 2023) |
| Linux arm64 | `codeassure-linux-arm64` | same glibc floor |
| macOS Apple Silicon | `codeassure-darwin-arm64` | unsigned, see Gatekeeper below |

## Install

`codeassure` builds a deterministic context graph for every finding by calling the **`context-graph`** binary
(from the `code-context-graph` repo). It looks next to its own executable first, then on `PATH`, so install both
side by side and keep the name `context-graph` (or pass `--no-context-graph` to skip it).

```bash
# 1. download both binaries for your platform plus SHA256SUMS from the releases, then verify
shasum -a 256 -c SHA256SUMS --ignore-missing        # on Linux: sha256sum -c SHA256SUMS --ignore-missing

# 2. install (example: Linux x86_64)
sudo install -m 0755 codeassure-linux-amd64     /usr/local/bin/codeassure
sudo install -m 0755 context-graph-linux-amd64  /usr/local/bin/context-graph

# 3. check
codeassure --help
```

macOS Gatekeeper: remove the quarantine flag from downloaded files once:
`xattr -d com.apple.quarantine codeassure-darwin-arm64 context-graph-darwin-arm64`.

For full data-flow graphs install Joern once (needs JDK 17+): `context-graph install-joern`.
Without it the graph falls back to the tree-sitter tier (or pass `--graph-no-joern`).

## Use

The binary does **not** embed a config. It resolves the model settings in this order:

1. `--config PATH`
2. `./codeassure.json` in the current directory
3. environment variables only (no file needed, good for CI):

```bash
export CODEASSURE_MODEL_NAME=your-model-name
export CODEASSURE_MODEL_PROVIDER=openai          # openai | openai-compatible | anthropic | google (default: openai)
export CODEASSURE_API_BASE=http://localhost:5000 # optional
export CODEASSURE_API_KEY=<key>
```

With none of the three it exits with "No codeassure.json found". Use a file when you need more than the
model (concurrency, enrichment, thinking map, ...); `codeassure.jsonc` in the repo is the fully commented
reference. Minimal example:

```json
{
  "model": {
    "provider": "openai-compatible",
    "name": "your-model-name",
    "api_base": "http://localhost:5000",
    "api_key": "$YOUR_API_KEY_ENV_VAR",
    "tool_calling": true
  },
  "concurrency": 4
}
```

Then run:

```bash
codeassure --codebase ./my-project --findings results.json --output verified.json
```

- `--codebase`: root the finding paths are relative to. `--findings`: SAST results (Semgrep/opengrep JSON).
- `--grouping` clusters co-located findings (off unless passed). `--severity HIGH,CRITICAL` limits AI analysis.
- Re-running the same command resumes from `verified.json.checkpoint.json` after a crash.
- Set `ACCUKNOX_BASE_URL` + `ACCUKNOX_BEARER_TOKEN` to reuse earlier human verdicts from AccuKnox.

## Build

Needs `uv` (macOS build) and Docker (Linux builds). Run from the repo root:

```bash
packaging/build-binaries.sh                 # macos-arm64 + linux-amd64 + linux-arm64
packaging/build-binaries.sh linux-amd64     # just one target
```

- macOS arm64 builds natively and must run on an Apple Silicon Mac.
- Linux builds run in `python:3.11-bullseye` (glibc 2.31). The script fails if the binary needs a newer glibc and
  smoke-tests `--help` in the container. linux-amd64 on an Apple Silicon Mac runs under emulation (slower).
- Output in `dist/release/`: the three binaries, `SHA256SUMS`, `BUILD-INFO.txt` (version, commit, time).
- The version comes from `pyproject.toml`. Bump it before building a release.
- The existing `build.sh` (host-only build into `dist/codeassure`) still works for local use.

## Release checklist

1. Merge the code to release, bump `version` in `pyproject.toml`, tag `vX.Y.Z`.
2. `packaging/build-binaries.sh` on a clean checkout of that tag.
3. Attach everything in `dist/release/` to the release for the tag, together with the matching `context-graph` binaries.
