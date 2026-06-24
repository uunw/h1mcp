# h1mcp

HackerOne MCP server (Rust) — exposes the HackerOne API as MCP tools for Claude
Code / Desktop. Published as `ghcr.io/uunw/h1mcp` (multi-arch amd64+arm64).
See `README.md` for the full tool list and client setup.

## Stack
- Rust + `rmcp` + `reqwest` (rustls, **no OpenSSL**) + tokio; static musl binary on alpine.
- Auth: HTTP Basic `H1_USERNAME:H1_API_KEY` (token from hackerone.com/settings/api_token).

## API path rules (critical)
A **hacker token** only works under `/v1/hackers/*`. The customer/program API
(`/v1/reports`, `/v1/programs`, `/v1/hacktivity` — no prefix) returns **401**.
- programs: `/v1/hackers/programs/{handle}` (+ `/structured_scopes`, `/weaknesses`)
- your reports: `/v1/hackers/me/reports` (filters: keyword/program/severity/state, sort, page)
- single report: `/v1/hackers/reports/{id}` (activities are **nested** here — no standalone endpoint)
- submit: `POST /v1/hackers/reports`; assisted: `POST /v1/hackers/report_intents`
- money: `/v1/hackers/payments/balance` and `/payments/earnings` (**NOT** `/hackers/me/payments` → 401)
- `/v1/hackers/me` (self profile) → **401**; derive identity from the reporter object in your reports.
- **Not in the hacker API**: add comment, close report, update severity, request disclosure —
  these tools return a descriptive error with a link to the web interface instead of a cryptic 401.
- `get_report_activities` extracts activities from the nested `get_report` response (no separate API call).
- Probe a write endpoint safely: POST an invalid body → **400** = endpoint+auth OK (no side effect).

## Build / release
- `[profile.release]`: `lto = "thin"`, `codegen-units = 16` — fast compile; runtime perf
  is irrelevant for this IO-bound server (do not restore fat LTO).
- CI `.github/workflows/docker.yml`: multi-arch on **native runners** (`ubuntu-latest` +
  `ubuntu-24.04-arm`) + digest-merge manifest — **not** QEMU. `concurrency` cancel-in-progress;
  `paths-ignore` docs. Actions pinned to Node-24 majors.
- Release: bump version in `Cargo.toml` + `Cargo.lock` + `src/server.rs` `tool_handler`; commit;
  tag `vX.Y.Z` → CI builds & pushes the image. Verify locally with `docker build` before pushing.

## Known landmines
- **Dockerised MCP env**: the client config `env` block is NOT forwarded into the container —
  must pass `-e H1_USERNAME -e H1_API_KEY` in docker `args`, else the server runs credential-less → 401.
- **Image tag drops the `v`** (semver normalize): `git tag v0.1.3` → image `:0.1.3`. Pin `:0.1.3`, not `:v0.1.3`.
- `Dockerfile` `ENV H1_API_KEY=""` trips a docker linter warning and masks the "env var not set"
  error (empty default = var is always "set"). Runtime supplies creds via `-e`, so the default is unneeded.

## Output
- Tool results are pruned (drop null / empty / `profile_picture`) then serialized as compact
  (non-pretty) JSON to cut LLM input tokens ~40–60%. See `prune()` in `src/server.rs`.

## Git identity
Commit as `uunw <uunw@proton.me>` (set per-repo).
