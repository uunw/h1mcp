# h1mcp — HackerOne MCP Server

[![Release](https://img.shields.io/github/v/release/uunw/h1mcp?sort=semver)](https://github.com/uunw/h1mcp/releases)
[![Build and push Docker image](https://github.com/uunw/h1mcp/actions/workflows/docker.yml/badge.svg)](https://github.com/uunw/h1mcp/actions/workflows/docker.yml)
[![Container](https://img.shields.io/badge/ghcr.io-uunw%2Fh1mcp-2496ED?logo=docker&logoColor=white)](https://github.com/uunw/h1mcp/pkgs/container/h1mcp)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-DEA584?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)

**h1mcp** is a [HackerOne](https://hackerone.com) [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server written in Rust. It exposes the full HackerOne API — reports, programs, scope, weaknesses, payouts, and hacktivity — plus local draft management as MCP tools you can drive from **Claude Desktop**, **Claude Code**, or any MCP-compatible client.

Use it to run your bug bounty workflow with an AI assistant: search and triage your reports, look up program scope before testing, draft submissions locally, and analyze patterns across your findings — all over the [HackerOne API](https://api.hackerone.com/).

## Features

- **Full report lifecycle** — search, read, submit, comment, close, update severity, request disclosure
- **Program discovery** — list programs, get scope (in-scope assets), get accepted weakness types
- **Hacker stats** — profile (signal, reputation, impact), balance, earnings, hacktivity search
- **Pattern analysis** — aggregate stats across your submitted reports
- **Local draft management** — save, review, edit, and submit drafts without immediately hitting the API
- **Single static binary / tiny Docker image** — built in Rust, no runtime dependencies

## Tools

| Tool | Description |
|---|---|
| `search_reports` | Search your submitted reports by keyword, program, severity, state |
| `get_report` | Get full report details by ID |
| `get_report_with_conversation` | Report + full activity timeline bundled |
| `get_report_activities` | Activity timeline for a report |
| `submit_report` | Submit directly (prefer draft flow) |
| `add_comment` | Comment on a report (supports internal flag) |
| `close_report` | Close/withdraw a report |
| `update_report_severity` | Update severity rating |
| `request_disclosure` | Request public disclosure |
| `list_programs` | List programs you have access to |
| `get_program_details` | Full program details |
| `get_program_scope` | In-scope assets |
| `get_program_weaknesses` | Accepted CWE types |
| `get_hacker_profile` | Your profile (signal, reputation, impact) |
| `get_balance` | Current payout balance |
| `get_earnings` | Earnings history |
| `search_disclosed_reports` | Search hacktivity (public disclosed reports) |
| `analyze_report_patterns` | Aggregate stats across your recent reports |
| `draft_report` | Save a report draft locally |
| `list_drafts` | List saved drafts |
| `get_draft` | Read a draft |
| `update_draft` | Update draft fields |
| `delete_draft` | Delete a draft |
| `submit_draft` | Submit a draft to H1 (deletes draft on success) |

## Setup

### Credentials

Create a HackerOne API token at <https://hackerone.com/settings/api_token>. The
**API username** shown on that page is used for HTTP Basic auth (`username:token`).

```
H1_USERNAME=your_hackerone_username
H1_API_KEY=your_api_key
```

### Docker (recommended)

Pull and run directly from GitHub Container Registry:

```sh
docker pull ghcr.io/uunw/h1mcp
docker run --rm -i -e H1_USERNAME=... -e H1_API_KEY=... ghcr.io/uunw/h1mcp
```

Or build locally:

```sh
docker build -t h1mcp .
```

> [!IMPORTANT]
> When configuring via an MCP client `env` block, you **must** still pass `-e H1_USERNAME -e H1_API_KEY` in the docker args. `docker run` does not automatically forward the parent process environment into the container — without these flags the server starts with no credentials and every request returns `401 Unauthorized`.

### Manual build

```sh
cargo build --release
./target/release/h1mcp
```

### Claude Desktop config

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

**Docker (recommended):**
```json
{
  "mcpServers": {
    "hackerone": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "-e", "H1_USERNAME", "-e", "H1_API_KEY", "ghcr.io/uunw/h1mcp"],
      "env": {
        "H1_USERNAME": "your_username",
        "H1_API_KEY": "your_api_key"
      }
    }
  }
}
```

**Binary:**
```json
{
  "mcpServers": {
    "hackerone": {
      "command": "/path/to/h1mcp",
      "env": {
        "H1_USERNAME": "your_username",
        "H1_API_KEY": "your_api_key"
      }
    }
  }
}
```

### Claude Code (CLI)

```sh
# user scope (available in all projects)
claude mcp add --scope user \
  --env H1_USERNAME=your_username \
  --env H1_API_KEY=your_api_key \
  h1mcp -- docker run --rm -i -e H1_USERNAME -e H1_API_KEY ghcr.io/uunw/h1mcp

# project scope (committed to .mcp.json, shared with team)
claude mcp add --scope project \
  --env H1_USERNAME=your_username \
  --env H1_API_KEY=your_api_key \
  h1mcp -- docker run --rm -i -e H1_USERNAME -e H1_API_KEY ghcr.io/uunw/h1mcp
```

Verify: `claude mcp list`

## Draft workflow

```
draft_report → get_draft → update_draft → submit_draft
```

Drafts are stored in `~/.config/h1mcp/drafts/` as JSON files.

## How it works

h1mcp talks to the HackerOne **hacker API** under `https://api.hackerone.com/v1/hackers/`,
authenticating with HTTP Basic auth (`H1_USERNAME:H1_API_KEY`). Responses are cached
briefly in-process, and rate-limit (`429`) and server errors are retried with backoff.

## License

[MIT](./LICENSE)
