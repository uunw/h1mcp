# h1mcp

HackerOne MCP server written in Rust. Exposes the HackerOne API as MCP tools usable from Claude Desktop or any MCP-compatible client.

## Features

- Full report lifecycle: search, read, submit, comment, close, update severity, request disclosure
- Program discovery: list programs, get scope, get weakness types
- Hacker stats: profile, balance, earnings, hacktivity search
- Pattern analysis across your submitted reports
- **Local draft management**: save, review, edit, and submit drafts without immediately hitting the API

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

Create a HackerOne API token at <https://hackerone.com/settings/api_token>.

```
H1_USERNAME=your_hackerone_username
H1_API_KEY=your_api_key
```

### Docker (recommended)

Pull and run directly from GitHub Container Registry:

```sh
docker pull ghcr.io/uunw/h1mcp
docker run --rm -e H1_USERNAME=... -e H1_API_KEY=... ghcr.io/uunw/h1mcp
```

Or build locally:

```sh
docker build -t h1mcp .
```

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
      "args": ["run", "--rm", "-i", "ghcr.io/uunw/h1mcp"],
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
  h1mcp -- docker run --rm -i ghcr.io/uunw/h1mcp

# project scope (committed to .mcp.json, shared with team)
claude mcp add --scope project \
  --env H1_USERNAME=your_username \
  --env H1_API_KEY=your_api_key \
  h1mcp -- docker run --rm -i ghcr.io/uunw/h1mcp
```

Verify: `claude mcp list`

## Draft workflow

```
draft_report → get_draft → update_draft → submit_draft
```

Drafts are stored in `~/.config/h1mcp/drafts/` as JSON files.
