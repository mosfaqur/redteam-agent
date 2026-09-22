# Bare-metal Kali Linux (no Docker)

RedTeam Agent can run entirely on a host Kali Linux install. Instead of spinning
up the `kali-redteam`, `mitmproxy`, and `katana` containers, the `local` runtime
executes the same tools directly from your `PATH`. This is controlled by one
variable:

```bash
REDTEAM_RUNTIME_MODE=local   # docker (default off-Kali) | local
```

## Install

```bash
# From the repo root:
./install.sh kali ~/redteam-agent

# Validate + auto-install any missing host pentest tools:
./install.sh kali ~/redteam-agent --install
```

On Kali, `install.sh` also auto-selects `local` mode for the `opencode`, `claude`,
and `codex` products unless you export `REDTEAM_RUNTIME_MODE` yourself. The
`docker` product always stays in Docker mode.

The installer:
1. Copies the agent runtime (OpenCode files, `skills/`, `references/`, `scripts/`, `labs/`).
2. Writes `REDTEAM_RUNTIME_MODE=local` into `<dir>/.env`.
3. Autodetects `katana` and `chromium` paths into `.env`.
4. Runs `scripts/check_local_tools.sh` (installs with `--install`).

## Verify the toolchain

```bash
./scripts/check_local_tools.sh            # report + install hints
./scripts/check_local_tools.sh --install  # install missing tools
```

It checks the tools the skills invoke via `run_tool`, plus the crawler/browser
stack:

| Category | Tools |
|---|---|
| Recon | `nmap`, `whatweb`, `nikto`, `dig`, `whois` |
| Web/fuzzing | `ffuf`, `gobuster`, `dirb`, `wfuzz`, `arjun`, `curl`, `wget` |
| Exploitation | `sqlmap`, `hydra`, `nc` |
| ProjectDiscovery | `nuclei`, `subfinder`, `katana` |
| Crawl/browser | `mitmdump`, `chromium`, `chromedriver` |
| Post-ex | `msfrpcd` (Metasploit) |
| Support | `jq`, `sqlite3`, `python3`, `openssl`, `rg`, `git` |
| Wordlists | `/usr/share/wordlists`, `/usr/share/seclists` |

Manual equivalents (Kali):

```bash
sudo apt-get update
sudo apt-get install -y nmap nikto whatweb gobuster ffuf dirb wfuzz sqlmap hydra \
  netcat-traditional wget curl nuclei subfinder katana arjun mitmproxy chromium \
  chromium-driver metasploit-framework ripgrep jq sqlite3 python3 openssl dnsutils \
  whois git seclists wordlists

# ProjectDiscovery tools can also be installed with Go:
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

## How the runtime switches

`scripts/lib/container.sh` branches on `REDTEAM_RUNTIME_MODE`:

| Function | `docker` | `local` |
|---|---|---|
| `run_tool <bin> …` | `docker run … kali-redteam <bin>` | runs the host binary (or `rtcurl`) |
| `start_proxy` / `stop_proxy` | proxy container | `mitmdump` directly |
| `start_katana` / `stop_katana` | katana container | `$KATANA_LOCAL_BIN` directly |
| `check_docker` / `check_images` | validates Docker + images | no-op success |
| `check_metasploit_runtime.sh` | `docker compose up metasploit` | starts local `msfrpcd` |

Tool paths are resolved in this order: an explicit `.env` value that exists on
`PATH` → the first matching binary on `PATH` → the `.env`/default value.
`container.sh` also loads repo `.env` defaults (non-destructively) so
`REDTEAM_RUNTIME_MODE=local` takes effect without exporting it in your shell.

## Metasploit MCP

The OpenCode `metasploit` MCP server still runs over stdio, but in local mode
`check_metasploit_runtime.sh` starts a host `msfrpcd` instead of a container:

```bash
msfrpcd -P msf -U msf -a 127.0.0.1 -p 55553 -S
```

Kali ships `metasploit-framework`, so no extra setup is required. MCP tools are
only enabled for the `exploit-developer` subagent.

## Usage

```bash
cd ~/redteam-agent
opencode
/engage http://your-ctf-target:8080
```

Everything else (commands, stages, lab profiles, reporting) is identical to the
Docker runtime.

## Troubleshooting

| Problem | Fix |
|---|---|
| `run_tool: command not found` | Tool missing from `PATH`. Run `./scripts/check_local_tools.sh --install`. |
| Katana can't find Chrome | Set `KATANA_CHROME_BIN` in `.env` (e.g. `/usr/bin/chromium`). |
| `browser_flow.py` fails | Install `chromium` + `chromium-driver`; optionally set `CHROMEDRIVER_BIN`. |
| Metasploit MCP unavailable | Ensure `msfrpcd` is installed and port 55553 is free; re-run `scripts/install_metasploit_mcp.sh .`. |
| Wrong mode | Check `REDTEAM_RUNTIME_MODE` in `.env`; explicit env vars win over `.env`. |

## Security note

Local mode runs tools **without container isolation**, as your user (some tools
may need root). Only run against targets you are authorized to test, and prefer
the Docker runtime when you want blast-radius isolation.
