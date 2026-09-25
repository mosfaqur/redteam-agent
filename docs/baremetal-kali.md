# Bare-Metal Kali Linux Runtime Guide

> **Deploying and running RedTeam Agent natively on Kali Linux hosts without Docker virtualization.**

---

## 1. Overview

While RedTeam Agent defaults to containerized execution to ensure isolation on general macOS and Linux workstations, it includes dedicated native support for **bare-metal Kali Linux**.

In native mode (`REDTEAM_RUNTIME_MODE=local`), all container abstractions are eliminated. Security tools (`nmap`, `ffuf`, `sqlmap`, `katana`, `mitmdump`, `msfrpcd`) are invoked directly from the host system's `PATH`.

### Advantages of Native Execution
* **Raw Network Access**: Enables low-level socket operations, raw TCP/SYN/UDP packet generation with `nmap`, and direct layer-2 network interface binding without Docker NAT or bridge latency.
* **Zero Container Overhead**: Eliminates Docker daemon dependencies, CPU virtualization overhead, and volume-mounting disk bottlenecks.
* **Direct Access to Local Tooling & Wordlists**: Seamlessly leverages Kali's pre-installed SecLists dictionaries (`/usr/share/seclists`), custom scripts, and bleeding-edge Go security binaries.

---

## 2. Quick Installation

From the repository root on your Kali Linux machine:

```bash
# Basic installation (configures local runtime mode)
./install.sh kali ~/redteam-agent

# Recommended: Install and auto-provision any missing Kali security packages
./install.sh kali ~/redteam-agent --install
```

### Automatic Runtime Detection
When running `install.sh` on a verified Kali Linux installation (`/etc/os-release` matching Kali), the installer **automatically selects `local` mode** for `opencode`, `claude`, and `codex` products unless `REDTEAM_RUNTIME_MODE=docker` is explicitly exported.

The installer:
1. Deploys the complete agent runtime (prompts, skills, references, scripts, lab profiles).
2. Generates a local configuration file (`.env`) with `REDTEAM_RUNTIME_MODE=local`.
3. Auto-detects local binary paths for `katana`, `chromium`, and `chromedriver`.
4. Executes [`agent/scripts/check_local_tools.sh`](../agent/scripts/check_local_tools.sh) to audit host package dependencies.

---

## 3. Host Toolchain Requirements

To ensure all 9 agents can execute their specialized capabilities, the host Kali installation requires the following security suites:

| Category | Utilities | Debian / Kali Package Names |
|---|---|---|
| **Reconnaissance** | `nmap`, `whatweb`, `nikto`, `dig`, `whois` | `nmap`, `whatweb`, `nikto`, `dnsutils`, `whois` |
| **Web & Fuzzing** | `ffuf`, `gobuster`, `dirb`, `wfuzz`, `arjun`, `curl`, `wget` | `ffuf`, `gobuster`, `dirb`, `wfuzz`, `arjun`, `curl`, `wget` |
| **Exploitation** | `sqlmap`, `hydra`, `nc` | `sqlmap`, `hydra`, `netcat-traditional` |
| **ProjectDiscovery** | `nuclei`, `subfinder`, `katana` | `nuclei`, `subfinder`, `katana` *(or via `go install`)* |
| **Traffic & Browser** | `mitmdump`, `chromium`, `chromedriver` | `mitmproxy`, `chromium`, `chromium-driver` |
| **Post-Exploitation**| `msfrpcd` (Metasploit) | `metasploit-framework` |
| **System & Parsing** | `jq`, `sqlite3`, `python3`, `openssl`, `rg`, `git` | `jq`, `sqlite3`, `python3`, `openssl`, `ripgrep`, `git` |
| **Dictionaries** | SecLists, rockyou, common wordlists | `seclists`, `wordlists` |

### Manual Dependency Installation
If you prefer manual package management:

```bash
sudo apt-get update && sudo apt-get install -y \
  nmap nikto whatweb gobuster ffuf dirb wfuzz sqlmap hydra \
  netcat-traditional wget curl nuclei subfinder katana arjun \
  mitmproxy chromium chromium-driver metasploit-framework \
  ripgrep jq sqlite3 python3 openssl dnsutils whois git \
  seclists wordlists
```

#### Installing ProjectDiscovery Tools via Go
If repository packages are outdated, compile the latest versions directly:
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Ensure Go binaries are in PATH
export PATH="$HOME/go/bin:$PATH"
```

---

## 4. Toolchain Verification

RedTeam Agent provides a built-in preflight utility to verify all required dependencies:

```bash
cd ~/redteam-agent

# Audit tools and report missing packages
./scripts/check_local_tools.sh

# Automatically install any detected missing packages
./scripts/check_local_tools.sh --install
```

---

## 5. Runtime Architecture & Execution Mechanics

Environment switching is managed by [`agent/scripts/lib/container.sh`](../agent/scripts/lib/container.sh):

```
                                  REDTEAM_RUNTIME_MODE
                                    /              \
                                   /                \
                       "docker"   /                  \   "local"
                                 ▼                    ▼
                    ┌─────────────────────┐  ┌─────────────────────┐
                    │ docker run ...      │  │ Host Executable     │
                    │ kali-redteam <tool> │  │ directly on $PATH   │
                    └─────────────────────┘  └─────────────────────┘
```

### Binary Path Resolution Order
1. An explicit environment variable defined in `.env` (e.g., `KATANA_LOCAL_BIN=/usr/local/bin/katana`).
2. The first matching executable found on the active system `$PATH`.
3. Default distribution fallback path (e.g., `/usr/bin/<tool>`).

### Metasploit RPC Integration
In native mode, [`agent/scripts/check_metasploit_runtime.sh`](../agent/scripts/check_metasploit_runtime.sh) starts a background `msfrpcd` service on the host:

```bash
msfrpcd -P msf -U msf -a 127.0.0.1 -p 55553 -S
```

The OpenCode Metasploit MCP server communicates with this local instance over stdio. Metasploit MCP tools are strictly restricted to the `exploit-developer` subagent.

---

## 6. Usage & Workflow

Launch your AI assistant directly within the installed directory:

```bash
cd ~/redteam-agent

# Launch OpenCode (or claude / codex)
opencode

# Start engagement against target
/engage http://target-web.local:8080

# Or initiate autonomous infrastructure scan
/autoengage 10.10.10.0/24
```

All commands, phases, case stages, lab profiles, and report generation operate identically to the Docker runtime.

---

## 7. Troubleshooting

| Issue | Root Cause | Solution |
|---|---|---|
| `run_tool: command not found` | The requested pentest utility is absent from host `$PATH`. | Run `./scripts/check_local_tools.sh --install` to install missing tools. |
| `Katana cannot find Chrome` | Headless Chrome binary not resolved. | Add `KATANA_CHROME_BIN=/usr/bin/chromium` to your `.env` file. |
| `browser_flow.py fails` | Selenium driver missing or mismatched. | Install host driver: `sudo apt-get install chromium-driver` and verify with `which chromedriver`. |
| `Metasploit MCP error -32000: Connection closed` | Python MCP venv has `mcp>=2.0` installed, incompatible with the vendored server v1 API. | Pin MCP package: `~/redteam-agent/.opencode/vendor/metasploitmcp-venv/bin/pip install "mcp<2"`, then restart your CLI. |
| `msfrpcd port conflict` | Port 55553 is bound by another service. | Kill conflicting processes: `fuser -k 55553/tcp` or configure `MSF_PORT` in `.env`. |
| `Permission denied (Nmap raw socket)` | UDP or SYN scan requires root privileges. | Either run OpenCode with appropriate network capabilities (`setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap`) or run under `sudo`. |

---

## 8. Security & Operational Safety

> [!CAUTION]
> **Host Isolation Warning**
> 
> Unlike the Docker runtime, which isolates disk, memory, and network interactions within container sandboxes, the bare-metal Kali runtime executes all security tooling **directly under your host user account**. 
> 
> * Exercise caution when testing untrusted exploit scripts or parsing unverified remote data.
> * Ensure testing is restricted strictly to explicitly authorized IP ranges and hostnames.
> * If testing targets that may return malicious payloads, utilize the Docker runtime (`./install.sh docker`) to maintain blast-radius isolation.
