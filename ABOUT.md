# About RedTeam Agent

> **Autonomous AI-Powered Red Team & Penetration Testing Orchestration Framework**

---

## 1. Mission & Vision

**RedTeam Agent** bridges the gap between frontier Large Language Models (LLMs) and rigorous, industrial-strength penetration testing. 

Historically, security automation oscillated between two extremes:
1. **Rigid DAST scanners & exploit scripts**: High speed and deterministic, but incapable of contextual reasoning, business logic deduction, novel payload adaptation, or multi-step attack chaining.
2. **Naive conversational AI wrappers**: Prone to context exhaustion, hallucinations, uncoordinated tool thrashing, lack of session persistence, and catastrophic loss of attack surface visibility.

RedTeam Agent re-engineers this paradigm from first principles. It transforms developer AI command-line assistants—including **[OpenCode](https://opencode.ai)**, **[Claude Code](https://docs.anthropic.com/en/docs/claude-code)**, and **[Codex](https://github.com/openai/codex)**—into a self-directed, multi-agent cyber operations team. By combining a deterministic, token-frugal state machine with 9 specialized AI personas, containerized Kali Linux security tooling, and 64 offensive methodology skills, RedTeam Agent executes thorough, reproducible security simulations with minimal human intervention.

---

## 2. Core Architectural Philosophy

### Separation of Cognitive Concerns
Modern penetration testing demands radically distinct cognitive shapes:
* **Strategic Command**: High-level attack path prioritization, scope guardrail enforcement, and resource allocation.
* **Rapid Surface Discovery**: High-throughput web crawling, DNS enumeration, and port scanning.
* **Deep Static Code & Asset Analysis**: Reverse engineering complex JavaScript bundles, client-side route tables, and API schemas.
* **Bounded Triage**: Precise, low-noise probing of specific HTTP input parameters or RPC endpoints.
* **Creative Exploit Synthesis**: Crafting multi-stage injection payloads, authorization bypasses, and memory corruptions.
* **Statistical Fuzzing**: High-volume noise reduction across thousands of permutations with zero cognitive overhead.

Rather than forcing a single model prompt to mode-switch across these conflicting responsibilities (which degrades reasoning accuracy and inflates context token consumption), RedTeam Agent partitions duties across **9 specialized agents**. Each operates with bounded permissions, purpose-built prompts, and dedicated tooling.

### Token-Frugal State Persistence
LLM tokens are scarce, high-latency resources. Conversational history is an unstable medium for tracking hundreds of endpoints, parameters, and scan states. RedTeam Agent decouples execution state from LLM memory:
* **SQLite Backed Case Pipeline (`cases.db`)**: Every endpoint, parameter permutation, and network service is indexed as a discrete work unit.
* **Zero-Token Shell Dispatcher**: Queue querying, batch locking, state transitions, and health checks are computed via shell scripts (`dispatcher.sh`), entirely eliminating token overhead for queue management.
* **Atomic Batch Execution**: Agents receive strictly isolated, serialized batches of work and report structured outcomes back to the database.

### Dual Runtime Flexibility
* **Docker Container Isolation**: Zero-configuration deployment packaging Kali Linux, ProjectDiscovery tools (`katana`, `nuclei`, `subfinder`), `mitmproxy`, and Metasploit RPC into isolated containers.
* **Bare-Metal Kali Native (`local`)**: First-class support for native execution on Kali Linux hosts, eliminating container virtualization overhead and facilitating raw network socket operations.

### Comprehensive Attack Surface Coverage
RedTeam Agent tests both modern web applications and raw infrastructure network services:
* **Web Applications**: REST APIs, GraphQL, Single Page Applications, file upload handlers, WebSockets, OAuth/JWT flows, and business logic.
* **Network Infrastructure (TCP/UDP)**: Active Directory & Kerberos environments, SMB/RPC shares, database listeners (PostgreSQL, MySQL, MSSQL, Redis, MongoDB), remote access (SSH, RDP, VNC), and core network services (DNS, SNMP, SMTP, NFS).

---

## 3. Comparison: How RedTeam Agent Differs

| Attribute | Generic LLM Chatbots | Traditional Scanners (Nessus, Burp) | RedTeam Agent |
|---|---|---|---|
| **Autonomous Chaining** | ❌ Hallucinates steps; loses context | ❌ Rule-bound; cannot pivot findings | ✅ Autonomous chaining across agents |
| **State Tracking** | ❌ Ephemeral chat history | ✅ Proprietary database | ✅ SQLite queue (`cases.db`) + Markdown artifacts |
| **Attack Scope** | ⚠️ Text-only suggestions | ⚠️ Siloed (Web OR Network) | ✅ Unified Web + TCP/UDP infrastructure |
| **Tool Execution** | ❌ Manual copy-paste | ✅ Pre-compiled binary engines | ✅ Containerized or bare-metal Kali tools |
| **Token Efficiency** | ❌ Rapid context window burnout | N/A | ✅ Zero-token shell dispatcher |
| **Resumability** | ❌ Lost on session reset | ⚠️ Scan state pause | ✅ Full checkpoint recovery (`/resume`) |
| **Verification Gate** | ❌ None | ⚠️ Static heuristics | ✅ Objective closure gates & CTF challenge parsers |

---

## 4. Intended Audience & Use Cases

### 1. Authorized Penetration Testers & Red Teams
Accelerate baseline reconnaissance, endpoint classification, and vulnerability triage across large scopes. Free human operators to focus on novel, complex exploit chains and business logic manipulation.

### 2. Security Researchers & CTF Competitors
Simulate autonomous adversaries against vulnerable-by-design targets (HackTheBox, TryHackMe, VulnHub, OWASP Juice Shop, DVWA). Utilize built-in lab profiles and automated flag capture verification.

### 3. DevSecOps & Enterprise Security Engineering
Integrate autonomous, adversarial testing into continuous validation pipelines, staging environments, and defensive monitoring (blue team detection verification).

---

## 5. Ethics, Authorization & Legal Notice

> [!CAUTION]
> **STRICT AUTHORIZATION REQUIRED**
> 
> RedTeam Agent contains capabilities designed to identify and exploit vulnerabilities across software, systems, and networks. It is developed exclusively for **authorized security testing, educational environments, research, and defensive evaluation**.
> 
> Testing targets without prior written authorization from the system owner is illegal and unethical. The authors and contributors assume no liability for misuse or damage caused by this software. Always ensure target scopes are strictly constrained and compliant with local, national, and international laws.
