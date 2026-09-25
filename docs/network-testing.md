# Network Service Testing Guide (TCP/UDP Infrastructure)

> **Methodology and operational specification for scanning, enumerating, and testing non-HTTP TCP/UDP services.**

---

## 1. Overview

While traditional automated penetration testing frameworks focus almost exclusively on web applications, enterprise environments and realistic CTF challenges frequently pivot on **network infrastructure vulnerabilities**.

RedTeam Agent treats network services as first-class citizens alongside web endpoints:
* Evaluates protocol services: **Active Directory, Kerberos, SMB, RPC, database listeners, remote access protocols, mail, DNS, SNMP, and NFS**.
* Integrates directly into the streaming case queue (`cases.db`) under `type=service`.
* Routes tasks through the dedicated **`network-analyst`** subagent.
* Escalates verified vulnerabilities to **`exploit-developer`** for chain construction.

---

## 2. Case Data Model for Services

Network services populate the standard SQLite `cases` table with dedicated fields:

```sql
-- Network Service Columns in cases.db
host             TEXT,       -- Target IP or hostname (e.g., '10.10.10.5')
port             INTEGER,    -- Destination port (e.g., 445)
proto            TEXT,       -- Protocol: 'tcp' or 'udp'
service          TEXT,       -- Service name: 'smb', 'ldap', 'mysql', 'ssh'
service_product  TEXT,       -- Detected daemon/software (e.g., 'OpenSSH')
service_version  TEXT,       -- Version string (e.g., '8.9p1 Ubuntu')
banner           TEXT,       -- Raw service banner or RPC response
scan_ref         TEXT        -- Path to raw Nmap XML or tool output
```

### Identity and Deduplication
To maintain consistency with the HTTP case model while preventing duplicate scans:
* `method`: Hardcoded to `'SERVICE'`
* `url`: Formatted as `'<proto>://<host>:<port>'` (e.g., `tcp://10.10.10.5:445`)
* `url_path`: Formatted as `'/<host>/<port>/<proto>'`
* `params_key_sig`: Calculated as `sha1(proto|host|port|service)`

---

## 3. Network Discovery Pipeline

```
     Target: CIDR / IP / Range
                 │
                 ▼
     ┌───────────────────────┐
     │   scripts/netscan.sh   │ ◄── Nmap TCP (-sV -sC) & UDP (--top-ports)
     └───────────┬───────────┘
                 │ Nmap XML (-oX)
                 ▼
     ┌───────────────────────┐
     │  scripts/net_ingest.sh│ ◄── Scope Filtering (host_in_scope)
     └───────────┬───────────┘     & Parameter Signature Generation
                 │
                 ▼
     ┌───────────────────────┐
     │ cases.db (type=service│ ◄── stage='ingested'
     └───────────────────────┘
```

### Discovery Tools & Scripts

#### 1. Automated Discovery Wrapper (`netscan.sh`)
Scans targets via Nmap, generates structured XML, and automatically pipes results to `net_ingest.sh`:
```bash
# Scan target defined in scope.json
./scripts/netscan.sh "$DIR"

# Scan specific subnet with port constraints
./scripts/netscan.sh "$DIR" 10.0.0.0/24 --top-ports 100

# Fast TCP-only scan against single host
./scripts/netscan.sh "$DIR" 10.10.10.5 --no-udp
```

#### 2. Direct Nmap XML Ingestion (`net_ingest.sh`)
Ingests pre-existing or manual Nmap scan artifacts:
```bash
./scripts/net_ingest.sh "$DIR/cases.db" recon-specialist --nmap-xml "$DIR/scans/nmap_tcp.xml"
```

#### 3. Streaming JSONL Ingestion
Allows the `recon-specialist` agent to stream discovered open ports during reconnaissance:
```bash
echo '{"host":"10.0.0.5","port":445,"proto":"tcp","service":"smb","state":"open"}' \
  | ./scripts/net_ingest.sh "$DIR/cases.db" recon-specialist
```

> **Scope Enforcement**: `net_ingest.sh` evaluates target IPs against `scope.json`. Any host falling outside defined CIDRs, ranges, or hostnames is dropped before queueing.

---

## 4. Network Engagement Mode

When initiating an engagement with an IP address, CIDR block, or range, RedTeam Agent automatically activates **network mode**:

```bash
# Subnet engagement
/engage 10.0.0.0/24

# Single host engagement
/engage 10.10.10.5

# IP range engagement
/engage 10.0.0.5-20
```

### Behavioral Adjustments in Network Mode
* **Web Crawlers Bypassed**: Katana crawler and `mitmproxy` intercepting proxy are not spawned.
* **Scope Definition**: `scope.json` sets `"mode": "network"` and records CIDR ranges.
* **Scope Evaluation**: `host_in_scope` handles CIDR subnet calculations (`ipcalc`/`python3 ipaddress`) and hyphenated ranges (`10.0.0.5-20`).

---

## 5. Service Attack Methodology Skills

The `network-analyst` subagent operates according to 18 dedicated skills located in [`agent/skills/`](../agent/skills/):

### 1. `network-service-testing`
General methodology orchestrator. Defines port-to-service classification, safe triage protocols, and stage transition criteria.

### 2. `smb-netbios`
* **Protocols**: SMB (TCP 445), NetBIOS (TCP 139), MSRPC (TCP 135).
* **Techniques**: Null session and guest account enumeration (`enum4linux-ng`, `smbclient`), share discovery, write permissions, EternalBlue (MS17-010) check, and SMB signing evaluation.

### 3. `database-services`
* **Protocols**: MySQL (3306), MSSQL (1433), PostgreSQL (5432), MongoDB (27017), Redis (6379), Elasticsearch (9200).
* **Techniques**: Default/blank credentials, unauthenticated Redis `CONFIG SET` or replication abuse, MongoDB exposed databases, MSSQL `xp_cmdshell` checks, and PostgreSQL `COPY ... FROM PROGRAM`.

### 4. `remote-access-services`
* **Protocols**: SSH (22), RDP (3389), VNC (5900), Telnet (23).
* **Techniques**: SSH key and banner enumeration, weak cipher detection, BlueKeep (CVE-2019-0708) check on RDP, VNC unauthenticated access, bounded password spraying with discovered credentials.

### 5. `mail-dns-services`
* **Protocols**: SMTP (25/587), IMAP (143/993), POP3 (110/995), DNS (53).
* **Techniques**: DNS zone transfers (`AXFR`), sub-domain brute forcing, recursive query amplification, SMTP user enumeration (`VRFY`/`EXPN`), and open relay verification.

### 6. `ldap-kerberos`
* **Protocols**: LDAP (389/636), Kerberos (88).
* **Techniques**: Anonymous LDAP binding, Active Directory domain discovery, AS-REP Roasting (users with `DONT_REQ_PREAUTH`), Kerberoasting (Service Principal Names), and ADCS certificate template abuse.

### 7. `snmp-ftp-nfs`
* **Protocols**: SNMP (UDP 161), FTP (21), NFS (2049).
* **Techniques**: Public/private SNMP community string brute-forcing (MIB enumeration), Anonymous FTP read/write checks, and NFS share mounting with `no_root_squash` analysis.

### 8. `tls-ssl-testing`
* **Protocols**: TLS/SSL on any service port (443, 8443, 636, 993, 9443, and non-standard).
* **Techniques**: Protocol downgrade (SSLv3/TLS 1.0–1.1), weak cipher and key-exchange suites, expired/self-signed/SAN-mismatched certificates, incomplete chains, weak renegotiation, missing OCSP stapling, and HSTS/security-header coverage.

### 9. `kubernetes-testing`
* **Ports**: Kubernetes API (6443), etcd (2379–2380), kubelet (10250/10255), dashboard (8001), NodePort range (30000–32767).
* **Techniques**: Anonymous API auth, `kubectl auth can-i` RBAC self-checks, unauthenticated etcd reads, kubelet read-only and log endpoints, dashboard exposure, and pod/container escape preconditions (privileged, host mounts, host namespaces).

### 10. `container-testing`
* **Ports**: Docker Remote API (2375/2376), Swarm (2377/7946), registries (5000/5001).
* **Techniques**: Unauthenticated Docker API enumeration and execution paths, exposed `docker.sock`, container escape classes (privileged, cgroup `release_agent`, capabilities), anonymous registry push/pull, Dockerfile/build-context secret leakage, and runtime CVEs (runc, containerd).

### 11. `cloud-testing`
* **Services**: AWS, Azure, and GCP instance metadata, object storage, identity and secret management.
* **Techniques**: IMDS reachability (including via SSRF), IMDSv2 enforcement, over-permissive instance roles, publicly listable buckets/containers/snapshots, managed identity and Cognito misconfiguration, and read-only CLI enumeration. Resource creation/deletion is never performed.

### 12. `ci-cd-security`
* **Ports**: Jenkins (8080), GoCD and registries (5000), exposed CI configuration.
* **Techniques**: Unauthenticated Jenkins/script console/CLI access, GitHub Actions `pull_request_target` and self-hosted runner exposure, Actions cache poisoning, GitLab CI variable leakage, secrets in repository history, dependency confusion, and artifact poisoning.

### 13. `voip-sip-testing`
* **Ports**: SIP signaling (5060/5061 TCP+UDP), SIP over TLS (5061), RTP media (dynamic range), WebRTC gateways.
* **Techniques**: REGISTER/AUTH challenges and weak SIP credentials, unauthenticated INVITE/OPTIONS, missing digest validation, header-injection through SIP URI user parts, codec/invitation enumeration, and RTP exposure checks. `sipp` is used only for bounded single-message scenarios.

### 14. `embedded-device-testing`
* **Ports**: Router/NAS/camera/gateway admin planes (80/443/8080/8443/37215/52869), Telnet (23), SSH (22), vendor RPC ports.
* **Techniques**: Unauthenticated admin-plane access, hardcoded/default device credentials, command-injection parameters in CGI handlers, session/API token exposure in config or export endpoints, and cross-protocol handoffs to the LAN segment.

### 15. `fastcgi-service-testing`
* **Ports**: FastCGI/FPM (9000/9090) and adjacent HTTP listeners.
* **Techniques**: Direct FastCGI record framing against the listener, `SCRIPT_FILENAME`/`PHP_VALUE`/`DOCUMENT_ROOT` path-state handling, front-controller and source-disclosure behavior, and HTTP-layer confirmation once the front end is identified. Always confirm-only: no PHP code execution on a listener that was not verified in scope.

### 16. `custom-protocol-reverse-engineering`
* **Ports**: Any TCP/UDP service that no known-protocol script identifies.
* **Techniques**: Banner and hexdump capture, framing classification (line/length-prefixed/TLV/fixed-header), bounded structural field mapping, a single read-only request per hypothesis, and byte-differential confirmation. Owns the unknown-service cases that `network-service-testing` classifies and hands off.

### 17. `web-admin-console-testing`
* **Ports**: Tomcat manager, phpMyAdmin, Druid, Grafana, Kibana, and generic admin panels on common management ports (8080, 8443, 8888, 3000, 5601, 9090).
* **Techniques**: Console fingerprinting and version mapping, a bounded default-credential check (static list, no spray), console-specific unauthenticated disclosure (monitor/status/datasource/query viewers), and broken function-level authorization on admin methods. Promotion is confirm-only; exploitation hands to `exploit-developer`.

### 18. `message-queue-testing`
* **Ports**: Kafka (9092/9093), RabbitMQ AMQP (5672/5671) and management API (15672), MQTT (1883/8883), ActiveMQ OpenWire (61616) and web console (8161), Redis Pub/Sub (6379, cross-referenced with `database-services`).
* **Techniques**: Unauthenticated broker metadata/topic enumeration, wildcard MQTT subscription and retained-message disclosure, RabbitMQ management API topology dump and default-credential check, Kafka consumer-group hijacking, and version-mapped RCE primitives (ActiveMQ OpenWire deserialization, RabbitMQ Erlang-cookie exposure). Confirm-only: no publishing onto production business topics/queues.

All eighteen skills enforce a confirm-only rule during enumeration: exploitation and resource mutation are handed to `exploit-developer` at `stage=vuln_confirmed`.

---

## 6. Safety Guardrails & Depth Constraints

To avoid denial of service and scanner lockouts during infrastructure testing, RedTeam Agent enforces strict operational guardrails:

* **Bounded Nmap Executions**: Nmap commands must specify `--host-timeout <= 120s` and `--max-retries 2`. Aggressive timing (`-T5`) is disallowed; `-T4` is standard.
* **Controlled Brute Force**: Hydra operations are restricted to small candidate credential sets discovered during OSINT or recon (`-t 4 -W 5`). Blind, dictionary-wide brute force is forbidden.
* **Credential Harvest & Immediate Persistence**: Any discovered usernames, hashes, or cleartext passwords must be written immediately to `$DIR/auth.json` to facilitate lateral movement across other services.

---

## 7. Lab Profiles for Network Engagements

For network CTF challenges and lab targets, the objective closure gate is driven by dedicated lab profiles:

| Profile | Target Environment | Objective Type |
|---|---|---|
| `generic-network.json` | General enterprise network / AD lab | Declared checklist (Domain Admin, Root, etc.) |
| `metasploitable.json` | Metasploitable 2 / 3 targets | Known service vulnerability checklist |
| `hackthebox.json` | HackTheBox machines | User (`user.txt`) and Root (`root.txt`) flags |
| `vulnhub.json` | VulnHub VMs | Flag capture markers (`flag{...}`) |
| `tryhackme.json` | TryHackMe challenge rooms | Flag or task objective checklists |

To manually assign a specific network profile during initialization:
```bash
python3 ./scripts/lab_objective.py detect "$DIR" --profile hackthebox
```
