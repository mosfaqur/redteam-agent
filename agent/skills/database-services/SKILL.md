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
| MSSQL | `xp_cmdshell` | `EXEC sp_configure 'show advanced options',1` → confirm only |
| PostgreSQL | `COPY ... TO PROGRAM` | `SELECT current_setting('is_superuser');` |
| Redis | config write RCE | `CONFIG GET dir` / `CONFIG SET dir` probe (no full RCE here) |
| MongoDB | unauth data | list DBs/collections, sample one doc |
| Elasticsearch | script/RCE CVE | version check + one known CVE probe |

Do NOT run destructive statements. Read-only proof + one command-exec primitive max;
hand the exploit to `exploit-developer`.

### 5. Data Handling
Any credential/hash/PII extracted → `$DIR/auth.json` + Credentials intel table; treat as a
sensitive-data finding (see `sensitive-data-detection` skill).

## Budget

`--host-timeout 120s`. One auth attempt per default credential pair. No unbounded dumps.
