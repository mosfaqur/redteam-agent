---
name: container-testing
description: Enumerate and test Docker, registries, Swarm, container runtimes, build contexts, and escape paths
origin: RedteamOpencode
---

# Container Testing

## When to Activate

- Ports 2375/2376 (Docker API), 4243 (Docker Swarm), 5000/5001 (registries), 2377/7946 (Swarm)
- Exposed `docker.sock`, Dockerfile/compose-file disclosure, or container-runtime indicators
- Container hosts, registries, orchestration services, or build artifacts in scope

## Tools

`run_tool nmap`, `run_tool curl`, `run_tool docker`, `run_tool skopeo`, `run_tool gitleaks`, `run_tool trivy`, `run_tool grype`, `run_tool kube-bench`, `run_tool nuclei`, `jq`

## Methodology

### 1. Fingerprint Docker, Swarm, and Registry Services

Map the management and registry surfaces without starting a workload:

```bash
run_tool nmap -sV -p 2375,2376,4243,5000,5001,2377,7946 HOST -oA "$DIR/scans/container_ports"
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:2375/_ping
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:2375/version
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:2375/containers/json
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:2375/images/json
run_tool curl -skS --connect-timeout 5 --max-time 20 https://HOST:2376/version
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:4243/version
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:2377/version
```

Record API version, authentication boundary, registry catalog exposure, and whether Swarm management is unauthenticated.

### 2. Confirm Unauthenticated Docker API Exposure

Use read-only client calls and inspect metadata. Do not create, start, restart, remove, or exec a container during confirmation:

```bash
run_tool docker -H tcp://HOST:2375 version
run_tool docker -H tcp://HOST:2375 ps -a
run_tool docker -H tcp://HOST:2375 images
run_tool docker -H tcp://HOST:2375 inspect CONTAINER_ID > "$DIR/scans/container_inspect.json"
run_tool docker -H tcp://HOST:2375 inspect --format '{{json .HostConfig}}' CONTAINER_ID > "$DIR/scans/container_hostconfig.json"
```

If anonymous API access permits `POST /containers/create` with a privileged flag, host bind mount, host namespace, and a following `/containers/.../start`, classify it as an unauthenticated API remote-code-execution candidate. Do not send those write requests here; hand the exact capability evidence to exploit-developer at `vuln_confirmed`.

### 3. Triage Container Escape Classes

Compare runtime metadata and an authorized inspection shell against the escape checklist: privileged containers, host bind mounts, host PID, host IPC, and host network namespaces, capabilities such as `CAP_SYS_ADMIN` or `CAP_SYS_PTRACE`, writable cgroup v1 paths, `release_agent`, `/proc`, and `/sys`:

```bash
run_tool docker -H tcp://HOST:2375 inspect --format '{{json .Mounts}}' CONTAINER_ID
run_tool docker -H tcp://HOST:2375 inspect --format '{{json .HostConfig.CapAdd}}' CONTAINER_ID
run_tool docker -H tcp://HOST:2375 inspect --format '{{json .HostConfig.Privileged}}' CONTAINER_ID
run_tool docker -H tcp://HOST:2375 inspect --format '{{json .HostConfig.PidMode}} {{json .HostConfig.IpcMode}} {{json .HostConfig.NetworkMode}}' CONTAINER_ID
run_tool docker -H tcp://HOST:2375 exec CONTAINER_ID sh -c 'id; mount; ls -la /proc /sys' # exploit-developer-only after confirmation
```

Treat cgroup `release_agent`/v1 escape, writable host mounts, and namespace sharing as candidates, not as permission to modify the host. Preserve exact container, mount, capability, and runtime evidence.

### 4. Enumerate Registries and Anonymous Push/Pull Policy

Check the registry API, catalog, tags, manifests, and upload policy without downloading or publishing an image:

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:5000/v2/
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:5000/v2/_catalog
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:5000/v2/IMAGE/tags/list
run_tool curl -sS -i -X OPTIONS --connect-timeout 5 --max-time 20 http://HOST:5000/v2/IMAGE/blobs/uploads/ # anonymous push-policy check only
run_tool skopeo inspect docker://HOST:5000/IMAGE
```

Anonymous pull is a confirmed data-exposure path when catalog, tags, or manifests are readable. An anonymous push capability is reportable from authorization policy only; never upload a layer, alter a tag, or pull an untrusted image on the host.

### 5. Inspect Build Contexts and Secret Material

Probe disclosed Dockerfile, compose, ignore, VCS, package-manager, and environment files, then scan only collected artifacts:

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/Dockerfile
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/.dockerignore
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/docker-compose.yml
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/.git/config
run_tool gitleaks detect --source "$DIR" --no-git
run_tool trivy fs "$DIR"
```

Record leaked registry credentials, build tokens, private keys, package tokens, and image-layer metadata. Write discovered credentials to `$DIR/auth.json` and reference the source in `$DIR/intel.md`; do not print secret values into logs.

### 6. Triage Runtime Versions and Known CVEs

Fingerprint Docker Engine, containerd, and runc through version output and targeted service checks, then map only evidence-backed CVEs:

```bash
run_tool docker -H tcp://HOST:2375 version
run_tool docker -H tcp://HOST:2375 info
run_tool nmap -sV -p 2375,2376,4243 HOST --script ssl-cert,http-title
run_tool grype IMAGE_REF
run_tool trivy image IMAGE_REF
```

Prefer registry metadata and remote scanners. Never pull or run an untrusted image on the host without explicit approval; a version match is a triage signal, not proof of exploitability.

## References

`references/vuln-checklists/A01-broken-access-control.md`, `references/vuln-checklists/A02-security-misconfiguration.md`, `references/vuln-checklists/A03-supply-chain-failures.md`, `references/api-security/API08-security-misconfiguration.md`, `references/offensive-tactics/red-team-infra/infra-setup.md`.

## Confirm-Only Rule

Remote API, registry, build-context, and metadata enumeration is confirm-stage. Exploitation is owned by exploit-developer at stage=vuln_confirmed; never create, destroy, or restart container resources, push images, pull or run untrusted images without explicit approval, or attempt an escape during this skill.

## Budget

`--host-timeout 120s`. One read-only API pass, one registry-policy pass, and one bounded build-artifact scan; no image pull, image execution, registry push, or infrastructure changes.
