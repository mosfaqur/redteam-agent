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

Also check for these additional escape-adjacent conditions from the inspect metadata alone: a mounted `docker.sock` inside the container (`/var/run/docker.sock` in `.Mounts` — grants a docker-in-docker escape via the same API), `CAP_SYS_MODULE`/`CAP_SYS_PTRACE`/`CAP_DAC_READ_SEARCH` in `CapAdd`, a `SecurityOpt` list missing `no-new-privileges`, an AppArmor/seccomp profile of `unconfined`, and a writable `/proc/sys/kernel/core_pattern` path (core-dump handler escape). A runtime version match to a known runc/containerd breakout (e.g. CVE-2024-21626 working-directory FD leak, CVE-2019-5736 runc `/proc/self/exe` overwrite) is a triage signal only — do not attempt the breakout here.

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

Check image-history metadata (without pulling the full layer) for secrets baked into build steps, and check for image/tag squatting exposure — a mutable `:latest`/floating tag that downstream automation pulls unpinned, and a namespace that could be typosquatted against an internal-sounding image name:
```bash
run_tool skopeo inspect --config docker://HOST:5000/IMAGE
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:5000/v2/IMAGE/manifests/latest -H 'Accept: application/vnd.docker.distribution.manifest.v2+json'
```
A registry served over plaintext HTTP (no TLS) or with a self-signed cert accepted without `--insecure-registry` warnings is a separate transport-security finding — record it alongside the anonymous-access result.

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

### 7. Deepen Escape Primitive Evidence (Privileged Mode, Socket, cgroup)

Gather the exact metadata that distinguishes a theoretical escape class from a confirmed capability, without executing the escape:

```bash
run_tool docker -H tcp://HOST:2375 inspect --format '{{json .HostConfig.Devices}}' CONTAINER_ID
run_tool docker -H tcp://HOST:2375 inspect --format '{{json .HostConfig.SecurityOpt}}' CONTAINER_ID
run_tool docker -H tcp://HOST:2375 exec CONTAINER_ID sh -c 'ls -la /var/run/docker.sock 2>/dev/null; cat /proc/self/status | grep CapEff' # exploit-developer-only after confirmation
```

A **privileged container** (`HostConfig.Privileged: true`) has every device node under `/dev` bind-mounted and every capability granted — record it as a full host-equivalent escape candidate and do not additionally validate each capability separately. A **mounted `docker.sock`** (`/var/run/docker.sock` present as a bind mount, distinct from a TCP API exposure) lets a process with only the Docker CLI/SDK inside the container create a new privileged container on the host through the same socket; the escape primitive is "control-plane access," not a kernel exploit, so record the mount path and stop there. For **cgroup v1 `release_agent` escape**, the exact precondition chain to record (never execute past inspection) is: cgroup v1 filesystem mounted and writable inside the container (`mount | grep cgroup`), a `notify_on_release` flag settable to `1`, and a writable `release_agent` file at the cgroup root — when all three hold, a process can register an arbitrary host-executed script that fires once the cgroup's last process exits. Treat the presence of all three preconditions together as `vuln_confirmed`-worthy evidence; treat any single precondition alone as informational.

Cross-reference known runtime-breakout CVEs by exact version match only, never by exploitation: CVE-2024-21626 (runc `WORKDIR`/`--mount` file-descriptor leak, runc ≤1.1.11), CVE-2022-0492 (cgroup v1 `release_agent` reachable even without `CAP_SYS_ADMIN` via legacy hierarchy misconfiguration), CVE-2019-5736 (runc `/proc/self/exe` overwrite during `docker exec`/attach), and CVE-2021-30465 (containerd symlink-race TOCTOU on bind-mount resolution enabling host-filesystem escape).

## References

`references/vuln-checklists/A01-broken-access-control.md`, `references/vuln-checklists/A02-security-misconfiguration.md`, `references/vuln-checklists/A03-supply-chain-failures.md`, `references/api-security/API08-security-misconfiguration.md`, `references/offensive-tactics/red-team-infra/infra-setup.md`.

## Confirm-Only Rule

Remote API, registry, build-context, and metadata enumeration is confirm-stage. Exploitation is owned by exploit-developer at stage=vuln_confirmed; never create, destroy, or restart container resources, push images, pull or run untrusted images without explicit approval, or attempt an escape during this skill.

## Budget

`--host-timeout 120s`. One read-only API pass, one registry-policy pass, and one bounded build-artifact scan; no image pull, image execution, registry push, or infrastructure changes.
