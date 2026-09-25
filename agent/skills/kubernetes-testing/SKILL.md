---
name: kubernetes-testing
description: Enumerate and test Kubernetes control planes, kubelets, workloads, RBAC, images, and escape paths
origin: RedteamOpencode
---

# Kubernetes Testing

## When to Activate

- Ports 6443 (API server), 2379-2380 (etcd), 10250/10255 (kubelet), 8001 (dashboard)
- TCP 30000-32767 (NodePort), exposed `.kube/config`, service-account token files, or cluster ingress
- Kubernetes API, etcd, kubelet, dashboard, or container-runtime indicators in scope

## Tools

`run_tool nmap`, `run_tool kubectl`, `run_tool curl`, `run_tool etcdctl`, `run_tool grype`, `run_tool trivy`, `run_tool kube-bench`, `run_tool kubesec`, `run_tool nuclei`, `jq`

## Methodology

### 1. Fingerprint the Control Plane

Scan only scoped management interfaces and preserve the service map:

```bash
run_tool nmap -sV -p 6443,2379-2380,10250,10255,8001,30000-32767 HOST -oA "$DIR/scans/k8s_ports"
run_tool curl -sk --connect-timeout 5 --max-time 20 https://HOST:6443/version
run_tool curl -sk --connect-timeout 5 --max-time 20 https://HOST:6443/api
run_tool curl -sk --connect-timeout 5 --max-time 20 https://HOST:6443/apis
run_tool curl -sk --connect-timeout 5 --max-time 20 https://HOST:6443/healthz
```

Treat a response without credentials as anonymous-auth evidence; do not infer authorization from a health endpoint.

### 2. Test Anonymous Authentication and Kubeconfigs

Probe `/api`, `/apis`, discovery, and dashboard routes with no credential. When an in-scope kubeconfig exists, set `KUBECONFIG` to that exact file and run the self-check before any write:

```bash
KUBECONFIG="$DIR/kubeconfig" run_tool kubectl version --short
KUBECONFIG="$DIR/kubeconfig" run_tool kubectl auth can-i --list
KUBECONFIG="$DIR/kubeconfig" run_tool kubectl get pods,secrets,configmaps -A -o yaml > "$DIR/scans/k8s_objects.yaml"
```

Record anonymous versus authenticated scope, API groups, user identity, and the exact self-check output. Do not replace an unavailable kubeconfig with a guessed cluster name.

### 3. Enumerate RBAC and Workload Data

Use `auth can-i` as a read-only authorization check. Test secret reads, pod creation, pod exec, workload mutation, impersonation, and token review without executing the permitted action:

```bash
KUBECONFIG="$DIR/kubeconfig" run_tool kubectl auth can-i get secrets --all-namespaces
KUBECONFIG="$DIR/kubeconfig" run_tool kubectl auth can-i create pods --all-namespaces
KUBECONFIG="$DIR/kubeconfig" run_tool kubectl auth can-i create pods/exec -n NAMESPACE
KUBECONFIG="$DIR/kubeconfig" run_tool kubectl auth can-i patch deployments.apps -n NAMESPACE
KUBECONFIG="$DIR/kubeconfig" run_tool kubectl auth can-i impersonate users
KUBECONFIG="$DIR/kubeconfig" run_tool kubectl get secrets,configmaps,pods -A -o json > "$DIR/scans/k8s_resources.json"
```

Enumerate service-account names, projected token paths, namespaces, image references, host mounts, and pod security contexts. Save tokens or credential material to `$DIR/auth.json` and reference the source in `$DIR/intel.md`.

### 4. Check etcd Exposure

Test unauthenticated health, membership, and key-prefix reads. If TLS is enabled, use only certificate material already in scope:

```bash
run_tool etcdctl --endpoints=http://HOST:2379 endpoint health
run_tool etcdctl --endpoints=http://HOST:2379 member list
run_tool etcdctl --endpoints=http://HOST:2379 get / --prefix --keys-only
run_tool etcdctl --endpoints=https://HOST:2379 --cacert "$DIR/etcd/ca.crt" --cert "$DIR/etcd/client.crt" --key "$DIR/etcd/client.key" endpoint status
```

A successful unauthenticated prefix read is a critical exposure; stop before dumping values and hand the exact read-only proof to exploit-developer.

### 5. Probe Kubelet and Dashboard

Read-only kubelet endpoints disclose pods, node metadata, and container logs. Authenticated RCE primitives require an explicit handoff:

```bash
run_tool curl -sk --connect-timeout 5 --max-time 20 https://HOST:10255/pods
run_tool curl -sk --connect-timeout 5 --max-time 20 https://HOST:10250/pods
run_tool curl -sk --connect-timeout 5 --max-time 20 https://HOST:10250/runningpods/
run_tool curl -sk --connect-timeout 5 --max-time 20 https://HOST:10250/containerLogs/NAMESPACE/POD/CONTAINER
run_tool curl -sk --connect-timeout 5 --max-time 20 https://HOST:8001/
run_tool curl -sk --connect-timeout 5 --max-time 20 https://HOST:8001/api/v1/namespaces
```

If a valid bearer token is already in scope, repeat the 10250 reads with `Authorization: Bearer TOKEN`. `/run`, `/exec`, and command-bearing log or exec requests are exploit-developer-owned at `vuln_confirmed`; do not send them during enumeration.

### 6. Triage Escape Conditions and Images

Collect pod specs, then compare namespace sharing, privileged mode, capabilities, host mounts, host PID, host IPC, and host network namespaces, and `/proc` or `/sys` exposure:

```bash
run_tool kubectl get pods -A -o json > "$DIR/scans/k8s_pod_specs.json"
jq -r '.items[] | {namespace:.metadata.namespace,name:.metadata.name,hostPID:.spec.hostPID,hostIPC:.spec.hostIPC,hostNetwork:.spec.hostNetwork,containers:.spec.containers}' "$DIR/scans/k8s_pod_specs.json" > "$DIR/scans/k8s_escape_candidates.jsonl"
run_tool kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' > "$DIR/scans/k8s_images.txt"
```

From inside a pod, only an exploit-developer may run the exact `kubectl exec` inspection or container escape primitive; record namespace, mount, capability, and cgroup evidence before handoff. Use registry-only image/vulnerability triage where possible; never run an untrusted image on the host.

```bash
run_tool trivy image IMAGE_REF
run_tool grype IMAGE_REF
run_tool kubesec scan "$DIR/scans/k8s_pod_specs.json"
```

### Lab objective recall closure

When the active profile lists a Kubernetes objective, requeue the one exact workflow named by its `recall_branches` instead of substituting a generic health check. Save the response or object listing to `$DIR/scans/k8s-objective.txt`, run `python3 ./scripts/lab_objective.py snapshot "$DIR"`, and hand off `objective=<name> status=solved|requeued evidence=<path> next=<exact action>`.

## References

`references/vuln-checklists/A01-broken-access-control.md`, `references/vuln-checklists/A02-security-misconfiguration.md`, `references/api-security/API08-security-misconfiguration.md`, `references/api-security/API10-unsafe-consumption.md`, `references/offensive-tactics/red-team-infra/infra-setup.md`.

## Confirm-Only Rule

Enumeration, anonymous-auth checks, `auth can-i`, and read-only `get/list` are confirm-stage. Exploitation is owned by exploit-developer at stage=vuln_confirmed; never destroy Kubernetes resources or perform a write, pod creation, exec, token use, or escape without that explicit ownership.

## Budget

`--host-timeout 120s`. Cap each service at one anonymous probe, one RBAC self-check set, and one read-only endpoint pass; no broad secret dump or mutation.
