---
name: ci-cd-security
description: Enumerate and test CI/CD control planes, pipelines, runners, repositories, artifacts, and secrets
origin: RedteamOpencode
---

# CI/CD Security

## When to Activate

- Ports 8080 (Jenkins), 5000 (GoCD or registry), 443 (Git forge), or an exposed CI webhook
- Disclosed `.github/workflows`, `.gitlab-ci.yml`, Jenkinsfiles, pipeline YAML, runner files, or build config
- Repository, forge, registry, runner, or pipeline credentials in scope

## Tools

`run_tool nmap`, `run_tool curl`, `run_tool git`, `run_tool gitleaks`, `run_tool trufflehog`, `run_tool semgrep`, `run_tool osv-scanner`, `run_tool nuclei`, `run_tool grype`, `jq`

## Methodology

### 1. Discover CI and Forge Surfaces

Map exposed control planes and repository endpoints without logging in or triggering jobs:

```bash
run_tool nmap -sV -p 8080,5000,443 HOST -oA "$DIR/scans/ci_ports"
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:8080/login
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:8080/api/json
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:5000/go/api/v1/version
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/.git/HEAD
run_tool git ls-remote https://HOST/ORG/REPO.git
```

Record forge type, authentication boundary, exposed job metadata, repository visibility, and webhook or runner indicators.

### 2. Test Jenkins Unauthenticated Access and Defaults

Check read-only API, Groovy/script-console, CLI, and agent-remoting surfaces. Try only a small operator-approved `ADMIN`/default candidate set:

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:8080/api/json?tree=jobs[name,url,color]
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:8080/scriptText
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:8080/computer/api/json
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:8080/jnlpJars/
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:8080/tcpSlaveAgentListener/
run_tool curl -sS --connect-timeout 5 --max-time 20 -u 'admin:admin' http://HOST:8080/api/json # bounded weak ADMIN/default check
```

Unauthenticated script-console or remoting access is a high-impact candidate. Do not submit Groovy, create jobs, connect an agent, or run a build; hand the exact access evidence to exploit-developer.

### 3. Review GitHub Actions Exposure

Retrieve public workflow and metadata files, then scan their text for trust-boundary mistakes:

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/ORG/REPO/.github/workflows/deploy.yml
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/ORG/REPO/actions/runs?per_page=10
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/ORG/REPO/actions/secrets
run_tool semgrep scan --config p/security-audit "$DIR"
run_tool gitleaks detect --source "$DIR" --no-git
```

Flag `pull_request_target` workflows that expose secrets while checking out untrusted pull-request code, over-permissioned `GITHUB_TOKEN`, self-hosted runner compromise paths, unpinned third-party actions, and Actions cache poisoning. Do not dispatch `workflow_dispatch` or publish a cache.

### 4. Review GitLab Variables and Triggers

Enumerate public project metadata, protected variables, pipeline definitions, and trigger/webhook references without starting a pipeline:

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 'https://HOST/api/v4/projects?visibility=public&per_page=100'
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/api/v4/projects/PROJECT_ID
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/ORG/REPO/-/raw/main/.gitlab-ci.yml
run_tool git ls-remote https://HOST/ORG/REPO.git
```

Record exposed variables, masked-value misuse, trigger tokens, protected-ref assumptions, and webhook endpoints. Never POST a pipeline trigger or use a discovered variable to authenticate elsewhere.

### 5. Search Repository History and Secret Material

Inspect an in-scope `.git` directory and history for committed keys, tokens, agent secrets, and forge credentials:

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/ORG/REPO.git/info/refs?service=git-upload-pack
run_tool git -C "$DIR/repo" log --all --oneline --decorate
run_tool git -C "$DIR/repo" log --all -p -- .github .gitlab-ci.yml Jenkinsfile
run_tool trufflehog filesystem "$DIR/repo" --no-verification
run_tool gitleaks detect --source "$DIR/repo"
```

Write any discovered credential to `$DIR/auth.json` and reference the commit, file, or endpoint in `$DIR/intel.md`; do not publish or rotate it from this skill.

### 6. Triage Supply Chain and Artifact Paths

Inspect manifests and lockfiles without installing, publishing, or uploading. Compare package namespaces and verify artifact checksums and provenance:

```bash
run_tool semgrep scan --config p/secrets "$DIR/repo"
run_tool osv-scanner -r "$DIR/repo"
run_tool grype dir:"$DIR/repo"
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/ORG/REPO/-/jobs/artifacts/main/download
```

Flag dependency confusion, typosquatting exposure, mutable action/image references, artifact or build poisoning, and unsigned CI webhooks. No package install, artifact upload, cache write, or webhook delivery belongs in enumeration.

## References

`references/vuln-checklists/A03-supply-chain-failures.md`, `references/vuln-checklists/A07-authentication-failures.md`, `references/vuln-checklists/A08-integrity-failures.md`, `references/api-security/API02-broken-authentication.md`, `references/api-security/API08-security-misconfiguration.md`, `references/offensive-tactics/credential-access/credential-theft-misc.md`, `references/offensive-tactics/red-team-infra/infra-setup.md`.

## Confirm-Only Rule

Unauthenticated access, default-credential checks, config/history/webhook enumeration, and secret scanning are confirm-stage. Exploitation is owned by exploit-developer at stage=vuln_confirmed; do not push commits, trigger pipelines against non-lab systems, modify CI config, execute Groovy, connect agents, or deliver webhooks.

## Budget

`--host-timeout 120s`. One read-only endpoint pass, one bounded default-credential check, and one repository-history scan; no build, trigger, upload, cache write, or package install.
