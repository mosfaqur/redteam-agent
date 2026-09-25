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

Also grep the workflow YAML for untrusted-context expression injection — `${{ github.event.issue.title }}`, `${{ github.event.pull_request.title }}`, `${{ github.head_ref }}`, or any `github.event.*` field interpolated directly into a `run:` shell step rather than passed as an `env:` variable. That pattern lets an external contributor's PR/issue title execute arbitrary shell in the runner context. Also check for a `workflow_run` trigger combined with artifact download from the triggering (untrusted) run, and for third-party actions pinned to a mutable tag (`@v3`) or branch name instead of a commit SHA — both are supply-chain injection points:
```bash
grep -nE '\$\{\{\s*github\.(event|head_ref)' "$DIR"/**/*.yml 2>/dev/null
grep -nE 'uses:\s*[^@]+@(v[0-9]+|main|master)\s*$' "$DIR"/**/*.yml 2>/dev/null
```

### 4. Review GitLab Variables and Triggers

Enumerate public project metadata, protected variables, pipeline definitions, and trigger/webhook references without starting a pipeline:

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 'https://HOST/api/v4/projects?visibility=public&per_page=100'
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/api/v4/projects/PROJECT_ID
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/ORG/REPO/-/raw/main/.gitlab-ci.yml
run_tool git ls-remote https://HOST/ORG/REPO.git
```

Record exposed variables, masked-value misuse, trigger tokens, protected-ref assumptions, and webhook endpoints. Never POST a pipeline trigger or use a discovered variable to authenticate elsewhere.

Check the pipeline YAML for a remote `include:` directive pointing at a project/ref the target does not control (`include: {project: 'external/group', ref: 'main'}`), which lets an outside party inject pipeline stages, and for a `rules:`/`only:` condition that runs on `merge_request_event` with access to CI/CD variables meant for protected branches only.

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

Also check package manifests for an internal/private package name that is not registered on the public registry (dependency-confusion candidate), a `postinstall`/`preinstall` lifecycle script in `package.json` or a `setup.py` with executable code that runs on `pip install`, and whether build provenance (SLSA attestation, Sigstore/cosign signature) is present and verified before deployment or only advisory. A missing provenance check on a pipeline that auto-deploys pulled artifacts is a supply-chain gap worth recording even without a proof-of-concept substitution.

### 7. Poisoned Pipeline Execution (PPE) and Runner Trust Boundaries

Distinguish direct PPE (attacker-controlled pipeline definition runs directly, e.g. a branch the attacker can push to) from indirect PPE (attacker-controlled *input* — a PR title, issue body, commit message, or a file the pipeline reads — is interpolated into a trusted pipeline run). Enumerate which trigger types a discovered pipeline honors before assuming either class applies:

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/ORG/REPO/-/raw/main/.gitlab-ci.yml
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/ORG/REPO/.github/workflows/
grep -nE 'pull_request_target|workflow_run|on:\s*\[?.*(issue_comment|pull_request)' "$DIR"/**/*.yml 2>/dev/null
```

Record whether a self-hosted runner (versus an ephemeral GitHub/GitLab-hosted runner) executes the pipeline — a self-hosted runner that persists state between jobs is a much higher-value PPE target because a poisoned job can leave a backdoor for the *next* legitimate job, not just exfiltrate the current run's secrets. Never submit a PR, comment, or commit to trigger this; enumeration only.

### 8. Secrets Exposure in Build Logs and Artifacts

Check whether a build log, cached artifact, or downloadable log bundle contains a secret value the pipeline was supposed to mask, without triggering a new build:

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 http://HOST:8080/job/JOB_NAME/lastBuild/consoleText
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/api/v4/projects/PROJECT_ID/jobs/JOB_ID/trace
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/ORG/REPO/actions/runs/RUN_ID/logs
grep -Eio 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[0-9A-Za-z-]+|-----BEGIN [A-Z ]*PRIVATE KEY-----' "$DIR"/scans/*.log 2>/dev/null
```

Flag `set -x`/`set +v` shell tracing left enabled around a secret-consuming step (echoes the value to the console log), a secret passed as a CLI argument (`--password=$SECRET`) rather than via stdin/env (arguments appear in process-list-style log capture and in `docker history` for build-time `ARG`), and a masking rule that only redacts an *exact* string match — a secret that gets base64-encoded, URL-encoded, or has whitespace appended before being printed bypasses provider-side log masking. Also check a public artifact/cache download for baked-in `.env` files or credentials committed during the build step.

### 9. Dependency Confusion and Typosquatting Depth

Beyond the manifest-scoped check in step 6, verify namespace/scope claims and registry precedence explicitly:

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 https://registry.npmjs.org/INTERNAL_PACKAGE_NAME
run_tool curl -sS --connect-timeout 5 --max-time 20 https://pypi.org/pypi/INTERNAL_PACKAGE_NAME/json
grep -nE '"registry"|index-url|extra-index-url' "$DIR"/repo/.npmrc "$DIR"/repo/pip.conf 2>/dev/null
```

A private package name that returns `404` on the public registry is a dependency-confusion candidate only when the build tool's resolution order is also confirmed — check `.npmrc`/`pip.conf`/`NuGet.config` for a missing or misordered `scope`-to-registry mapping (an unscoped `npm install` falls back to the public registry unless `.npmrc` pins the scope). Distinguish this from typosquatting, where the package name itself is a visually similar variant (`reqeusts` vs `requests`, `colour` vs `color`) of a legitimate public dependency already in the lockfile — grep the lockfile for near-duplicate names via edit-distance-1 comparison against the declared direct dependencies rather than assuming every unfamiliar name is malicious.

## References

`references/vuln-checklists/A03-supply-chain-failures.md`, `references/vuln-checklists/A07-authentication-failures.md`, `references/vuln-checklists/A08-integrity-failures.md`, `references/api-security/API02-broken-authentication.md`, `references/api-security/API08-security-misconfiguration.md`, `references/offensive-tactics/credential-access/credential-theft-misc.md`, `references/offensive-tactics/red-team-infra/infra-setup.md`.

## Confirm-Only Rule

Unauthenticated access, default-credential checks, config/history/webhook enumeration, and secret scanning are confirm-stage. Exploitation is owned by exploit-developer at stage=vuln_confirmed; do not push commits, trigger pipelines against non-lab systems, modify CI config, execute Groovy, connect agents, or deliver webhooks.

## Budget

`--host-timeout 120s`. One read-only endpoint pass, one bounded default-credential check, and one repository-history scan; no build, trigger, upload, cache write, or package install.
