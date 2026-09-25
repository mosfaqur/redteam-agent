---
name: gcp-security-testing
description: Deep GCP-specific IAM privilege-escalation chains, service-account impersonation, and service-level misconfiguration
origin: RedteamOpencode
---

# GCP Security Testing

For generic cross-provider ground (IMDS reachability, storage-ACL enumeration, snapshot/secret listing, cross-account trust/federation, Kubernetes credential overlap, serverless/CI credential theft), use `cloud-testing` first. This skill is the GCP-specific deep dive once a foothold (any valid credential, however low-privilege) is confirmed.

## When to Activate

- Any valid GCP credential is in `auth.json` (user OAuth token, service-account key, `gcloud` CLI session, or GCE/GKE metadata-sourced token)
- Target infrastructure is confirmed GCP (project ID from `gcloud config get-value project`, `*.googleapis.com`/`*.run.app`/`storage.googleapis.com` endpoints, GKE presence)

## Tools

`run_tool gcloud` (all components), `jq`, `run_tool curl` for direct metadata/REST API access.

## Methodology

### 1. Establish Identity and Enumerate Own Permissions

```bash
run_tool gcloud auth list --format=json
run_tool gcloud config list --format=json
run_tool gcloud projects get-iam-policy PROJECT_ID --format=json
run_tool gcloud iam service-accounts get-iam-policy SA_EMAIL --format=json
```
Build the effective-permission set from all IAM bindings that include the current principal (directly, or via a group it belongs to — `gcloud identity groups memberships list` if Cloud Identity/Workspace access is available). GCP IAM inherits down the resource hierarchy (Organization → Folder → Project → Resource); a binding at the folder level applies to every project beneath it.

### 2. Service-Account Impersonation and IAM Privilege-Escalation Catalog

```bash
run_tool gcloud iam service-accounts list --project PROJECT_ID --format=json
run_tool gcloud projects get-iam-policy PROJECT_ID --flatten='bindings[].members' --filter='bindings.role:roles/iam.serviceAccountTokenCreator' --format=json
```
Confirm-only: identify which chains are reachable via IAM-policy review, then record as `vuln_confirmed` evidence rather than walking to full impersonation unless exploit-developer directs it.

- [ ] **`iam.serviceAccounts.getAccessToken`** (bundled in `roles/iam.serviceAccountTokenCreator`) on a higher-privileged service account — directly mint an OAuth token as that identity: `gcloud auth print-access-token --impersonate-service-account=TARGET_SA`
- [ ] **`iam.serviceAccounts.signJwt`** / **`iam.serviceAccounts.signBlob`** — forge a signed JWT/blob as the target service account without needing its private key
- [ ] **`iam.serviceAccountKeys.create`** — mint a long-lived exportable key for a higher-privileged service account (this creates persistent, harder-to-revoke access — note but avoid actually exporting unless exploit-developer authorizes)
- [ ] **`iam.serviceAccounts.actAs` + `compute.instances.create`** — launch a GCE instance running as a privileged service account, then retrieve its token from the instance's own metadata server (equivalent to AWS `PassRole`+`RunInstances`)
- [ ] **`iam.serviceAccounts.actAs` + `cloudfunctions.functions.create`** (or `.update` on an existing function) — deploy/modify a Cloud Function that runs under a privileged service account
- [ ] **`iam.serviceAccounts.actAs` + `run.services.create`** — deploy a Cloud Run service under a privileged service account
- [ ] **`iam.serviceAccounts.actAs` + `cloudbuild.builds.create`** — trigger a Cloud Build job that executes under the (often highly privileged, by default `PROJECT_NUMBER@cloudbuild.gserviceaccount.com`) build service account
- [ ] **`deploymentmanager.deployments.create`** — Deployment Manager historically ran under a privileged Google-managed service account; a deployment can include an IAM-policy-modifying resource
- [ ] **`iam.roles.update`** on a custom role already bound elsewhere — widen the role's included permissions after the fact, escalating everywhere it's already assigned
- [ ] **`resourcemanager.projects.setIamPolicy`** — direct, no chain needed; grants the principal (or any controlled principal) `roles/owner`

### 3. Compute Engine Default Service Account Over-Permissioning

```bash
run_tool gcloud compute instances list --format=json
run_tool gcloud compute instances describe INSTANCE --zone ZONE --format='value(serviceAccounts)'
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes'
```
- [ ] Instance still using the **default Compute Engine service account** (`PROJECT_NUMBER-compute@developer.gserviceaccount.com`) with the broad legacy `cloud-platform` OAuth scope — this account historically defaults to `roles/editor` at project level unless explicitly downgraded, making any SSRF/RCE on that instance a near-project-wide compromise
- [ ] `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes` reveals the actual granted scopes independent of IAM role — a `cloud-platform` scope means IAM role is the only remaining restriction, while a narrower legacy scope list further limits blast radius even if IAM is broad

### 4. Cloud Storage IAM/ACL and Uniform Bucket-Level Access

```bash
run_tool gcloud storage buckets describe gs://BUCKET --format='value(iamConfiguration)'
run_tool gcloud storage buckets get-iam-policy gs://BUCKET --format=json
```
- [ ] `uniformBucketLevelAccess: false` — legacy ACLs (`gsutil acl get`) can grant per-object access that the bucket-level IAM policy review misses entirely; check both
- [ ] `allUsers`/`allAuthenticatedUsers` bound at bucket or object level — distinguish `roles/storage.objectViewer` (public read) from `roles/storage.objectAdmin` (public write/delete)

### 5. Cloud Functions / Cloud Run Source and Secret Exposure

```bash
run_tool gcloud functions describe FUNCTION --format=json
run_tool gcloud run services describe SERVICE --region REGION --format=json
run_tool gcloud functions get-iam-policy FUNCTION --format=json
```
- [ ] Environment variables in `describe` output not routed through Secret Manager references — plaintext secret disclosure to anyone who can read function config
- [ ] `allUsers`/`allAuthenticatedUsers` IAM binding on the function/Cloud Run service — unauthenticated invocation; cross-reference exposed source (`gcloud functions describe --format='value(sourceArchiveUrl)'` or the Cloud Run container image) for further secrets
- [ ] Cloud Build trigger tied to the function/service with a public/writable source repo — supply-chain injection path via `ci-cd-security`

### 6. BigQuery Dataset and Authorized-View Exposure

```bash
run_tool bq ls --format=json
run_tool bq get-iam-policy --format=json DATASET
```
- [ ] Dataset IAM policy with `allUsers`/`allAuthenticatedUsers` — direct public data read
- [ ] Authorized views granting query access to a dataset without granting the underlying table read — confirm whether the view logic itself leaks more than intended (e.g., no row-level filtering)

### 7. Workload Identity Federation and GKE Workload Identity

```bash
run_tool gcloud iam workload-identity-pools list --project PROJECT_ID --format=json
run_tool gcloud iam workload-identity-pools providers describe PROVIDER --workload-identity-pool POOL --location global --format=json
run_tool kubectl get serviceaccount -A -o json
```
- [ ] Workload Identity Pool provider with an unrestricted or overly broad `attribute-condition` (e.g. accepting any GitHub repo/any Kubernetes namespace rather than a specific one) — external identities beyond the intended set can assume the federated identity
- [ ] GKE Workload Identity binding (`iam.gke.io/gcp-service-account` annotation) mapping a Kubernetes ServiceAccount to an over-privileged GCP service account — a compromised pod in that namespace inherits the full GCP-side permission set
- [ ] GKE node pool still using the legacy node service account (not Workload Identity) — every pod on that node can reach the node's own broad service-account token via the metadata server unless `GKE_METADATA` mode / metadata concealment is enforced

### 8. Organization Policy and Resource Hierarchy

```bash
run_tool gcloud resource-manager org-policies list --project PROJECT_ID --format=json
run_tool gcloud organizations list --format=json
run_tool gcloud resource-manager folders list --organization ORG_ID --format=json
```
- [ ] Missing or permissive `iam.allowedPolicyMemberDomains` org policy — allows binding IAM roles to external/personal Google accounts
- [ ] Missing `iam.disableServiceAccountKeyCreation` constraint — permits the `iam.serviceAccountKeys.create` escalation path noted above at scale across the org

## Confirm-Only Rule

Enumeration and IAM-policy review are confirm-stage. Do not actually impersonate a higher-privileged service account, create exportable service-account keys, modify IAM policies, or deploy resources under a passed service account — record the exact reachable chain (permission held, target identity, resulting privilege) as `vuln_confirmed` evidence for exploit-developer.

## Budget

Cap at 15 read-only calls per service area above; no bulk resource enumeration (`gcloud asset search-all-resources` unscoped) beyond what's needed to confirm a specific chain.
