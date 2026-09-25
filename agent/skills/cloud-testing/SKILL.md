---
name: cloud-testing
description: Enumerate and test AWS, Azure, and GCP identity, metadata, storage, secrets, and trust boundaries
origin: RedteamOpencode
---

# Cloud Testing

## When to Activate

- AWS IMDS at `169.254.169.254`, Azure Instance Metadata Service, or GCP metadata host reachable
- Public S3 buckets, Azure Blob containers, GCS buckets, storage ACLs, snapshots, or images
- IAM roles, instance profiles, managed identities, Cognito, secret managers, or exposed cloud credentials
- Kubernetes workloads carrying cloud credentials or overlapping trust with a cloud control plane

## Tools

`run_tool nmap`, `run_tool curl`, `run_tool aws`, `run_tool az`, `run_tool gcloud`, `run_tool kubectl`, `run_tool s3scanner`, `run_tool nuclei`, `run_tool trivy`, `jq`

## Methodology

### 1. Establish Provider Identity Context

Use only credentials already present in the engagement. Record account, subscription, project, principal, and token audience separately:
```bash
run_tool nmap -sV -p 80,443 HOST -oA "$DIR/scans/cloud_endpoints"
run_tool aws sts get-caller-identity --output json
run_tool aws s3 ls
run_tool az account show --output json
run_tool gcloud auth list --format=json
```
Treat every result as unsigned/unsigned-credential evidence until the provider validates the account, subscription, project, and audience. An empty, unsigned, or expired credential is not proof of public access.
### 2. Test Instance Metadata Services

Check AWS IMDSv2 token enforcement, then compare a valid-token request with an invalid-token request:
```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' http://169.254.169.254/latest/api/token
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'X-aws-ec2-metadata-token: TOKEN' http://169.254.169.254/latest/meta-data/
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'X-aws-ec2-metadata-token: INVALID' http://169.254.169.254/latest/meta-data/iam/security-credentials/
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'X-aws-ec2-metadata-token: TOKEN' http://169.254.169.254/latest/user-data
```
Test Azure and GCP equivalents with their required headers:
```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/project/project-id
```
If metadata is reachable only through an application URL, save the request/response and cross-reference the `ssrf-testing` skill; do not pivot into a cloud write.
### 3. Review Roles and Managed Identities

Map instance roles, workload identities, service accounts, and policy attachments without changing them:
```bash
run_tool aws iam get-role --role-name ROLE_NAME
run_tool aws iam list-role-policies --role-name ROLE_NAME
run_tool aws iam list-attached-role-policies --role-name ROLE_NAME
run_tool aws sts get-caller-identity --output json
run_tool az role assignment list --scope SUBSCRIPTION_ID --output json
run_tool az ad signed-in-user show --output json
run_tool az identity list --output json
run_tool gcloud projects get-iam-policy PROJECT_ID --format=json
run_tool gcloud iam service-accounts list --project PROJECT_ID --format=json
```
Flag wildcard actions, broad resource scopes, trust-policy overreach, pass-role access, and cross-tenant identities as authorization findings, not as permission to use them.
### 4. Enumerate Object Storage and ACLs

Check bucket/container existence, listing, object reads, ACLs, policies, encryption, and public-access blocks:
```bash
run_tool aws s3api list-buckets --output json
run_tool aws s3 ls s3://BUCKET --recursive
run_tool aws s3api get-bucket-acl --bucket BUCKET
run_tool aws s3api get-bucket-policy --bucket BUCKET
run_tool aws s3api get-public-access-block --bucket BUCKET
run_tool az storage blob list --account-name ACCOUNT --container-name CONTAINER --output json
run_tool az storage account list --output json
run_tool gcloud storage ls gs://BUCKET
run_tool gcloud storage buckets get-iam-policy gs://BUCKET
run_tool gcloud storage objects ls gs://BUCKET
```
Distinguish an open listing from public object read, signed-URL leakage, and a policy that grants only a narrow prefix. Save one representative response, not a bulk data dump.
### 5. Check Snapshots, Images, and Secret Managers

Enumerate public sharing and metadata for snapshots/images, then list secret-manager inventory without retrieving values:
```bash
run_tool aws ec2 describe-snapshots --owner-ids self
run_tool aws ec2 describe-images --owners self
run_tool aws secretsmanager list-secrets --output json
run_tool aws kms list-aliases --output json
run_tool az vm image list --output json
run_tool az keyvault list --output json
run_tool az keyvault secret list --vault-name VAULT --output json
run_tool gcloud compute images list --no-filter --format=json
run_tool gcloud secrets list --project PROJECT_ID --format=json
```
A public snapshot, image, or secret reference is a finding even when the payload is encrypted; validate the access path and owner before reporting.
### 6. Review Cognito, Managed Identity, and SaaS Ownership

Enumerate user pools, app/service principals, and service accounts, then compare tenant identity with resource ownership:
```bash
run_tool aws cognito-idp list-user-pools --max-results 10
run_tool aws cognito-idp list-users --user-pool-id POOL_ID
run_tool az ad app list --output json
run_tool az ad sp list --output json
run_tool gcloud iam service-accounts list --project PROJECT_ID --format=json
```
Never claim ownership of abandoned SaaS resources. Report provider, tenant, resource identifier, and evidence separately; ownership claims require an explicit in-scope administrative source.
### 7. Check Kubernetes and Cloud Credential Overlap

Inventory service-account files, projected tokens, cloud environment-variable names, kubeconfigs, and secret references without printing values:
```bash
run_tool kubectl get pods,secrets,configmaps -A -o json > "$DIR/scans/cloud_k8s_objects.json"
jq -r '.items[] | {namespace:.metadata.namespace,name:.metadata.name,serviceAccount:.spec.serviceAccountName,envNames:[.spec.containers[]?.env[]?.name]}' "$DIR/scans/cloud_k8s_objects.json" > "$DIR/scans/cloud_k8s_env_names.jsonl"
run_tool kubectl auth can-i --list
```
Immediately write every discovered credential to `$DIR/auth.json` and reference its source in `$DIR/intel.md`; never commit or print secret values.
### Lab objective recall closure

When the active profile lists a cloud identity, metadata, or storage objective, requeue the one exact workflow named by its `recall_branches` instead of substituting a broad account dump. Save the response or policy artifact to `$DIR/scans/cloud-objective.txt`, run `python3 ./scripts/lab_objective.py snapshot "$DIR"`, and hand off `objective=<name> status=solved|requeued evidence=<path> next=<exact action>`.

## References

`references/vuln-checklists/A01-broken-access-control.md`, `references/vuln-checklists/A02-security-misconfiguration.md`, `references/vuln-checklists/A04-cryptographic-failures.md`, `references/vuln-checklists/A07-authentication-failures.md`, `references/api-security/API02-broken-authentication.md`, `references/api-security/API10-unsafe-consumption.md`, `references/offensive-tactics/credential-access/credential-theft-misc.md`, `references/offensive-tactics/red-team-infra/infra-setup.md`.

## Confirm-Only Rule

Identity, metadata, IAM/ACL, storage, secret-manager, SaaS, and Kubernetes-overlap enumeration is confirm-stage. Exploitation is owned by exploit-developer at stage=vuln_confirmed; use read-only enumeration only—no resource creation, deletion, policy changes, secret-manager writes, infrastructure changes, or ownership claims for abandoned SaaS resources.

## Budget

`--host-timeout 120s`. Cap each provider at 10 read-only CLI or API checks plus one representative object/secret metadata check; no bulk dump, mutation, or policy test.
