---
name: cloud-testing
description: Enumerate and test AWS, Azure, and GCP identity, metadata, storage, secrets, and trust boundaries
origin: RedteamOpencode
---

# Cloud Testing

Cross-provider ground floor: IMDS reachability, storage-ACL enumeration, snapshot/secret listing, Cognito/managed-identity/service-account inventory, cross-account trust/federation, Kubernetes credential overlap, and serverless/CI credential theft — all applied uniformly across AWS/Azure/GCP below. Once a foothold is confirmed on a specific provider, switch to that provider's deep-dive skill for the full IAM privilege-escalation chain catalog: `aws-security-testing`, `azure-security-testing`, or `gcp-security-testing`.

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
If metadata is reachable only through an application URL, save the request/response and cross-reference the `ssrf-testing` skill; do not pivot into a cloud write. When the SSRF sink allows a custom `Redirects`/hop count, also test the AWS IMDSv1 fallback path (no token header at all) and a low `X-Forwarded-For`/hop-limit-1 request — some proxied SSRF paths strip the `X-aws-ec2-metadata-token` header but still reach IMDSv1. For containerized/serverless workloads, check the ECS task-metadata endpoint (`http://169.254.170.2/v2/credentials/$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`) and Lambda's `/2018-06-01/runtime/invocation/next` for leaked environment credentials in the same SSRF chain.
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
### 7. Trust and Federation Abuse Paths

Enumerate cross-account role trust, OIDC federation, and delegated-identity boundaries without assuming a role you were not issued:
```bash
run_tool aws iam get-role --role-name ROLE_NAME --query 'Role.AssumeRolePolicyDocument'
run_tool aws iam list-open-id-connect-providers --output json
run_tool aws sts get-caller-identity --output json
run_tool az ad app federated-credential list --id APP_ID --output json
run_tool gcloud iam workload-identity-pools list --project PROJECT_ID --format=json
run_tool gcloud iam workload-identity-pools providers list --workload-identity-pool POOL_ID --location global --project PROJECT_ID --format=json
```
Flag an overly broad `sts:AssumeRole` trust principal (`"Principal": "*"` or a wildcard external ID), a GitHub Actions OIDC trust policy missing a `repo:`/`ref:` subject condition (any workflow in any repo can assume the role), and a GCP workload-identity-pool provider with an unrestricted `attribute-condition`. Record the exact trust document; do not attempt the assumption unless a valid external-ID/subject match is already in scope.

Also check for dangling cloud-resource takeover: a DNS CNAME pointing at a deprovisioned S3 bucket, Azure Blob endpoint, or GCS bucket name, and a still-valid pre-signed URL or SAS token with an excessive expiry or overly broad scope (write/delete instead of read).
### 8. Check Kubernetes and Cloud Credential Overlap

Inventory service-account files, projected tokens, cloud environment-variable names, kubeconfigs, and secret references without printing values:
```bash
run_tool kubectl get pods,secrets,configmaps -A -o json > "$DIR/scans/cloud_k8s_objects.json"
jq -r '.items[] | {namespace:.metadata.namespace,name:.metadata.name,serviceAccount:.spec.serviceAccountName,envNames:[.spec.containers[]?.env[]?.name]}' "$DIR/scans/cloud_k8s_objects.json" > "$DIR/scans/cloud_k8s_env_names.jsonl"
run_tool kubectl auth can-i --list
```
Immediately write every discovered credential to `$DIR/auth.json` and reference its source in `$DIR/intel.md`; never commit or print secret values.
### 9. Serverless, CI Runner, and Local Credential-Cache Theft

Check function-level and impersonation-chain credential paths beyond the base instance metadata service, and enumerate local credential-cache files that carry cloud tokens outside IMDS:
```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 http://169.254.170.2/v2/credentials/$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net'
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=TARGET_AUDIENCE'
run_tool gcloud iam service-accounts get-iam-policy IMPERSONATED_SA --format=json
run_tool aws sts assume-role --role-arn ROLE_ARN --role-session-name test --tags Key=aws:PrincipalTag/team,Value=eng
```
Flag a CI/CD runner (self-hosted GitHub Actions, GitLab runner, Jenkins agent) executing inside a cloud VM or pod that inherits the node's instance-profile/managed-identity/service-account credentials instead of a scoped OIDC-federated identity — that is a direct lateral path from pipeline compromise (cross-reference `ci-cd-security`) to full cloud-account takeover. Also check for locally cached credential material left behind by an application, CI job, or interactive session: `~/.aws/credentials`, `~/.azure/msal_token_cache.json`, `~/.config/gcloud/legacy_credentials/*/adc.json`, and Kubernetes-mounted `token`/`ca.crt` under `/var/run/secrets/`. A GCP service-account with `iam.serviceAccounts.actAs`/`iam.serviceAccounts.getAccessToken` on a higher-privileged SA is an impersonation-chain escalation path — record the chain, do not walk it. Read-only discovery only; never generate or consume an impersonated token beyond confirming the API accepts the request shape.

### 10. Provider-Specific Misconfiguration Patterns

Beyond generic ACL/IAM review, check these concrete, provider-specific patterns without mutating anything:
```bash
run_tool aws iam simulate-principal-policy --policy-source-arn ROLE_ARN --action-names 's3:GetObject' 'iam:PassRole' --resource-arns '*'
run_tool aws lambda get-policy --function-name FUNCTION_NAME
run_tool az functionapp keys list --name FUNC_APP --resource-group RG
run_tool az webapp config appsettings list --name APP --resource-group RG
run_tool gcloud functions describe FUNCTION_NAME --format=json
run_tool gcloud run services get-iam-policy SERVICE_NAME --region REGION --format=json
```
Flag an AWS Lambda resource policy with `"Principal": "*"` and no `SourceArn`/`SourceAccount` condition (any AWS account can invoke), an `iam:PassRole` grant with a wildcard resource (privilege-escalation primitive when paired with any role-attaching action), an Azure Function/Web App with app settings exposing connection strings in plaintext instead of Key Vault references, and a GCP Cloud Run service with `allUsers`/`allAuthenticatedUsers` in its IAM policy binding. These are authorization/configuration findings from read-only policy retrieval — do not invoke, deploy, or update any of them.

### Lab objective recall closure

When the active profile lists a cloud identity, metadata, or storage objective, requeue the one exact workflow named by its `recall_branches` instead of substituting a broad account dump. Save the response or policy artifact to `$DIR/scans/cloud-objective.txt`, run `python3 ./scripts/lab_objective.py snapshot "$DIR"`, and hand off `objective=<name> status=solved|requeued evidence=<path> next=<exact action>`.

## References

`references/vuln-checklists/A01-broken-access-control.md`, `references/vuln-checklists/A02-security-misconfiguration.md`, `references/vuln-checklists/A04-cryptographic-failures.md`, `references/vuln-checklists/A07-authentication-failures.md`, `references/api-security/API02-broken-authentication.md`, `references/api-security/API10-unsafe-consumption.md`, `references/offensive-tactics/credential-access/credential-theft-misc.md`, `references/offensive-tactics/red-team-infra/infra-setup.md`.

## Confirm-Only Rule

Identity, metadata, IAM/ACL, storage, secret-manager, SaaS, and Kubernetes-overlap enumeration is confirm-stage. Exploitation is owned by exploit-developer at stage=vuln_confirmed; use read-only enumeration only—no resource creation, deletion, policy changes, secret-manager writes, infrastructure changes, or ownership claims for abandoned SaaS resources.

## Budget

`--host-timeout 120s`. Cap each provider at 10 read-only CLI or API checks plus one representative object/secret metadata check; no bulk dump, mutation, or policy test.
