---
name: aws-security-testing
description: Deep AWS-specific IAM privilege-escalation chains, service-level misconfiguration, and cross-service abuse paths
origin: RedteamOpencode
---

# AWS Security Testing

For generic cross-provider ground (IMDS reachability, storage-ACL enumeration, snapshot/secret listing, Cognito, cross-account trust/federation, Kubernetes credential overlap, serverless/CI credential theft), use `cloud-testing` first. This skill is the AWS-specific deep dive once a foothold (any valid credential, however low-privilege) is confirmed — its focus is the IAM privilege-escalation chain catalog and AWS-service-specific abuse paths.

## When to Activate

- Any valid AWS credential is in `auth.json` (access key, assumed-role session, IMDS-sourced instance-profile credential, or federated/OIDC token)
- Target infrastructure is confirmed AWS (account ID from `sts get-caller-identity`, `*.amazonaws.com` endpoints, EC2/Lambda/ECS/EKS presence)

## Tools

`run_tool aws` (all service subcommands), `jq`, optionally `run_tool nuclei` for exposed-service templates.

## Methodology

### 1. Establish Identity and Enumerate Own Permissions

```bash
run_tool aws sts get-caller-identity --output json
run_tool aws iam get-user --output json
run_tool aws iam list-attached-user-policies --user-name USER
run_tool aws iam list-user-policies --user-name USER
run_tool aws iam get-user-policy --user-name USER --policy-name POLICY
run_tool aws iam simulate-principal-policy --policy-source-arn ARN --action-names 'iam:*' 'sts:AssumeRole' 'lambda:*' --resource-arns '*'
```
Never assume documentation matches reality — `simulate-principal-policy` against the actual attached/inline/SCP-combined policy set is the only reliable ground truth. Build the full effective-permission set before attempting any escalation.

### 2. IAM Privilege-Escalation Chain Catalog

Confirm-only: identify which of these the current principal can reach via `simulate-principal-policy`, then record the chain as `vuln_confirmed` evidence rather than walking it end-to-end unless exploit-developer directs it.

- [ ] **`iam:CreatePolicyVersion`** — set a new default policy version granting `"Action":"*","Resource":"*"` on any policy the principal can already modify
- [ ] **`iam:SetDefaultPolicyVersion`** — revert to a prior overly-permissive version if one exists in version history
- [ ] **`iam:CreateAccessKey`** — mint new credentials for a higher-privileged user
- [ ] **`iam:CreateLoginProfile`** / **`iam:UpdateLoginProfile`** — set/reset console password for a higher-privileged user without existing console access
- [ ] **`iam:AttachUserPolicy`** / **`iam:AttachRolePolicy`** / **`iam:AttachGroupPolicy`** — attach `AdministratorAccess` (or any broader managed policy) to self or a controlled principal
- [ ] **`iam:PutUserPolicy`** / **`iam:PutRolePolicy`** / **`iam:PutGroupPolicy`** — inline-attach an unrestricted policy
- [ ] **`iam:AddUserToGroup`** — join a group with broader attached policies
- [ ] **`iam:UpdateAssumeRolePolicy`** + **`sts:AssumeRole`** — rewrite a role's trust policy to allow the current principal to assume it, then assume it
- [ ] **`iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction`** (or `lambda:AddPermission` + `lambda:CreateEventSourceMapping`) — pass a higher-privileged role to a new Lambda function and execute code under it
- [ ] **`iam:PassRole` + `lambda:UpdateFunctionCode`** on an existing function already running under a privileged role — overwrite its code instead of creating a new one
- [ ] **`iam:PassRole` + `ec2:RunInstances`** — launch an instance with a privileged instance profile, retrieve credentials via its IMDS (userdata script or SSM if available)
- [ ] **`iam:PassRole` + `glue:CreateDevEndpoint`** — spin up a Glue dev endpoint with a privileged role and SSH in for a root shell under that role
- [ ] **`iam:PassRole` + `datapipeline:CreatePipeline` + `datapipeline:PutPipelineDefinition`** — deploy a pipeline that executes under a privileged role
- [ ] **`iam:PassRole` + `cloudformation:CreateStack`** — deploy a stack whose resources (Lambda, EC2, custom resource) run under a passed privileged role
- [ ] **`iam:PassRole` + `sagemaker:CreateNotebookInstance`** (or `CreatePresignedNotebookInstanceUrl` on an existing one) — attach/reach a privileged execution role via a Jupyter terminal
- [ ] **`iam:PassRole` + `codebuild:CreateProject` + `codebuild:StartBuild`** — run a buildspec under a privileged service role
- [ ] **`sts:AssumeRole`** direct — trust policy already permits the current principal; just call it
- [ ] **`organizations:*`** from a member/management account — SCP misconfiguration allowing broader-than-intended actions across the org

Each successful chain confirmation should record: exact API calls used, the resulting principal/ARN gained, and whether the escalation was to account-admin equivalent or a narrower lateral gain.

### 3. S3-Specific Abuse Beyond Basic ACL Review

```bash
run_tool aws s3api get-bucket-policy --bucket BUCKET
run_tool aws s3api get-bucket-policy-status --bucket BUCKET
run_tool aws s3api get-bucket-notification-configuration --bucket BUCKET
run_tool aws s3api list-multipart-uploads --bucket BUCKET
```
- [ ] Bucket policy with a wildcard `Principal` and no `aws:SourceArn`/`aws:SourceAccount` condition — confused-deputy risk if any AWS service is granted access
- [ ] `s3:PutBucketNotification` write access — wire a malicious Lambda trigger onto object-create events if a privileged Lambda execution role is reachable via `PassRole`
- [ ] Abandoned multipart uploads leaking partial object data or incurring storage-cost DoS if left incomplete
- [ ] Cross-account bucket replication configuration disclosing a second in-scope (or out-of-scope — flag immediately) account ID

### 4. Lambda and Serverless-Specific Checks

```bash
run_tool aws lambda list-functions --output json
run_tool aws lambda get-function --function-name FN
run_tool aws lambda get-function-configuration --function-name FN
run_tool aws lambda get-policy --function-name FN
run_tool aws lambda list-layers --output json
```
- [ ] Environment variables returned in plaintext by `get-function-configuration` (not marked `KMSKeyArn`-encrypted) — direct secret disclosure
- [ ] Function resource policy (`get-policy`) with `"Principal":"*"` and no `SourceArn` condition — anyone can invoke
- [ ] Layer version with public/cross-account `add-layer-version-permission` — supply-chain injection point if the principal can publish a new version to a layer consumed by a privileged function
- [ ] Function URL (`aws lambda get-function-url-config`) with `AuthType: NONE` — direct unauthenticated HTTP invocation path, cross-reference `ssrf-testing`/`web-recon` if it fronts an internal API

### 5. ECS/EKS Task and Pod Credential Theft

```bash
run_tool aws ecs list-clusters --output json
run_tool aws ecs list-tasks --cluster CLUSTER --output json
run_tool aws ecs describe-task-definition --task-definition TASKDEF
run_tool kubectl get serviceaccount -A -o json
```
- [ ] ECS task role over-scoped relative to what the container actually needs — same `iam:PassRole` chains above apply when the principal can register/update a task definition
- [ ] EKS pod using the node's IAM role instead of IRSA (IAM Roles for Service Accounts) — any pod on that node inherits the full node role, not just its own service account's scoped role; check `aws eks describe-cluster` for IRSA/OIDC provider configuration and cross-reference pod annotations (`eks.amazonaws.com/role-arn`)
- [ ] IMDSv1 still reachable from within a pod/container (hop-limit not reduced) — a pod-level SSRF becomes a node-role credential theft path

### 6. Secrets Manager, KMS, and Parameter Store

```bash
run_tool aws secretsmanager list-secrets --output json
run_tool aws secretsmanager get-resource-policy --secret-id SECRET
run_tool aws kms list-grants --key-id KEY
run_tool aws ssm describe-parameters --output json
run_tool aws ssm get-parameters-by-path --path / --recursive --output json
```
- [ ] SSM Parameter Store entries not marked `SecureString`, or marked `SecureString` but the principal already holds `kms:Decrypt` on the backing key — read value only to confirm exposure, do not exfiltrate bulk
- [ ] KMS key policy or grant allowing broader-than-expected `kms:Decrypt`/`kms:GenerateDataKey` — record the principal set, do not decrypt unrelated ciphertext
- [ ] Secrets Manager resource policy with cross-account or wildcard principal

### 7. Detection Awareness (Do Not Evade — Note Only)

This is a confirm-only testing context; do not attempt GuardDuty/CloudTrail evasion. Note whether CloudTrail is enabled/multi-region and whether GuardDuty is active, since their absence is itself a finding (detection-gap), and their presence means every API call made during testing is logged — coordinate destructive/escalation-confirming calls with the client's blue-team point of contact per engagement scope.

## Confirm-Only Rule

Enumeration, `simulate-principal-policy` checks, and read-only API calls are confirm-stage. Do not execute an escalation chain end-to-end (create access keys, attach policies, launch instances, deploy Lambda/CodeBuild/Glue resources) without exploit-developer ownership — record the exact reachable chain as `vuln_confirmed` evidence instead.

## Budget

Cap at 15 read-only API calls per service area above; no bulk resource enumeration beyond what's needed to confirm a specific chain is reachable.
