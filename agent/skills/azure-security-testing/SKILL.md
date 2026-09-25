---
name: azure-security-testing
description: Deep Azure/Entra ID-specific privilege-escalation chains, RBAC abuse, Managed Identity theft, and service-level misconfiguration
origin: RedteamOpencode
---

# Azure Security Testing

For generic cross-provider ground (IMDS reachability, storage-ACL enumeration, snapshot/secret listing, cross-account trust/federation, Kubernetes credential overlap, serverless/CI credential theft), use `cloud-testing` first. This skill is the Azure/Entra ID-specific deep dive once a foothold (any valid credential, however low-privilege) is confirmed.

## When to Activate

- Any valid Azure credential is in `auth.json` (user/service-principal token, Managed Identity token, or `az` CLI session)
- Target infrastructure is confirmed Azure (tenant ID from `az account show`, `*.azurewebsites.net`/`*.blob.core.windows.net`/`*.vault.azure.net` endpoints, Entra ID presence)

## Tools

`run_tool az` (all extensions), `jq`, `run_tool curl` for direct Graph API / Kudu access.

## Methodology

### 1. Establish Identity and Tenant Context

```bash
run_tool az account show --output json
run_tool az account list --output json
run_tool az ad signed-in-user show --output json
run_tool az role assignment list --assignee <principal> --all --output json
```
Record subscription IDs, tenant ID, and every role assignment the current principal holds across every scope (management group, subscription, resource group, resource). Azure RBAC is scope-inherited — a role assigned at management-group level applies to every subscription beneath it, which is easy to miss when only checking the current resource group.

### 2. RBAC and Custom Role Privilege-Escalation Catalog

```bash
run_tool az role definition list --custom-role-only true --output json
run_tool az role assignment list --all --output json
```
- [ ] **`Microsoft.Authorization/roleAssignments/write`** on any scope — the principal can grant itself (or any controlled principal) `Owner`/`Contributor` at that scope; this permission alone is a full escalation primitive
- [ ] **Custom role with wildcard `Actions: ["*"]`** minus a short `NotActions` list — often functionally equivalent to `Owner` while looking scoped in a cursory review; diff `Actions`/`NotActions` carefully
- [ ] **`Microsoft.Resources/deployments/write`** (deployment/ARM template rights) at a scope with higher-privileged managed identities attached to existing resources — deploy a template that runs a script/extension under that identity (`Microsoft.Compute/virtualMachines/extensions` with a custom script, or a Logic App/Automation Runbook using a system-assigned identity)
- [ ] **`Microsoft.Automation/automationAccounts/*`** write access — Automation Account Run As accounts and Managed Identities often hold `Contributor` at subscription scope; a principal that can create/modify a runbook inherits that identity's permissions on execution
- [ ] **`Microsoft.Web/sites/config/list/action`** (list publishing credentials) — retrieve deployment credentials/connection strings for an App Service/Function App running under a higher-privileged Managed Identity
- [ ] **User-assigned Managed Identity `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`** — assign an existing privileged user-assigned identity to a resource the principal controls

### 3. Managed Identity and IMDS Token Theft

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/'
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net'
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&client_id=<user-assigned-client-id>&resource=https://management.azure.com/'
```
- [ ] System-assigned Managed Identity token via bare IMDS request — confirm which `resource=` audiences the identity has been granted a token for, since each audience maps to a different scope of downstream access (ARM, Graph, Key Vault, Storage)
- [ ] Multiple user-assigned identities on the same resource — enumerate via `az vm identity show` / `az webapp identity show`, then request tokens for each `client_id` separately; they frequently carry different (and sometimes more privileged) role assignments than the system-assigned one
- [ ] Local token cache files if shell access is available: `~/.azure/msal_token_cache.json`, `~/.azure/accessTokens.json` (legacy CLI) — cross-reference with `post-exploitation`

### 4. Key Vault Access Model Confusion

```bash
run_tool az keyvault list --output json
run_tool az keyvault show --name VAULT --query 'properties.{rbac:enableRbacAuthorization,accessPolicies:accessPolicies}'
run_tool az keyvault secret list --vault-name VAULT
run_tool az keyvault key list --vault-name VAULT
```
- [ ] Vault still on the legacy **access-policy model** rather than RBAC — access policies are vault-scoped and easy to over-grant (`list`+`get` on secrets) without the tenant-wide RBAC audit trail; check whether `enableRbacAuthorization` is `false`
- [ ] Network ACL (`az keyvault network-rule list`) allowing `AzureServices` bypass combined with an over-permissive access policy — any Azure-internal caller can reach the vault regardless of firewall rules
- [ ] Soft-delete/purge-protection disabled — a deleted secret's prior version may still be recoverable, or conversely an attacker with delete rights can destroy audit evidence

### 5. Storage Account: Keys vs SAS vs Azure AD Auth

```bash
run_tool az storage account keys list --account-name ACCOUNT --output json
run_tool az storage account show --name ACCOUNT --query 'allowSharedKeyAccess'
run_tool az storage blob list --account-name ACCOUNT --container-name CONTAINER --auth-mode login
```
- [ ] `allowSharedKeyAccess: true` alongside RBAC-based access controls being the intended model — anyone with a storage account key bypasses all RBAC/Conditional Access entirely; a principal with `Microsoft.Storage/storageAccounts/listkeys/action` (often bundled in broad "Contributor"-style roles) gets unrestricted access regardless of narrower blob-level RBAC grants
- [ ] SAS token scope/expiry: an account-level SAS (vs container/blob-level) with write/delete permissions and a multi-year expiry found in app settings, source code, or a config endpoint

### 6. App Service / Function App: Kudu and Deployment Credentials

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -u '$deploymentUser:deploymentPassword' https://APP.scm.azurewebsites.net/api/settings
run_tool az webapp config appsettings list --name APP --resource-group RG
run_tool az functionapp keys list --name FUNC --resource-group RG
```
- [ ] Kudu/SCM console (`*.scm.azurewebsites.net`) reachable and either unauthenticated or reachable with deployment credentials pulled from `list-publishing-credentials` — the Kudu debug console (`/DebugConsole`) is a direct RCE primitive under the App Service's Managed Identity once authenticated
- [ ] App settings containing plaintext connection strings/API keys instead of Key Vault references (`@Microsoft.KeyVault(...)`) — direct secret disclosure via a permission the principal may hold even without deployment access

### 7. Entra ID (Azure AD) Enumeration and Abuse

```bash
run_tool az ad app list --output json
run_tool az ad sp list --output json
run_tool az ad app federated-credential list --id APP_ID --output json
```
- [ ] Application/Service Principal with `Application.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, or `AppRoleAssignment.ReadWrite.All` Graph API permission — each is a directory-wide privilege-escalation primitive (can grant itself Global Administrator via a self-authored app role or directory role assignment)
- [ ] Federated credential (workload identity federation, e.g. GitHub Actions OIDC) with a subject claim that isn't scoped to a specific repo/branch/environment — any workflow matching the loose pattern can mint a token for that app
- [ ] Legacy authentication protocols (IMAP/POP/SMTP basic auth, or apps still permitting password-based auth) bypassing Conditional Access policies that only cover modern auth flows
- [ ] Illicit consent grant risk: an OAuth app requesting broad delegated (`Mail.Read`, `Files.ReadWrite.All`) or application permissions that a user/admin may have already consented to — check `az ad app permission list-grants`
- [ ] AAD Connect / Entra Connect sync account — if reachable, this account typically holds `Directory Synchronization Accounts` role, and compromise is functionally equivalent to an on-prem DCSync against the synced on-prem AD (cross-reference `ldap-kerberos`)

## Confirm-Only Rule

Enumeration and token-audience confirmation are confirm-stage. Do not create role assignments, modify app registrations/federated credentials, retrieve and use deployment credentials for code execution, or decrypt/read Key Vault secret values beyond a single representative check — record the exact reachable chain as `vuln_confirmed` evidence for exploit-developer.

## Budget

Cap at 15 read-only calls per service area above; no bulk directory dump (`az ad user list` without filters) beyond what's needed to confirm a specific principal/role.
