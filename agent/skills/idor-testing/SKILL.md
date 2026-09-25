---
name: idor-testing
description: Insecure direct object reference testing for broken access control
origin: RedteamOpencode
---

# IDOR Testing (Insecure Direct Object Reference)

## When to Activate

- API endpoints reference objects by ID (numeric, UUID, slug)
- User-specific resources accessible via direct reference
- Multi-tenant application with shared API surface

## Tools

- run_tool curl with multiple auth tokens
- Burp Suite Repeater + Autorize extension
- Two or more test accounts (different privilege levels)
- Burp Comparer for response diffing

## Methodology

### 1. Map Object References

- [ ] Identify all IDs in URLs: `/api/users/123`, `/orders/456`
- [ ] Identify IDs in request body and query params
- [ ] Identify IDs in headers (custom auth, tenant ID)
- [ ] Note ID formats: numeric, UUID, base64-encoded, hashed
- [ ] Catalog all CRUD operations per object type

### 2. Horizontal Access Testing (Same Role)

- [ ] Create two accounts: User A and User B
- [ ] As User A, access User B's resources by swapping ID
- [ ] Test on GET (read), PUT/PATCH (modify), DELETE (remove)
- [ ] Test POST with another user's parent ID (e.g., create order for User B)
- [ ] Check file/document access: `/files/{fileId}`
- [ ] Check export/download endpoints with swapped IDs

### 3. Vertical Access Testing (Cross Role)

- [ ] As regular user, access admin-only resource IDs
- [ ] Swap user ID to admin ID in requests
- [ ] Test admin actions (delete user, change role) with user token
- [ ] Check if API hides endpoints but doesn't enforce authz on IDs

### 4. ID Manipulation Techniques

- [ ] Numeric: increment/decrement (`123` → `124`, `122`)
- [ ] UUID: try UUID of another user's object (obtained via other endpoint)
- [ ] Base64: decode, modify, re-encode
- [ ] Hashed/encoded: check if predictable (MD5 of sequential number)
- [ ] Negative or zero IDs: `-1`, `0`
- [ ] Array injection: `id[]=1&id[]=2` — may return multiple objects
- [ ] Wildcard or special values: `*`, `all`, `null`

### 5. Bypass Techniques

- [ ] Change HTTP method: GET blocked → try PUT/PATCH/DELETE
- [ ] Add wrapping: `/api/users/me/../123`
- [ ] Parameter pollution: `?id=myId&id=victimId`
- [ ] Case change on endpoints: `/API/Users/123`
- [ ] Version switch: `/v1/users/123` if `/v2/` is protected
- [ ] JSON body vs query param: move ID between locations

### 6. Bulk / Mass Assignment

- [ ] Test listing endpoints without filter: `/api/orders` returns all
- [ ] Remove or blank the user filter parameter
- [ ] GraphQL: query relationships to access other users' nested data

### 7. Batch/Bulk-Endpoint and Filter Manipulation

- [ ] Array/list endpoints accepting an ID filter: widen or remove the filter (`?owner_id=` → drop param, `?owner_id[]=`) to see if server-side scoping was enforced only client-side
- [ ] Bulk-export endpoints (`/api/export?ids=1,2,3`) — append other users' IDs to a batch you legitimately own; a common miss is per-item authz being skipped when items are processed as a batch
- [ ] Pagination bypass: some APIs scope the *first page* to the caller but an unscoped `?cursor=`/`?offset=` value reveals other users' records on subsequent pages
- [ ] Search/autocomplete endpoints without an explicit ID: does a broad or empty query return cross-tenant/cross-user results that a filtered query correctly scopes?

### 8. Indirect Object Reference Chains

- [ ] Multi-step object relationships: object A (owned) → references object B (via a nested field) → does accessing B directly, or via A's relation endpoint, apply the same ownership check as accessing A?
- [ ] File/attachment IDs returned inside another object's JSON response are often unauthenticated-by-design once known — test whether the attachment endpoint re-checks ownership independent of the parent object
- [ ] WebSocket/real-time channels: subscribing to another user's channel/room ID (`ws://.../rooms/{roomId}`) — IDOR applies identically to subscription-based protocols, see `websocket-testing`
- [ ] GraphQL node/global-ID lookups (Relay-style `id: "VXNlcjox"` base64 `Type:id`): decode, increment the numeric portion, re-encode, and query the generic `node(id: ...)` resolver directly — it frequently skips the type-specific authz the dedicated query enforces

### 9. Validate Impact

- [ ] Confirm data belongs to another user (check names, emails)
- [ ] Demonstrate modification: change another user's data
- [ ] Demonstrate deletion if safe to do so (staging only)

## What to Record

- Endpoint, HTTP method, and parameter with IDOR
- Auth context (which user token was used)
- Object accessed/modified and its owner
- Horizontal vs vertical access
- Request/response evidence (redact sensitive data)
- Severity: High (data access) or Critical (data modification/deletion)
- Remediation: enforce server-side ownership checks, indirect references
