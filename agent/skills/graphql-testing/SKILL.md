---
name: graphql-testing
description: GraphQL security testing — introspection, injection, auth bypass, DoS
origin: RedteamOpencode
---

# GraphQL Security Testing

## When to Activate

- Application exposes a GraphQL endpoint (`/graphql`, `/gql`, `/api/graphql`)
- Requests contain `query`, `mutation`, or `operationName` parameters
- GraphQL Playground or GraphiQL interface discovered

## Tools

- `run_tool curl` / Burp Suite Repeater
- Altair GraphQL Client
- InQL (Burp extension for GraphQL)
- graphql-voyager (schema visualization)
- BatchQL (batch query testing)
- CrackQL (brute-force via GraphQL)

## Methodology

### 1. Endpoint Discovery

- [ ] Common paths: `/graphql`, `/gql`, `/api/graphql`, `/graphql/console`
- [ ] Check for GraphiQL / Playground: `/graphiql`, `/playground`
- [ ] Look in JavaScript bundles for endpoint URLs
- [ ] Test both GET and POST methods
- [ ] Check WebSocket subscriptions: `ws://target/graphql`

### 2. Introspection Query

- [ ] Full schema dump:
      ```graphql
      { __schema { types { name fields { name type { name } } } } }
      ```
- [ ] Query types: `{ __schema { queryType { fields { name } } } }`
- [ ] Mutation types: `{ __schema { mutationType { fields { name } } } }`
- [ ] If introspection disabled, test partial: `{ __type(name: "User") { fields { name } } }`
- [ ] Field suggestion: send typo, observe "Did you mean..." errors
- [ ] Systematic schema reconstruction when introspection is fully disabled but suggestions remain on: brute-force common type/field names via the "Did you mean" oracle (tools like `clairvoyance` automate this); treat this as a bounded 1-2 probe confirmation here, escalate full reconstruction to `fuzzer`
- [ ] Introspection re-enabled on an alternate operation name or via POST when GET is blocked (or vice versa) — some gateways only disable introspection on the default route
- [ ] Check for a leaked SDL/schema file directly: `/schema.graphql`, `/graphql/schema.json`, exposed in JS bundle source maps

### 3. Information Gathering

- [ ] Enumerate all types, queries, mutations, subscriptions
- [ ] Identify sensitive fields: password, token, secret, ssn, creditCard
- [ ] Map relationships: User→Orders→Payments
- [ ] Find hidden/internal queries not exposed in docs
- [ ] Check for debug fields: `_debug`, `__internal`

### 4. Authorization Testing

- [ ] Query other users' data via relationships:
      `{ user(id: "other-id") { email orders { total } } }`
- [ ] Access admin-only mutations with user token
- [ ] Test field-level access: can user query `user { role passwordHash }`?
- [ ] Nested IDOR: `{ order(id: 1) { user { email } } }`
- [ ] Remove or modify authorization header — test anonymous access

### 5. Injection via GraphQL

- [ ] SQLi in arguments: `{ user(name: "' OR 1=1--") { id } }`
- [ ] NoSQL injection in filters
- [ ] Variables injection: pass malicious input via `$variables`
- [ ] Stored XSS through mutations that save user content

### 6. Denial of Service

- [ ] Deeply nested queries:
      ```graphql
      { user { friends { friends { friends { friends { name } } } } } }
      ```
- [ ] Circular relationships: exploit to consume server resources
- [ ] Batch queries: send array of queries `[{query:...},{query:...},...]`
- [ ] Alias-based amplification:
      ```graphql
      { a: user(id:1){name} b: user(id:2){name} ... z: user(id:26){name} }
      ```
- [ ] Test depth limit, complexity limit, rate limit
- [ ] Fragment-cycle amplification: define mutually-referencing fragments that spread into each other so a shallow-looking query expands exponentially server-side before depth limiters (which often only count literal nesting, not fragment expansion) catch it
      ```graphql
      query { user { ...F1 } }
      fragment F1 on User { friends { ...F2 } }
      fragment F2 on User { friends { ...F1 } }
      ```
- [ ] Directive-repetition overload: repeat `@include(if: true)`/`@skip(if: false)` hundreds of times on the same field to inflate AST-processing cost without increasing visible query depth
- [ ] Array-argument amplification: request a large `first`/`limit`/`ids: [...]` argument value where the resolver doesn't cap pagination size server-side

### 7. Batched Query Attacks

- [ ] Brute-force via batching: send 1000 login mutations in one request
- [ ] OTP bypass: batch OTP verification attempts
- [ ] Rate limit bypass: single HTTP request with multiple operations

### 8. Mutation Abuse

- [ ] Mass assignment: include extra fields in mutation input
- [ ] Test all mutations without auth
- [ ] Modify other users' data via mutations
- [ ] Delete/destructive mutations access control

### 9. CSRF & Content-Type Tricks

- [ ] Check whether GraphQL accepts queries/mutations via `GET` with query-string params — if so and the response uses cookie-based auth with no CSRF token, a bare `<img src>`/link can trigger a state-changing mutation (GraphQL over GET is a common oversight since most CSRF training focuses on POST)
- [ ] Check whether the endpoint accepts `Content-Type: text/plain` or `multipart/form-data` with a JSON-shaped body — a simple-request Content-Type avoids the CORS preflight, enabling cross-site POST CSRF even when the app "requires POST"
- [ ] Confirm SameSite cookie attribute and Origin/Referer validation on the GraphQL endpoint specifically — it's often exempted from CSRF middleware applied to REST routes
- [ ] Persisted-query / APQ bypass: if the app restricts to persisted query hashes in production, test whether arbitrary query bodies are still accepted alongside the `extensions.persistedQuery` field, or whether a new query can be persisted by an unauthenticated client (`APQ` registration abuse)

## What to Record

- GraphQL endpoint URL and supported methods
- Schema dump or partial schema (sanitized)
- Queries/mutations with broken access control
- Injection payload and result
- DoS threshold (depth/complexity before failure)
- Severity based on impact (data leak, RCE, DoS)
- Remediation: disable introspection in prod, enforce depth/complexity limits, field-level authz
