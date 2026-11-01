# SPIFFE workload identity

Status: proposed, not implemented. Nothing below exists in the code yet.

## Summary

Let workloads log in to Scion with a [JWT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md)
issued by a SPIFFE implementation such as SPIRE. A workload exchanges its short-lived SVID for a
short-lived Scion token. Everything after login stays as it is: bearer tokens, the daemon and
ACL enforcement.

This replaces the shared service secret for agents and CI. GitHub login stays for people, because
SPIFFE identifies workloads rather than humans.

## Why

Today every agent shares one principal, such as `service:agent`, and one long-lived secret:

- A leaked secret is valid until someone rotates it, and rotation touches every agent.
- All agents have the same rights.
- `creator` and the ref log show `service:agent`, not which agent acted.

With this feature:

| Goal | How it is met |
| --- | --- |
| Each agent has its own identity | The principal is the workload's SPIFFE ID |
| No shared secret | No static credential is stored in pods or volumes |
| Identities are short-lived | SVIDs expire in minutes; Scion tokens get their own short TTL |
| Rights per agent | `acl.toml` can name a SPIFFE ID |
| Audit per agent | `creator`, the ref log, `audit_log` and RPC logs carry that ID |

## Non-goals

- Login for people. GitHub device flow stays.
- mTLS with X.509-SVIDs. The daemon sits between job and server, so a client certificate would
  identify the daemon rather than the job. Scion authorizes per-request tokens for this reason
  (SPEC 17).
- SVIDs for the server's own TLS certificate or for CockroachDB and S3 access.
- Removing service secrets. They remain for bootstrap and for environments without SPIFFE.
- Federation between trust domains. v1 accepts exactly one trust domain.
- Kubernetes manifests. Note that a production cluster also needs a TLS client for the metadata
  store, which `scion-server` lacks today (`tls: None` in `crates/scion-server/src/main.rs`).

## Design

### Login flow

```text
agent pod            SPIRE agent              scion-server            trust bundle
    │ FetchJWTSVID(aud)   │                        │                       │
    ├────────────────────▶│                        │                       │
    │◀──── JWT-SVID ──────┤                        │                       │
    │ Login{jwt_svid}     │                        │  cached keys, refresh │
    ├─────────────────────┼───────────────────────▶│◀─────────────────────▶│
    │                     │              verify signature, alg, aud, exp,  │
    │                     │              sub in trust domain               │
    │◀──── Scion token (principal = SPIFFE ID) ────┤                       │
    │ RPCs with bearer token, directly or through scion-daemon             │
    ├─────────────────────┼───────────────────────▶│                       │
```

The client learns the audience from `GetServerInfo`, as it already does for the GitHub client id,
so agents need no Scion-specific configuration besides the endpoint.

### Protocol

Additive changes to `proto/scion/v1/scion.proto`:

```proto
message LoginRequest {
  oneof credential {
    string github_access_token = 1;
    ServiceCredential service = 2;
    string jwt_svid = 3;
  }
}
```

`GetServerInfoResponse` gains `string spiffe_audience`, empty when the feature is off. The next
free field number is chosen during implementation.

### Principal

A SPIFFE ID does not fit `service:<name>`: `valid_name` rejects `/` and `:`, and names stop at 255
bytes, while SPIFFE implementations must support IDs of up to 2048 bytes. So this adds a variant:

```rust
pub enum Principal {
    GitHub { login: String, id: Option<u64> },
    Service(String),
    Spiffe(String), // the full ID: spiffe://example.org/agent/reviewer
}
```

`id_string()` returns the ID unchanged, and `parse` recognizes the `spiffe://` prefix. Existing
principals and stored `creator` values do not change.

The principal keeps the path exactly as issued. Scion does no case folding or normalization,
because two IDs that differ in any byte are different identities.

### Identity naming

Each Kubernetes service account gets one SPIFFE ID. Replicas of an agent share it, so the audit
trail identifies the agent, not the individual pod.

IDs use the form `spiffe://<trust-domain>/agent/<name>` and contain no Kubernetes namespace.
`creator` stores the ID permanently, so it should name the agent rather than where it runs. The
`ns/<namespace>/sa/<name>` form is only a common SPIRE template, not a SPIFFE requirement.
Namespace and service account stay in the registration's selectors, where they still decide which
workload receives the ID:

```sh
spire-server entry create \
  -spiffeID spiffe://example.org/agent/reviewer \
  -parentID spiffe://example.org/spire-agent \
  -selector k8s:ns:agents \
  -selector k8s:sa:reviewer
```

With SPIRE Controller Manager, the same comes from a `ClusterSPIFFEID` whose `spiffeIDTemplate` is
`spiffe://{{ .TrustDomain }}/agent/{{ .PodSpec.ServiceAccountName }}`.

Scion treats the path as opaque and cannot enforce this form. Without the namespace, two service
accounts with the same name in different namespaces would map to one ID, so operators must keep
agent names unique across namespaces and clusters, and must scope the template accordingly.

### Configuration

```toml
[auth.spiffe]
trust_domain = "example.org"
audience = "scion://monorepo"     # unique to this Scion deployment
token_ttl = "1h"                  # Scion token lifetime for SPIFFE logins
bundle_url = "https://spire-bundle.example.internal/keys"
# bundle_file = "/run/spire/bundle/jwks.json"   # exactly one of url and file
bundle_refresh = "5m"
```

The section is optional; without it the server rejects `jwt_svid` logins. As everywhere in
Scion, unknown keys and invalid values are startup errors. Exactly one bundle source is required.

`token_ttl` is separate from `auth.token_ttl`, which defaults to 12h. Using that default would
undo the benefit of short-lived SVIDs.

### Access policy

`acl.toml` accepts SPIFFE IDs wherever it accepts other principals:

```toml
[groups]
writers = ["spiffe://example.org/agent/reviewer", "group:ci"]
ci = ["spiffe://example.org/ci/runner"]
```

Listing every workload is enough for v1. Prefix members such as
`spiffe://example.org/agent/*` are a later extension, because they change the way
`groups_of` evaluates membership.

### Validation

The server implements these rules, following JWT-SVID sections 2 to 4, and rejects everything
else with `UNAUTHENTICATED`:

1. The token is JWS Compact Serialization.
2. `alg` is one of `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384`,
   `PS512`, checked before any other processing. `none` and `HS*` are never accepted.
3. `typ`, if present, is `JWT` or `JOSE`.
4. The signature verifies against a key with `use: jwt-svid` from the bundle. `kid` is optional
   in JWT-SVID, so a token without one is tried against each key of the trust domain.
5. `exp` is present and in the future, with at most 30 seconds of leeway.
6. `aud` is present and contains the configured audience. Tokens with more than one audience are
   rejected, because JWT-SVID warns that the other audience could replay them.
7. `sub` is a valid SPIFFE ID in the configured trust domain.

Error messages do not reveal which rule failed. The reason goes to the server log, and the token
itself never does (SPEC 15.1).

### Token lifetime and revocation

- The Scion token lives for `auth.spiffe.token_ttl`, independently of the SVID's `exp`.
- ACLs apply per request, so removing a principal from `acl.toml` takes effect on the next reload.
- There is no token revocation. A deleted workload keeps any access that the ACL still grants
  until its token expires. This bounds how high `token_ttl` should be set.
- Rotating `auth.signing_keys` invalidates all tokens, as it does today.

### Bundle handling

The server caches the keys and refreshes them every `bundle_refresh`.

- Startup fails if the first load fails, like other invalid configuration (SPEC 6).
- A failed refresh keeps the last good bundle and logs an error, like an invalid policy reload.
- Without any usable key, login fails with `UNAVAILABLE`, as it does when GitHub is down
  (SPEC 16.1 class 10). Existing tokens keep working.
- `/readyz` stays independent of the bundle. An unreachable bundle must not take down reads and
  writes for clients that already hold tokens.

Bundle age is exposed as a metric so that operators see a failing refresh before keys rotate.

### Client

`scion login --spiffe` fetches a JWT-SVID through the Workload API, at `SPIFFE_ENDPOINT_SOCKET`,
for the advertised audience. It then calls `Login` and stores the token in the credentials file
as usual.

Agents should not have to log in by hand. When `SPIFFE_ENDPOINT_SOCKET` is set and a request
fails with `UNAUTHENTICATED`, the CLI repeats this exchange once, extending the existing GitHub
path (`can_reexchange` and `reexchange` in `crates/scion-cli/src/cli/ctx.rs`). `scion-import`
gets the same fallback alongside `SCION_SERVICE_NAME`.

`scion-daemon` needs no change: it forwards auth RPCs verbatim and authorizes on tokens. The
tests below confirm that.

### Affected code

| Area | Change |
| --- | --- |
| `proto/scion/v1/scion.proto` | `jwt_svid`, `spiffe_audience` |
| `scion-core` | `Principal::Spiffe` |
| `scion-auth` | SVID validation, bundle cache, token issue and parse for the new variant |
| `scion-config` | `[auth.spiffe]` |
| `scion-policy` | SPIFFE members |
| `scion-server` | `Login` branch, `GetServerInfo`, bundle refresh task, metric |
| `scion-cli`, `scion-import` | Workload API client, re-exchange |
| `schemas/v1/login.schema.json` | `method` value `spiffe` |
| `scion-testkit` | Fake SVID issuer (see below) |
| `SPEC.md` | Sections 4.3.8, 6.1, 6.2, 7.7, 12, 19.11 |

The proto change and new JWT dependency are amendments, so log them in
`docs/contracts/amendments.md`. `scripts/layers.toml` needs no change, since `scion-auth` already
sits below its callers.

## Testing

The default suite must stay free of Docker and network access, as it is today. So most tests use
a fake issuer, and only one gated suite uses real SPIRE.

### Test infrastructure

Add `FakeSpiffe` to `scion-testkit`, next to `FakeGitHub`:

- It generates a signing key and serves a SPIFFE bundle on loopback.
- It issues JWT-SVIDs with any `sub`, `aud`, `exp`, `alg`, `kid` and `typ`, so that tests can
  build malformed tokens on purpose.
- It rotates keys and can fail or stall on demand, for the bundle tests.
- It serves a fake Workload API on a Unix socket for the CLI tests.

### Build order

Follow red-green-refactor with one behavior per commit. Each step leaves the workspace working:

1. `Principal::Spiffe` parsing and round trip through the token.
2. Validation rules, one test and one rule at a time.
3. `[auth.spiffe]` parsing.
4. ACL members.
5. Bundle cache and refresh.
6. `Login` and `GetServerInfo`.
7. CLI login, then re-exchange, then `scion-import`.
8. Gated SPIRE suite.

### Unit tests: validation (`scion-auth`)

Each case asserts `UNAUTHENTICATED` and an unchanged client-visible message, except the first.

| Case | Expected |
| --- | --- |
| Valid token for each of the nine algorithms | Accepted; principal equals `sub` |
| No `kid`, bundle has several keys | Accepted |
| `alg: none`, `HS256`, or a value that is not on the list | Rejected before any signature check |
| `HS256` signed with the public key as secret (key confusion) | Rejected |
| Tampered header, payload or signature | Rejected |
| Signed by a key outside the bundle | Rejected |
| Key has `use: x509-svid` | Rejected |
| `exp` missing, expired, or inside and outside the leeway | Rejected, except inside the leeway |
| `aud` missing, wrong, or containing a second value | Rejected |
| `typ` is neither `JWT` nor `JOSE` | Rejected |
| `sub` missing or not a SPIFFE ID | Rejected |
| `sub` in another trust domain | Rejected |
| `sub` with query, fragment, empty segment or `..` | Rejected |
| `sub` of exactly 2048 bytes / of 2049 bytes | Accepted / rejected |
| JWS JSON Serialization, or oversized input | Rejected without parsing the whole input |

Add a proptest that arbitrary byte strings never panic and never validate.

### Unit tests: configuration and policy

- Config: valid section, section absent, unknown key, both or neither bundle source, zero
  `token_ttl`, and an invalid `trust_domain`.
- Policy: a SPIFFE member grants read, write and ref rights. A group containing one resolves
  through `groups_of`. IDs that differ only in case are different principals. A malformed member
  fails validation and keeps the last good policy on reload.
- Principal: `parse(id_string(p)) == p` for all three variants, and existing `github:` and
  `service:` strings parse unchanged.

### Server tests (`crates/scion-server/tests`)

Use the in-process server with loopback TLS, in the style of `core_auth.rs`:

- Valid SVID: `Login` returns a token, and `WhoAmI` shows the SPIFFE ID and its groups.
- The token's expiry matches `auth.spiffe.token_ttl`, not `auth.token_ttl`.
- With `[auth.spiffe]` absent, `jwt_svid` is rejected and `GetServerInfo` has an empty audience.
- GitHub and service login behave as before with the section present.
- Authorization: agent A may write `/a` and is denied `/b`, while agent B gets the reverse, using
  two SVIDs and one server.
- Attribution: after commit and land, `creator` and the ref log hold the SPIFFE ID, and setting
  `SCION_AUTHOR` does not change `creator`. A forced update appears in `audit_log` with that ID.
- Logs: run a login and scan the captured output to confirm that the token never appears.
- Rate limit: repeated failed logins from one peer end in `RESOURCE_EXHAUSTED`.

### Bundle and failure tests

| Scenario | Expected |
| --- | --- |
| Bundle unreachable at startup | Startup fails with a named error |
| Bundle fails later | Last good keys stay in use; error logged; metric shows growing age |
| Key rotation, old and new key both published | Old and new SVIDs accepted |
| Old key removed, next refresh | SVIDs from it rejected |
| Bundle stalls during refresh | `Login` latency unaffected |
| Bundle returns invalid JSON or no `jwt-svid` key | Last good keys stay in use |
| Bundle down, client already holds a token | RPCs continue; `/readyz` stays 200 |
| ACL entry removed | Next RPC is `PERMISSION_DENIED`, while the token stays valid |
| Two servers using the same bundle | A token from one verifies on the other |

Use a fake clock for expiry and refresh timing, so that no test sleeps.

### CLI and daemon tests

- `scion login --spiffe` against the fake Workload API writes credentials with mode `0600` and
  reports method `spiffe` in `--json`, valid against `schemas/v1/login.schema.json`.
- Workload API missing or returning no identity: a clear error and a non-zero exit code.
- Expired Scion token with `SPIFFE_ENDPOINT_SOCKET` set: the command succeeds after exactly one
  re-exchange. If the retry also fails, the error is shown and there is no loop.
- `scion-import` works without `SCION_SERVICE_SECRET`.
- Through `scion-daemon`: login succeeds, a cached object is served only to a principal with
  read access, and two agents on one daemon stay separate principals in `creator`.
- A new client against an old server fails with a readable error rather than hanging.

### End-to-end test with real SPIRE (gated)

The fake issuer can share a misunderstanding with the validator, so one suite runs against real
SPIRE. Name it `external_spiffe_*` and gate it on an environment variable, following the
convention in [docs/testing.md](../testing.md), so it reports `SKIP` by default.

Run it on a [kind](https://kind.sigs.k8s.io/) cluster with SPIRE, or with `spire-server` and
`spire-agent` in `docker/compose.test.yml` using the `unix` workload attestor:

1. Register two workloads, `reviewer` and `runner`, with different ACL rights.
2. From each workload, run `scion login --spiffe` and `scion whoami`.
3. Commit and land from both, then check `scion log` and `creator`.
4. Confirm that `reviewer` is denied the path that only `runner` may write.
5. Delete the `reviewer` registration entry. Confirm that the next login fails, and that an
   existing token works only until it expires.
6. Rotate the SPIRE signing key, and confirm that logins continue without a Scion restart.
7. Stop `spire-server`, and confirm that existing tokens continue to work.
8. Run the client with a stolen expired SVID, and confirm rejection.

### Manual security review

Before merging, have someone check that:

- `alg` is pinned before the key lookup, and the JWT library cannot be steered by the token header.
- The bundle URL is `https` outside tests, with certificates verified.
- The audience is unique to this deployment and documented as such.
- No log line, error or metric label contains a token. Consider whether SPIFFE IDs in metric
  labels would create unbounded cardinality.

### Acceptance criteria

The feature is done when:

- [ ] Two agents with separate SPIFFE IDs work on one server without any service secret.
- [ ] Each one is limited to its own ACL rights.
- [ ] `creator`, the ref log and RPC logs identify each agent.
- [ ] A lost agent pod leaves nothing that works after `auth.spiffe.token_ttl`.
- [ ] Key rotation and a SPIRE outage need no Scion restart.
- [ ] GitHub and service login are unchanged.
- [ ] `scripts/check.sh --full` passes, and the gated SPIRE suite passes.

## Open questions

1. **Default `token_ttl`:** 1h is proposed. Shorter limits a stolen token but means more logins.
2. **Bundle source in Kubernetes:** a URL is simplest for the server. The Workload API's
   `FetchJWTBundles` would avoid polling, but the server then needs a SPIRE agent beside it.
