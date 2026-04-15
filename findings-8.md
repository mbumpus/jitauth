# Production Hardening Gaps After `v0.5.1`

Date: 2026-04-14

Scope:

- adversarial pass for “bulletproof” public deployment readiness
- focused on remaining trust-boundary and abuse-resistance gaps, not closed backlog items

## Findings

### High: The broker control plane is still unauthenticated, so callers can spoof requester/approver identities and operate admin routes directly

Relevant code:

- task creation trusts caller-supplied `requester_id` and `requester_auth_context` directly from the request body: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:61)
- approval trusts caller-supplied `approver_id` directly from the request body: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:221)
- revocation trusts caller-supplied `revoked_by` directly from the request body: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:499)
- audit and task query endpoints are exposed without any auth dependency: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:108), [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:535)
- there is no auth middleware or identity enforcement in app setup: [server.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/server.py:56)

Why this matters:

- any network caller who can reach the broker can create tasks as any requester, approve tasks as any approver, revoke capabilities as any operator, and read audit data
- audit provenance is therefore not anchored to an authenticated principal; it is only a recorded string
- this is the biggest remaining gap relative to the TRSAA trust model, because the “who asked / who approved / who revoked” answers are not trustworthy at the API boundary

What would close it:

- add real broker-side authentication for every control-plane endpoint
- derive requester/operator identity from authenticated context, not request JSON
- separate runtime execution auth from human/operator/admin auth
- gate audit read, approval, revocation, and task lookup by policy

### High: The broker still accepts a known default JWT signing secret in server mode

Relevant code:

- the default signing secret is a public placeholder string: [settings.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/config/settings.py:20)
- startup does not reject it: [server.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/server.py:36)
- token mint/verify use that secret directly: [tokens.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/core/tokens.py:71), [tokens.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/core/tokens.py:109)
- the public quick start tells operators to `jitauth serve` without any required secret-setup step: [README.md](/Users/mikebumpus/Documents/GitHub/jitauth/README.md:17)

Why this matters:

- a publicly deployed broker that starts with `CHANGE-ME-IN-PRODUCTION` is using a known shared secret
- that weakens the cryptographic integrity of capability tokens and turns a configuration miss into a silent security failure

What would close it:

- hard-fail startup when `jwt_secret` is default, blank, or too short
- document minimum key requirements explicitly
- ideally support asymmetric signing for production deployments

### Medium: `max_actions` is enforced per capability, not per task, so multi-system tasks can exceed their declared action budget

Relevant code:

- each per-system capability gets `max_calls=task.max_actions`: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:336)
- enforcement checks only the capability-local counter: [gateway.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/proxy/gateway.py:255)

Why this matters:

- a task with `max_actions=3` and three target systems can receive three capabilities each with three allowed calls
- the real total budget becomes nine calls, not three
- that breaks the task object’s declared execution bound and matters most on multi-step cross-system workflows, which are exactly where TRSAA drift risk shows up

What would close it:

- enforce a task-level total invocation counter in addition to per-capability limits, or
- split the task budget across minted capabilities deterministically

### Medium: Request-size limiting only trusts `Content-Length`, so streamed or chunked bodies can bypass the limit

Relevant code:

- the request-size middleware checks only the `content-length` header and never reads the body stream: [middleware.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/middleware.py:67)

Why this matters:

- a client that omits or lies about `Content-Length` can still send a large body
- this leaves a memory/DoS hole in the “1MB max body” protection story for public-facing deployments

What would close it:

- enforce limits while consuming the request body stream, not only from headers
- make reverse-proxy size limits part of the documented deployment baseline

### Medium: Policy effects `require_simulation` and `quarantine` exist in the engine but are not implemented in the execution lifecycle

Relevant code:

- the policy engine can return `require_simulation` and `quarantine`: [engine.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/policy/engine.py:25)
- route handling treats anything other than `allow`, `allow_reduced`, or `require_approval` as a denied task state: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:174)

Why this matters:

- the policy vocabulary is broader than the broker behavior
- “quarantine” and “require simulation” are currently labels, not enforced workflows
- that is not a bypass, but it is a governance gap if those effects are advertised as supported outcomes

What would close it:

- add first-class task states and routes for simulation/quarantine review, or
- remove unsupported effects from the public policy contract until they are real

### Medium: Runtime binding is still optional by default in the public SDK path

Relevant code:

- SDK `task()` leaves `runtime_secret` optional and does not auto-generate one: [client.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/sdk/client.py:214)
- decorator path also leaves it optional: [decorators.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/sdk/decorators.py:35)
- the README example does not use runtime authentication: [README.md](/Users/mikebumpus/Documents/GitHub/jitauth/README.md:27)

Why this matters:

- without `runtime_secret`, the execution path falls back to possession of the capability token plus DB state
- that is still scoped, but it is weaker than the repo’s stronger task-to-runtime binding model
- for a “bulletproof by default” posture, the secure path should be the default path

What would close it:

- auto-generate a per-task runtime secret in the SDK unless explicitly disabled
- update examples to show runtime-bound execution as the default integration

## Suggested Hardening Order

1. Add broker API authentication and derive requester/operator identity from auth context.
2. Refuse startup with the default JWT secret and enforce minimum signing-key strength.
3. Add task-level total action-budget enforcement.
4. Replace header-only body-size checks with streaming enforcement and document reverse-proxy limits.
5. Either implement `require_simulation` / `quarantine` flows or remove them from the supported policy surface.
6. Make runtime-bound execution the default in the SDK and MCP integration path.

## Bottom Line

The core broker is strong enough for public release, but “bulletproof” requires closing the last trust-boundary assumptions around operator identity, deployment defaults, and total-task governance. The most important remaining work is not in the adapters anymore; it is in the control plane.
