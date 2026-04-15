# JITAuth

Just-in-time, task-scoped authentication and authorization for AI agents.

## The problem

Traditional IAM assumes the acting entity is a human with judgment or a deterministic system with fixed logic. AI agents are neither. They're probabilistic, tool-using, and vulnerable to prompt injection. Giving them persistent credentials is how you end up explaining yourself to security.

## What JITAuth does

JITAuth is a security broker that replaces standing credentials with ephemeral, scoped capabilities bound to a specific task, runtime, and time window.

**Core principle:** Agents do not possess standing authority. Tasks receive temporary capability under policy.

Every tool call goes through the broker, which classifies the request, evaluates policy, mints a time-limited capability, proxies the execution, and logs everything. The agent never sees the credentials.

## Quick start

```bash
pip install jitauth
jitauth init-db
jitauth serve
```

The broker starts on `http://localhost:8700`. Define your tools in `adapters.yaml` and your rules in `policies/default.yaml`.

## Authentication

The broker requires API key authentication by default. Configure keys in your environment or `.env`:

```bash
JITAUTH_API_KEYS='{"sk-ops-key": "operator:admin", "sk-agent-key": "runtime:my-agent"}'
JITAUTH_JWT_SECRET="your-secret-at-least-32-chars-long"
```

Each key maps to `role:caller_id`. The two roles are "operator" (full access — approve tasks, query audit, manage any task) and "runtime" (can only manage tasks it created). The `/health` endpoint is always public.

Runtime callers must use their own `caller_id` as the `runtime_id` when creating tasks. In the example above, the key `sk-agent-key` resolves to `caller_id="my-agent"`, so all tasks created with that key must use `runtime_id="my-agent"`. This prevents one runtime from impersonating another.

The `requester_id` field on task creation is caller-supplied metadata identifying the end-user on whose behalf the task runs. The broker records it but does not authenticate it — upstream identity verification (e.g. your application's login system) is expected to validate the requester before calling the broker.

For local development and testing, set `JITAUTH_REQUIRE_API_AUTH=false` to disable auth.

## Python SDK

```python
from jitauth.sdk import JITAuthClient

client = JITAuthClient(
    "http://localhost:8700",
    api_key="sk-agent-key",           # Required when auth is enabled
    runtime_id="my-agent",            # Must match caller_id from API key
)

async with client.task(
    requester="user_123",
    objective="Look up client and draft follow-up",
    actions=[
        {"system": "crm", "action": "read_account", "action_class": "read"},
        {"system": "email", "action": "create_draft", "action_class": "write"},
    ],
) as task:
    account = await task.execute("crm.read_account", {"account_id": "456"})
    await task.execute("email.create_draft", {"body": "...", "to": "client@co.com"})
    # Capabilities auto-expire on exit; runtime_secret auto-generated
```

If policy denies the task, you get a `TaskDeniedError`. If approval is required, you get an `ApprovalRequiredError` with the `task_id` for out-of-band approval.

## MCP Server

JITAuth runs as an MCP server, so any MCP-compatible agent gets governed tool access:

```bash
pip install jitauth[mcp]
JITAUTH_API_KEYS='{"sk-mcp-key": "runtime:mcp-agent"}' \
jitauth mcp-serve --adapters adapters.yaml \
  --api-key sk-mcp-key --runtime-id mcp-agent
```

Every tool call from the agent goes through the full governance pipeline. The agent sees tools, calls them normally, and JITAuth handles policy, scoping, credentials, and audit transparently.

## Policy

Policies are YAML files. Deny-by-default — if no rule matches, the task is rejected.

```yaml
rules:
  - name: deny-destructive-default
    priority: 10
    match:
      risk_tier: "tier_4"
    effect: deny
    reason: "Destructive actions denied by default"

  - name: allow-reads
    priority: 50
    match:
      action_class: "read"
      risk_tier: ["tier_0", "tier_1"]
    effect: allow

  - name: require-approval-send
    priority: 30
    match:
      action_class: "send"
    effect: require_approval
    reason: "External send requires human approval"
```

Match on `risk_tier`, `system`, `action`, `action_class`, or `runtime_trust_tier`. Effects: `allow`, `allow_reduced`, `require_approval`, `deny`, `quarantine`.

## Adapters

Adapters connect JITAuth to downstream systems. Two built-in:

**HTTP adapter** — for REST APIs. Credentials are injected server-side (the agent never sees them):

```yaml
adapters:
  - system_name: crm
    adapter_type: http
    config:
      base_url: "https://api.example.com/v2"
      actions:
        read_account:
          method: GET
          path: "/accounts/${account_id}"
    credentials:
      type: bearer
      token: "${CRM_API_TOKEN}"
```

**Shell adapter** — allowlisted command templates only. No raw shell access:

```yaml
  - system_name: devtools
    adapter_type: shell
    config:
      commands:
        git_log:
          template: "git log --oneline -n ${count}"
          params:
            count:
              type: int
              min: 1
              max: 100
```

## Risk tiers

Actions are classified into risk tiers that drive policy:

| Tier | Examples | Default handling |
|------|----------|-----------------|
| 0 | Read public docs | Auto-allow |
| 1 | Read CRM notes, fetch calendar | Auto-allow |
| 2 | Create draft, add comment | Allow under scope |
| 3 | Send email, edit customer data | Require approval |
| 4 | Delete data, shell commands, infra changes | Deny by default |

## Audit

Every action produces an audit event. Events are hash-chained for tamper detection.

```bash
curl -H "Authorization: Bearer sk-ops-key" \
  http://localhost:8700/audit?task_id=01HXYZ...
```

The audit trail answers: who requested the task, which runtime acted, what policy allowed it, what capability was issued, what tools were called, and what happened.

## Architecture

```
Agent Runtime → JITAuth Broker → Target Systems
                    │
            ┌───────┼───────┐
            │       │       │
         Policy  Capability  Audit
         Engine   Broker    Logger
```

The broker is the trust boundary. The model proposes, the broker executes.

## JWT Capability Tokens

Capabilities are minted as signed JWTs, providing cryptographic proof that a capability was legitimately issued and hasn't been tampered with. The token is bound to a specific task, runtime, system, and time window.

```python
# Capability response includes a signed token
caps = await client.request_capabilities(task_id)
print(caps[0].token)  # eyJhbGciOiJIUzI1NiIs...
```

The broker still validates against the database for revocation checks and call counting — the JWT is an additional integrity layer, not a replacement.

## Docker

```bash
cp .env.example .env   # Edit with your secrets
docker compose up -d
```

This runs the broker backed by Postgres 16. See `docker-compose.yaml` for the full configuration.

## API

| Endpoint | Description |
|----------|-------------|
| `POST /tasks` | Create a governed task |
| `POST /tasks/{id}/classify` | Classify risk tier |
| `POST /tasks/{id}/policy-evaluate` | Evaluate against policy |
| `POST /tasks/{id}/capabilities` | Mint scoped capabilities (returns signed JWTs) |
| `POST /execute` | Execute a tool call |
| `POST /tasks/{id}/approve` | Approve a pending task |
| `POST /capabilities/{id}/revoke` | Revoke a capability |
| `GET /audit` | Query audit trail |
| `GET /health` | Broker health check |

Export the full OpenAPI 3.1 spec:

```bash
jitauth openapi -o openapi.json
```

## Security

JITAuth is designed with defense in depth:

- **API key authentication** — all broker endpoints require Bearer token auth (configurable)
- **Task ownership enforcement** — runtime callers can only access tasks they created
- **Deny-by-default policy** — no action proceeds without an explicit allow rule
- **Credential isolation** — agent runtimes never see downstream credentials
- **Runtime binding** — SDK auto-generates a session secret; execution is bound to the creating runtime
- **JWT startup validation** — rejects weak signing secrets at boot
- **Atomic budget enforcement** — per-task action budgets use row locking under concurrency
- **Rate limiting** — configurable per-IP sliding window (120 req/min default)
- **Request size limiting** — 1MB max body, streaming enforcement (configurable)
- **Input validation** — Pydantic field constraints on all API schemas
- **Audit hash chain** — SHA-256 linked events with DB-serialized writes for tamper detection
- **Shell sandboxing** — allowlisted commands only, dangerous character rejection
- **scrypt KDF** — runtime secrets hashed with scrypt, constant-time comparison

## Status

v0.7.2 — production-hardened governance pipeline with 190+ tests. Eleven rounds of adversarial code review (D → A). Control-plane authentication, runtime identity binding, task ownership, atomic budgets, streaming body size enforcement, and secure-by-default SDK. Ready for integration testing with real agent frameworks.

## License

MIT
