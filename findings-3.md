# Follow-Up Review Against `findings-2.md`

Date: 2026-04-14

Verification:

- Reviewed `CHANGELOG.md` and the current implementation
- Re-ran the full suite in the local Python 3.11 virtualenv
- Result: `117 passed, 1 warning` via `.venv/bin/pytest -q`

## Re-Score

**B-**

This is a meaningful improvement over the prior `C`. Four of the six remaining items from `findings-2.md` are now genuinely addressed in code:

- audit chain initialization is wired on startup
- task-scoped audit verification no longer false-alarms on interleaving
- startup adapter loading now goes through the real loader with env-var resolution
- value-based secret scanning now covers raw string outputs, not just key names

Two areas are only partially closed:

- runtime authentication exists, but the primary SDK path does not expose it
- policy-derived scope now flows into capability minting, but the narrowing logic is not monotonic in all cases

## Findings

### 1. High: approval “reductions” can still widen authority beyond the policy/request intersection

Relevant code:

- capability minting first computes `effective_scope = _intersect_scopes(policy_scope, requester_scope)`: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:322)
- then approval reduction replaces that scope outright instead of intersecting with it: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:325), [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:329)

Impact:

- A caller can submit a broad `reduced_scope` payload during approval and the broker will treat it as authoritative, even if it is broader than the policy ceiling or broader than the requester's original scope.
- That contradicts the changelog claim that approval reductions “further narrow.”

Why this matters:

- This is the one remaining scope-enforcement issue that is still security-relevant, not just semantic cleanup.

### 2. Medium: `_intersect_scopes()` does not always narrow requester scope

Relevant code:

- helper implementation: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:565)
- no-overlap dict case falls back to `policy_scope`: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:592), [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:598)

Observed behavior:

- `_intersect_scopes({"account_id": ["a1"]}, {"account_id": ["a2"]})` returns `{"account_id": ["a1"]}`.

Impact:

- Requester-supplied scope does not always act as a narrowing constraint.
- In a no-overlap case, the broker silently broadens back to the policy scope instead of producing an empty intersection or a denial.

Why this matters:

- The fix is directionally correct, but the monotonic “requester can only narrow, never widen” claim is not yet true in all cases.

### 3. Medium: runtime authentication is implemented in the broker, but not in the SDK

Relevant code:

- broker supports `runtime_secret` on task creation and execution: [schemas.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/core/schemas.py:28), [schemas.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/core/schemas.py:128), [gateway.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/proxy/gateway.py:174)
- `JITAuthClient.task()` does not accept or send `runtime_secret`: [client.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/sdk/client.py:211), [client.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/sdk/client.py:257)
- `TaskHandle.execute()` does not send `runtime_secret` either: [client.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/sdk/client.py:121)

Impact:

- Teams using the Python SDK, which is the main advertised integration surface, cannot currently opt into the new runtime-auth control without bypassing the SDK and calling the REST API directly.
- So the broker primitive exists, but the main client path still defaults to bearer-token-only execution.

Why this matters:

- This weakens the practical closure of the original runtime-binding finding even though the broker implementation itself is a real improvement.

### 4. Low: the claimed test count is incorrect

Observed result:

- Current executed suite result is `117 passed, 1 warning`, not `133 passed`.

Relevant code/docs:

- user claim and changelog state “133 tests pass” / “16 new tests ... (133 total, was 117)”: [CHANGELOG.md](/Users/mikebumpus/Documents/GitHub/jitauth/CHANGELOG.md:18)

Impact:

- This is a documentation/reporting mismatch, not a product security flaw.
- It does matter for release credibility and for handoff accuracy to other agents or reviewers.

## Resolved Since `findings-2.md`

These items appear genuinely fixed:

- runtime secret hashing and broker-side verification are implemented
- policy scope now participates in capability minting
- audit chain initialization is wired into broker startup
- per-task audit verification now verifies the global chain correctly
- startup adapter loading uses `config/loader.py`
- string-value secret scanning covers shell/stdout and raw text outputs

## Bottom Line

This version is substantially better and closer to a coherent governed-execution layer. The biggest remaining issue is the scope math: approval reductions can still widen authority, and requester narrowing is not truly monotonic in no-overlap cases. After that, the main product gap is that the new runtime-auth feature is not yet surfaced through the SDK.

If those are corrected, the project is close to a `B+` range. As it stands, `B-` is the defensible score.
