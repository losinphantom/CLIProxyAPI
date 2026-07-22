# Codex Agent Identity architecture

Codex Agent Identity is implemented as a narrow CPA core seam plus a separate native plugin. It is not a zero-core-change feature.

## Core seam

`internal/runtime/executor/helps.CodexOutboundAuth` is the only interface the Codex executors know:

- `Match(authMetadata)` selects credentials handled by a plugin.
- `Authorization(ctx, authIndex)` returns an opaque final `Authorization` value.
- `RecoverTask(ctx, authIndex, authorization, status, body)` may repair credential state and request one retry.

The recovery call includes the exact authorization value sent by that request. The plugin uses it as an opaque recovery token to identify the task version that failed. This prevents concurrent failures from registering multiple replacement tasks while keeping AgentAssertion parsing out of CPA core.

The seam is called after native Bearer and custom-header processing, immediately before every HTTP/SSE send and every WebSocket dial. A recovery is attempted only for the first rejected response. A WebSocket retry always creates a new dial and a new assertion.

## Plugin lifecycle

`plugins/codex-agent-identity` owns all protocol-specific behavior:

1. Read the physical credential with `host.auth.get` by stable `auth_index`.
2. Accept standard `auth_mode: agent_identity`/`agentIdentity` nested auth JSON (snake_case or camelCase) and the flat CPA compatibility shape, then parse Base64 PKCS#8 Ed25519 key material.
3. If `task_id` is absent, sign `runtime_id:RFC3339_timestamp` and register it at the OpenAI account auth endpoint.
4. Accept plaintext task IDs or decrypt NaCl anonymous sealed-box task IDs using the Ed25519-to-Curve25519 conversion used by Codex.
5. Persist the new task through `host.auth.save` in the same flat or nested credential location.
6. Sign `runtime_id:task_id:RFC3339_timestamp` for every send or dial.
7. On `invalid_task_id`, `task_not_found`, or `task_expired`, re-register under an auth-index lock and request one retry.

The host binds plugin HTTP callbacks to the selected auth, so task registration uses the same global/per-auth proxy policy as normal upstream traffic.

## Compatibility and security

Agent Identity is classified separately from OAuth and is never scheduled for OAuth refresh. Existing OAuth and API-key Codex credentials retain their Bearer behavior. Explicit Agent Identity credentials fail closed when the plugin is not loaded.

Private keys remain only in the physical auth store and the trusted plugin callback. They are never sent upstream, logged, or included in plugin errors. Management downloads replace private-key fields with `[redacted]`; the persisted file is unchanged. Authorization logging continues to use CPA's existing header masking.
