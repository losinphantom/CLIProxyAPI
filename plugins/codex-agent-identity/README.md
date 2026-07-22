# Codex Agent Identity plugin

This native plugin adds the Agent Identity credential lifecycle to CPA's built-in Codex executor. See `docs/codex-agent-identity-architecture.md` for the seam and lifecycle design.

## Build and enable

Build a shared library with Go 1.26+ and a C toolchain. Do not commit the generated binary.

Linux:

```bash
cd plugins/codex-agent-identity
CGO_ENABLED=1 go build -buildmode=c-shared -o ../codex-agent-identity.so .
```

Windows (from a shell with GCC available):

```powershell
cd plugins/codex-agent-identity
$env:CGO_ENABLED = "1"
go build -buildmode=c-shared -o ../codex-agent-identity.dll .
```

Enable the plugin in `config.yaml`:

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    codex-agent-identity:
      enabled: true
      priority: 100
```

Restart CPA after installing or replacing the shared library.

## Import a credential

Import a Codex Agent Identity `auth.json` through the existing auth-file API or place it in the configured auth directory. The standard nested shape is accepted directly; `type: codex` is optional because CPA infers the provider from `auth_mode`:

```json
{
  "auth_mode": "agentIdentity",
  "agent_identity": {
    "agent_runtime_id": "agent-runtime-id",
    "agent_private_key": "<base64-pkcs8-ed25519-private-key>",
    "task_id": "optional-existing-task-id",
    "account_id": "chatgpt-account-id",
    "chatgpt_user_id": "chatgpt-user-id",
    "email": "optional@example.com"
  }
}
```

The equivalent camelCase nested shape and the earlier flat CPA shape (`type: codex`, `auth_kind: agent_identity`) are also accepted. `task_id` is optional. The first request registers and persists one in the same flat or nested location when it is absent. `chatgpt_account_id` is accepted as an alias for `account_id`; `private_key_pkcs8_base64` and `private_key` are accepted as private-key import aliases.

This plugin consumes an already-provisioned Agent Identity file; it does not create an Agent Identity or convert a normal ChatGPT OAuth login into one. The public `codex login` browser flow produces ordinary ChatGPT OAuth credentials, not the Ed25519 Agent Identity material required here.

Example Management API import (replace the placeholder locally; do not paste credentials into logs or shell history):

```text
POST /v0/management/auth-files?name=codex-agent.json
Content-Type: application/json
```

Send the JSON file as the request body. Management downloads intentionally redact private-key fields, so a downloaded file is not a credential backup.

## Security and rollback

- Store auth files with owner-only permissions and restrict the Management API.
- Never commit Agent Identity JSON, private keys, assertions, or generated test keys.
- The plugin emits generic key/registration errors and never includes credential values.
- Agent Identity credentials do not use OAuth refresh tokens.

Rollback order:

1. Disable or remove Agent Identity auth files so they cannot be selected.
2. Disable `plugins.configs.codex-agent-identity.enabled` and restart CPA.
3. Remove the shared library if desired.

Existing OAuth/API-key Codex credentials continue to work throughout rollback. If the plugin is disabled while an Agent Identity auth remains selectable, that auth fails closed instead of falling back to Bearer.
