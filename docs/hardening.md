# Hardening guide

This process holds a DirectAdmin **admin login key**. Treat it like root.
The intended operator is an **AI agent** — see [agent.md](agent.md).

## DirectAdmin side

1. Create a **login key**, never use the main admin password.
2. Restrict the key to the MCP host IP.
3. Allow only the commands you need (`CMD_API_*` + plugin `csf` if you use CSF).
4. Short expiry for temporary deployments.
5. Rotate the key after any paste into chat, tickets, or CI logs.

## MCP side

| Control | Default | Why |
| --- | --- | --- |
| `MCP_HOST` | `127.0.0.1` | No public bind |
| `MCP_AUTH_TOKEN` | required for HTTP, ≥ 24 chars | Bearer on every non-health route |
| `MCP_ALLOW_ANONYMOUS` | `false` | Lab-only escape hatch |
| `REQUIRE_CONFIRM` | `true` | Destructive tools no-op without `confirm=true` |
| `ENABLE_EXECUTE` | `false` | `/api/execute` is a shell-shaped foot-gun |
| `ENABLE_CSF_DISABLE` | `false` | `csf -x` is almost never the right fix |
| `TOOL_DENYLIST` | `da_execute,csf_disable` | Defence in depth |
| `DA_SSL_VERIFY` | `true` | No silent MITM |
| `RATE_LIMIT_PER_MINUTE` | `60` | Brute-force the token |
| Docker | non-root, `cap_drop: ALL`, read-only FS | Blast radius |

Bind `0.0.0.0` only behind TLS (Caddy / nginx) **and** with a token. The
process refuses a public bind without `MCP_AUTH_TOKEN`.

The token is read from the `Authorization` header only. A `?token=` query
parameter is ignored on purpose.

`/health` is liveness (no panel call). `/ready` is readiness (panel ping,
no exception strings). Docker HEALTHCHECK uses `/health`.

## Network

- Put a reverse proxy in front. Terminate TLS there.
- Set `MCP_ALLOWED_CIDRS` to the assistant / jump-host network.
- Do not trust `X-Forwarded-For` (the server ignores it).
- Publish Docker as `127.0.0.1:8888:8888` only.

## Least privilege

If the assistant only renews SSL and unblocks CSF:

```
TOOL_ALLOWLIST=ssl_,csf_,bfm_,firewall_,da_ping,da_list,da_describe,session_get
```

## Audit

`logs/audit.jsonl` records every tool call with redacted arguments. Login keys,
passwords, bearer tokens and PEM material never land in logs.

## Supply chain

- Pin your own hashes in production if policy requires it.
- CI runs `ruff` + `pytest` on Python 3.10 and 3.12 with SHA-pinned Actions.
- Dependabot watches `pip` and GitHub Actions.
- Refresh `tools/api_spec.json` from a current panel `/static/swagger.json`.
