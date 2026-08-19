# Hardening guide

This process holds a DirectAdmin **admin login key**. Treat it like root.
The intended operator is an **AI agent** — see [agent.md](agent.md).
Agents will pass `confirm=true` without asking. Defaults assume that.

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
| `MCP_TOKENS_FILE` | empty | Named hashed tokens; actor = token name |
| `MCP_PROFILE` | `helpdesk` | readonly / helpdesk / operator / break-glass |
| `REQUIRE_REASON` | `true` | Ticket / why on every mutate |
| `IDEMPOTENCY_TTL_SECONDS` | `900` | Replay SSL/unblock instead of doubling |
| `MAX_RESPONSE_CHARS` | `12000` | Truncate BFM/CSF dumps to the model |
| `AUDIT_RETENTION_DAYS` | `90` | GDPR-sized log, not forever |
| `ALERT_WEBHOOK_URL` | empty | Wake someone on delete / window / bad approval |
| `MCP_ALLOW_ANONYMOUS` | `false` | Lab-only escape hatch |
| `REQUIRE_CONFIRM` | `true` | Mutating tools no-op without approval |
| `APPROVAL_TOKEN` | empty | When set, `confirm=true` is **not** enough — paste the token |
| `ENABLE_DELETE` | `false` | Mailbox/FTP/WP/unit/cert deletes |
| `ENABLE_ACCOUNT_WRITE` | `false` | Create/delete/suspend users, passwords, login keys |
| `ENABLE_FILEMANAGER_WRITE` | `false` | rm/mv/chmod through the panel |
| `ENABLE_CUSTOMBUILD` | `false` | Compile the stack |
| `ENABLE_OS_UPDATES` | `false` | `yum`/`apt` via the panel |
| `ENABLE_PLUGIN_WRITE` | `false` | Install/remove plugins |
| `ENABLE_BACKUP_RESTORE` | `false` | Restore overwrites live data |
| `ENABLE_SERVICE_CONTROL` | `false` | restart/stop/start httpd etc. |
| `ENABLE_CONFIG_WRITE` | `false` | `directadmin.conf`, hostname |
| `ENABLE_DA_WRITE` | `false` | Generic `da_api` / `da_legacy` writes |
| `ENABLE_CLOUDLINUX` | `false` | LVE Manager — only on CL boxes |
| `ENABLE_EXECUTE` | `false` | `/api/execute` is a shell |
| `ENABLE_CSF_DISABLE` | `false` | `csf -x` |
| `ENABLE_CSF` | `true` | Unblock is why the agent exists |
| `TOOL_DENYLIST` | `da_execute,csf_disable` | Defence in depth |
| `DA_SSL_VERIFY` | `true` | No silent MITM |
| `RATE_LIMIT_PER_MINUTE` | `60` | Brute-force the token |
| `MCP_ACTOR` / `X-Agent-Id` | `unknown` | Stamped on every audit line |
| `MAINTENANCE_WINDOW` | empty | Mutating families only; SSL/CSF stay 24/7 |
| `AUDIT_LOG` | `logs/audit.jsonl` | Query with `audit_search` |

Always-on helpdesk surface (still needs `confirm` / approval token for writes):
SSL reissue, CSF/BFM unblock, reads.

`policy_status` prints the live flags. If a tool is denied, flip the matching
`ENABLE_*` — do not ask the agent to work around it.

### Approval token (recommended)

```
python -c "import secrets; print(secrets.token_urlsafe(24))"
```

Put the value in `APPROVAL_TOKEN`. The agent must pass that string as
`confirm=`, not `confirm=true`. A model that “just deletes” cannot invent it.

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
TOOL_ALLOWLIST=ssl_,csf_,bfm_,firewall_,da_ping,da_list,da_describe,session_get,policy_
```

To allow one extra family on a single box, flip **one** flag, not all of them.

## Audit

`logs/audit.jsonl` records every tool call with redacted arguments. Login keys,
passwords, bearer tokens, approval tokens and PEM material never land in logs.

## Supply chain

- Pin your own hashes in production if policy requires it.
- CI runs `ruff` + `pytest` on Python 3.10 and 3.12 with SHA-pinned Actions.
- Dependabot watches `pip` and GitHub Actions.
- Refresh `tools/api_spec.json` from a current panel `/static/swagger.json`.
