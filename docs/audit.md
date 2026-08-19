# Audit, policy, rate limits, maintenance window

Every MCP tool call is a **structured event**. That is the point versus SSH:
you can log, rate-limit, approve, or block by policy *before* DirectAdmin
sees the action.

```
logs/audit.jsonl
{"ts":"2026-08-19T20:01:00Z","event":"tool_call","actor":"cursor-helpdesk","ip":"10.0.0.8","request_id":"a1b2c3d4","tool":"services_restart","args":{"service":"httpd","confirm":true}}
{"ts":"2026-08-19T20:01:01Z","event":"tool_ok","actor":"cursor-helpdesk","ip":"10.0.0.8","request_id":"a1b2c3d4","tool":"services_restart"}
```

Secrets (passwords, login keys, bearer, approval token, PEM) are redacted.

## Questions this answers

| Question | How |
| --- | --- |
| Which agent restarted which service, when? | `audit_search tool=services_restart` |
| Who triggered a package update? | `audit_search tool=system_packages_update_run` |
| Was it inside the maintenance window? | `window_now` + `event=tool_window_denied` |
| Who was blocked by policy? | `audit_search event=tool_capability_denied` |

```
audit_search  tool=services_restart  actor=cursor-helpdesk
audit_recent  limit=20
window_now
```

## Actor

Set `MCP_ACTOR=helpdesk-bot` on the process. HTTP clients should send:

```
X-Agent-Id: cursor-helpdesk
```

(`X-MCP-Actor` is accepted too.) The value is stamped on every audit line.
It is advisory — anyone with `MCP_AUTH_TOKEN` can spoof the header. Give
each agent its own token + CIDR if you need a hard identity.

## Rate limit / approve / block

| Control | What it does |
| --- | --- |
| `RATE_LIMIT_PER_MINUTE` | 429 after N HTTP requests / identity |
| `REQUIRE_CONFIRM` + `APPROVAL_TOKEN` | mutating tools wait for a human |
| `ENABLE_*` / `TOOL_ALLOWLIST` | family or name denied before DA is called |
| `MAINTENANCE_WINDOW` | mutating families refused outside the window |

## Maintenance window

```
MAINTENANCE_WINDOW=Mon-Fri 01:00-05:00 Europe/Sofia
WINDOW_ENFORCE=true
```

Applies to **opt-in mutating families** (restart, OS updates, deletes,
CustomBuild, …). **SSL reissue and CSF unblock stay 24/7** — a locked-out
customer or an expired cert is not a scheduled change.

Retention: `AUDIT_RETENTION_DAYS=90` (rotated files older than that are
deleted). Size rotate at `AUDIT_MAX_BYTES` (default 20 MiB).

Dangerous events can POST to `ALERT_WEBHOOK_URL` (no secrets in the body):
`tool_window_denied`, `users_delete`, `csf_disable`, `approval_fail`,
`tool_capability_denied`.
