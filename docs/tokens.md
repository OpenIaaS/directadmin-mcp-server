# Named tokens, profiles, reason, hops

The actor in the audit log is the **token name**, not `X-Agent-Id`. Anyone
who has a bearer token could spoof a header. They cannot spoof a hash they
do not have.

## Profiles

| Profile | Typical owner | Allowed writes |
| --- | --- | --- |
| `readonly` | chatty / mail-reading agent | none (plus `ip_block_reason`, audit, inventory) |
| `helpdesk` | day-to-day support agent | SSL reissue, CSF/BFM unblock only |
| `operator` | scheduled work | helpdesk + process `ENABLE_*` except account delete / `csf_disable` |
| `break-glass` | owner or emergency sysadmin | process `ENABLE_*` (still no execute unless you flip that flag) |

Process flags are a **ceiling**. A helpdesk token cannot delete users even if
`ENABLE_ACCOUNT_WRITE=true` on the box.

## Create a token

```
python tokens.py
```

Copy the `sha256:…` line into `tokens-write.json` / `tokens-readonly.json`.
Give the raw secret only to that agent. Example file:
[tokens.example.json](../tokens.example.json).

```
MCP_TOKENS_FILE=tokens-write.json
MCP_PROFILE=helpdesk
```

`MCP_AUTH_TOKEN` still works as a single legacy token (profile = `MCP_PROFILE`).

Emergency sysadmin: a second hash with `"name": "emergency", "profile": "break-glass"`
in the write listener’s file — or a separate compose env. Do not share the
helpdesk secret with the break-glass agent.

## reason=

Mutating tools (including helpdesk SSL/CSF) require:

```
reason="DA-1234 customer locked out of IMAP"
```

or header `X-Change-Reason`. Stored on the audit line. Cyrillic is fine.

## Idempotency

```
idempotency_key="ticket-1234-unblock"
```

or header `Idempotency-Key`. Same key + same arguments inside 15 minutes
replays the first result (no second Let's Encrypt, no second unblock). Same
key + different arguments is rejected.

## Hops Docker

The compose file runs **two** loopback listeners, one stack per DA box:

| Port | Service | Agent |
| --- | --- | --- |
| `127.0.0.1:8888` | `mcp-readonly` | mail/chat agent |
| `127.0.0.1:8889` | `mcp-write` | helpdesk / emergency |

Login key via Docker secret (`secrets/da_login_key`), not `.env`. See
[secrets/README.md](../secrets/README.md).

`inventory.json` on the hops host lists every panel (CloudLinux, profile).
This process still has **one** `DA_URL` — copy the compose + env per box.
`inventory_this` tells the agent which row it is.
