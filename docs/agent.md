# Agent operating contract

This server is meant to be driven by an AI assistant, not a human clicking a
panel. The model is an operator with a scoped login key. Treat every tool call
as production.

The FastMCP `instructions` string repeats the same contract so the client
model sees it at session start.

## Always

1. **Read first.** `users_list` / `ssl_list_domain_certs` / `csf_search_ip`
   before any write.
2. **Do not set `confirm=true` unless the human approved the exact action**
   (who, what, why). If `APPROVAL_TOKEN` is set, `confirm=true` is rejected —
   ask the human to paste the token. Never invent one. “Unlock this IP” is
   not a blank cheque to disable CSF or delete a user.
3. **Prefer curated tools.** `da_api` / `da_legacy` are escape hatches.
4. **Impersonate the owning user** for domain TLS, mailboxes, FTP, cron, files.
5. **Never echo secrets.** Login keys, passwords, PEM, bearer tokens stay out
   of the chat.
6. **Verify after write.** Re-list the cert, re-grep the IP, re-read the user.

## Never

- `csf_disable` / `ENABLE_CSF_DISABLE`
- `/api/execute` / `ENABLE_EXECUTE`
- `confirm=true` “just in case” or guessing `APPROVAL_TOKEN`
- Deleting users, files, databases, or WordPress (those flags default off)
- Bypassing a `denied_by` flag — call `policy_status` and stop
- Putting `MCP_AUTH_TOKEN` in a query string
- Using the main admin password instead of a login key

## Decision tree

| Human says | First tool | Then |
| --- | --- | --- |
| “SSL for shop.example.com is expired” | `ssl_get_domain_acme_config` (impersonate owner) | dry-run → `ssl_reissue_domain confirm=true` |
| “Reissue SSL for these clients” (Admin SSL icon) | `ssl_admin_list` | `ssl_admin_reissue domains=[…] confirm=true` |
| “The panel hostname cert is bad” | `ssl_server_status` | `ssl_reissue_server confirm=true` |
| “Customer IP is locked out” | `csf_search_ip` + `bfm_list` | `firewall_unblock_everywhere confirm=true` |
| “Restart php-fpm83” | `services_get php-fpm83` | `services_restart confirm=true` |
| “User alice is over quota” | `users_get_usage alice` | tell the operator; do not silently raise limits |
| “Back up bob before we touch him” | `backups_admin_list` | `backups_create username=bob confirm=true` |
| “Throttle alice (CloudLinux)” | `cl_status` then `cl_lve_get` | `cl_lve_set confirm=true` |
| “WordPress / Unit / Redis” | `propack_inventory` | matching curated tool |
| Anything else in `/api/*` | `da_list_endpoints` | `da_describe_endpoint` → `da_api` |

## Least privilege for a help-desk agent

If the assistant only renews certs and unblocks customers:

```
TOOL_ALLOWLIST=ssl_,csf_,bfm_,firewall_,da_ping,da_list,da_describe,session_get,users_get,users_search
REQUIRE_CONFIRM=true
APPROVAL_TOKEN=<paste-from-host>
ENABLE_CSF=true
ENABLE_CSF_DISABLE=false
ENABLE_EXECUTE=false
ENABLE_DELETE=false
ENABLE_ACCOUNT_WRITE=false
```

Create the DirectAdmin login key with the same blast radius (IP-restricted,
command-restricted, short expiry).

## Transports

| Who | How |
| --- | --- |
| Local IDE / Claude Desktop / Cursor | `python server.py` (stdio). No HTTP token needed. |
| Remote agent | `python main.py` behind TLS. `Authorization: Bearer <MCP_AUTH_TOKEN>`. |

stdio is the default for a single operator on the same host. HTTP/SSE is for
when the model runs somewhere else — then the token, CIDR list, and reverse
proxy are mandatory.

## After every session

Read `logs/audit.jsonl`. Rotate the login key if it was pasted into chat.
