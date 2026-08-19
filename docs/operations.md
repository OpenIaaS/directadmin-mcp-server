# Operations runbooks

Day-2 work an agent can do safely. Every mutating step needs `confirm=true`
and a human go-ahead.

## 1. Reissue customer certs (Admin SSL icon)

```
ssl_admin_list
ssl_admin_reissue  domains=["shop.example.com"]  confirm=true
```

This is `CMD_ADMIN_SSL action=multiple` — the Admin Level icon. Pro Pack
required. For one modern-panel domain, prefer the New API path below.

## 2. Reissue a domain certificate (New API)

See [ssl.md](ssl.md). Short path:

```
users_search                     q=shop.example.com
ssl_get_domain_acme_config       domain=shop.example.com  impersonate=<owner>
ssl_reissue_domain               domain=shop.example.com  impersonate=<owner>  dry_run=true
ssl_reissue_domain               domain=shop.example.com  impersonate=<owner>  confirm=true
ssl_list_domain_certs            domain=shop.example.com  impersonate=<owner>
```

If HTTP-01 fails, check CSF did not ban the CA validators, then retry.

## 3. Reissue the panel hostname certificate

```
ssl_server_status
ssl_reissue_server  confirm=true
```

## 4. Unlock a customer IP

See [csf.md](csf.md).

```
csf_search_ip                    ip=203.0.113.44
bfm_ip_reason                    ip=203.0.113.44
firewall_unblock_everywhere      ip=203.0.113.44  confirm=true
csf_search_ip                    ip=203.0.113.44
```

Do **not** run `csf_disable`.

## 5. Restart a service

Off by default (`ENABLE_SERVICE_CONTROL=false`). Flip the flag on that box
first, then:

```
services_list
services_get        service=httpd
services_restart    service=httpd  confirm=true
services_get        service=httpd
```

Valid names look like `httpd`, `exim`, `dovecot`, `named`, `php-fpm83`.
Anything with `/` or `..` is rejected.

## 6. Inspect / create a user

```
users_search          q=alice
users_get_config      username=alice
users_get_usage       username=alice
```

Creating accounts is a dedicated write (`users_create` / reseller tools) and
always needs `confirm=true`. Prefer a package over ad-hoc limits.

## 7. Backup then change

```
backups_admin_list
backups_create        username=alice  where=local  confirm=true
```

Restore is extra-gated (`confirm=true` plus the extra destructive flag).
Backup filenames cannot contain `..`.

## 8. Mailbox / FTP / cron (user context)

Always impersonate the owner:

```
# examples — see the tool catalog for the exact names
# impersonate=alice on every call
```

## 9. Pro Pack / CloudLinux

```
propack_inventory
cl_status
cl_lve_get     username=alice
cl_lve_set     username=alice  speed=50%  confirm=true
unit_list      domain=shop.example.com  impersonate=alice
```

Web Terminal is blocked. CloudLinux writes go through the LVE Manager plugin.

## 10. When there is no curated tool

```
da_list_endpoints       prefix=/api/…
da_describe_endpoint    method=GET  path=/api/…
da_api                  method=GET  path=/api/…   # reads
da_api                  method=POST path=/api/…  confirm=true
```

`/api/execute`, `/api/login`, `/api/logout`, `/api/terminal` are blocked.

## 11. Incident: key leaked

1. Revoke the DirectAdmin login key in the panel.
2. Rotate `MCP_AUTH_TOKEN`.
3. Read `logs/audit.jsonl` for the window after the leak.
4. Issue a new IP-restricted login key.

## 12. Health

| URL | Auth | Meaning |
| --- | --- | --- |
| `/health` | public | Process is up. Docker HEALTHCHECK uses this. Does **not** hit the panel. |
| `/ready` | public | Panel reachable. Returns `degraded` without exception strings. |
| `/mcp/tools` | bearer | Tool list. |
| `/sse` | bearer | MCP session. |

Never put the bearer token in the query string.
