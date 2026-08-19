# SSL reissue playbook

Three surfaces matter on a DirectAdmin box:

| Certificate | Tool | API |
| --- | --- | --- |
| **Admin SSL** (all customer domains) | `ssl_admin_list` / `ssl_admin_reissue` | `CMD_ADMIN_SSL` (Pro Pack, not in New API) |
| One user domain (Let's Encrypt / ZeroSSL) | `ssl_reissue_domain` | `POST /api/domain-tls/{domain}/provision-certs` |
| Panel hostname (`:2222`) | `ssl_reissue_server` | `POST /api/server-tls/obtain` |

Admin SSL is the admin-level icon: overview of every user/domain cert and a
bulk “request” that queues ACME in dataskq. It does **not** need
impersonation. Per-domain New API calls **do** — always impersonate the owner.

## Admin SSL — reissue for selected clients

```
ssl_admin_list
ssl_admin_flags
ssl_admin_reissue  domains=["shop.example.com","blog.example.com"]  confirm=true
ssl_admin_list
```

`ssl_admin_reissue` POSTs `CMD_ADMIN_SSL` with `action=multiple` and
`select0…N`. Max 50 domains per call (Let's Encrypt rate limits).
The login key must be allowed to run `CMD_ADMIN_SSL`.

Automatic poller (install-to-missing / replace-expired) is
`admin_ssl_*` in `directadmin.conf` — read with `ssl_admin_flags`, change
with `da_config_local_patch` (and a panel restart if DA requires it).
Do not leave `admin_ssl_replace_all_expired_invalid=1` on permanently.

## Domain cert expired or missing (one site)

```
ssl_get_domain_acme_config   domain=shop.example.com  impersonate=alice
ssl_reissue_domain           domain=shop.example.com  impersonate=alice  dry_run=true
ssl_reissue_domain           domain=shop.example.com  impersonate=alice  confirm=true
ssl_list_domain_certs        domain=shop.example.com  impersonate=alice
```

If ACME is off, turn it on first:

```
ssl_set_domain_acme_config
  domain=shop.example.com
  enabled=true
  provider=letsencrypt
  key_type=ec256
  impersonate=alice
  confirm=true
```

Wildcard (`*.example.com`) needs a DNS-01 provider:

```
ssl_acme_dns_providers
ssl_set_domain_acme_config  prefer_wildcard=true  dns_provider=cloudflare  …
```

## Hostname / panel cert

```
ssl_server_status
ssl_server_acme_config
ssl_reissue_server  confirm=true
```

Use `ssl_server_upload_files` only when a commercial CA issued the cert.

## Older panels (no `/api/domain-tls`)

```
ssl_reissue_domain_legacy  domain=shop.example.com  impersonate=alice  confirm=true
```

This POSTs `CMD_API_SSL` with `request=letsencrypt`.

## After a reissue

- Wait for HTTP-01 (ports 80/443) or DNS-01 to complete.
- If CSF blocked Let's Encrypt validators, temporarily allow them, then reissue.
- `confirm=true` is required — the model must get an operator go-ahead.
