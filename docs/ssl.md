# SSL reissue playbook

Two certificates matter on a DirectAdmin box:

| Certificate | Tool | New API |
| --- | --- | --- |
| User domain (Let's Encrypt / ZeroSSL) | `ssl_reissue_domain` | `POST /api/domain-tls/{domain}/provision-certs` |
| Panel hostname (`:2222`) | `ssl_reissue_server` | `POST /api/server-tls/obtain` |

Always **impersonate the owning user** for domain TLS. Admin context cannot
provision a user domain.

## Domain cert expired or missing

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
