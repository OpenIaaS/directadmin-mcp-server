# Changelog

## 2.3.1 — 2026-08-19

- CloudLinux is opt-in. `ENABLE_CLOUDLINUX` defaults to **false** so the
  majority of (non-CL) servers never hit LVE Manager. `cl_status` still
  answers. Set `true` only on the CloudLinux boxes.

## 2.3.0 — 2026-08-19


### Pro Pack

- `propack_inventory` maps every Pro Pack feature to a curated tool.
- Nginx Unit: `unit_list` / `unit_create` / `unit_delete` (`CMD_UNIT`).
- Nginx CMS templates: `nginx_set_template` (closed allow-list).
- IMAP sync import / export / cancel.
- Git deploy webhook rotation.
- Web Terminal (`/api/terminal`) stays blocked.

### CloudLinux

- New module `cl_*` talks to LVE Manager / CloudLinux Manager plugin.
- Detect, list/set LVE limits, CageFS enable/disable, PHP Selector.
- Gated by `ENABLE_CLOUDLINUX`. No shell, no `/api/execute`.
- Limit values must be a number, a percent, or `unlimited`.

## 2.2.0 — 2026-08-19


### Admin SSL

- `ssl_admin_list` / `ssl_admin_reissue` / `ssl_admin_flags` wrap the Admin
  Level **Admin SSL** icon (`CMD_ADMIN_SSL` / `CMD_API_ADMIN_SSL`, Pro Pack).
  This is how an admin queues Let's Encrypt for selected customer domains
  without impersonating each user. Not present in the New JSON API swagger.

## 2.1.0 — 2026-08-19


Second hardening pass for agent-driven administration.

### Security

- Bearer token is **header-only**. Query-string `?token=` is rejected (it leaks
  via access logs, Referer, and browser history).
- `/health` is process liveness and does **not** call DirectAdmin (safe for
  Docker HEALTHCHECK). `/ready` probes the panel and never returns exception
  strings.
- Reused `httpx.AsyncClient` with connection limits; closed on shutdown.
- Rate limiter evicts idle identities so it cannot grow without bound.
- `MCP_AUTH_TOKEN` must be ≥ 24 characters when set.
- Impersonation targets are validated as usernames.
- Service names and backup filenames are validated (no `/../` injection).
- Search queries are length-capped.
- `Content-Security-Policy` on HTTP responses.

### Agent contract

- FastMCP `instructions` now encode the operating contract (read first,
  confirm only after a human go-ahead, never disable CSF, never print secrets).
- New playbooks: [docs/agent.md](docs/agent.md), [docs/operations.md](docs/operations.md).

### CI

- GitHub Actions on 3.10 + 3.12, SHA-pinned actions, `contents: read`,
  no persisted credentials, concurrency cancel.

## 2.0.0 — 2026-08-19

Complete rewrite of the half-finished OpenIaaS / omryatia fork.

### Highlights

- **SSL reissue** for user domains (`ssl_reissue_domain`) and the panel hostname
  (`ssl_reissue_server`), plus ACME config, CSR, upload, self-signed, dry-run,
  and a legacy `CMD_API_SSL` fallback.
- **CSF / LFD unblock** (`csf_unblock_ip`, `firewall_unblock_everywhere`) plus
  allow / deny / ignore / search / restart, and native **Brute Force Monitor**
  unblock (`bfm_unblock_ip`).
- **Full New API coverage** via `da_list_endpoints` / `da_describe_endpoint` /
  `da_api` over the official swagger (320 operations) plus curated admin tools
  for users, resellers, packages, IPs, DNS, domains, mailboxes, FTP, cron,
  backups, CustomBuild, services, login keys, MFA, ModSecurity, databases,
  file manager, WordPress, git, …
- **Legacy admin API** where the New API is still incomplete (create/delete
  users, packages, DNS, backups, BFM, IP manager, POP, forwarders).

### Security

- Login keys stored as `SecretStr`; log redaction; audit JSONL
- Bearer token + CIDR allow-list + rate limit + body-size cap on HTTP
- Security headers (`nosniff`, `DENY` framing, `no-store`, noindex)
- No wildcard CORS; refuse `0.0.0.0` without a token
- `confirm=true` on destructive tools
- `/api/execute` and `csf_disable` disabled by default
- Path-traversal checks on file-manager paths
- Sanitised CSF comments; rejected `0.0.0.0/0`
- Docker: non-root, dropped caps, read-only FS, loopback publish

### Breaking

- `DA_LOGIN_KEY` is required (no silent empty default)
- HTTP listener defaults to `127.0.0.1`
- Anonymous HTTP is off (`MCP_ALLOW_ANONYMOUS=false`)
- `TOOL_DENYLIST` now includes `csf_disable` as well as `da_execute`
