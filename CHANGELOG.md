# Changelog

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
