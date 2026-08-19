# DirectAdmin MCP Server

[![ci](https://github.com/OpenIaaS/directadmin-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/OpenIaaS/directadmin-mcp-server/actions/workflows/ci.yml)
[![version](https://img.shields.io/badge/version-2.6.0-0b6bcb.svg)](https://github.com/OpenIaaS/directadmin-mcp-server)
[![license](https://img.shields.io/badge/license-MIT-0b6bcb.svg)](LICENSE)

A production [Model Context Protocol](https://modelcontextprotocol.io) control
plane for **DirectAdmin**. An AI agent (helpdesk, owner, or emergency sysadmin)
talks to this process; the process talks to the panel. Every call is
authenticated as a **named hashed token**, authorised by a **profile**
(readonly / helpdesk / operator / break-glass), optionally confirmed, logged
as structured JSON, rate-limited, and refused outside a maintenance window.
SSL reissue and CSF/BFM unlock are first-class helpdesk actions — they are
not the whole product.

The intended layout is an ops host, not an install on every DirectAdmin
server. Bind a read-only listener for inspection and a separate write
listener for approved changes (SSL reissue, CSF/BFM unlock). Per-server
facts such as CloudLinux and the policy profile live in `inventory.json`
on that host.

It covers the [DirectAdmin New JSON API](https://docs.directadmin.com/developer/api/)
(320 operations from the official swagger) **and** the legacy `CMD_API_*`
admin calls the New API still does not replace (create user, DNS, backups, BFM).

Read [docs/agent.md](docs/agent.md) and [docs/tokens.md](docs/tokens.md)
before pointing a model at production.


```
┌──────────────┐     MCP (stdio / SSE)     ┌──────────────────┐     HTTPS      ┌─────────────┐
│  Claude /    │ ─────────────────────────► │  directadmin-mcp │ ─────────────► │ DirectAdmin │
│  Cursor /    │                            │  confirm=true    │  Basic+key    │  :2222/api  │
│  any MCP     │ ◄───────────────────────── │  audit.jsonl     │               │  + CSF plug │
└──────────────┘                            └──────────────────┘               └─────────────┘
```

## What you can ask

| You say | Tool |
| --- | --- |
| “Reissue the Let's Encrypt cert for shop.example.com” | `ssl_reissue_domain` |
| “The hostname cert expired, renew it” | `ssl_reissue_server` |
| “Customer 203.0.113.44 is locked out of CSF” | `csf_unblock_ip` / `firewall_unblock_everywhere` |
| “Is that IP blocked? Why? Tell the customer.” | `ip_block_reason` |
| “List users over quota” | `users_list_all` + `users_get_usage` |
| “Restart php-fpm74” | `services_restart` (needs `ENABLE_SERVICE_CONTROL=true`) |
| Anything else in `/api/*` | `da_list_endpoints` → `da_api` |

Destructive calls (`delete`, `deny`, `restart`, `reissue`, `unblock`, …)
**require `confirm=true`**. The model must get an explicit go-ahead.

## Requirements

- Python 3.10+ (3.12 recommended) or Docker
- DirectAdmin with API access and a **login key** (not the main password)
- For CSF tools: the [ConfigServer Security & Firewall](https://docs.directadmin.com/operation-system-level/securing/csf.html) DirectAdmin plugin
- Network path from the MCP host to `https://your-panel:2222`

## Quick start (stdio — Claude Desktop / Cursor)

```bash
git clone https://github.com/OpenIaaS/directadmin-mcp-server.git
cd directadmin-mcp-server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.sample .env
# edit .env — DA_URL, DA_USERNAME, DA_LOGIN_KEY
```

Generate a login key in **Admin Level → Account Manager → Login Keys**. Restrict
it to this machine's IP. Put the key in `.env`:

```ini
DA_URL=https://panel.example.com:2222
DA_USERNAME=admin
DA_LOGIN_KEY=...
DA_SSL_VERIFY=true
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "directadmin": {
      "command": "/absolute/path/to/directadmin-mcp/.venv/bin/python",
      "args": ["/absolute/path/to/directadmin-mcp/server.py"],
      "env": {
        "DA_URL": "https://panel.example.com:2222",
        "DA_USERNAME": "admin",
        "DA_LOGIN_KEY": "your-login-key"
      }
    }
  }
}
```

Cursor / other MCP clients use the same `command` + `args` + `env` shape.

## HTTP / SSE mode (remote assistant)

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"   # MCP_AUTH_TOKEN
# put the token in .env, keep MCP_HOST=127.0.0.1
python main.py
```

Put Caddy or nginx in front with TLS. Clients send
`Authorization: Bearer <MCP_AUTH_TOKEN>` to `/sse`.
Do not put the token in the query string.

Docker (loopback only):

```bash
cp .env.sample .env   # fill DA_* and MCP_AUTH_TOKEN
docker compose up -d --build
curl -sS http://127.0.0.1:8888/health
```

The image runs as UID 10001, drops all capabilities, and uses a read-only root
filesystem. See [SECURITY.md](SECURITY.md).

## SSL reissue

**Admin SSL icon** (all customer domains, Pro Pack, not in the New API):

```
ssl_admin_list
ssl_admin_reissue  domains=["shop.example.com","blog.example.com"]  confirm=true
```

This is `CMD_ADMIN_SSL` `action=multiple` — the same action as Admin Level →
Admin SSL. The login key must be allowed to run that command.

**One domain** (New API, DirectAdmin 1.660+ / current Evolution):

```
ssl_get_domain_acme_config  domain=shop.example.com  impersonate=alice
ssl_reissue_domain          domain=shop.example.com  impersonate=alice  confirm=true
ssl_reissue_domain          domain=shop.example.com  dry_run=true
ssl_reissue_server          confirm=true
```

`ssl_reissue_domain` is `POST /api/domain-tls/{domain}/provision-certs`.
`ssl_reissue_server` is `POST /api/server-tls/obtain`.

On older panels the same intent is `ssl_reissue_domain_legacy` (`CMD_API_SSL`
Let's Encrypt request). Always impersonate the **owning user** when you are
logged in as admin — domain TLS is a user-level resource.

Related: `ssl_list_domain_certs`, `ssl_set_domain_acme_config`,
`ssl_upload_cert_files`, `ssl_create_csr`, `ssl_install_self_signed`,
`ssl_acme_dns_providers`.

## CSF / firewall unblock

CSF is **not** in the New JSON API. These tools POST to the official plugin
`/CMD_PLUGINS_ADMIN/csf/`. The plugin must be installed.

An IP is often blocked in **two** places (LFD *and* DirectAdmin BFM). Use the
combined tool when a customer is locked out:

```
csf_search_ip                ip=203.0.113.44
bfm_ip_reason                ip=203.0.113.44
ip_block_reason              ip=203.0.113.44
firewall_unblock_everywhere  ip=203.0.113.44  confirm=true
csf_unblock_ip               ip=203.0.113.44  also_allow=true  confirm=true
bfm_unblock_ip               ip=203.0.113.44  confirm=true
```

`csf_unblock_ip` runs the plugin Quick Unblock (`action=kill` → `csf -dr` +
`csf -tr` + drop states). `also_allow=true` adds a 1-hour temporary allow so
the next handshake is not immediately re-banned.

Other CSF tools: `csf_allow_ip`, `csf_deny_ip`, `csf_ignore_ip`,
`csf_flush_temp`, `csf_restart`, `csf_enable`, `csf_disable`, `csf_status`.

`csf_disable` is denied by default (`TOOL_DENYLIST` + `ENABLE_CSF_DISABLE=false`). Unlock customers with `firewall_unblock_everywhere` instead.

## Tool map

Curated tools are grouped by module. Everything else is reachable with
`da_api` / `da_legacy`. Playbooks: [docs/agent.md](docs/agent.md),
[docs/operations.md](docs/operations.md), [docs/ssl.md](docs/ssl.md),
[docs/csf.md](docs/csf.md), [docs/propack.md](docs/propack.md),
[docs/cloudlinux.md](docs/cloudlinux.md), [docs/hardening.md](docs/hardening.md),
[docs/audit.md](docs/audit.md), [docs/tokens.md](docs/tokens.md).
Inventory: [docs/tools.json](docs/tools.json) (273 curated tools + 320 swagger ops).

| Module | Tools (prefix) | Notes |
| --- | --- | --- |
| SSL | `ssl_*` | Domain + hostname ACME, reissue, upload |
| CSF | `csf_*`, `firewall_*` | Plugin; needs ENABLE_CSF=true |
| BFM | `bfm_*` | Native panel blocks |
| Accounts | `users_*`, `resellers_*`, `admins_*` | New API + CMD_API_ACCOUNT_* |
| Packages | `packages_*` | User / reseller packages |
| System | `system_*`, `license_*`, `maintenance_*` | Version, OS updates, usage |
| Services | `services_*` | start/stop/restart/reload/logs |
| Settings | `hostname_*`, `da_config_*`, `timezone_*`, `email_server_*` | directadmin.conf |
| Auth | `login_keys_*`, `login_urls_*`, `mfa_*`, `sessions_*` | Prefer scoped keys |
| Security | `modsecurity_*`, `clamav_*`, `security_txt_*`, `redis_*` | WAF / AV |
| Data | `db_*`, `fm_*`, `email_*`, `dns_*`, `ips_*`, `backups_*`, `domains_*`, `ftp_*`, `cron_*` | Admin day-2 |
| Build | `cb_*`, `plugins_*`, `wp_*`, `git_*`, `cpanel_*` | CustomBuild / apps |
| Pro Pack | `unit_*`, `nginx_set_template`, `imapsync_*`, `propack_inventory` | Unit + templates; no web terminal |
| CloudLinux | `cl_*` | Opt-in (`ENABLE_CLOUDLINUX=false` by default) |
| Policy | `policy_status` | Live `ENABLE_*` flags; approval-token required? |
| Audit | `audit_search`, `audit_recent`, `window_now` | Who did what, when, in-window? |
| Escape hatches | `da_ping`, `da_list_endpoints`, `da_describe_endpoint`, `da_api`, `da_legacy` | Full swagger |

`da_api` only accepts paths that exist in the bundled
[`tools/api_spec.json`](tools/api_spec.json) (exported from
`https://demo.directadmin.com:2222/static/swagger.json`). `/api/execute` is
blocked unless `ENABLE_EXECUTE=true`.

## Configuration

See [`.env.sample`](.env.sample). Important knobs:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DA_URL` | required | `https://host:2222` |
| `DA_USERNAME` / `DA_LOGIN_KEY` | required | Login key, not the password |
| `DA_IMPERSONATE` | empty | Default login-as; prefer per-tool `impersonate=` |
| `DA_SSL_VERIFY` | `true` | Verify the panel certificate |
| `MCP_HOST` / `PORT` | `127.0.0.1` / `8888` | HTTP bind |
| `MCP_AUTH_TOKEN` | empty | Required for HTTP in production |
| `MCP_ALLOWED_CIDRS` | empty | Optional client allow-list |
| `TOOL_ALLOWLIST` / `TOOL_DENYLIST` | empty / `da_execute` | Reduce blast radius |
| `REQUIRE_CONFIRM` | `true` | Destructive tools need `confirm=true` |
| `ENABLE_CSF` | `true` | CSF plugin calls |
| `ENABLE_EXECUTE` | `false` | `/api/execute` passthrough |
| `RATE_LIMIT_PER_MINUTE` | `60` | Per client identity |
| `AUDIT_LOG` | `logs/audit.jsonl` | Redacted JSON lines |

## Security

Read [SECURITY.md](SECURITY.md). Short version:

- Login key + IP restriction on the DirectAdmin side
- Bearer token + loopback bind + TLS proxy on the MCP side
- Confirm gate, allow/deny tool lists, no wildcard CORS
- Secrets never written to logs
- Docker: non-root, `cap_drop: ALL`, read-only root

If a token or key leaks, rotate **both** immediately. A login key that was
pasted into a chat is burned.

## Development

```bash
pip install -r requirements-dev.txt
pytest -q
ruff check .
```

Adding a curated tool: create a function in `tools/`, decorate with
`@mcp.tool()` + `@log_tool_call`, validate inputs (`validate_ip`,
`validate_domain`, `validate_username`), and call `guard_confirm` if the
call mutates state.

The generic catalog picks up new swagger paths when you replace
`tools/api_spec.json` with a fresh export from your own panel
(`/static/swagger.json`).

## Compatibility

| Transport | File | When |
| --- | --- | --- |
| stdio | `server.py` | Claude Desktop, Cursor, local agents |
| SSE | `main.py` → `/sse` | Older remote MCP clients |
| HTTP health / tool list | `main.py` | `/health` (liveness), `/ready` (panel), `/mcp/tools` |

Tested against the official New API swagger (`info.version = 1.0`, 269 paths /
320 operations). Legacy calls follow
[docs.directadmin.com/developer/api/legacy-api.html](https://docs.directadmin.com/developer/api/legacy-api.html).

## License

[MIT](LICENSE). Use it, modify it, and ship it with your panel tooling.

This repository is an independent implementation, first published by OpenIaaS
in **August 2026**. A 2025 MIT release
([omryatia/directadmin-mcp](https://github.com/omryatia/directadmin-mcp))
supplied the original layout — entrypoints and module names. That starting
point is preserved as a derivative-work notice in [LICENSE](LICENSE). As of
20 August 2026 it is a small fraction of the tree: about one in twenty of
the original unique code lines still appear verbatim; the Python sources are
roughly three and a half times larger, and the domain tools (SSL, CSF, policy,
audit) are new.

With thanks to the DirectAdmin community — the documentation, the forum, and
the operators who have been running these boxes for **23+ years**.
