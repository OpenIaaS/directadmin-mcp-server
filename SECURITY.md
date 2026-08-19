# Security policy

This server holds a DirectAdmin **admin** login key. Treat it like root.

## Report a vulnerability

Open a **private** security advisory on the GitHub repository. Do not file a
public issue that includes a working exploit against a live panel.

## Hardening checklist

See [docs/hardening.md](docs/hardening.md) for the full guide. Short version:

1. **Never use the main admin password.** Create a [login key](https://docs.directadmin.com/developer/api/)
   restricted to:
   - the MCP host IP
   - only the commands you need (`CMD_API_*` + plugin `csf` if you use CSF)
   - a short expiry if the deployment is temporary
2. **Set `MCP_AUTH_TOKEN`** to a 48-byte urlsafe secret (≥ 24 characters).
   HTTP / SSE mode refuses to start usefully without it (unless
   `MCP_ALLOW_ANONYMOUS=true`, which is lab-only). Send it as
   `Authorization: Bearer …` — **never** as `?token=`.
3. Bind HTTP to `127.0.0.1` and put TLS in front (Caddy, nginx, Traefik). The
   Docker Compose file already publishes only on loopback.
4. Keep `DA_SSL_VERIFY=true`. `DA_ALLOW_INSECURE_HTTP` is for labs.
5. Leave `REQUIRE_CONFIRM=true`. Prefer `APPROVAL_TOKEN` so `confirm=true`
   is not enough — a rogue model will set that boolean on its own.
6. Leave the blast-radius flags **off** (`ENABLE_DELETE`,
   `ENABLE_ACCOUNT_WRITE`, `ENABLE_FILEMANAGER_WRITE`, `ENABLE_CUSTOMBUILD`,
   `ENABLE_OS_UPDATES`, `ENABLE_PLUGIN_WRITE`, `ENABLE_BACKUP_RESTORE`,
   `ENABLE_SERVICE_CONTROL`, `ENABLE_CONFIG_WRITE`, `ENABLE_DA_WRITE`).
   SSL reissue and CSF unblock stay available.
7. Leave `ENABLE_EXECUTE=false`. `/api/execute` is a shell-shaped foot-gun.
8. Leave `ENABLE_CSF_DISABLE=false`. Unlock a customer with
   `firewall_unblock_everywhere`, do not turn CSF off.
9. Use `TOOL_ALLOWLIST` in production if the assistant only needs SSL + CSF:
   ```
   TOOL_ALLOWLIST=ssl_,csf_,bfm_,firewall_,da_ping,da_list,da_describe,session_get
   ```
10. Set `MCP_ALLOWED_CIDRS` to the assistant / jump-host network.
11. Rotate the login key and `MCP_AUTH_TOKEN` after any suspected leak.
12. Read `logs/audit.jsonl`. Secrets are redacted; the file still tells you
    *which* tool ran, from where. Call `policy_status` to see live flags.

## What this server will not do

- Embed credentials in `DA_URL`
- Follow redirects from DirectAdmin (those are almost always a login failure)
- Accept `0.0.0.0/0` as a CSF target
- Log login keys, passwords, private keys, or bearer tokens
- Bind `0.0.0.0` without `MCP_AUTH_TOKEN`
- Disable CSF unless you flip two explicit flags
- Authenticate a token from a query string
- Return DirectAdmin exception strings on public `/ready`

## Supply chain

Pin your own hashes in production if your policy requires it. CI runs
`ruff` + `pytest` on 3.10 and 3.12 with SHA-pinned Actions.
The Docker image runs as UID 10001, `cap_drop: ALL`, `no-new-privileges`,
read-only root filesystem.
