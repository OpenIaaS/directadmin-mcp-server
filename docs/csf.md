# CSF / firewall unblock playbook

A locked-out customer is usually blocked in **two** places:

1. **CSF / LFD** (iptables) — ConfigServer plugin, not in the New JSON API
2. **DirectAdmin Brute Force Monitor** — native panel (`CMD_API_BRUTE_FORCE_MONITOR`)

Use the combined tool first:

```
firewall_unblock_everywhere  ip=203.0.113.44  confirm=true
```

That runs `csf_unblock_ip` (plugin Quick Unblock: `csf -dr` + `csf -tr` + drop
states) **and** `bfm_unblock_ip`.

## Diagnose first

```
ip_block_reason ip=203.0.113.44
csf_search_ip   ip=203.0.113.44
bfm_ip_reason   ip=203.0.113.44
bfm_list
csf_status
```

`ip_block_reason` is the one to call when someone asks **why**. It returns:

- `operator_reason` — CSF list + LFD comment and BFM service/user/log line
- `customer_message.bg` / `.en` — paste to the client (no host paths)
- empty/honest text if there is **no** recorded reason (does not invent one)

`bfm_ip_reason` is BFM only. `csf_ip_reason` is CSF/LFD only (`csf -g` comment
like `lfd: (sshd) Failed SSH login … 8 in the last 3600 secs`).

## Unblock only CSF

```
csf_unblock_ip  ip=203.0.113.44  also_allow=true  confirm=true
```

`also_allow=true` adds a 1-hour temporary allow so the next handshake is not
immediately re-banned.

## Permanent allow / ignore

```
csf_allow_ip   ip=203.0.113.44  confirm=true     # csf.allow
csf_ignore_ip  ip=203.0.113.44  confirm=true     # LFD never blocks
bfm_skip_ip    ip=203.0.113.44  confirm=true     # BFM skip list
```

## What this server will not do

- Accept `0.0.0.0/0` (or any prefix broader than `/8`)
- Disable CSF unless `ENABLE_CSF_DISABLE=true` **and** `confirm=true`
  (`csf_disable` is also on the default `TOOL_DENYLIST`)
- Interpolate raw comments into the plugin — comments are sanitised

The CSF plugin must be installed (`/CMD_PLUGINS_ADMIN/csf/`). If the plugin is
missing, tools return a clear error instead of posting to a login page.
