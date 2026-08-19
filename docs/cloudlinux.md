# CloudLinux

Some of our servers run CloudLinux. The panel integration is the **LVE Manager
/ CloudLinux Manager** plugin — not the New JSON API. These tools talk to that
plugin the same way CSF talks to ConfigServer.

They **never** spawn `lvectl` / `cagefsctl` and they **never** use
`/api/execute`. The MCP process is not root on the host.

## Enable

```
ENABLE_CLOUDLINUX=false   # default — most servers do not run CloudLinux
ENABLE_CLOUDLINUX=true    # only on the 7–8 boxes with LVE Manager
```

Default is **off**. `cl_status` still answers (reports opt-in is off) so the
agent does not guess. Every other `cl_*` tool refuses until the flag is on.

The login key must be allowed to run `CMD_PLUGINS_ADMIN`.

## Detect

```
cl_status
plugins_list
```

`cl_status` pings LVE Manager. If the plugin is missing it says so instead of
posting to a login page.

## LVE limits

```
cl_lve_users
cl_lve_get     username=alice
cl_lve_set     username=alice  speed=100%  pmem=1024  nproc=100  confirm=true
```

Limits accept a number, a percent (`100%`), or `unlimited`. Anything else is
rejected (no shell-shaped strings).

## CageFS

```
cl_cagefs_enable   username=alice  confirm=true
cl_cagefs_disable  username=alice  confirm=true
```

Disable only when you must (migration, debugging). New users should stay caged.

## PHP Selector

On CloudLinux:

```
cl_php_selector_get  username=alice
cl_php_selector_set  username=alice  version=8.3  confirm=true
```

On Alma/RHEL without CloudLinux use DirectAdmin's own selector
(`domains_set_php`). Do not mix the two.

## What we will not do

- `cagefsctl --init` / remount-all (host-wide, needs root CLI)
- MySQL Governor policy changes via shell
- AccelerateWP / X-Ray (separate CL Shared Pro products)
- Opening a web terminal to run `lvectl` by hand

For host-wide CageFS init, do it on the box as root once, then let the agent
manage per-user enable/disable through the plugin.
