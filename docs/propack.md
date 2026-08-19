# Pro Pack

Modern DirectAdmin licenses **include** the old Pro Pack. The agent should
use `propack_inventory` to see the map. Web Terminal is **not** wrapped
(`/api/terminal` is blocked — it is a shell).

## What we cover

| Feature | Tool | Transport |
| --- | --- | --- |
| Admin SSL | `ssl_admin_list`, `ssl_admin_reissue` | `CMD_ADMIN_SSL` |
| Redis | `redis_status`, `redis_enable`, `redis_disable` | `/api/redis/*` |
| WordPress | `wp_*` | `/api/wordpress/*` |
| Git | `git_list`, `git_deploy`, `git_fetch`, `git_webhook` | `/api/git/*` |
| ClamAV | `clamav_*` | `/api/clamav` |
| Email Track & Trace | `email_logs*` | `/api/email-logs*` |
| IMAP sync | `imapsync_*` | `/api/imapsync/*` |
| Mail autoconfig | `email_mobileconfig` | `/api/email-config/mobileconfig` |
| CGroups metrics | `system_resource_usage_*`, `system_global_usage_*` | `/api/*resource-usage*` |
| DB Monitor | `db_processes`, `db_kill_process` | `/api/db-monitor/*` |
| security.txt | `security_txt_status` | `/api/security-txt/status` |
| System Packages | `system_packages_*` | `/api/system-packages/*` |
| Nginx Unit | `unit_list`, `unit_create`, `unit_delete` | `CMD_UNIT` |
| Nginx CMS templates | `nginx_set_template` | `CMD_API_DOMAIN` |
| Web Terminal | **blocked** | `/api/terminal` |

## Nginx Unit

```
unit_list     domain=shop.example.com  impersonate=alice
unit_create   domain=shop.example.com  name=api  impersonate=alice  confirm=true
unit_delete   domain=shop.example.com  names=["api"]  impersonate=alice  confirm=true
```

Enable on the box first: `da build set unit yes && da build unit`.
Do not open Unit ports in CSF unless TLS is configured.

## Nginx CMS template

```
nginx_set_template  domain=shop.example.com  template=wordpress  impersonate=alice  confirm=true
```

Allowed templates: `wordpress`, `wordpress_cache`, `drupal`, `joomla`,
`magento`, `laravel`, `default`, `none`.

## IMAP sync

```
imapsync_migrations
imapsync_import   payload={…}  confirm=true
imapsync_cancel   migration_id=…  confirm=true
```

Passwords in the payload are redacted in the audit log.

## Resource throttle (cgroups)

Read live usage:

```
system_resource_usage_latest
system_global_usage_latest
system_global_usage_history  user=alice
```

Setting cgroup *limits* is a package / user.conf concern (`users_get_config`).
On CloudLinux boxes use `cl_lve_set` instead — see [cloudlinux.md](cloudlinux.md).
