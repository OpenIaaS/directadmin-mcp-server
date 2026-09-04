"""Regression tests: write-shaped tools must be gated for readonly/helpdesk.

The 2.6.0 mutation classifier only looked for substring hints in the tool
name, so write tools like dns_record_add / imapsync_import / git_deploy /
session_login_as slipped past profile checks: a readonly token could add DNS
records, create cron jobs, or mint one-shot admin login URLs.
"""

from security import capability_denied, capability_for, confirm_or_reject
from tokens import profile_denied

# Tools that mutate panel state but carry no ENABLE_* flag and no old hint.
WRITE_SHAPED = (
    "dns_record_add",
    "ips_add",
    "cron_create",
    "domains_create",
    "subdomains_create",
    "db_create",
    "db_repair",
    "db_optimize",
    "ftp_create",
    "redirects_create",
    "email_vacation_set",
    "imapsync_import",
    "imapsync_export",
    "imapsync_cancel",
    "git_deploy",
    "git_fetch",
    "git_webhook",
    "clamav_scan",
    "redis_enable",
    "mfa_enable",
    "profile_settings_update",
    "modsecurity_global_update",
    "session_switch_domain",
    "session_login_as",
    "services_watchdog",
    "domains_set_php",
    "nginx_set_template",
    "packages_user_save",
    "bfm_skip_ip",
    "wp_install",
    "wp_install_quick",
    "ssl_install_self_signed",
    "ssl_server_enable",
    "ssl_create_csr",
    "ssl_set_domain_acme_config",
    "email_pop_modify",
    "fm_mkdir",
    "fm_move",
    "fm_chmod",
    "maintenance_fix",
    "backups_admin_now",
    "login_url_one_shot",
    "phpmyadmin_sso",
)

# Reads that contain write-looking fragments and must stay open.
READ_SHAPED = (
    "cb_updates",
    "system_packages_updates",
    "system_packages_update_test",
    "cpanel_import_tasks",
    "maintenance_check",
    "db_check",
    "db_server_config_test",
    "mfa_generate_secret",
    "session_login_as_return",
    "session_login_as_users",
    "cb_removals",
    "users_list",
    "ssl_get_cert_files",
    "fm_list",
    "email_vacation_get",
    "profile_settings",
    "login_keys_history",
)

# POST-shaped tools that must stay readonly-gated even though they "just check":
# the panel dials out (or burns resources) when they run.
POST_BUT_GATED = (
    "cpanel_import_check_remote",
)


def test_write_shaped_tools_require_confirm():
    for name in WRITE_SHAPED:
        blocked = confirm_or_reject(name, confirm=False)
        assert blocked is not None and blocked.get("needs_confirm") is True, name
        assert confirm_or_reject(name, confirm=True) is None, name


def test_read_shaped_tools_need_no_confirm():
    for name in READ_SHAPED:
        assert confirm_or_reject(name, confirm=False) is None, name


def test_post_but_gated_tools_are_confirm_gated():
    for name in POST_BUT_GATED:
        assert confirm_or_reject(name, confirm=False) is not None, name
        assert profile_denied(name, "readonly") is not None, name


def test_readonly_profile_cannot_call_write_shaped_tools():
    for name in WRITE_SHAPED:
        if capability_for(name):  # flag-gated first, profile check still denies
            continue
        denied = profile_denied_readonly(name)
        assert denied is not None and denied["denied_by"].startswith("profile:"), name


def profile_denied_readonly(name):
    return profile_denied(name, "readonly")


def test_helpdesk_profile_stays_ssl_and_unblock_only():
    for name in (
        "dns_record_add",
        "cron_create",
        "domains_create",
        "db_create",
        "imapsync_import",
        "git_deploy",
        "session_login_as",
        "login_url_one_shot",
        "phpmyadmin_sso",
        "packages_user_save",
        "profile_settings_update",
    ):
        denied = profile_denied(name, "helpdesk")
        assert denied is not None and "helpdesk" in denied["denied_by"], name


def test_helpdesk_still_allowed_the_documented_writes():
    for name in (
        "ssl_reissue_domain",
        "ssl_admin_reissue",
        "ssl_set_domain_acme_config",
        "ssl_create_csr",
        "csf_unblock_ip",
        "csf_allow_ip",
        "bfm_unblock_ip",
        "firewall_unblock_everywhere",
    ):
        assert profile_denied(name, "helpdesk") is None, name


def test_operator_profile_keeps_write_shaped_tools():
    from config import settings

    previous = settings.REQUIRE_CONFIRM
    settings.REQUIRE_CONFIRM = False  # confirm is a separate gate
    try:
        for name in ("dns_record_add", "db_create", "git_deploy", "cron_create"):
            assert profile_denied(name, "operator") is None, name
        assert profile_denied("users_delete", "operator") is not None
        assert profile_denied("da_execute", "operator") is not None
        assert profile_denied("csf_disable", "operator") is not None
    finally:
        settings.REQUIRE_CONFIRM = previous


def test_one_shot_login_url_is_account_write():
    assert capability_for("login_url_one_shot") == "ENABLE_ACCOUNT_WRITE"
    denied = capability_denied("login_url_one_shot")
    assert denied and denied["denied_by"] == "ENABLE_ACCOUNT_WRITE"


def test_confirm_gate_fires_from_policy_not_docstrings(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "REQUIRE_CONFIRM", True)
    # These tool bodies call guard_confirm() themselves, which was a no-op
    # before the segment fix — the wrapper gate must catch them.
    for name in ("dns_record_add", "ips_add", "git_deploy", "maintenance_fix"):
        assert confirm_or_reject(name, confirm=False) is not None, name


def test_confirm_gate_disabled_when_require_confirm_false(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "REQUIRE_CONFIRM", False)
    # Operator-level opt-out: no confirm gates at all when the flag is off.
    assert confirm_or_reject("dns_record_add", confirm=False) is None
    assert confirm_or_reject("users_delete", confirm=False) is None