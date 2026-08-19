from pydantic import SecretStr

from security import (
    capability_denied,
    capability_for,
    confirm_or_reject,
)


def test_dangerous_families_are_off_by_default():
    assert capability_for("users_delete") == "ENABLE_ACCOUNT_WRITE"
    assert capability_for("email_pop_delete") == "ENABLE_DELETE"
    assert capability_for("fm_remove") == "ENABLE_FILEMANAGER_WRITE"
    assert capability_for("cb_run") == "ENABLE_CUSTOMBUILD"
    assert capability_for("system_packages_update_run") == "ENABLE_OS_UPDATES"
    assert capability_for("plugins_install_url") == "ENABLE_PLUGIN_WRITE"
    assert capability_for("backups_restore") == "ENABLE_BACKUP_RESTORE"
    assert capability_for("services_restart") == "ENABLE_SERVICE_CONTROL"
    assert capability_for("da_config_local_patch") == "ENABLE_CONFIG_WRITE"
    assert capability_for("cl_lve_set") == "ENABLE_CLOUDLINUX"
    denied = capability_denied("users_delete")
    assert denied and denied["denied_by"] == "ENABLE_ACCOUNT_WRITE"


def test_helpdesk_tools_stay_open():
    assert capability_for("ssl_reissue_domain") is None
    assert capability_for("ssl_admin_reissue") is None
    assert capability_for("csf_unblock_ip") is None
    assert capability_for("firewall_unblock_everywhere") is None
    assert capability_for("users_list") is None
    assert capability_for("policy_status") is None
    assert capability_denied("ssl_reissue_domain") is None


def test_confirm_true_is_enough_without_token():
    assert confirm_or_reject("csf_unblock_ip", confirm=True) is None
    blocked = confirm_or_reject("csf_unblock_ip", confirm=False)
    assert blocked and blocked["needs_confirm"] is True


def test_approval_token_rejects_boolean(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "APPROVAL_TOKEN", SecretStr("operator-secret-token"))
    blocked = confirm_or_reject("csf_unblock_ip", confirm=True)
    assert blocked and blocked.get("needs_approval_token") is True
    assert confirm_or_reject("csf_unblock_ip", confirm="wrong")["success"] is False
    assert confirm_or_reject("csf_unblock_ip", confirm="operator-secret-token") is None


def test_default_flags_are_safe():
    from config import Settings

    fields = Settings.model_fields
    for name in (
        "ENABLE_DELETE",
        "ENABLE_ACCOUNT_WRITE",
        "ENABLE_FILEMANAGER_WRITE",
        "ENABLE_CUSTOMBUILD",
        "ENABLE_OS_UPDATES",
        "ENABLE_PLUGIN_WRITE",
        "ENABLE_BACKUP_RESTORE",
        "ENABLE_SERVICE_CONTROL",
        "ENABLE_CONFIG_WRITE",
        "ENABLE_DA_WRITE",
        "ENABLE_CLOUDLINUX",
        "ENABLE_EXECUTE",
        "ENABLE_CSF_DISABLE",
    ):
        assert fields[name].default is False, name
    assert fields["ENABLE_CSF"].default is True
    assert fields["REQUIRE_CONFIRM"].default is True
