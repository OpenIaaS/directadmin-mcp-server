# Independent security audit — directadmin-mcp-server v2.7.0

- **Auditor:** kimi-k3 (second opinion, READ-ONLY) · **Range:** `6facf7b..795c783`. Tests verified: **119 passed**.
- **Method:** full read of `security.py`, `tokens.py`, `main.py`, `config.py`, `da.py`, `idempotency.py`, `alerts.py`, `tools/audit.py`, `tools/common.py`, `tools/catalog.py` + AST scans of all 30 tool modules. No live panel (same sandbox limit as first audit).

## Section A — Verdicts on the 6 fix commits

| Commit | Verdict | Evidence |
|---|---|---|
| `700b2ea` policy gating | **PARTLY** | Segment classifier sound (security.py:483-497); my run confirms 138/303 confirm-classified. But confirm is enforced per-tool via `guard_confirm` (tools/common.py:133), not centrally — 7 confirm-classified tools never call it (K-01–K-03), incl. 3 of its own `_ALWAYS_CONFIRM` members (security.py:385-393). Tests assert only the policy function, never a real tool call (tests/test_policy_bypass.py:170-177). Message says "41 tools"; the report itself measures 51 (AUDIT_REPORT.md:35). |
| `fed6d97` injection | **AGREE** | Validators cover every `call_da_api` f-string interpolation (per-variable AST scan, zero misses); `_fill_path` percent-encodes after the traversal check (tools/catalog.py:44-50); `da_legacy` rejects `..` (tools/catalog.py:208-209); `call_plugin` retries GET only (da.py:262-267). Residue at tools/email.py:160 (K-07). |
| `30f3229` token hot-reload | **AGREE** | `(path, mtime_ns, size)` fingerprint reload correct (tokens.py:111-146); stat→open TOCTOU is benign and self-heals next request. Legacy-token restart disclosed as O-02. |
| `9cc2d72` redaction | **AGREE** | All three secrets share `str.replace` redaction (config.py:200-209); file tokens exist only as sha256 (tokens.py:70-80) so cannot leak. |
| `bcbb806` DoS bounds | **AGREE** | Cap 10k oldest-first (idempotency.py:36-40); semaphore 8 + drop (alerts.py:19, 55-58); 1 MB tail-read (tools/audit.py:38-43). O-05 race disclosed. |
| `4975473` dep floors | **AGREE (numbers unverified)** | Floors raised in both files, install-safe. Advisory mapping unverifiable here too (web search down) — keep O-01 open. httpx redirect-credential fix moot anyway: `follow_redirects=False` (da.py:97, 171-176). |

## Section B — New findings (missed or mis-claimed by the first audit)

| ID | Severity | File:line | Problem | Fix |
|---|---|---|---|---|
| K-01 | HIGH | tools/search.py:41-49 (+ security.py:391) | `cpanel_import_check_remote` = panel-side request forgery (arbitrary host + creds in `payload`, never validated) and, despite `_ALWAYS_CONFIRM`, has **no `guard_confirm`** and no capability flag → operator/break-glass tokens run it with no confirm. | Add `guard_confirm`; validate payload host/scheme. |
| K-02 | HIGH | tools/login_keys.py:143-149, tools/search.py:52-65 | `login_url_one_shot` and `phpmyadmin_sso` mint credential-equivalents (one-shot panel URL / DB SSO) with no in-body confirm despite `_ALWAYS_CONFIRM` (security.py:388-390). The first is flag-gated by default (F-02 only half-fixed), the second by profile alone. AUDIT_REPORT F-02 says "needed no confirm … FIXED" — the confirm half persists. | Call `guard_confirm` in both bodies. |
| K-03 | MEDIUM | tools/sessions.py:165-171, :50-61; tools/ssl_certs.py:303-322; tools/git_deploy.py:55-62 | Same gap, lower blast radius: `profile_settings_update` (arbitrary panel-profile PATCH), `session_switch_domain` (rewrites shared-session context), `ssl_create_csr`, `git_fetch` — confirm-classified, no enforcement (my scan: 138 gated, exactly these 7 unguarded). | Enforce `confirm_or_reject` centrally in `log_tool_call` via `needs_confirm(name)`; add a registry coverage test. |
| K-04 | MEDIUM | tools/common.py:88-96 → idempotency.py:21-25 | Idempotency fingerprint is computed over **redacted** args: distinct `users_change_password` calls with the same key produce identical digests → the second call replays cached "success" and the password change is silently skipped (idempotency.py:64-73). Pre-existing. | Fingerprint raw args (hash `bound.arguments` before `redact`). |
| K-05 | MEDIUM | security.py:682-683 | Window gate keys on `capability_for` only, so every confirm-only write tool expanded by 700b2ea (`dns_record_add`, `db_create`, `cron_create`, …) mutates freely outside the window while the denial message claims coverage of "a mutating action". | Gate on `capability_for(name) or needs_confirm(name)`. |
| K-06 | LOW (unverified) | tools/catalog.py:210-218 | `da_legacy` needs neither `ENABLE_DA_WRITE` nor confirm for **GET**; legacy `CMD_API_*` historically act on GET (panel-dependent, unverified in sandbox). | Require `ENABLE_DA_WRITE` + confirm for all `da_legacy` calls, or a read-only CMD allowlist. |
| K-07 | LOW (unverified) | tools/email.py:160 | `imapsync_cancel`'s inline regex `[A-Za-z0-9._-]{1,80}` admits literal `..` → normalizes to a collection DELETE on `/api/imapsync/migrations`; live-panel impact unverified. | Use `validate_path_segment` (security.py:204). |
| K-08 | LOW | security.py:25-28 | `_SENSITIVE_KEY` is suffix-anchored: a future param named `password_hash`/`token_id` would log cleartext in the audit trail. Verified: no such param exists at v2.7.0 (AST scan). | Match the sensitive word anywhere in the key. |

## Section C — Overall verdict

v2.7.0 is materially safer than v2.6.0: the six diffs do what they claim, tests pass, defaults stay fail-closed, and O-01–O-05 are honestly disclosed. Safe to run **with readonly/helpdesk tokens** — the auth/CIDR/profile/reason chain holds (main.py:64-111, tools/common.py:60-82); withhold operator/break-glass tokens until K-01–K-03 land. Top residual risk: **confirm enforcement is per-tool opt-in, not centralized — 7 confirm-classified mutators (phpmyadmin_sso, cpanel_import_check_remote, login_url_one_shot above all) run with no confirm/approval for operator+ tokens**; move it into `log_tool_call`.
