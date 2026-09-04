# Security audit report — directadmin-mcp-server

- **Date:** 2026-09-04
- **Auditor:** glm-5.3-flash via DeepSeek Harness (orchestrated)
- **Baseline audited:** `6facf7b` (public `OpenIaaS/directadmin-mcp-server`, branch `master`)
- **Result:** 12 findings fixed across 6 security/fix commits + 1 docs commit; 5 residual items open (2 Low, 3 Info). No Critical findings.

## Scope and methodology

Static security review of the whole tree at `6facf7b`, followed by fixes and
regression tests. Areas reviewed:

- `security.py` — destructive/confirm classification, `ENABLE_*` capability
  mapping, profile denial, reason/backup/maintenance-window gates, validators,
  audit writing, log redaction.
- `tokens.py` — hashed token store, profile resolution, `helpdesk_write`.
- `config.py` — settings, `_RedactingFormatter`.
- `da.py` and `tools/catalog.py` — HTTP assembly (`_fill_path`, `da_api`,
  `da_legacy`), plugin call retries, error paths.
- Curated tool modules under `tools/` (14 modules re-touched for input
  validation), `idempotency.py`, `alerts.py`, `tools/audit.py`.
- `pyproject.toml` / `requirements.txt` dependency floors.
- Documentation integrity: `docs/tools.json` cross-checked against the live
  registry (AST scan of `@mcp.tool()`-decorated functions).

Verification method: manual code reading, AST cross-checks of the registered
tool catalog, and 56 new regression tests (63 → 119 passing). **No live
DirectAdmin panel was available in the sandbox**, so fixes are verified
against code and unit tests, not against a live panel.

## Findings (fixed)

| ID | Severity | Area | Description | Status |
| --- | --- | --- | --- | --- |
| F-01 | High | Policy bypass | `needs_confirm()` matched only substring hints in tool names, so write verbs buried mid-name (`dns_record_add`, `ssl_set_*`, `imapsync_import`, `git_deploy`, `clamav_scan`, …) executed without `confirm=true` and were counted as reads by profile checks — a readonly token could mutate DNS, cron, databases, domains, FTP, ModSecurity. Verified count: 51 tool names present at the baseline became confirm-gated by the new whole-segment classifier (the commit message says 41; the measured number is 51 — this report corrects it). 303 tools are now confirm-classified in total (75 at baseline). | FIXED in 700b2ea |
| F-02 | High | Policy bypass | `login_url_one_shot` mints a one-shot admin login URL (credential-equivalent) but was mapped to no capability and needed no confirm; a readonly/helpdesk token could mint it. | FIXED in 700b2ea |
| F-03 | High | Injection | Curated tools interpolated identifiers (`cert_id`, `key_id`, `message_id`, session `public_id`, `plugin_id`, WP/Git UUIDs, db names, subdomain labels, …) into f-string API paths with no validation. A value like `../../api/system-packages/update-run` is dot-segment normalized by the HTTP stack into a request against a different endpoint, bypassing `ENABLE_DA_WRITE` and per-family flags; `?`, `#`, `&` in a parameter could split or retarget the URL. New `validate_path_segment` / `validate_label` validators applied in `tools/catalog.py` + 14 curated tool modules; `da_api` path parameters are percent-encoded after the existing traversal check; `da_legacy` rejects dot-segments in `CMD_*` commands. | FIXED in fed6d97 |
| F-04 | Medium | Integrity | `call_plugin` re-sent a failed plugin request as raw text on `DirectAdminError`. For a mutating POST the first attempt may already have been applied → double application. Now only GETs are retried. | FIXED in fed6d97 |
| F-05 | Medium | Injection | `da_legacy` accepted dot-segments inside `CMD_*` names (path traversal into arbitrary legacy endpoints). | FIXED in fed6d97 |
| F-06 | Medium | Secret ops | `MCP_TOKENS_FILE` was cached forever, so revoking a token (editing the file) required a process restart; a burned token stayed valid until an operator restarted the service. Now the file is fingerprinted by `(path, mtime_ns, size)` and hot-reloaded on change. Legacy `MCP_AUTH_TOKEN` still needs a restart (no file to watch) — see O-02. | FIXED in 30f3229 |
| F-07 | Medium | Logging | `_RedactingFormatter` redacted only `DA_LOGIN_KEY` and `MCP_AUTH_TOKEN`; `APPROVAL_TOKEN` (which gates `confirm=`) could appear in log lines. All three are now redacted. | FIXED in 9cc2d72 |
| F-08 | Medium | DoS | The idempotency cache grew without bound when a client spammed unique `Idempotency-Key` headers; TTL purge did not bound size. Now hard-capped at 10,000 entries, oldest evicted first. Residual eviction race: see O-05. | FIXED in bcbb806 |
| F-09 | Low | DoS | `alerts.fire_alert` spawned one unbounded daemon thread per audit event; a failing webhook in a loop thread-bombed the process. Now a `BoundedSemaphore(8)` caps concurrent webhooks; events are dropped (with a warning log) when saturated. | FIXED in bcbb806 |
| F-10 | Low | DoS | `audit_search` slurped the whole audit log (rotates at 20 MB) into memory per query. Now binary tail-read of the last 1 MB with the cut partial line dropped. | FIXED in bcbb806 |
| F-11 | Medium | Dependencies | `pyproject.toml`/`requirements.txt` floors allowed dependency versions predating the 2024 multipart-parsing and redirect-credential fixes: `fastapi>=0.110.0`, `starlette>=0.36.0`, `httpx>=0.27.0`, `python-multipart>=0.0.9`. Floors raised to `fastapi>=0.115.0`, `starlette>=0.40.0`, `httpx>=0.28.0`, `python-multipart>=0.0.18`. The venv already resolves newer versions, so the change is install-safe. Caveat: the exact fixed versions were chosen from model knowledge without re-verifying the advisory numbers — see O-01. | FIXED in 4975473 |
| F-12 | Low | Docs integrity | `docs/tools.json` had drifted from the registered tool catalog — a **pre-existing** condition at the baseline: code registers 303 curated tools, the doc listed 276 (27 undocumented tools, 12 of them write-shaped), and the README claimed 273. Resynced the doc to the registry, marked the `destructive` flag on every row consistently with `needs_confirm()`, and added regression tests (`test_tools_json_in_sync_with_registry`, `test_destructive_flags_match_policy`) so drift now fails CI. | FIXED in fe584ae |

Severity counts: **0 Critical, 3 High, 6 Medium, 3 Low** fixed; plus open
items below.

## Open findings (not fixed)

| ID | Severity | Area | Description | Recommendation |
| --- | --- | --- | --- | --- |
| O-01 | Low | Dependencies | The specific advisory/fixed versions behind the F-11 floors were not re-verified against GHSA/CVE advisories (web search unavailable during the audit). The floors are directionally correct and install-safe, but the pinned numbers are from model knowledge. | Confirm each floor against the upstream advisories before citing them in an incident report. |
| O-02 | Low | Secret ops | Legacy `MCP_AUTH_TOKEN` rotation still requires a process restart — there is no file to hot-reload (by design of the hot-reload fix). | Prefer `MCP_TOKENS_FILE` for all deployments, or extend hot-reload to the legacy token via a watched file. |
| O-03 | Info | Availability | When 8 webhooks are in flight, `fire_alert` drops new events (logged as a warning) instead of queueing them. A long webhook outage silently loses alert volume. | Add a small bounded delivery queue with retry/backoff if alert loss matters to your ops. |
| O-04 | Info | Audit | `audit_search` now reads only the last 1 MB of the audit log; within one 20 MB rotation window, older lines are not queryable via the tool. Deliberate DoS trade-off. | Document the window, or add offset/`before`-cursor pagination over rotated files. |
| O-05 | Info | Integrity | In the idempotency cache, a reservation can be evicted (cap 10,000) between `check_idempotency` and `store_idempotency`; a replay after eviction re-executes the tool. Only reachable when a client holds >10,000 unique keys inside the 15-minute TTL. | Keep the cap but reserve by key-in-flight marker, or reject new keys when at cap instead of evicting. |

## Commits produced by this audit

```
700b2ea security(policy): gate write-shaped tools behind confirm and profiles
fed6d97 security(injection): validate path identifiers; encode da_api params; no mutating POST retry
30f3229 security(tokens): hot-reload MCP_TOKENS_FILE on mtime change
9cc2d72 security(logging): redact APPROVAL_TOKEN in log lines
bcbb806 fix(dos): bound idempotency cache, cap alert threads, tail-read the audit log
4975473 security(deps): raise floors for starlette, python-multipart, httpx, fastapi
fe584ae docs(tools): resync tools.json with the registered tool catalog
```

Regression tests added: `tests/test_policy_bypass.py`,
`tests/test_path_injection.py`, `tests/test_dos.py`, `tests/test_redaction.py`,
plus extensions to `tests/test_tokens.py` and `tests/test_catalog.py`
(63 → 119 tests).

## Verify locally

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
.venv/bin/python -m pytest -q        # expected: 119 passed
.venv/bin/python -m ruff check .     # expected: All checks passed!
```

No live DirectAdmin panel was contacted during this audit; behavioural fixes
are verified by the regression tests above.