# Contributing

1. Open an issue first for large changes (new transports, new auth schemes).
2. Keep secrets out of tests, fixtures, and docs. Use `.env.sample` only.
3. Every mutating tool must call `guard_confirm`.
4. Validate IPs / usernames / domains with `security.py` — do not interpolate
   raw strings into paths.
5. `pytest -q` and `ruff check .` must pass.
6. When DirectAdmin ships new swagger paths, refresh `tools/api_spec.json`
   from `/static/swagger.json` on a current panel (or the public demo).
