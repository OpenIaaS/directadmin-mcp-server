# Secrets on the hops host

Do **not** put the DirectAdmin login key or MCP tokens in git or in a shared `.env`
on disk if you can avoid it. Lab `.env` is fine. Production uses files.

## Docker Compose

```
mkdir -p secrets
umask 077
# login key from the panel — one line, no quotes
printf '%s' "$DA_LOGIN_KEY" > secrets/da_login_key
chmod 600 secrets/da_login_key
```

`docker-compose.yml` mounts that as `DA_LOGIN_KEY_FILE=/run/secrets/da_login_key`.
The process reads the file at startup; the value never needs to sit in `.env`.

## systemd LoadCredential

```
# /etc/systemd/system/directadmin-mcp.service.d/override.conf
[Service]
LoadCredential=da_login_key:/etc/directadmin-mcp/da_login_key
Environment=DA_LOGIN_KEY_FILE=%d/da_login_key
```

Same pattern: `MCP_AUTH_TOKEN_FILE`, `APPROVAL_TOKEN_FILE`.

## Named tokens

Generate a token and its hash (store the hash in `tokens-*.json`, give the
raw token to the agent only):

```
python tokens.py
```

Prints the raw secret and `sha256:…`. Put the hash in `tokens-write.json`
or `tokens-readonly.json`. Never commit the raw secret.
