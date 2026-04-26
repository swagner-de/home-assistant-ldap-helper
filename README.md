# home-assistant-ldap-helper

[![CI](https://github.com/swagner-de/home-assistant-ldap-helper/actions/workflows/ci.yml/badge.svg)](https://github.com/swagner-de/home-assistant-ldap-helper/actions/workflows/ci.yml)
[![Docker](https://github.com/swagner-de/home-assistant-ldap-helper/actions/workflows/build.yml/badge.svg)](https://github.com/swagner-de/home-assistant-ldap-helper/actions/workflows/build.yml)

A lightweight Flask server that authenticates users against LDAP and returns group membership, designed to work as a sidecar for [Home Assistant's command-line auth provider](https://www.home-assistant.io/docs/authentication/providers/#command-line).

It supports two endpoints — one with HTTP Basic Auth headers and one with JSON POST — and maps users to `system-admin` or `system-users` groups based on configurable LDAP filters. Output is compatible with Home Assistant's `meta: true` format.

Based on yumenohikari's [gist](https://gist.github.com/yumenohikari/8440144023cf33ab3ef0d68084a1b42f), rewritten to run as a standalone sidecar container instead of requiring modifications to the Home Assistant image.

## Configuration

All options can be passed as CLI flags or as environment variables with the `HA_LDAP_` prefix.

| Environment Variable | CLI Flag | Required | Description |
|---|---|---|---|
| `HA_LDAP_HOST` | `--host` / `-h` | Yes | LDAP server hostname |
| `HA_LDAP_BIND_DN` | `--bind-dn` | Yes | DN for the initial bind (used to search for users) |
| `HA_LDAP_BIND_DN_PASSWORD` | `--bind-dn-password` | Yes | Password for the bind DN |
| `HA_LDAP_BASE_DN` | `--base-dn` | Yes | Base DN for user lookups |
| `HA_LDAP_ADMIN_FILTER` | `--admin-filter` | Yes | LDAP filter identifying admin users (returns group `system-admin`) |
| `HA_LDAP_USER_FILTER` | `--user-filter` | Yes | LDAP filter identifying regular users (returns group `system-users`) |
| `HA_LDAP_SSL` | `--ssl` | No | Enable SSL for the LDAP connection |
| `HA_LDAP_LOG_LEVEL` | `--log-level` | No | Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). Default: `INFO` |

LDAP filters must contain `{username}` as a placeholder. The admin filter is checked first — if the user matches, they are assigned `system-admin` and the user filter is skipped.

## Endpoints

### `GET /auth-header`

Authenticates via HTTP Basic Auth header. Returns a `200` with key-value pairs on success, `401` if no credentials are provided, or `403` if authentication fails.

```bash
curl -u "myuser:mypassword" http://localhost:5000/auth-header
```

```
name = My User
group = system-admin
local_only = false
```

### `POST /json-auth`

Authenticates via JSON body. Returns a `200` with JSON on success, `400` for bad requests, or `403` if authentication fails.

```bash
curl -X POST http://localhost:5000/json-auth \
  -H "Content-Type: application/json" \
  -d '{"username": "myuser", "password": "mypassword"}'
```

```json
{"message": "login succeeded", "data": {"name": "My User", "group": "system-admin", "local_only": "false"}}
```

## Deployment

### Docker

```bash
docker run --rm \
  -e HA_LDAP_HOST=ldap.example.com \
  -e HA_LDAP_BIND_DN="cn=service,ou=users,dc=example,dc=com" \
  -e HA_LDAP_BIND_DN_PASSWORD="secret" \
  -e HA_LDAP_BASE_DN="dc=example,dc=com" \
  -e HA_LDAP_ADMIN_FILTER="(&(objectClass=person)(cn={username})(memberOf=cn=admins,ou=groups,dc=example,dc=com))" \
  -e HA_LDAP_USER_FILTER="(&(objectClass=person)(cn={username})(memberOf=cn=users,ou=groups,dc=example,dc=com))" \
  -e HA_LDAP_SSL=true \
  ghcr.io/swagner-de/home-assistant-ldap-helper:latest \
  run-server --listen-address 0.0.0.0 --port 5000
```

### Kubernetes sidecar (with Home Assistant Helm chart)

This example uses [gabe565's Home Assistant chart](https://github.com/gabe565/charts/blob/main/charts/home-assistant/) and shares a unix socket via an emptyDir volume:

```yaml
persistence:
  ldap-auth-helper:
    enabled: true
    type: emptyDir
    mountPath: /var/run/ldap-auth-helper/

sidecars:
  ldap-auth-helper:
    name: ldap-auth-helper
    enabled: true
    image: ghcr.io/swagner-de/home-assistant-ldap-helper:latest
    envFrom:
    - secretRef:
        name: home-assistant-ldap-auth
    args:
    - run-server
    - --unix-socket
    - /var/run/ldap-auth-helper/ldap-helper.sock
    volumeMounts:
    - name: ldap-auth-helper
      mountPath: /var/run/ldap-auth-helper
```

Create the secret with your LDAP configuration:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: home-assistant-ldap-auth
stringData:
  HA_LDAP_HOST: "ldap.example.com"
  HA_LDAP_BIND_DN: "cn=service,ou=users,dc=example,dc=com"
  HA_LDAP_BIND_DN_PASSWORD: "secret"
  HA_LDAP_BASE_DN: "dc=example,dc=com"
  HA_LDAP_ADMIN_FILTER: "(&(objectClass=person)(cn={username})(memberOf=cn=admins,ou=groups,dc=example,dc=com))"
  HA_LDAP_USER_FILTER: "(&(objectClass=person)(cn={username})(memberOf=cn=users,ou=groups,dc=example,dc=com))"
  HA_LDAP_SSL: "true"
```

### Home Assistant configuration

Configure the command-line auth provider in `configuration.yaml` to call the sidecar via the unix socket:

```yaml
homeassistant:
  auth_providers:
  - type: command_line
    meta: true
    command: /bin/bash
    args:
    - -c
    - |
      AUTH=$(python3 -c "import os,base64;print(base64.b64encode(f'{os.environ[\"username\"]}:{os.environ[\"password\"]}'.encode()).decode())")
      curl -sf -H "Authorization: Basic $AUTH" --unix-socket /var/run/ldap-auth-helper/ldap-helper.sock http://localhost/auth-header
```

## CLI commands

Besides `run-server`, two additional commands are available for debugging:

```bash
# Search for a user
python ldap-helper.py --host ldap.example.com --bind-dn "..." --bind-dn-password "..." \
  --base-dn "..." --admin-filter "..." --user-filter "..." \
  search --user myuser

# Authenticate a user
python ldap-helper.py --host ldap.example.com --bind-dn "..." --bind-dn-password "..." \
  --base-dn "..." --admin-filter "..." --user-filter "..." \
  auth --user myuser --password mypassword
```

## Development

```bash
# Set up a virtual environment
pyenv virtualenv 3.12.7 home-assistant-ldap-helper
pyenv local home-assistant-ldap-helper

# Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Run tests
pytest tests/ -v

# Lint
ruff check .
```

## License

[GPL-3.0](LICENSE)
