# home-assistant-ldap-helper
A simple flask server that can listen on a unix socket or ip/port and forwards username/password to ldap. It will return a HTTP 403 if the authentication failed and a 200 if the authentication succeeded.

This script is based on yumenohikari's [gist](https://gist.github.com/yumenohikari/8440144023cf33ab3ef0d68084a1b42f) solving the same problem. However I didn't like the startup dependency to pip or having to build my own Home Assistant Image which had `ldap3` installed, that is why I decided to run it in a sidecar, so I only have to rebuild the sidecars image once it a while.

it complies with the meta: true arguments on Home Assistants [docs](https://www.home-assistant.io/docs/authentication/providers/#command-line) and can return a user group.

All options are documented, the main subcommand is `run-server`. All option can be supplied as environment variables using the prefix `HA_LDAP`:
```Usage: ldap-helper.py [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --host TEXT                 LDAP server to connect  [required]
  --bind-dn TEXT                  DN used to make the initial bind and search
                                  for the to be authenticated user  [required]
  --bind-dn-password TEXT         Password for the bind dn user  [required]
  --base-dn TEXT                  Base DN to use when looking up users
                                  [required]
  --ldap-filter TEXT              Filter for LDAP search to identify the right
                                  group membership  [required]
  --ssl                           Use SSL connection
  --log-level [DEBUG|INFO|WARNING|ERROR|CRITICAL]
                                  Log level
  --help                          Show this message and exit.

Commands:
  auth
  run-server
  search
```

## Run it
I run it as a sidecar next to home assistant and share the socket as an empty dir. I use [gabe565's Home Assistant Chart](https://github.com/gabe565/charts/blob/main/charts/home-assistant/) with the following additions:

values.yaml
```
persistence:
  ldap-auth-helper:
    enabled: true
    type: emptyDir
    mountPath: /var/run/ldap-auth-helper/

sidecars:
  ldap-auth-helper:
    name: ldap-auth-helper
    enabled: true
    image: ghcr.io/swagner-de/home-assistant-ldap-helper:v0.2.0
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

secrets:
  ldap-auth:
    enabled: true
    stringData:
      HA_LDAP_HOST: "ldap.mydomain.com"
      HA_LDAP_BIND_DN: "cn=ldapservice,ou=users,dc=ldap,dc=goauthentik,dc=io"
      HA_LDAP_BIND_DN_PASSWORD: "supersecure"
      HA_LDAP_BASE_DN: "DC=ldap,DC=goauthentik,DC=io"
      HA_LDAP_ADMIN_FILTER: "(&(objectClass=person)(cn={username})(memberOf=cn=homeassistantAdmins,ou=groups,dc=ldap,dc=goauthentik,dc=io))"
      HA_LDAP_USER_FILTER: "(&(objectClass=person)(cn={username})(memberOf=cn=homeassistantUsers,ou=groups,dc=ldap,dc=goauthentik,dc=io))"
      HA_LDAP_SSL: "true"
```

### Home Assistant Config:
configuration.yaml
```
homeassistant:
  auth_providers:
  - type: command_line
    meta: true
    command: /bin/sh
    args:
    - -c
    - |
      curl -X GET --fail-with-body --unix-socket /var/run/ldap-auth-helper/ldap-helper.sock -u $username:$password http://dummy/ldap-auth
```