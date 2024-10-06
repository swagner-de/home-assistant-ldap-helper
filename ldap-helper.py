#! /usr/bin/env python3
import base64
import logging
import os
import sys
from typing import Optional, Tuple

import click
import ldap3
from ldap3.utils.conv import escape_filter_chars
from ldap3.core.exceptions import LDAPInvalidCredentialsResult
from flask import Flask, request, Response, jsonify


app = Flask(__name__)

LOG = logging.getLogger(__name__)
formatter = logging.Formatter('%(levelname)s %(asctime)s %(message)s')
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(formatter)
LOG.addHandler(handler)

LDAP_HELPER = None

class LdapHelper:
    ADMIN_GROUP = 'system-admin'
    USER_GROUP = 'system-users'

    def __init__(self, host:str , bind_dn: str, bind_pw: str, base_dn: str,
                 admin_filter: str, user_filer: str, ssl=False):
        self.server = ldap3.Server(host, use_ssl=ssl, get_info=ldap3.NONE)
        self.host = host
        self.bind_dn = bind_dn
        self.bind_pw = bind_pw
        self.base_dn = base_dn
        self.admin_filter = admin_filter
        self.user_filter = user_filer
        con = self.connect()
        con.unbind()
    
    def connect(self) -> ldap3.Connection:
        return ldap3.Connection(self.server, self.bind_dn, self.bind_pw, auto_bind=True, raise_exceptions=True)


    def search(self, user: str) -> Tuple[Optional[dict], ldap3.Connection]:
        user = escape_filter_chars(user)
        con = self.connect()
        filter_args = dict(username=user)
        
        result = []
        user_data = dict()

        for user_group, current_filter in [(self.ADMIN_GROUP, self.admin_filter), (self.USER_GROUP, self.user_filter)]:
            con.search(self.base_dn, current_filter.format(**filter_args), attributes=['displayName', 'name'])
            result = con.entries
            if len(result) > 0:
                if len(result) > 1:
                    LOG.debug('Found more than one entry for filter %s' % (self.current_filter.format(**filter_args)))
                    LOG.info(('Found more than one entry for filter args %s' % (filter_args)))
                    return None, con
                LOG.debug('Found user %s: %s' % (user, user_data))
                result = result[0]

                user_data['dn'] = result.entry_dn
                if result.displayName.value:
                    user_data['name'] = result.displayName.value
                elif result.name.value: 
                    user_data['name'] = result.name.value
                else:
                    user_data['name'] = user
                user_data['group'] = user_group
                user_data['local_only'] = "false"

                return user_data, con
        if len(result) == 0:
            LOG.info(('No result found for filter args %s' % (filter_args)))
            return None, con

    def auth(self, con, user_dn, password):
        try:
            con.rebind(user=user_dn, password=escape_filter_chars(password))
            LOG.debug("Username %s with supplied password is valid" % (user_dn))
            return True
        except LDAPInvalidCredentialsResult:
            LOG.warning("Username %s credentials were incorrect" % (user_dn))
            return False


@app.route('/json-auth', methods=['POST'])
def json_auth():
    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"message": "Bad request"}), 400

    username = data['username']
    password = data['password']

    if not username or not password:
        return jsonify({"message": "user and password must be provided"}), 400

    helper: LdapHelper = LDAP_HELPER
    user_data, con = helper.search(username)
    if not user_data:
        con.unbind()
        return jsonify({"message": "invalid credential"}), 403

    dn = user_data.pop('dn')
    if not helper.auth(con, dn, password):
        return jsonify({"message": "invalid credential"}), 403
    else:
        return jsonify({"message": "login succeeded", "data": user_data}), 200


@app.route('/auth-header', methods=['GET'])
def auth_header():
    
    auth = request.headers.get('Authorization')

    if not auth or not auth.startswith('Basic '):
        return Response(
                'Could not verify your login!\n',
                401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'}
            )
    
    try:
        base64_credentials = auth.split(' ')[1]
        decoded_credentials = base64.b64decode(base64_credentials).decode('utf-8')
        username, password = decoded_credentials.split(':')
        if not username or not password:
            return Response('Username or password may not be empty\n', status=400)
    except Exception as e:
        return Response('Invalid request format\n', status=400)
    
    helper: LdapHelper = LDAP_HELPER
    user_data, con = helper.search(username)
    if not user_data:
        con.unbind()
        return Response('Forbidden\n', status=403)

    dn = user_data.pop('dn')
    if not helper.auth(con, dn, password):
        return Response('Forbidden\n', status=403)
    else:
        resp = '\n'.join([f'{k} = {v}' for k, v in user_data.items()])
        return Response(resp + '\n', status=200)

        
@click.group()
@click.option('--host', '-h', type=str, required=True,
              help="LDAP server to connect")
@click.option('--bind-dn', type=str, required=True,
              help='DN used to make the initial bind and search for the to be authenticated user')
@click.option('--bind-dn-password', type=str, required=True,
              help='Password for the bind dn user')
@click.option('--base-dn', type=str, required=True,
              help="Base DN to use when looking up users")
@click.option('--admin-filter', type=str, required=True,
              help="Filter for LDAP search to identify an admin user (returns 'system-admin')")
@click.option('--user-filter', type=str, required=True,
              help="Filter for LDAP search to identify an admin user (returns 'system-user')")
@click.option('--ssl', is_flag=True, default=False,
              help="Use SSL connection")
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']),
              default='INFO', help='Log level')
@click.pass_context
def group(ctx, host, bind_dn, bind_dn_password, base_dn, admin_filter, user_filter, ssl, log_level):
    LOG.setLevel(log_level)
    helper = LdapHelper(host, bind_dn, bind_dn_password, base_dn, admin_filter, user_filter, ssl)
    ctx.ensure_object(dict)
    ctx.obj.update({'helper': helper})


@group.command()
@click.option('--user', '-u', type=str, required=True,
              help='User to look up')
@click.pass_context
def search(ctx, user):
    helper: LdapHelper = ctx.obj['helper']
    _, con = _search(helper, user)
    con.unbind()

def _search(helper, user):
    user_data, con = helper.search(user)
    if user_data:
        print(f'Success finding user {user}: {user_data}')
    else:
        print(f"User {user} not found")
    return user_data['dn'], con

@group.command()
@click.option('--user', '-u', type=str, required=True,
              help='User to look up')
@click.option('--password', type=str, required=True)
@click.pass_context
def auth(ctx, user, password):
    helper: LdapHelper = ctx.obj['helper']
    dn, _, con = _search(helper, user)
    helper.auth(con, dn, password)


@group.command()
@click.option('--unix-socket', required=False,
              help="Run on a unix socket")
@click.option('--listen-address', default="127.0.0.1", help="Address to bind on")
@click.option('--port', default="5000", help="Port to bind on")
@click.pass_context
def run_server(ctx, unix_socket, listen_address, port):
    global LDAP_HELPER
    LDAP_HELPER = ctx.obj['helper']
    if unix_socket:
        if os.path.exists(unix_socket):
            os.remove(unix_socket)
        app.run(host=f'unix://{unix_socket}')
    else:
        app.run(host=listen_address, port=port)

if __name__ == "__main__":
    group(auto_envvar_prefix='HA_LDAP')