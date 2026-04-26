import base64
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, ".")


def make_mock_entry(dn="cn=testuser,ou=users,dc=example,dc=com", display_name="Test User", name="testuser"):
    entry = MagicMock()
    entry.entry_dn = dn
    entry.displayName.value = display_name
    entry.name.value = name
    return entry


def make_helper(admin_filter="(&(cn={username})(group=admin))", user_filter="(&(cn={username})(group=users))"):
    with patch("ldap3.Connection"):
        from importlib import import_module
        mod = import_module("ldap-helper")
        helper = mod.LdapHelper(
            host="ldap://localhost",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_pw="adminpass",
            base_dn="dc=example,dc=com",
            admin_filter=admin_filter,
            user_filter=user_filter,
        )
    return helper, mod


class TestLdapHelperSearch:
    def test_search_finds_admin_user(self):
        helper, mod = make_helper()
        entry = make_mock_entry()

        with patch.object(helper, "connect") as mock_connect:
            mock_con = MagicMock()
            mock_connect.return_value = mock_con
            mock_con.entries = [entry]

            user_data, con = helper.search("testuser")

            assert user_data is not None
            assert user_data["name"] == "Test User"
            assert user_data["group"] == "system-admin"
            assert user_data["local_only"] == "false"
            assert user_data["dn"] == "cn=testuser,ou=users,dc=example,dc=com"

    def test_search_falls_through_to_user_group(self):
        helper, mod = make_helper()
        entry = make_mock_entry()

        with patch.object(helper, "connect") as mock_connect:
            mock_con = MagicMock()
            mock_connect.return_value = mock_con
            # First search (admin) returns nothing, second (user) returns entry
            mock_con.entries = []

            def search_side_effect(base_dn, filter_str, attributes=None):
                if "admin" in filter_str:
                    mock_con.entries = []
                else:
                    mock_con.entries = [entry]

            mock_con.search.side_effect = search_side_effect

            user_data, con = helper.search("testuser")

            assert user_data is not None
            assert user_data["group"] == "system-users"

    def test_search_returns_none_when_user_not_found(self):
        helper, mod = make_helper()

        with patch.object(helper, "connect") as mock_connect:
            mock_con = MagicMock()
            mock_connect.return_value = mock_con
            mock_con.entries = []

            user_data, con = helper.search("nonexistent")

            assert user_data is None

    def test_search_returns_none_for_multiple_results(self):
        helper, mod = make_helper()

        with patch.object(helper, "connect") as mock_connect:
            mock_con = MagicMock()
            mock_connect.return_value = mock_con
            mock_con.entries = [make_mock_entry(), make_mock_entry()]

            user_data, con = helper.search("ambiguous")

            assert user_data is None

    def test_search_uses_name_fallback(self):
        helper, mod = make_helper()
        entry = make_mock_entry(display_name=None, name="fallbackname")

        with patch.object(helper, "connect") as mock_connect:
            mock_con = MagicMock()
            mock_connect.return_value = mock_con
            mock_con.entries = [entry]

            user_data, _ = helper.search("testuser")

            assert user_data["name"] == "fallbackname"

    def test_search_uses_username_as_last_resort(self):
        helper, mod = make_helper()
        entry = make_mock_entry(display_name=None, name=None)

        with patch.object(helper, "connect") as mock_connect:
            mock_con = MagicMock()
            mock_connect.return_value = mock_con
            mock_con.entries = [entry]

            user_data, _ = helper.search("myuser")

            # Username is escaped, so the value used is the escaped form
            assert user_data["name"] is not None

    def test_search_escapes_username(self):
        helper, mod = make_helper()

        with patch.object(helper, "connect") as mock_connect:
            mock_con = MagicMock()
            mock_connect.return_value = mock_con
            mock_con.entries = []

            helper.search("user*with(special)chars")

            call_args = mock_con.search.call_args_list[0]
            filter_used = call_args[0][1]
            assert "*" not in filter_used
            assert "(" not in filter_used.split("cn=")[1].split(")")[0]


class TestLdapHelperAuth:
    def test_auth_success(self):
        helper, mod = make_helper()
        mock_con = MagicMock()

        result = helper.auth(mock_con, "cn=user,dc=example,dc=com", "password")

        assert result is True
        mock_con.rebind.assert_called_once_with(
            user="cn=user,dc=example,dc=com", password="password"
        )

    def test_auth_failure(self):
        from ldap3.core.exceptions import LDAPInvalidCredentialsResult

        helper, mod = make_helper()
        mock_con = MagicMock()
        mock_con.rebind.side_effect = LDAPInvalidCredentialsResult()

        result = helper.auth(mock_con, "cn=user,dc=example,dc=com", "wrong")

        assert result is False

    def test_auth_does_not_escape_password(self):
        helper, mod = make_helper()
        mock_con = MagicMock()

        helper.auth(mock_con, "cn=user,dc=example,dc=com", "p@ss(w)rd*")

        mock_con.rebind.assert_called_once_with(
            user="cn=user,dc=example,dc=com", password="p@ss(w)rd*"
        )


class TestJsonAuthEndpoint:
    @pytest.fixture(autouse=True)
    def setup(self):
        _, self.mod = make_helper()
        self.app = self.mod.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def _set_helper(self, search_return, auth_return=True):
        mock_helper = MagicMock()
        mock_con = MagicMock()
        mock_helper.search.return_value = (search_return, mock_con)
        mock_helper.auth.return_value = auth_return
        self.mod.LDAP_HELPER = mock_helper
        return mock_helper, mock_con

    def test_success(self):
        user_data = {"dn": "cn=test,dc=example", "name": "Test", "group": "system-admin", "local_only": "false"}
        self._set_helper(user_data.copy())

        resp = self.client.post("/json-auth", json={"username": "test", "password": "pass"})

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["data"]["name"] == "Test"
        assert data["data"]["group"] == "system-admin"

    def test_missing_fields(self):
        resp = self.client.post("/json-auth", json={"username": "test"})
        assert resp.status_code == 400

    def test_empty_username(self):
        resp = self.client.post("/json-auth", json={"username": "", "password": "pass"})
        assert resp.status_code == 400

    def test_user_not_found(self):
        self._set_helper(None)

        resp = self.client.post("/json-auth", json={"username": "unknown", "password": "pass"})

        assert resp.status_code == 403

    def test_wrong_password(self):
        user_data = {"dn": "cn=test,dc=example", "name": "Test", "group": "system-admin", "local_only": "false"}
        self._set_helper(user_data.copy(), auth_return=False)

        resp = self.client.post("/json-auth", json={"username": "test", "password": "wrong"})

        assert resp.status_code == 403

    def test_no_json_body(self):
        resp = self.client.post("/json-auth", content_type="application/json", data="")
        assert resp.status_code == 400

    def test_connection_unbound_on_success(self):
        user_data = {"dn": "cn=test,dc=example", "name": "Test", "group": "system-admin", "local_only": "false"}
        _, mock_con = self._set_helper(user_data.copy())

        self.client.post("/json-auth", json={"username": "test", "password": "pass"})

        mock_con.unbind.assert_called()

    def test_connection_unbound_on_not_found(self):
        _, mock_con = self._set_helper(None)

        self.client.post("/json-auth", json={"username": "unknown", "password": "pass"})

        mock_con.unbind.assert_called()


class TestAuthHeaderEndpoint:
    @pytest.fixture(autouse=True)
    def setup(self):
        _, self.mod = make_helper()
        self.app = self.mod.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def _set_helper(self, search_return, auth_return=True):
        mock_helper = MagicMock()
        mock_con = MagicMock()
        mock_helper.search.return_value = (search_return, mock_con)
        mock_helper.auth.return_value = auth_return
        self.mod.LDAP_HELPER = mock_helper
        return mock_helper, mock_con

    def _basic_auth_header(self, username, password):
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Authorization": f"Basic {creds}"}

    def test_success(self):
        user_data = {"dn": "cn=test,dc=example", "name": "Test", "group": "system-admin", "local_only": "false"}
        self._set_helper(user_data.copy())

        resp = self.client.get("/auth-header", headers=self._basic_auth_header("test", "pass"))

        assert resp.status_code == 200
        body = resp.data.decode()
        assert "name = Test" in body
        assert "group = system-admin" in body

    def test_missing_auth_header(self):
        resp = self.client.get("/auth-header")

        assert resp.status_code == 401
        assert "WWW-Authenticate" in resp.headers

    def test_non_basic_auth(self):
        resp = self.client.get("/auth-header", headers={"Authorization": "Bearer token123"})

        assert resp.status_code == 401

    def test_user_not_found(self):
        self._set_helper(None)

        resp = self.client.get("/auth-header", headers=self._basic_auth_header("unknown", "pass"))

        assert resp.status_code == 403

    def test_wrong_password(self):
        user_data = {"dn": "cn=test,dc=example", "name": "Test", "group": "system-admin", "local_only": "false"}
        self._set_helper(user_data.copy(), auth_return=False)

        resp = self.client.get("/auth-header", headers=self._basic_auth_header("test", "wrong"))

        assert resp.status_code == 403

    def test_empty_username(self):
        resp = self.client.get("/auth-header", headers=self._basic_auth_header("", "pass"))
        assert resp.status_code == 400

    def test_invalid_base64(self):
        resp = self.client.get("/auth-header", headers={"Authorization": "Basic !!!notbase64"})
        assert resp.status_code == 400

    def test_connection_unbound_on_success(self):
        user_data = {"dn": "cn=test,dc=example", "name": "Test", "group": "system-admin", "local_only": "false"}
        _, mock_con = self._set_helper(user_data.copy())

        self.client.get("/auth-header", headers=self._basic_auth_header("test", "pass"))

        mock_con.unbind.assert_called()
