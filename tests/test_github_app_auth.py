# File: tests/test_github_app_auth.py
#
# Copyright (c) 2019-2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
"""Unit tests for GitHub App authentication helpers.

Tests cover:
- JWT generation (structure, claims, algorithm)
- Installation token exchange (mocked HTTP call)
- Token caching and expiry behavior
"""

import datetime
import sys
import time
import types
import unittest
from unittest.mock import MagicMock, patch

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key


# ---------------------------------------------------------------------------
# Minimal stubs for Splunk SOAR modules (not available outside the platform)
# ---------------------------------------------------------------------------

def _build_phantom_stub():
    """Return a minimal stub for phantom.app."""
    phantom_app = types.ModuleType("phantom.app")
    phantom_app.APP_SUCCESS = True
    phantom_app.APP_ERROR = False

    def is_fail(status):
        return status is False or status == phantom_app.APP_ERROR

    phantom_app.is_fail = is_fail
    return phantom_app


phantom_stub = _build_phantom_stub()
sys.modules.setdefault("phantom", types.ModuleType("phantom"))
sys.modules["phantom"].app = phantom_stub
sys.modules.setdefault("phantom.app", phantom_stub)

# Stub phantom.action_result
action_result_mod = types.ModuleType("phantom.action_result")


class _ActionResult:
    def __init__(self, param=None):
        self._status = phantom_stub.APP_SUCCESS
        self._message = ""

    def set_status(self, status, status_message=""):
        self._status = status
        self._message = status_message
        return status

    def get_status(self):
        return self._status

    def get_message(self):
        return self._message

    def add_data(self, data):
        pass

    def update_summary(self, summary):
        return summary

    def update_data(self, data):
        pass


action_result_mod.ActionResult = _ActionResult
sys.modules.setdefault("phantom.action_result", action_result_mod)

# Stub phantom.base_connector
base_connector_mod = types.ModuleType("phantom.base_connector")


class _BaseConnector:
    def __init__(self):
        self._python_version = 3

    def get_config(self):
        return {}

    def load_state(self):
        return {}

    def save_state(self, state):
        pass

    def get_asset_id(self):
        return "test_asset"

    def debug_print(self, *args, **kwargs):
        pass

    def save_progress(self, msg):
        pass

    def send_progress(self, msg):
        pass

    def set_status(self, status, msg=""):
        return status

    def add_action_result(self, ar):
        return ar

    def get_action_identifier(self):
        return "test_connectivity"

    def _handle_py_ver_compat_for_input_str(self, value, always_encode=False):
        return value


base_connector_mod.BaseConnector = _BaseConnector
sys.modules.setdefault("phantom.base_connector", base_connector_mod)

# Stub django.http
django_mod = types.ModuleType("django")
django_http_mod = types.ModuleType("django.http")
django_http_mod.HttpResponse = MagicMock()
sys.modules.setdefault("django", django_mod)
sys.modules.setdefault("django.http", django_http_mod)

# Stub bs4
bs4_mod = types.ModuleType("bs4")
bs4_mod.BeautifulSoup = MagicMock()
bs4_mod.UnicodeDammit = MagicMock()
sys.modules.setdefault("bs4", bs4_mod)

# Stub requests (will be patched per-test as needed)
requests_mod = types.ModuleType("requests")
sys.modules.setdefault("requests", requests_mod)

# ---------------------------------------------------------------------------
# Now import the connector module (stubs must be in place first)
# ---------------------------------------------------------------------------
import importlib
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
github_consts = importlib.import_module("github_consts")
github_connector_mod = importlib.import_module("github_connector")
GithubConnector = github_connector_mod.GithubConnector


# ---------------------------------------------------------------------------
# Helper: generate a throwaway RSA key pair for tests
# ---------------------------------------------------------------------------

def _generate_test_rsa_key_pair():
    """Generate a temporary RSA-2048 key pair for test use only."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return private_pem


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestGenerateGithubAppJWT(unittest.TestCase):
    """Tests for GithubConnector._generate_github_app_jwt."""

    def setUp(self):
        self.connector = GithubConnector()
        self.private_pem = _generate_test_rsa_key_pair()
        self.connector._app_id = "12345"
        self.connector._app_private_key = self.private_pem
        self.connector._app_installation_id = "67890"

    def test_jwt_is_string(self):
        token = self.connector._generate_github_app_jwt()
        self.assertIsInstance(token, str)

    def test_jwt_has_three_parts(self):
        token = self.connector._generate_github_app_jwt()
        parts = token.split(".")
        self.assertEqual(len(parts), 3, "A JWT must consist of exactly three dot-separated parts")

    def test_jwt_uses_rs256_algorithm(self):
        token = self.connector._generate_github_app_jwt()
        header = jwt.get_unverified_header(token)
        self.assertEqual(header["alg"], "RS256")

    def test_jwt_claims_iss_equals_app_id(self):
        token = self.connector._generate_github_app_jwt()
        # Decode without verification to inspect claims
        payload = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(payload["iss"], "12345")

    def test_jwt_iat_is_in_the_past(self):
        before = int(time.time())
        token = self.connector._generate_github_app_jwt()
        payload = jwt.decode(token, options={"verify_signature": False})
        # iat should be ~60 seconds before now
        self.assertLessEqual(payload["iat"], before)

    def test_jwt_exp_is_after_iat(self):
        token = self.connector._generate_github_app_jwt()
        payload = jwt.decode(token, options={"verify_signature": False})
        self.assertGreater(payload["exp"], payload["iat"])

    def test_jwt_exp_within_ten_minutes(self):
        now = int(time.time())
        token = self.connector._generate_github_app_jwt()
        payload = jwt.decode(token, options={"verify_signature": False})
        # exp must not exceed 10 minutes from now
        self.assertLessEqual(payload["exp"], now + 600 + 1)  # +1 for rounding

    def test_jwt_signature_verifiable(self):
        """Verify the JWT signature using the corresponding public key."""
        private_key_obj = load_pem_private_key(self.private_pem.encode(), None)
        public_key = private_key_obj.public_key()
        token = self.connector._generate_github_app_jwt()
        decoded = jwt.decode(token, public_key, algorithms=["RS256"])
        self.assertEqual(decoded["iss"], "12345")

    def test_invalid_private_key_raises(self):
        self.connector._app_private_key = "not-a-valid-pem-key"
        with self.assertRaises(Exception):
            self.connector._generate_github_app_jwt()

    # ------------------------------------------------------------------
    # PEM normalization tests
    # ------------------------------------------------------------------

    def test_pem_with_literal_escaped_newlines_parses_successfully(self):
        """PEM key with literal \\n sequences (two chars) is normalized and signs."""
        # Simulate a config field that stored real newlines as literal \n
        collapsed = self.private_pem.replace("\n", "\\n")
        self.connector._app_private_key = collapsed
        token = self.connector._generate_github_app_jwt()
        self.assertIsInstance(token, str)
        parts = token.split(".")
        self.assertEqual(len(parts), 3)

    def test_pem_with_leading_trailing_whitespace_parses_successfully(self):
        """PEM key with extra leading/trailing whitespace is stripped and signs."""
        self.connector._app_private_key = "\n\n  " + self.private_pem + "  \n\n"
        token = self.connector._generate_github_app_jwt()
        self.assertIsInstance(token, str)

    def test_pem_with_bom_parses_successfully(self):
        """PEM key prefixed with a UTF-8 BOM is stripped and signs."""
        self.connector._app_private_key = "\ufeff" + self.private_pem
        token = self.connector._generate_github_app_jwt()
        self.assertIsInstance(token, str)

    def test_public_key_produces_specific_error(self):
        """Pasting a public key produces a clear, actionable error message."""
        private_key_obj = load_pem_private_key(self.private_pem.encode(), None)
        public_key = private_key_obj.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        self.connector._app_private_key = public_pem
        with self.assertRaises(ValueError) as ctx:
            self.connector._generate_github_app_jwt()
        self.assertIn("public key", str(ctx.exception).lower())

    def test_garbage_string_produces_generic_invalid_pem_error(self):
        """A completely invalid string produces the generic invalid PEM error."""
        self.connector._app_private_key = "this-is-not-a-pem-key-at-all"
        with self.assertRaises(ValueError) as ctx:
            self.connector._generate_github_app_jwt()
        self.assertIn("PRIVATE KEY", str(ctx.exception))


class TestGetInstallationAccessToken(unittest.TestCase):
    """Tests for GithubConnector._get_installation_access_token."""

    _FAKE_TOKEN = "ghs_fake_installation_token"
    _EXPIRES_IN_1H = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    def _make_connector(self):
        connector = GithubConnector()
        connector._app_id = "12345"
        connector._app_private_key = _generate_test_rsa_key_pair()
        connector._app_installation_id = "67890"
        connector._installation_token = None
        connector._installation_token_expires_at = None
        return connector

    def test_exchanges_jwt_for_token(self):
        connector = self._make_connector()
        action_result = _ActionResult()

        api_response = MagicMock()
        api_response.status_code = 201
        api_response.json.return_value = {"token": self._FAKE_TOKEN, "expires_at": self._EXPIRES_IN_1H}

        with patch.object(connector, "_make_rest_call", return_value=(phantom_stub.APP_SUCCESS, {"token": self._FAKE_TOKEN, "expires_at": self._EXPIRES_IN_1H})):
            status, token = connector._get_installation_access_token(action_result)

        self.assertEqual(status, phantom_stub.APP_SUCCESS)
        self.assertEqual(token, self._FAKE_TOKEN)

    def test_stores_token_in_cache(self):
        connector = self._make_connector()
        action_result = _ActionResult()

        with patch.object(connector, "_make_rest_call", return_value=(phantom_stub.APP_SUCCESS, {"token": self._FAKE_TOKEN, "expires_at": self._EXPIRES_IN_1H})):
            connector._get_installation_access_token(action_result)

        self.assertEqual(connector._installation_token, self._FAKE_TOKEN)
        self.assertIsNotNone(connector._installation_token_expires_at)

    def test_reuses_cached_token_while_valid(self):
        connector = self._make_connector()
        action_result = _ActionResult()

        # Pre-populate cache with a token that expires far in the future
        connector._installation_token = self._FAKE_TOKEN
        connector._installation_token_expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)

        with patch.object(connector, "_make_rest_call") as mock_call:
            status, token = connector._get_installation_access_token(action_result)
            mock_call.assert_not_called()  # No HTTP call should be made

        self.assertEqual(status, phantom_stub.APP_SUCCESS)
        self.assertEqual(token, self._FAKE_TOKEN)

    def test_refreshes_expired_token(self):
        connector = self._make_connector()
        action_result = _ActionResult()

        # Cache an already-expired token (expired 10 minutes ago)
        connector._installation_token = "old_token"
        connector._installation_token_expires_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=10)

        new_token = "ghs_new_token"
        with patch.object(connector, "_make_rest_call", return_value=(phantom_stub.APP_SUCCESS, {"token": new_token, "expires_at": self._EXPIRES_IN_1H})):
            status, token = connector._get_installation_access_token(action_result)

        self.assertEqual(status, phantom_stub.APP_SUCCESS)
        self.assertEqual(token, new_token)
        self.assertEqual(connector._installation_token, new_token)

    def test_refreshes_nearly_expired_token(self):
        """Token with less than 5 minutes remaining should be refreshed."""
        connector = self._make_connector()
        action_result = _ActionResult()

        # Cache a token that expires in 2 minutes (within the 5-minute buffer)
        connector._installation_token = "almost_expired_token"
        connector._installation_token_expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=2)

        new_token = "ghs_fresh_token"
        with patch.object(connector, "_make_rest_call", return_value=(phantom_stub.APP_SUCCESS, {"token": new_token, "expires_at": self._EXPIRES_IN_1H})):
            status, token = connector._get_installation_access_token(action_result)

        self.assertEqual(status, phantom_stub.APP_SUCCESS)
        self.assertEqual(token, new_token)

    def test_returns_error_on_api_failure(self):
        connector = self._make_connector()
        action_result = _ActionResult()

        with patch.object(connector, "_make_rest_call", return_value=(phantom_stub.APP_ERROR, None)):
            action_result.set_status(phantom_stub.APP_ERROR, "API Error")
            status, token = connector._get_installation_access_token(action_result)

        self.assertEqual(status, phantom_stub.APP_ERROR)
        self.assertIsNone(token)

    def test_returns_error_when_token_missing_from_response(self):
        connector = self._make_connector()
        action_result = _ActionResult()

        with patch.object(connector, "_make_rest_call", return_value=(phantom_stub.APP_SUCCESS, {})):
            status, token = connector._get_installation_access_token(action_result)

        self.assertEqual(status, phantom_stub.APP_ERROR)
        self.assertIsNone(token)

    def test_returns_error_on_bad_jwt(self):
        connector = self._make_connector()
        connector._app_private_key = "invalid-pem"
        action_result = _ActionResult()

        status, token = connector._get_installation_access_token(action_result)

        self.assertEqual(status, phantom_stub.APP_ERROR)
        self.assertIsNone(token)

    def test_fallback_expiry_when_expires_at_missing(self):
        connector = self._make_connector()
        action_result = _ActionResult()

        with patch.object(connector, "_make_rest_call", return_value=(phantom_stub.APP_SUCCESS, {"token": self._FAKE_TOKEN})):
            connector._get_installation_access_token(action_result)

        self.assertIsNotNone(connector._installation_token_expires_at)
        # Should be approximately 1 hour from now
        delta = connector._installation_token_expires_at - datetime.datetime.now(datetime.timezone.utc)
        self.assertGreater(delta.total_seconds(), 3500)
        self.assertLessEqual(delta.total_seconds(), 3700)


if __name__ == "__main__":
    unittest.main()
