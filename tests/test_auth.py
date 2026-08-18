# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Unit tests for GitHub App (installation) authentication."""

import datetime
from unittest.mock import Mock

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from soar_sdk.exceptions import ActionFailure

from src import auth as auth_module
from src.auth import (
    GitHubAppAuth,
    generate_github_app_jwt,
    has_github_app_config,
    resolve_github_auth,
)


def _generate_test_rsa_key_pair() -> str:
    """Generate a temporary RSA-2048 private key (PEM) for test use only."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _make_asset(**overrides):
    defaults = {
        "personal_access_token": None,
        "client_id": None,
        "client_secret": None,
        "app_id": "12345",
        "app_private_key": _generate_test_rsa_key_pair(),
        "app_installation_id": "67890",
    }
    defaults.update(overrides)
    return Mock(**defaults)


class TestGenerateGithubAppJwt:
    def test_jwt_has_three_parts(self):
        asset = _make_asset()
        token = generate_github_app_jwt(asset)
        assert len(token.split(".")) == 3

    def test_jwt_uses_rs256_algorithm(self):
        asset = _make_asset()
        token = generate_github_app_jwt(asset)
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "RS256"

    def test_jwt_claims_iss_equals_app_id(self):
        asset = _make_asset()
        token = generate_github_app_jwt(asset)
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["iss"] == "12345"

    def test_jwt_exp_after_iat_within_ten_minutes(self):
        asset = _make_asset()
        now = int(datetime.datetime.now(datetime.UTC).timestamp())
        token = generate_github_app_jwt(asset)
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["exp"] > payload["iat"]
        assert payload["exp"] <= now + 600 + 1

    def test_jwt_signature_verifiable(self):
        private_pem = _generate_test_rsa_key_pair()
        asset = _make_asset(app_private_key=private_pem)
        private_key_obj = load_pem_private_key(private_pem.encode(), None)
        public_key = private_key_obj.public_key()

        token = generate_github_app_jwt(asset)
        decoded = jwt.decode(token, public_key, algorithms=["RS256"])
        assert decoded["iss"] == "12345"

    def test_pem_with_literal_escaped_newlines_parses_successfully(self):
        private_pem = _generate_test_rsa_key_pair()
        collapsed = private_pem.replace("\n", "\\n")
        asset = _make_asset(app_private_key=collapsed)
        token = generate_github_app_jwt(asset)
        assert len(token.split(".")) == 3

    def test_pem_with_leading_trailing_whitespace_parses_successfully(self):
        private_pem = _generate_test_rsa_key_pair()
        asset = _make_asset(app_private_key="\n\n  " + private_pem + "  \n\n")
        token = generate_github_app_jwt(asset)
        assert len(token.split(".")) == 3

    def test_pem_with_bom_parses_successfully(self):
        private_pem = _generate_test_rsa_key_pair()
        asset = _make_asset(app_private_key="\ufeff" + private_pem)
        token = generate_github_app_jwt(asset)
        assert len(token.split(".")) == 3

    def test_public_key_produces_specific_error(self):
        private_pem = _generate_test_rsa_key_pair()
        private_key_obj = load_pem_private_key(private_pem.encode(), None)
        public_pem = (
            private_key_obj.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )

        asset = _make_asset(app_private_key=public_pem)
        with pytest.raises(ValueError, match="public key"):
            generate_github_app_jwt(asset)

    def test_garbage_string_produces_generic_invalid_pem_error(self):
        asset = _make_asset(app_private_key="this-is-not-a-pem-key-at-all")
        with pytest.raises(ValueError, match="PRIVATE KEY"):
            generate_github_app_jwt(asset)


class TestGitHubAppAuth:
    _FAKE_TOKEN = "ghs_fake_installation_token"
    _EXPIRES_IN_1H = (
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _mock_post_response(
        self, monkeypatch, *, status_code=201, token=None, expires_at=None
    ):
        response = Mock(status_code=status_code)
        response.json.return_value = {
            "token": token or self._FAKE_TOKEN,
            "expires_at": expires_at or self._EXPIRES_IN_1H,
        }
        response.text = ""
        client = Mock()
        client.post.return_value = response
        client.__enter__ = Mock(return_value=client)
        client.__exit__ = Mock(return_value=False)
        monkeypatch.setattr(auth_module.httpx, "Client", Mock(return_value=client))
        return client

    def test_exchanges_jwt_for_installation_token(self, monkeypatch):
        asset = _make_asset()
        self._mock_post_response(monkeypatch)
        github_app_auth = GitHubAppAuth(asset)

        token = github_app_auth._fetch_installation_token()

        assert token == self._FAKE_TOKEN
        assert github_app_auth._token == self._FAKE_TOKEN
        assert github_app_auth._expires_at is not None

    def test_reuses_cached_token_while_valid(self, monkeypatch):
        asset = _make_asset()
        github_app_auth = GitHubAppAuth(asset)
        github_app_auth._token = self._FAKE_TOKEN
        github_app_auth._expires_at = datetime.datetime.now(
            datetime.UTC
        ) + datetime.timedelta(hours=1)

        client_cls = Mock()
        monkeypatch.setattr(auth_module.httpx, "Client", client_cls)

        request = Mock(headers={})
        generator = github_app_auth.auth_flow(request)
        next(generator)

        client_cls.assert_not_called()
        assert request.headers["Authorization"] == f"Bearer {self._FAKE_TOKEN}"

    def test_refreshes_nearly_expired_token(self, monkeypatch):
        asset = _make_asset()
        github_app_auth = GitHubAppAuth(asset)
        github_app_auth._token = "almost_expired_token"
        github_app_auth._expires_at = datetime.datetime.now(
            datetime.UTC
        ) + datetime.timedelta(minutes=2)

        self._mock_post_response(monkeypatch, token="ghs_fresh_token")

        request = Mock(headers={})
        generator = github_app_auth.auth_flow(request)
        next(generator)

        assert request.headers["Authorization"] == "Bearer ghs_fresh_token"

    def test_raises_action_failure_on_api_error(self, monkeypatch):
        asset = _make_asset()
        self._mock_post_response(monkeypatch, status_code=401)
        github_app_auth = GitHubAppAuth(asset)

        with pytest.raises(ActionFailure):
            github_app_auth._fetch_installation_token()

    def test_raises_action_failure_when_token_missing(self, monkeypatch):
        asset = _make_asset()
        response = Mock(status_code=201)
        response.json.return_value = {"expires_at": self._EXPIRES_IN_1H}
        response.text = ""
        client = Mock()
        client.post.return_value = response
        client.__enter__ = Mock(return_value=client)
        client.__exit__ = Mock(return_value=False)
        monkeypatch.setattr(auth_module.httpx, "Client", Mock(return_value=client))

        github_app_auth = GitHubAppAuth(asset)

        with pytest.raises(ActionFailure):
            github_app_auth._fetch_installation_token()


class TestResolveGithubAuth:
    def test_prefers_pat_over_github_app(self):
        asset = _make_asset(personal_access_token="pat-token")
        result = resolve_github_auth(asset)
        assert result.__class__.__name__ == "StaticTokenAuth"

    def test_uses_github_app_when_no_pat(self):
        asset = _make_asset()
        result = resolve_github_auth(asset)
        assert isinstance(result, GitHubAppAuth)

    def test_falls_back_to_oauth_app(self):
        asset = _make_asset(app_id=None, app_private_key=None, app_installation_id=None)
        asset.client_id = "client-id"
        asset.client_secret = "client-secret"
        asset.auth_state = {}
        result = resolve_github_auth(asset)
        assert result.__class__.__name__ == "OAuthBearerAuth"

    def test_raises_when_unconfigured(self):
        asset = _make_asset(app_id=None, app_private_key=None, app_installation_id=None)
        with pytest.raises(ActionFailure):
            resolve_github_auth(asset)


class TestHasGithubAppConfig:
    def test_true_when_fully_configured(self):
        assert has_github_app_config(_make_asset()) is True

    def test_false_when_partially_configured(self):
        asset = _make_asset(app_installation_id=None)
        assert has_github_app_config(asset) is False
