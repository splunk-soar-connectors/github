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
# Authentication for the GitHub app, built entirely on soar_sdk.auth.
#
# GitHub supports three credential styles:
#   1. Personal Access Token (PAT) — a static bearer token.
#   2. OAuth App (client_id / client_secret) — the authorization code flow,
#      with tokens persisted in the SDK-managed asset.auth_state.
#   3. GitHub App (app_id / app_private_key / app_installation_id) — a
#      short-lived JWT signed with the App's private key is exchanged for an
#      installation access token, which is cached until shortly before expiry.
#
# resolve_github_auth() picks between them and returns an httpx.Auth that
# call_github() hands directly to httpx.Client(auth=...).

from __future__ import annotations

import datetime
import re
import time
from collections.abc import Callable, Generator
from typing import TYPE_CHECKING

import httpx
import jwt as pyjwt

from soar_sdk.auth import (
    OAuthBearerAuth,
    OAuthConfig,
    SOARAssetOAuthClient,
    StaticTokenAuth,
)
from soar_sdk.auth.client import ConfigurationChangedError, OAuthToken
from soar_sdk.exceptions import ActionFailure

from .consts import (
    DEFAULT_TIMEOUT,
    GITHUB_API_BASE_URL,
    GITHUB_APP_INSTALLATION_TOKEN_FAILED_MSG,
    GITHUB_APP_INSTALLATION_TOKEN_MISSING_MSG,
    GITHUB_APP_INVALID_PEM_FORMAT_MSG,
    GITHUB_APP_INVALID_PEM_PUBLIC_KEY_MSG,
    GITHUB_APP_JWT_EXP_SECONDS,
    GITHUB_APP_JWT_GENERATION_FAILED_MSG,
    GITHUB_APP_JWT_IAT_BACKDATE_SECONDS,
    GITHUB_APP_TOKEN_EXPIRY_BUFFER,
    GITHUB_AUTHORIZE_ENDPOINT,
    GITHUB_CONFIG_PARAMS_REQUIRED,
    GITHUB_ENDPOINT_APP_INSTALLATION_TOKEN,
    GITHUB_OAUTH_FAILED_MSG,
    GITHUB_SCOPE,
    GITHUB_TC_STATUS_SLEEP,
    GITHUB_TOKEN_ENDPOINT,
)

if TYPE_CHECKING:
    from .asset import Asset

# How long test_connectivity waits (in seconds) for the user to complete the
# browser authorization step before giving up.
_OAUTH_POLL_TIMEOUT = 300

# Pre-compiled patterns used to validate/normalize the GitHub App private key.
_PEM_PUBLIC_KEY_RE = re.compile(r"-----BEGIN (?:RSA )?PUBLIC KEY-----")
_PEM_PRIVATE_KEY_HEADER_RE = re.compile(r"-----BEGIN (?:\w+ )*PRIVATE KEY-----")
_PEM_PRIVATE_KEY_FOOTER_RE = re.compile(r"-----END (?:\w+ )*PRIVATE KEY-----")


def build_pat_auth(asset: Asset) -> StaticTokenAuth:
    """Return SDK bearer auth for a Personal Access Token."""
    return StaticTokenAuth(asset.personal_access_token)


def _build_oauth_config(
    asset: Asset, *, redirect_uri: str | None = None
) -> OAuthConfig:
    """Build the OAuth config shared by the flow and the bearer auth."""
    return OAuthConfig(
        client_id=asset.client_id,
        client_secret=asset.client_secret,
        authorization_endpoint=GITHUB_AUTHORIZE_ENDPOINT,
        token_endpoint=GITHUB_TOKEN_ENDPOINT,
        redirect_uri=redirect_uri,
        scope=GITHUB_SCOPE,
    )


def _github_oauth_http_client() -> httpx.Client:
    """HTTP client for the OAuth token endpoint.

    GitHub's token endpoint returns a form-encoded body by default; the SDK's
    OAuth client parses the response as JSON. Sending ``Accept: application/json``
    makes GitHub respond with JSON so token exchange and refresh succeed.
    """
    return httpx.Client(headers={"Accept": "application/json"}, timeout=DEFAULT_TIMEOUT)


def build_oauth_client(
    asset: Asset, *, redirect_uri: str | None = None
) -> SOARAssetOAuthClient:
    """Return the SDK OAuth client bound to the asset's persisted auth_state."""
    return SOARAssetOAuthClient(
        _build_oauth_config(asset, redirect_uri=redirect_uri),
        asset.auth_state,
        http_client=_github_oauth_http_client(),
    )


def build_oauth_auth(asset: Asset) -> OAuthBearerAuth:
    """Return SDK bearer auth that reads/refreshes the OAuth token from auth_state."""
    return OAuthBearerAuth(build_oauth_client(asset), auto_refresh=True)


def complete_oauth_authorization(
    asset: Asset,
    *,
    asset_id: str,
    redirect_uri: str,
    announce_url: Callable[[str], None],
    poll_timeout: int = _OAUTH_POLL_TIMEOUT,
    poll_interval: int = GITHUB_TC_STATUS_SLEEP,
) -> OAuthToken:
    """Drive the authorization code flow to obtain and persist an OAuth token.

    If a valid token is already stored for the current credentials it is reused.
    Otherwise an authorization URL is generated and handed to ``announce_url``
    (so the caller can surface it to the user), then this polls ``auth_state``
    until the webhook callback lands the authorization code, exchanges it for a
    token, and returns it. Raises ActionFailure if the user does not authorize
    within ``poll_timeout`` seconds.
    """
    client = build_oauth_client(asset, redirect_uri=redirect_uri)

    # Reuse an existing token when the stored credentials still match.
    try:
        if client.get_stored_token() is not None:
            return client.get_valid_token(auto_refresh=True)
    except ConfigurationChangedError:
        # client_id changed → stored token was cleared, fall through to re-auth.
        pass

    auth_url, _ = client.create_authorization_url(asset_id, use_pkce=False)
    announce_url(auth_url)

    deadline = time.time() + poll_timeout
    while time.time() < deadline:
        time.sleep(poll_interval)
        code = client.get_authorization_code(force_reload=True)
        if code:
            token = client.fetch_token_with_authorization_code(code)
            # SDK bug workaround: fetch_token_with_authorization_code() stores the
            # token, then clears the session by re-saving a state object it loaded
            # *before* the token existed — which wipes the token from auth_state.
            # It still returns a valid token, so re-persist it here; otherwise the
            # subsequent connectivity probe reads an empty auth_state and raises
            # AuthorizationRequiredError ("No OAuth token available").
            client._store_token(token)
            return token

    raise ActionFailure(
        f"{GITHUB_OAUTH_FAILED_MSG}: timed out after {poll_timeout}s "
        "waiting for user authorization."
    )


def generate_github_app_jwt(asset: Asset) -> str:
    """Generate a signed JWT for GitHub App authentication (RS256).

    The JWT is built per GitHub's App authentication spec:
      * iat: issued ~60 seconds in the past to compensate for clock drift.
      * exp: 9 minutes from now (GitHub enforces a 10-minute maximum).
      * iss: the App ID.

    Raises ValueError if the private key is missing, a public key, or
    otherwise not a valid PEM private key.
    """
    key_str = asset.app_private_key or ""

    # Strip a UTF-8 BOM if present.
    key_str = key_str.lstrip("\ufeff")

    # Normalize literal "\n" escape sequences (two characters) to real newlines.
    if "\\n" in key_str:
        key_str = key_str.replace("\\n", "\n")

    key_str = key_str.strip()

    if _PEM_PUBLIC_KEY_RE.search(key_str):
        raise ValueError(GITHUB_APP_INVALID_PEM_PUBLIC_KEY_MSG)

    if not (
        _PEM_PRIVATE_KEY_HEADER_RE.search(key_str)
        and _PEM_PRIVATE_KEY_FOOTER_RE.search(key_str)
    ):
        raise ValueError(GITHUB_APP_INVALID_PEM_FORMAT_MSG)

    now = int(time.time())
    payload = {
        "iat": now - GITHUB_APP_JWT_IAT_BACKDATE_SECONDS,
        "exp": now + GITHUB_APP_JWT_EXP_SECONDS,
        "iss": asset.app_id,
    }
    return pyjwt.encode(payload, key_str.encode("utf-8"), algorithm="RS256")


class GitHubAppAuth(httpx.Auth):
    """HTTPX authentication for a GitHub App installation.

    Exchanges a short-lived JWT (signed with the App's private key) for an
    installation access token via POST /app/installations/{id}/access_tokens,
    and caches it until shortly before it expires.
    """

    def __init__(self, asset: Asset) -> None:
        self._asset = asset
        self._token: str | None = None
        self._expires_at: datetime.datetime | None = None

    def _token_is_valid(self) -> bool:
        if not (self._token and self._expires_at):
            return False
        buffer = datetime.timedelta(seconds=GITHUB_APP_TOKEN_EXPIRY_BUFFER)
        return datetime.datetime.now(datetime.UTC) < self._expires_at - buffer

    def _fetch_installation_token(self) -> str:
        try:
            jwt_token = generate_github_app_jwt(self._asset)
        except ValueError:
            raise
        except Exception as exc:
            raise ActionFailure(
                f"{GITHUB_APP_JWT_GENERATION_FAILED_MSG} Details: {exc}"
            ) from exc

        endpoint = GITHUB_ENDPOINT_APP_INSTALLATION_TOKEN.format(
            installation_id=self._asset.app_installation_id
        )
        url = f"{GITHUB_API_BASE_URL}{endpoint}"
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
        }

        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
                response = client.post(url, headers=headers)
        except httpx.RequestError as exc:
            raise ActionFailure(f"Error connecting to GitHub API: {exc}") from exc

        if response.status_code >= 400:
            raise ActionFailure(
                f"{GITHUB_APP_INSTALLATION_TOKEN_FAILED_MSG}: "
                f"HTTP {response.status_code} — {response.text}"
            )

        data = response.json()
        token = data.get("token")
        if not token:
            raise ActionFailure(GITHUB_APP_INSTALLATION_TOKEN_MISSING_MSG)

        expires_at_str = data.get("expires_at", "")
        try:
            self._expires_at = datetime.datetime.fromisoformat(
                expires_at_str.replace("Z", "+00:00")
            )
        except (ValueError, AttributeError):
            self._expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(
                hours=1
            )

        self._token = token
        return token

    def auth_flow(
        self,
        request: httpx.Request,
    ) -> Generator[httpx.Request, httpx.Response]:
        """Add the installation access token to the request, refreshing as needed."""
        if not self._token_is_valid():
            self._fetch_installation_token()

        request.headers["Authorization"] = f"Bearer {self._token}"
        yield request


def build_github_app_auth(asset: Asset) -> GitHubAppAuth:
    """Return SDK-compatible bearer auth backed by a GitHub App installation token."""
    return GitHubAppAuth(asset)


def resolve_github_auth(asset: Asset) -> httpx.Auth:
    """Return the correct httpx.Auth for the configured asset credentials.

    Priority order:
      1. personal_access_token (PAT)          → StaticTokenAuth
      2. app_id / app_private_key / app_installation_id (GitHub App)
                                               → GitHubAppAuth (installation token)
      3. client_id / client_secret (OAuth App) → OAuthBearerAuth (auth_state)

    Raises ActionFailure when no credential set is present.
    """
    if asset.personal_access_token:
        return build_pat_auth(asset)

    if asset.app_id and asset.app_private_key and asset.app_installation_id:
        return build_github_app_auth(asset)

    if asset.client_id and asset.client_secret:
        return build_oauth_auth(asset)

    raise ActionFailure(GITHUB_CONFIG_PARAMS_REQUIRED)


def has_github_app_config(asset: Asset) -> bool:
    """Return True if GitHub App credentials are fully configured on the asset."""
    return bool(asset.app_id and asset.app_private_key and asset.app_installation_id)
