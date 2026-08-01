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
# GitHub supports two credential styles:
#   1. Personal Access Token (PAT) — a static bearer token.
#   2. OAuth App (client_id / client_secret) — the authorization code flow,
#      with tokens persisted in the SDK-managed asset.auth_state.
#
# resolve_github_auth() picks between them and returns an httpx.Auth that
# call_github() hands directly to httpx.Client(auth=...).

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from soar_sdk.auth import (
    OAuthBearerAuth,
    OAuthConfig,
    SOARAssetOAuthClient,
    StaticTokenAuth,
)
from soar_sdk.auth.client import ConfigurationChangedError, OAuthToken
from soar_sdk.auth.models import OAuthState
from soar_sdk.logging import getLogger
from soar_sdk.exceptions import ActionFailure

from .consts import (
    DEFAULT_TIMEOUT,
    GITHUB_AUTHORIZE_ENDPOINT,
    GITHUB_CONFIG_PARAMS_REQUIRED,
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
_LEGACY_AUTH_STATE_KEYS = frozenset(
    {
        "access_token",
        "authorization_url",
        "code",
        "oauth_token",
        "redirect_uri",
        "refresh_token",
        "session",
        "token",
    }
)
logger = getLogger()


def _migrate_legacy_oauth_state(asset: Asset) -> None:
    """Move pre-SDK OAuth data into encrypted auth state and remove raw copies."""
    auth_state = asset.auth_state
    backend = auth_state.backend
    state = backend.load_state() or {}
    legacy_keys = _LEGACY_AUTH_STATE_KEYS.intersection(state)
    if not legacy_keys:
        return

    legacy_token = state.get("token")
    current_auth = auth_state.get_all()
    if isinstance(legacy_token, dict) and "oauth" not in current_auth:
        try:
            token = OAuthToken.model_validate(legacy_token)
        except Exception:
            logger.warning(
                "Discarding invalid legacy OAuth token state; reauthorization is required"
            )
        else:
            current_auth["oauth"] = OAuthState(
                token=token,
                client_id=asset.client_id,
            ).model_dump(mode="json", exclude_none=True)
            auth_state.put_all(current_auth)

    sanitized_state = backend.load_state() or {}
    for key in _LEGACY_AUTH_STATE_KEYS:
        sanitized_state.pop(key, None)
    backend.save_state(sanitized_state)

    legacy_file = Path(backend.get_app_dir()) / f"{auth_state.asset_id}_state.json"
    if legacy_file.is_file():
        try:
            file_state = backend.load_state_from_file(auth_state.asset_id)
        except Exception:
            file_state = {}
        if _LEGACY_AUTH_STATE_KEYS.intersection(file_state):
            legacy_file.unlink()


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
    _migrate_legacy_oauth_state(asset)
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


def resolve_github_auth(asset: Asset) -> httpx.Auth:
    """Return the correct httpx.Auth for the configured asset credentials.

    Priority order:
      1. personal_access_token (PAT)          → StaticTokenAuth
      2. client_id / client_secret (OAuth App) → OAuthBearerAuth (auth_state)

    Raises ActionFailure when neither credential set is present.
    """
    if asset.personal_access_token:
        return build_pat_auth(asset)

    if asset.client_id and asset.client_secret:
        return build_oauth_auth(asset)

    raise ActionFailure(GITHUB_CONFIG_PARAMS_REQUIRED)
