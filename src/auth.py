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

from typing import TYPE_CHECKING

import httpx

from soar_sdk.auth import (
    AuthorizationCodeFlow,
    OAuthBearerAuth,
    OAuthConfig,
    SOARAssetOAuthClient,
    StaticTokenAuth,
)
from soar_sdk.exceptions import ActionFailure

from .consts import (
    GITHUB_AUTHORIZE_ENDPOINT,
    GITHUB_CONFIG_PARAMS_REQUIRED,
    GITHUB_SCOPE,
    GITHUB_TOKEN_ENDPOINT,
)

if TYPE_CHECKING:
    from .app import Asset


def build_pat_auth(asset: Asset) -> StaticTokenAuth:
    """Return SDK bearer auth for a Personal Access Token."""
    return StaticTokenAuth(asset.personal_access_token)


def _build_oauth_config(asset: Asset) -> OAuthConfig:
    """Build the OAuth config shared by the flow and the bearer auth."""
    return OAuthConfig(
        client_id=asset.client_id,
        client_secret=asset.client_secret,
        authorization_endpoint=GITHUB_AUTHORIZE_ENDPOINT,
        token_endpoint=GITHUB_TOKEN_ENDPOINT,
        scope=GITHUB_SCOPE,
    )


def build_oauth_client(asset: Asset) -> SOARAssetOAuthClient:
    """Return the SDK OAuth client bound to the asset's persisted auth_state."""
    return SOARAssetOAuthClient(_build_oauth_config(asset), asset.auth_state)


def build_oauth_auth(asset: Asset) -> OAuthBearerAuth:
    """Return SDK bearer auth that reads/refreshes the OAuth token from auth_state."""
    return OAuthBearerAuth(build_oauth_client(asset), auto_refresh=True)


def build_oauth_flow(
    asset: Asset,
    asset_id: str,
    *,
    redirect_uri: str,
) -> AuthorizationCodeFlow:
    """Return the authorization code flow used to kick off user authorization."""
    return AuthorizationCodeFlow(
        asset.auth_state,
        asset_id,
        client_id=asset.client_id,
        client_secret=asset.client_secret,
        authorization_endpoint=GITHUB_AUTHORIZE_ENDPOINT,
        token_endpoint=GITHUB_TOKEN_ENDPOINT,
        redirect_uri=redirect_uri,
        scope=GITHUB_SCOPE,
        use_pkce=False,
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
