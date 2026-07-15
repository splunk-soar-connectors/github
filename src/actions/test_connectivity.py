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

from __future__ import annotations

from typing import TYPE_CHECKING

from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from ..asset import Asset
from ..auth import complete_oauth_authorization
from ..client import call_github
from ..consts import (
    GITHUB_CONFIG_PARAMS_REQUIRED,
    GITHUB_CURRENT_USER_ENDPOINT,
    GITHUB_MAKING_CONNECTION_MSG,
    GITHUB_OAUTH_CALLBACK_ROUTE,
    GITHUB_OAUTH_CALLBACK_URL_MSG,
    GITHUB_OAUTH_LOGIN_URL_MSG,
    GITHUB_TEST_CONNECTIVITY_FAILED_MSG,
    GITHUB_TEST_CONNECTIVITY_PASSED_MSG,
    GITHUB_WAITING_FOR_AUTHORIZATION_MSG,
)
from ._helpers import _check_response

if TYPE_CHECKING:
    from soar_sdk.app import App

logger = getLogger()


def run_test_connectivity(
    soar: SOARClient, asset: Asset, *, app: App | None = None
) -> None:
    """Validate the asset configuration for connectivity using supplied configuration.

    Supports both credential styles:
      * Personal Access Token — probes GET /user directly.
      * OAuth App (client_id/client_secret) — runs the authorization code flow
        (prompting the user to authorize in a browser) before probing GET /user.
    """

    logger.progress("Starting connectivity test")

    if not asset.personal_access_token:
        _authorize_oauth(soar, asset, app=app)

    # GET /user is the canonical connectivity probe.
    endpoint = GITHUB_CURRENT_USER_ENDPOINT

    logger.progress(GITHUB_MAKING_CONNECTION_MSG)
    logger.debug("Sending GET request to %s", endpoint)
    response = call_github("GET", endpoint, asset)
    logger.debug("Received HTTP %s from %s", response.status_code, endpoint)

    if response.status_code == 401:
        logger.error("Authentication failed (HTTP 401) during connectivity test")
        raise ActionFailure(
            f"{GITHUB_TEST_CONNECTIVITY_FAILED_MSG}: "
            "HTTP 401 — check your configured credentials."
        )
    _check_response(response)

    logger.progress(GITHUB_TEST_CONNECTIVITY_PASSED_MSG)


def _authorize_oauth(soar: SOARClient, asset: Asset, *, app: App | None) -> None:
    """Run the OAuth authorization code flow, persisting a token in auth_state."""
    if not (asset.client_id and asset.client_secret):
        logger.error("No Personal Access Token or OAuth credentials configured")
        raise ActionFailure(GITHUB_CONFIG_PARAMS_REQUIRED)

    if app is None:  # pragma: no cover - defensive; app is always supplied at runtime
        raise ActionFailure(
            f"{GITHUB_TEST_CONNECTIVITY_FAILED_MSG}: OAuth flow unavailable."
        )

    # Use the SDK-native webhook URL as the OAuth redirect URI. This resolves to
    # the platform's configured webhook port (defaulting to 3500).
    redirect_uri = app.get_webhook_url(GITHUB_OAUTH_CALLBACK_ROUTE)
    asset_id = str(soar.get_asset_id())

    # The callback URL is known before we build the authorize URL, so surface it
    # up front — the user must register it on the GitHub OAuth App or the redirect
    # after login will fail.
    logger.progress(f"{GITHUB_OAUTH_CALLBACK_URL_MSG}:\n{redirect_uri}")

    def announce_url(auth_url: str) -> None:
        # Emit both URLs in one final message so the SOAR UI — which typically
        # surfaces only the latest progress line — keeps the callback URL (to
        # register) and the login URL (to open) visible while we poll.
        logger.progress(
            f"{GITHUB_OAUTH_CALLBACK_URL_MSG}:\n{redirect_uri}\n\n"
            f"{GITHUB_OAUTH_LOGIN_URL_MSG}:\n{auth_url}\n\n"
            f"{GITHUB_WAITING_FOR_AUTHORIZATION_MSG}"
        )

    complete_oauth_authorization(
        asset,
        asset_id=asset_id,
        redirect_uri=redirect_uri,
        announce_url=announce_url,
    )
