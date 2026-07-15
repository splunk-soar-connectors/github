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
# OAuth callback webhook for the GitHub app.
#
# The authorization code flow needs a public endpoint for GitHub to redirect the
# user back to with a `?code=` query parameter. This registers that endpoint using
# the SDK's create_oauth_callback_handler, which stores the code in the asset's
# auth_state so test_connectivity's polling loop can pick it up and exchange it.

from __future__ import annotations

from soar_sdk.app import App
from soar_sdk.auth import create_oauth_callback_handler

from .auth import build_oauth_client
from .consts import (
    GITHUB_OAUTH_CALLBACK_ROUTE,
    GITHUB_OAUTH_SUCCESS_MSG,
)


def register_oauth_webhook(app: App) -> App:
    """Enable webhooks and register the OAuth callback route on the app.

    The callback route must be reachable by the user's browser after GitHub
    redirects, so it is registered without requiring SOAR authentication.
    """
    app.enable_webhooks(default_requires_auth=False)

    # The SDK handler pulls ?code= off the redirect, resolves the OAuth client
    # from request.asset (already a typed Asset with auth_state bound), and
    # stores the code so test_connectivity's poll loop can exchange it.
    oauth_callback = create_oauth_callback_handler(
        build_oauth_client,
        success_message=GITHUB_OAUTH_SUCCESS_MSG,
    )

    @app.webhook(GITHUB_OAUTH_CALLBACK_ROUTE, allowed_methods=["GET"])
    def github_oauth_callback(request):
        return oauth_callback(request)

    return app
