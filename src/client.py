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
# Shared HTTP client utilities used by both test_connectivity and make_request.
#
# The legacy connector centralised auth resolution in _handle_update_request and
# all HTTP calls in _make_rest_call.  This module is the SDK equivalent — a single
# place that knows how to pick the right credentials and fire a request, so every
# action doesn't duplicate that logic.

from collections.abc import Generator

import httpx

from soar_sdk.exceptions import ActionFailure

from .consts import (
    GITHUB_API_BASE_URL,
    GITHUB_CONFIG_PARAMS_REQUIRED,
)

# GitHub's recommended headers for REST API v3 calls.
# X-GitHub-Api-Version pins the behaviour to the 2022-11-28 schema version.
GITHUB_DEFAULT_HEADERS: dict[str, str] = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


class _BearerAuth(httpx.Auth):
    """Injects 'Authorization: Bearer <token>' for OAuth access tokens."""

    def __init__(self, token: str) -> None:
        self._token = token

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response]:
        request.headers["Authorization"] = f"Bearer {self._token}"
        yield request


def resolve_auth(asset) -> httpx.Auth:
    """Return the correct httpx.Auth object for the configured asset credentials.

    Priority order:
      1. personal_access_token (PAT)  →  Authorization: Bearer

    Raises ActionFailure when no credentials are present.
    """
    if asset.personal_access_token:
        return _BearerAuth(asset.personal_access_token)

    raise ActionFailure(GITHUB_CONFIG_PARAMS_REQUIRED)


def call_github(
    method: str,
    endpoint: str,
    asset,
    *,
    params: dict | None = None,
    json: dict | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 30.0,
    verify: bool = True,
) -> httpx.Response:
    """Make a single authenticated request to the GitHub REST API.

    Builds the full URL from GITHUB_API_BASE_URL + endpoint, attaches the
    default GitHub headers (Accept / X-GitHub-Api-Version), merges any
    caller-supplied headers on top, and resolves auth from the asset.

    Raises ActionFailure on network errors so callers don't need try/except.
    """
    url = f"{GITHUB_API_BASE_URL}{endpoint}"

    headers = {**GITHUB_DEFAULT_HEADERS, **(extra_headers or {})}
    auth = resolve_auth(asset)  # raises ActionFailure when unconfigured

    try:
        with httpx.Client(timeout=timeout, verify=verify) as client:
            return client.request(
                method=method,
                url=url,
                auth=auth,
                headers=headers,
                params=params,
                json=json,
            )
    except httpx.RequestError as exc:
        raise ActionFailure(f"Error connecting to GitHub API: {exc}") from exc
    except Exception as exc:
        raise ActionFailure(f"Unexpected error during request: {exc}") from exc
