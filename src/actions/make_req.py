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
# Make Request Action — arbitrary GitHub API call using the asset's configured credentials.
#
# This mirrors what the legacy connector's _handle_update_request + _make_rest_call did,
# but exposed as a first-class SOAR action so playbooks can hit any GitHub endpoint
# without needing a dedicated handler.

import json

import httpx
from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import MakeRequestParams, Param

from ..asset import Asset
from ..auth import resolve_github_auth
from ..client import GITHUB_DEFAULT_HEADERS
from ..consts import GITHUB_API_BASE_URL

logger = getLogger()


# ---------------------------------------------------------------------------
# Params / Output
# ---------------------------------------------------------------------------


class GitHubMakeRequestParams(MakeRequestParams):
    """Custom params: overrides the endpoint description for GitHub-specific context."""

    endpoint: str = Param(
        description=(
            "GitHub API endpoint path appended to https://api.github.com. "
            "Do not include the base URL. "
            "Examples: '/user', '/repos/owner/name/issues', '/orgs/my-org/teams', "
            "'/repos/owner/name/issues/1/labels'."
        ),
    )


class GitHubMakeRequestOutput(MakeRequestOutput):
    """Output for the make_request action.

    Inherits status_code and response_body from MakeRequestOutput.
    Additionally, if the GitHub API returns a JSON object, its top-level keys are
    merged in as individual output fields so downstream playbook steps can reference
    them directly (e.g. action_result.data.*.number for an issue number).
    """

    def __init__(self, **data):
        # Separate the two declared fields from any extra JSON keys we want to attach
        known = {
            "status_code": data.pop("status_code", None),
            "response_body": data.pop("response_body", None),
        }
        super().__init__(**{k: v for k, v in known.items() if v is not None})

        # Attach extra keys directly so they show up in the SOAR action result data
        for key, value in data.items():
            object.__setattr__(self, key, value)

    @classmethod
    def from_response(cls, response: httpx.Response) -> "GitHubMakeRequestOutput":
        """Build the output from an httpx Response, merging JSON keys when possible."""
        data: dict = {
            "status_code": response.status_code,
            "response_body": response.text,
        }

        try:
            json_body = response.json()
            # Only merge top-level keys when the response is a single JSON object.
            # GitHub list endpoints return arrays — those are preserved as response_body
            # and not merged, because there is no stable set of keys to promote.
            if isinstance(json_body, dict):
                data.update(json_body)
        except Exception as exc:
            logger.warning(f"Response body is not JSON — skipping field merge: {exc!s}")

        return cls(**data)


# ---------------------------------------------------------------------------
# Validation helpers (query string)
# ---------------------------------------------------------------------------


def _is_valid_query_string(query_string: str) -> bool:
    """Return True if the string follows key=value&key2=value2 format."""
    if not query_string or not query_string.strip():
        return False
    for raw_pair in query_string.split("&"):
        pair = raw_pair.strip()
        if not pair or "=" not in pair:
            return False
        key, _, _ = pair.partition("=")
        if not key.strip():
            return False
    return True


# ---------------------------------------------------------------------------
# Action handler
# ---------------------------------------------------------------------------


def make_request(
    params: GitHubMakeRequestParams, asset: Asset
) -> GitHubMakeRequestOutput:
    """Execute an arbitrary HTTP request against the GitHub API.

    Handles all three authentication modes configured on the asset:
    username/password basic auth, personal access token, and OAuth Bearer token.
    The endpoint is appended to https://api.github.com — do not include the base URL.
    """
    logger.info(f"make_request: {params.http_method} {params.endpoint}")

    # --- endpoint validation -------------------------------------------------

    endpoint = params.endpoint

    # Reject full URLs — the base URL is fixed to api.github.com
    if endpoint.startswith(("http://", "https://")):
        raise ActionFailure(
            f"Invalid endpoint '{endpoint}': provide only the path after "
            f"https://api.github.com (e.g. '/repos/owner/repo/issues')."
        )

    # Normalise: ensure a leading slash
    if not endpoint.startswith("/"):
        endpoint = f"/{endpoint}"

    url = f"{GITHUB_API_BASE_URL}{endpoint}"

    # --- query parameters ----------------------------------------------------

    query_params: dict | None = None

    if params.query_parameters:
        try:
            # Accept a JSON object: {"per_page": 100, "page": 2}
            query_params = json.loads(params.query_parameters)
        except (json.JSONDecodeError, TypeError):
            # Fall back to raw key=value&key2=value2 string — append directly to URL
            raw_qs = params.query_parameters.lstrip("?")
            if not _is_valid_query_string(raw_qs):
                raise ActionFailure(
                    f"Invalid query_parameters: expected a JSON object or "
                    f"key=value&key2=value2 format, got: {params.query_parameters!r}"
                ) from None
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}{raw_qs}"

    # --- request body --------------------------------------------------------

    json_body: dict | None = None

    if params.body:
        try:
            json_body = json.loads(params.body)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ActionFailure(f"Invalid JSON body: {params.body!r}") from exc

    # --- headers -------------------------------------------------------------

    merged_headers: dict[str, str] = dict(GITHUB_DEFAULT_HEADERS)

    if params.headers:
        try:
            parsed_headers = json.loads(params.headers)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ActionFailure(f"Invalid JSON headers: {params.headers!r}") from exc
        # Caller-supplied headers override defaults (e.g. a custom Accept value)
        merged_headers.update(parsed_headers)

    # --- auth ----------------------------------------------------------------

    auth = resolve_github_auth(asset)

    # --- send the request ----------------------------------------------------

    timeout = params.timeout if params.timeout else 30
    verify = params.verify_ssl if params.verify_ssl is not None else True

    try:
        with httpx.Client(timeout=timeout, verify=verify) as client:
            response = client.request(
                method=params.http_method,
                url=url,
                auth=auth,
                headers=merged_headers,
                params=query_params,
                # json= sends the body as application/json with Content-Type set automatically
                json=json_body if json_body is not None else None,
            )
    except httpx.RequestError as exc:
        # Network-level error (DNS failure, connection refused, timeout, etc.)
        raise ActionFailure(f"Error connecting to GitHub API: {exc}") from exc
    except Exception as exc:
        raise ActionFailure(f"Unexpected error during request: {exc}") from exc

    logger.info(
        f"make_request completed: HTTP {response.status_code} "
        f"for {params.http_method} {params.endpoint}"
    )

    return GitHubMakeRequestOutput.from_response(response)
