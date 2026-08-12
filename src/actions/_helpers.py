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

from soar_sdk.exceptions import ActionFailure
from urllib.parse import quote

from ..client import call_github
from ..consts import (
    GITHUB_INVALID_TEAM_ID,
    GITHUB_JSON_ID,
    GITHUB_JSON_NAME,
    GITHUB_JSON_PERMISSIONS,
    GITHUB_LIST_TEAMS_ENDPOINT,
    GITHUB_ORGANIZATION_REQUIRED_MSG,
    GITHUB_PAGINATION_MAX_PAGES,
    GITHUB_PAGINATION_MAX_SIZE,
    GITHUB_REPO_ROLE_ADMIN,
    GITHUB_REPO_ROLE_PULL,
    GITHUB_REPO_ROLE_PUSH,
)


def _format_endpoint(template: str, **segments: object) -> str:
    """Format an API endpoint after encoding each caller-controlled path segment."""
    normalized = {name: str(value) for name, value in segments.items()}
    invalid_segments = [
        name for name, value in normalized.items() if value in {".", ".."}
    ]
    if invalid_segments:
        raise ActionFailure(
            f"Invalid path identifier: {', '.join(sorted(invalid_segments))} cannot be a dot segment"
        )

    return template.format(
        **{name: quote(value, safe="") for name, value in normalized.items()}
    )


def _paginate_all(
    endpoint: str,
    asset,
    extra_params: dict | None = None,
    limit: int | None = None,
) -> list:
    """Exhaust all pages of a GitHub list endpoint and return every item, up to limit."""
    results = []
    for page in range(1, GITHUB_PAGINATION_MAX_PAGES + 1):
        query = {
            "per_page": GITHUB_PAGINATION_MAX_SIZE,
            "page": page,
            **(extra_params or {}),
        }
        response = call_github("GET", endpoint, asset, params=query)
        _check_response(response)
        page_items = response.json()
        if isinstance(page_items, dict):
            page_items = [page_items]
        results.extend(page_items)
        if limit is not None and len(results) >= limit:
            return results[:limit]
        if len(page_items) < GITHUB_PAGINATION_MAX_SIZE:
            return results
    raise ActionFailure(
        f"GitHub pagination exceeded the {GITHUB_PAGINATION_MAX_PAGES}-page safety limit"
    )


def _resolve_team_id(team: str, org_name: str | None, asset) -> int:
    """Return a numeric team ID from either a numeric string or a team name.

    Mirrors legacy _verify_and_get_team_id: numeric input is used directly;
    a name requires org_name and triggers a search across GET /orgs/{org}/teams.
    Raises ActionFailure when the team cannot be found.
    """
    if team.isdigit():
        return int(team)

    if not org_name:
        raise ActionFailure(GITHUB_ORGANIZATION_REQUIRED_MSG)

    teams = _paginate_all(
        _format_endpoint(GITHUB_LIST_TEAMS_ENDPOINT, org_name=org_name), asset
    )
    for t in teams:
        if t.get(GITHUB_JSON_NAME, "").lower() == team.lower():
            return t[GITHUB_JSON_ID]

    raise ActionFailure(GITHUB_INVALID_TEAM_ID.format(team=team))


def _check_response(response) -> None:
    """Raise ActionFailure for any non-2xx GitHub API response."""
    if not response.is_success:
        raise ActionFailure(f"GitHub API error {response.status_code}: {response.text}")


def _if_role_same(collaborator: dict, role: str) -> bool:
    """Mirror of legacy _if_role_same: check whether collaborator's current permissions match role."""
    perms = collaborator.get(GITHUB_JSON_PERMISSIONS, {})
    pull = perms.get(GITHUB_REPO_ROLE_PULL, False)
    push = perms.get(GITHUB_REPO_ROLE_PUSH, False)
    admin = perms.get(GITHUB_REPO_ROLE_ADMIN, False)
    if role == GITHUB_REPO_ROLE_PULL:
        return pull and not push and not admin
    if role == GITHUB_REPO_ROLE_PUSH:
        return pull and push and not admin
    if role == GITHUB_REPO_ROLE_ADMIN:
        return pull and push and admin
    return False
