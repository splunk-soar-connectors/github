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

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..consts import (
    GITHUB_LIST_USERS_ENDPOINT,
)
from ._helpers import _format_endpoint, _paginate_all

logger = getLogger()


class ListUsersParams(Params):
    organization_name: str = Param(
        description="Organization name",
        primary=True,
        cef_types=["github organization name"],
    )
    limit: int | None = Param(description="Maximum number of users to be fetched")


class ListUsersOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/29919753?v=4"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/test/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/test/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/test/following{/other_user}"],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/test/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test"]
    )
    id: float = OutputField(example_values=[29939753])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    name: str | None = OutputField(example_values=["Test User"])
    email: str | None = OutputField(
        cef_types=["email"], example_values=["test@example.com"]
    )
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjI5OTM5NzUz"]  # pragma: allowlist secret
    )
    organizations_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/test/orgs"]
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/test/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/test/repos"]
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/test/starred{/owner}{/repo}"],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/test/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/test"]
    )
    starred_at: str | None = OutputField(example_values=["2020-07-09T00:17:55Z"])
    user_view_type: str | None = OutputField(example_values=["public"])


class ListUsersSummary(ActionOutput):
    total_users: int = OutputField(example_values=[10])


def list_users(
    params: ListUsersParams, soar: SOARClient, asset: Asset
) -> list[ListUsersOutput]:
    if params.limit is not None and params.limit <= 0:
        raise ActionFailure("limit must be a positive integer")
    endpoint = _format_endpoint(
        GITHUB_LIST_USERS_ENDPOINT, organization_name=params.organization_name
    )
    output = [
        ListUsersOutput(**u) for u in _paginate_all(endpoint, asset, limit=params.limit)
    ]
    soar.set_summary(ListUsersSummary(total_users=len(output)))
    return output
