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

from ..app import Asset, app
from ..consts import (
    GITHUB_LIST_ORGANIZATIONS_ENDPOINT,
)
from ..views import display_view
from ._helpers import _paginate_all

logger = getLogger()

class ListOrganizationsParams(Params):
    limit: float | None = Param(
        description="Maximum number of organizations to be fetched"
    )


class ListOrganizationsOutput(ActionOutput):
    # Column fields in widget display order
    id: float = OutputField(example_values=[41301665], column_name="Organization Id")
    login: str = OutputField(
        cef_types=["github organization name"],
        example_values=["test"],
        column_name="Organization Name",
    )
    description: str | None = OutputField(column_name="Organization Description")
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/orgs/test"],
        column_name="Organization Url",
    )
    # Non-column fields
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars0.githubusercontent.com/u/41301665?v=4"],
    )
    events_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/orgs/test/events"]
    )
    hooks_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/orgs/test/hooks"]
    )
    issues_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/orgs/test/issues"]
    )
    members_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/orgs/test/members{/member}"],
    )
    node_id: str = OutputField(
        example_values=["MDEyOk9yZ2FuaXphdGlvbjQxMzA5NjY1"]  # pragma: allowlist secret
    )
    public_members_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/orgs/test/public_members{/member}"],
    )
    repos_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/orgs/test/repos"]
    )


class ListOrganizationsSummary(ActionOutput):
    total_organizations: int = OutputField(example_values=[10])


@app.action(
    description="List all organizations",
    action_type="investigate",
    view_handler=display_view,
)
def list_organizations(
    params: ListOrganizationsParams, soar: SOARClient, asset: Asset
) -> list[ListOrganizationsOutput]:
    limit = int(params.limit) if params.limit is not None else None
    if limit is not None and limit <= 0:
        raise ActionFailure("limit must be a positive integer")
    output = [
        ListOrganizationsOutput(**o)
        for o in _paginate_all(GITHUB_LIST_ORGANIZATIONS_ENDPOINT, asset, limit=limit)
    ]
    soar.set_summary(ListOrganizationsSummary(total_organizations=len(output)))
    return output

