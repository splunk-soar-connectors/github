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
    GITHUB_LIST_TEAMS_ENDPOINT,
)
from ..views import display_view
from ._helpers import _paginate_all

logger = getLogger()


class ListTeamsParams(Params):
    organization_name: str = Param(
        description="Organization name",
        primary=True,
        cef_types=["github organization name"],
        column_name="Organization Name",
    )
    limit: float | None = Param(description="Maximum number of teams to be fetched")


class ListTeamsOutput(ActionOutput):
    id: float = OutputField(
        cef_types=["github team id"], example_values=[2825460], column_name="Team Id"
    )
    name: str = OutputField(
        cef_types=["github team name"],
        example_values=["new team"],
        column_name="Team Name",
    )
    description: str | None = OutputField(
        example_values=["New team"], column_name="Team Description"
    )
    privacy: str = OutputField(example_values=["closed"], column_name="Privacy")
    permission: str = OutputField(example_values=["pull"], column_name="Permission")
    members_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/teams/2825460/members{/member}"],
    )
    node_id: str = OutputField(
        example_values=["MDQ6VGVhbTI4JmcyNjA="]  # pragma: allowlist secret
    )
    repositories_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/teams/2825460/repos"]
    )
    slug: str = OutputField(example_values=["new-team"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/teams/2825460"]
    )


class ListTeamsSummary(ActionOutput):
    total_teams: int = OutputField(example_values=[10])


@app.action(
    description="List all teams of an organization",
    action_type="investigate",
    view_handler=display_view,
)
def list_teams(
    params: ListTeamsParams, soar: SOARClient, asset: Asset
) -> list[ListTeamsOutput]:
    limit = int(params.limit) if params.limit is not None else None
    if limit is not None and limit <= 0:
        raise ActionFailure("limit must be a positive integer")
    endpoint = GITHUB_LIST_TEAMS_ENDPOINT.format(org_name=params.organization_name)
    output = [ListTeamsOutput(**t) for t in _paginate_all(endpoint, asset, limit=limit)]
    soar.set_summary(ListTeamsSummary(total_teams=len(output)))
    return output
