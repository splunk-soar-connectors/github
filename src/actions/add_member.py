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
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..client import call_github
from ..consts import (
    GITHUB_ADD_MEMBER_MSG,
    GITHUB_ADD_MEMBER_PENDING_MSG,
    GITHUB_ADD_REMOVE_MEMBER_ENDPOINT,
    GITHUB_ALREADY_TEAM_MEMBER_MSG,
    GITHUB_GET_MEMBERS_ENDPOINT,
    GITHUB_JSON_LOGIN,
    GITHUB_JSON_ROLE,
    GITHUB_REQUEST_PUT,
)
from ..views import display_view
from ._helpers import _check_response, _paginate_all, _resolve_team_id

logger = getLogger()

class AddMemberParams(Params):
    organization_name: str | None = Param(
        description="Organization name",
        primary=True,
        cef_types=["github organization name"],
        column_name="Organization Name",
    )
    team: str = Param(
        description="Team name or team ID",
        primary=True,
        cef_types=["github team name", "github team id"],
        column_name="Team",
    )
    user: str = Param(
        description="Username",
        primary=True,
        cef_types=["github username"],
        column_name="User",
    )
    role: str | None = Param(
        description="Role of the user (Default: Member)",
        default="Member",
        value_list=["Member", "Maintainer"],
        column_name="Role",
    )


class AddMemberOutput(ActionOutput):
    state: str = OutputField(
        example_values=["active", "pending"], column_name="Membership State"
    )
    status: str = OutputField(
        example_values=["success", "failed"], column_name="Status"
    )
    role: str = OutputField(example_values=["member", "maintainer"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/teams/2830072/memberships/test"],
    )


@app.action(
    description="Add user in a team",
    action_type="generic",
    read_only=False,
    verbose="Parameter 'organization name' is mandatory if the team name is provided instead of team ID.",
    view_handler=display_view,
)
def add_member(
    params: AddMemberParams, soar: SOARClient, asset: Asset
) -> AddMemberOutput:
    role = (params.role or "Member").lower()
    team_id = _resolve_team_id(params.team, params.organization_name, asset)

    members = _paginate_all(
        GITHUB_GET_MEMBERS_ENDPOINT.format(team_id=team_id),
        asset,
        extra_params={GITHUB_JSON_ROLE: role},
    )
    for member in members:
        if member.get(GITHUB_JSON_LOGIN, "").lower() == params.user.lower():
            soar.set_message(
                GITHUB_ALREADY_TEAM_MEMBER_MSG.format(
                    user_name=params.user, team=params.team, role=role
                )
            )
            return AddMemberOutput(**member, status="success")

    response = call_github(
        GITHUB_REQUEST_PUT.upper(),
        GITHUB_ADD_REMOVE_MEMBER_ENDPOINT.format(
            team_id=team_id, user_name=params.user
        ),
        asset,
        json={GITHUB_JSON_ROLE: role},
    )
    _check_response(response)
    data = response.json()
    if data.get("state") == "pending":
        soar.set_message(
            GITHUB_ADD_MEMBER_PENDING_MSG.format(
                user_name=params.user, team=params.team, role=role
            )
        )
    else:
        soar.set_message(
            GITHUB_ADD_MEMBER_MSG.format(
                user_name=params.user, team=params.team, role=role
            )
        )
    return AddMemberOutput(**data, status="success")

