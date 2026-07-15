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

from ..asset import Asset
from ..client import call_github
from ..consts import (
    GITHUB_ADD_REMOVE_MEMBER_ENDPOINT,
    GITHUB_GET_MEMBERS_ENDPOINT,
    GITHUB_JSON_LOGIN,
    GITHUB_LIST_MEMBERS_PENDING_INVITATIONS_ENDPOINT,
    GITHUB_MEMBER_REMOVAL_MSG,
    GITHUB_REQUEST_DELETE,
    GITHUB_USER_NOT_TEAM_MEMBER_MSG,
)
from ._helpers import _check_response, _paginate_all, _resolve_team_id

logger = getLogger()


class RemoveMemberParams(Params):
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


class RemoveMemberOutput(ActionOutput):
    status: str = OutputField(
        example_values=["success", "failed"], column_name="Status"
    )


def remove_member(
    params: RemoveMemberParams, soar: SOARClient, asset: Asset
) -> RemoveMemberOutput:
    team_id = _resolve_team_id(params.team, params.organization_name, asset)

    members = _paginate_all(GITHUB_GET_MEMBERS_ENDPOINT.format(team_id=team_id), asset)
    for member in members:
        if member.get(GITHUB_JSON_LOGIN, "").lower() == params.user.lower():
            _check_response(
                call_github(
                    GITHUB_REQUEST_DELETE.upper(),
                    GITHUB_ADD_REMOVE_MEMBER_ENDPOINT.format(
                        team_id=team_id, user_name=params.user
                    ),
                    asset,
                )
            )
            soar.set_message(
                GITHUB_MEMBER_REMOVAL_MSG.format(
                    user_name=params.user, team=params.team
                )
            )
            return RemoveMemberOutput(status="success")

    pending = _paginate_all(
        GITHUB_LIST_MEMBERS_PENDING_INVITATIONS_ENDPOINT.format(team_id=team_id), asset
    )
    for invitation in pending:
        if params.user.lower() == invitation.get(GITHUB_JSON_LOGIN, "").lower():
            _check_response(
                call_github(
                    GITHUB_REQUEST_DELETE.upper(),
                    GITHUB_ADD_REMOVE_MEMBER_ENDPOINT.format(
                        team_id=team_id, user_name=params.user
                    ),
                    asset,
                )
            )
            soar.set_message(
                GITHUB_MEMBER_REMOVAL_MSG.format(
                    user_name=params.user, team=params.team
                )
            )
            return RemoveMemberOutput(status="success")

    soar.set_message(
        GITHUB_USER_NOT_TEAM_MEMBER_MSG.format(team=params.team, user_name=params.user)
    )
    return RemoveMemberOutput(status="success")
