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
    GITHUB_ADD_REMOVE_COLLABORATOR_ENDPOINT,
    GITHUB_COLLABORATOR_REMOVED_MSG,
    GITHUB_JSON_ID,
    GITHUB_JSON_INVITEE,
    GITHUB_JSON_LOGIN,
    GITHUB_LIST_COLLABORATOR_ENDPOINT,
    GITHUB_LIST_COLLABORATOR_PENDING_INVITATIONS_ENDPOINT,
    GITHUB_PARAM_AFFILIATION,
    GITHUB_PARAM_AFFILIATION_DIRECT,
    GITHUB_REQUEST_DELETE,
    GITHUB_UPDATE_DELETE_COLLABORATOR_INVITATION_ENDPOINT,
    GITHUB_USER_NOT_COLLABORATOR_MSG,
)
from ._helpers import _check_response, _paginate_all

logger = getLogger()


class RemoveCollaboratorParams(Params):
    repo_owner: str = Param(
        description="Owner of the repository",
        primary=True,
        cef_types=["github repo owner", "github username"],
        column_name="Repo Owner",
    )
    repo_name: str = Param(
        description="Name of the repository",
        primary=True,
        cef_types=["github repo"],
        column_name="Repo Name",
    )
    user: str = Param(
        description="Username",
        primary=True,
        cef_types=["github username"],
        column_name="User",
    )


class RemoveCollaboratorOutput(ActionOutput):
    invite_deleted: bool = OutputField(column_name="Invite Deleted")


def remove_collaborator(
    params: RemoveCollaboratorParams, soar: SOARClient, asset: Asset
) -> RemoveCollaboratorOutput:
    repo = f"{params.repo_owner}/{params.repo_name}"
    user = params.user

    direct_endpoint = GITHUB_LIST_COLLABORATOR_ENDPOINT.format(repo_full_name=repo)
    direct_collaborators = _paginate_all(
        direct_endpoint,
        asset,
        extra_params={GITHUB_PARAM_AFFILIATION: GITHUB_PARAM_AFFILIATION_DIRECT},
    )

    for collaborator in direct_collaborators:
        if user.lower() == collaborator.get(GITHUB_JSON_LOGIN, "").lower():
            remove_endpoint = GITHUB_ADD_REMOVE_COLLABORATOR_ENDPOINT.format(
                repo_full_name=repo, user_name=user
            )
            _check_response(
                call_github(GITHUB_REQUEST_DELETE.upper(), remove_endpoint, asset)
            )
            soar.set_message(
                GITHUB_COLLABORATOR_REMOVED_MSG.format(
                    repo_full_name=repo, user_name=user
                )
            )
            return RemoveCollaboratorOutput(invite_deleted=False)

    invitations_endpoint = GITHUB_LIST_COLLABORATOR_PENDING_INVITATIONS_ENDPOINT.format(
        repo_full_name=repo
    )
    pending = _paginate_all(invitations_endpoint, asset)

    invite_deleted = False
    for invitation in pending:
        if (
            user.lower()
            == invitation.get(GITHUB_JSON_INVITEE, {})
            .get(GITHUB_JSON_LOGIN, "")
            .lower()
        ):
            del_endpoint = GITHUB_UPDATE_DELETE_COLLABORATOR_INVITATION_ENDPOINT.format(
                repo_full_name=repo, invitation_id=invitation[GITHUB_JSON_ID]
            )
            _check_response(
                call_github(GITHUB_REQUEST_DELETE.upper(), del_endpoint, asset)
            )
            invite_deleted = True

    if not invite_deleted:
        soar.set_message(
            GITHUB_USER_NOT_COLLABORATOR_MSG.format(user_name=user, repo_full_name=repo)
        )
    else:
        soar.set_message(
            GITHUB_COLLABORATOR_REMOVED_MSG.format(repo_full_name=repo, user_name=user)
        )
    return RemoveCollaboratorOutput(invite_deleted=invite_deleted)
