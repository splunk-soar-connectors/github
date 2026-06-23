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
from ..client import call_github
from ..consts import (
    GITHUB_ADD_REMOVE_COLLABORATOR_ENDPOINT,
    GITHUB_COLLABORATOR_ADDED_MSG,
    GITHUB_COLLABORATOR_INVITATION_NOT_UPDATED_MSG,
    GITHUB_COLLABORATOR_ROLE_NOT_UPDATED_MSG,
    GITHUB_JSON_COLLABORATOR_ADDED,
    GITHUB_JSON_ID,
    GITHUB_JSON_INVITEE,
    GITHUB_JSON_INVITE_SENT,
    GITHUB_JSON_LOGIN,
    GITHUB_JSON_PERMISSIONS,
    GITHUB_JSON_REPO_ROLE,
    GITHUB_LIST_COLLABORATOR_ENDPOINT,
    GITHUB_LIST_COLLABORATOR_PENDING_INVITATIONS_ENDPOINT,
    GITHUB_PARAM_AFFILIATION,
    GITHUB_PARAM_AFFILIATION_DIRECT,
    GITHUB_REPO_ROLE_ADMIN,
    GITHUB_REPO_ROLE_PULL,
    GITHUB_REPO_ROLE_PUSH,
    GITHUB_REPO_ROLE_READ,
    GITHUB_REPO_ROLE_WRITE,
    GITHUB_REQUEST_PATCH,
    GITHUB_REQUEST_PUT,
    GITHUB_UPDATE_DELETE_COLLABORATOR_INVITATION_ENDPOINT,
)
from ..views import display_view
from ._helpers import _check_response, _if_role_same, _paginate_all

logger = getLogger()


class AddCollaboratorParams(Params):
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
    role: str | None = Param(
        description="Role of the user (Default: Push)",
        default="Push",
        value_list=["Pull", "Push", "Admin"],
        column_name="Role",
    )
    override: bool | None = Param(
        description="Override existing role of collaborator",
        column_name="Override Role",
    )


class InviteeOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/29930053?v=4"],
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
    id: float = OutputField(example_values=[29900753])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    node_id: str = OutputField(
        example_values=["MDQ6VXlNcjI5OTM5NzUz"]  # pragma: allowlist secret
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


class InviterOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/41300385?v=4"],
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
    id: float = OutputField(example_values=[41300385])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    node_id: str = OutputField(
        example_values=["MDQ6VXlNcjQxMzMxMzg1"]  # pragma: allowlist secret
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


class AddCollaboratorOutput(ActionOutput):
    collaborator_added: bool = OutputField(column_name="Collaborator Added")
    created_at: str | None = OutputField(example_values=["2018-07-25T12:47:00Z"])
    html_url: str | None = OutputField(
        cef_types=["url"],
        example_values=["https://github.com/test/test-repo/invitations"],
    )
    id: float | None = OutputField(example_values=[10200401])
    invite_sent: bool = OutputField(column_name="Invite Sent")
    invitee: InviteeOutput | None = OutputField()
    inviter: InviterOutput | None = OutputField()
    node_id: str | None = OutputField(
        example_values=[
            "MDIwOlJlGc9zaXRvcnlJbnZpdGF0aW9uMTAyNDU0MDE="  # pragma: allowlist secret
        ]  # pragma: allowlist secret
    )
    permissions: str | None = OutputField(example_values=["admin"])
    url: str | None = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/user/repository_invitations/10245401"],
    )


@app.action(
    description="Add user as a collaborator to repo",
    action_type="generic",
    read_only=False,
    verbose="For repo whose owner is an organization, if the user is not a member of the organization, GitHub will send an email invite to the user to join as a collaborator. Otherwise, he will be directly added as a collaborator. For repo whose owner is a user, GitHub will always send an email invite to the user to join as a collaborator. If an invite is already sent to the user, re-invite will not be sent. If the user is already a collaborator, his role will be updated.",
    view_handler=display_view,
)
def add_collaborator(
    params: AddCollaboratorParams, soar: SOARClient, asset: Asset
) -> AddCollaboratorOutput:
    repo = f"{params.repo_owner}/{params.repo_name}"
    user = params.user
    role = (params.role or "Push").lower()
    override = params.override or False

    role_mapping = {
        GITHUB_REPO_ROLE_PULL: GITHUB_REPO_ROLE_READ,
        GITHUB_REPO_ROLE_PUSH: GITHUB_REPO_ROLE_WRITE,
        GITHUB_REPO_ROLE_ADMIN: GITHUB_REPO_ROLE_ADMIN,
    }

    # 1. Check direct collaborators
    direct_endpoint = GITHUB_LIST_COLLABORATOR_ENDPOINT.format(repo_full_name=repo)
    direct_collaborators = _paginate_all(
        direct_endpoint,
        asset,
        extra_params={GITHUB_PARAM_AFFILIATION: GITHUB_PARAM_AFFILIATION_DIRECT},
    )

    collaborator_exists_diff_role = False
    for collaborator in direct_collaborators:
        if user.lower() == collaborator.get(GITHUB_JSON_LOGIN, "").lower():
            if _if_role_same(collaborator, role):
                return AddCollaboratorOutput(
                    invite_sent=False, collaborator_added=False
                )
            collaborator_exists_diff_role = True
            break
    else:
        # 2. User is not a direct collaborator — check pending invitations
        invitations_endpoint = (
            GITHUB_LIST_COLLABORATOR_PENDING_INVITATIONS_ENDPOINT.format(
                repo_full_name=repo
            )
        )
        pending = _paginate_all(invitations_endpoint, asset)

        for invitation in pending:
            if (
                user.lower()
                == invitation.get(GITHUB_JSON_INVITEE, {})
                .get(GITHUB_JSON_LOGIN, "")
                .lower()
            ):
                if (
                    role_mapping[role].lower()
                    == invitation.get(GITHUB_JSON_PERMISSIONS, "").lower()
                ):
                    return AddCollaboratorOutput(
                        invite_sent=False, collaborator_added=False
                    )
                if override:
                    upd_endpoint = (
                        GITHUB_UPDATE_DELETE_COLLABORATOR_INVITATION_ENDPOINT.format(
                            repo_full_name=repo,
                            invitation_id=invitation[GITHUB_JSON_ID],
                        )
                    )
                    _check_response(
                        call_github(
                            GITHUB_REQUEST_PATCH.upper(),
                            upd_endpoint,
                            asset,
                            json={GITHUB_JSON_PERMISSIONS: role_mapping[role]},
                        )
                    )
                    return AddCollaboratorOutput(
                        invite_sent=True, collaborator_added=False
                    )
                raise ActionFailure(GITHUB_COLLABORATOR_INVITATION_NOT_UPDATED_MSG)

    # 3. Collaborator exists with different role — update only if override=True
    if collaborator_exists_diff_role and not override:
        raise ActionFailure(GITHUB_COLLABORATOR_ROLE_NOT_UPDATED_MSG)

    # 4. PUT /repos/{repo}/collaborators/{user} — adds new collaborator or updates role
    add_endpoint = GITHUB_ADD_REMOVE_COLLABORATOR_ENDPOINT.format(
        repo_full_name=repo, user_name=user
    )
    response = call_github(
        GITHUB_REQUEST_PUT.upper(),
        add_endpoint,
        asset,
        json={GITHUB_JSON_REPO_ROLE: role},
    )
    _check_response(response)

    body = response.json() if response.content else {}
    if body and isinstance(body, dict):
        # 201 — invitation sent
        soar.set_message(
            GITHUB_COLLABORATOR_ADDED_MSG.format(
                user_name=user, repo_full_name=repo, repo_role=role
            )
        )
        return AddCollaboratorOutput(
            **{
                **body,
                GITHUB_JSON_INVITE_SENT: True,
                GITHUB_JSON_COLLABORATOR_ADDED: False,
            }
        )
    # 204 — user directly added (org member)
    soar.set_message(
        GITHUB_COLLABORATOR_ADDED_MSG.format(
            user_name=user, repo_full_name=repo, repo_role=role
        )
    )
    return AddCollaboratorOutput(invite_sent=False, collaborator_added=True)
