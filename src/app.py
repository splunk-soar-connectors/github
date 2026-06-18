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
from pydantic import model_validator
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params


# Custom Imports
from .client import call_github
from .consts import (
    GITHUB_ADD_MEMBER_MSG,
    GITHUB_ADD_MEMBER_PENDING_MSG,
    GITHUB_ADD_REMOVE_COLLABORATOR_ENDPOINT,
    GITHUB_ADD_REMOVE_MEMBER_ENDPOINT,
    GITHUB_ALREADY_TEAM_MEMBER_MSG,
    GITHUB_COLLABORATOR_ADDED_MSG,
    GITHUB_COLLABORATOR_INVITATION_NOT_UPDATED_MSG,
    GITHUB_COLLABORATOR_REMOVED_MSG,
    GITHUB_COLLABORATOR_ROLE_NOT_UPDATED_MSG,
    GITHUB_CONFIG_PARAMS_REQUIRED_CONNECTIVITY,
    GITHUB_CURRENT_USER_ENDPOINT,
    GITHUB_ENDPOINT_COMMENTS,
    GITHUB_ENDPOINT_GET_ISSUE,
    GITHUB_ENDPOINT_ISSUES,
    GITHUB_ENDPOINT_LABELS,
    GITHUB_EVENTS_ENDPOINT,
    GITHUB_GET_MEMBERS_ENDPOINT,
    GITHUB_INVALID_TEAM_ID,
    GITHUB_JSON_COLLABORATOR_ADDED,
    GITHUB_JSON_ID,
    GITHUB_JSON_INVITEE,
    GITHUB_JSON_INVITE_SENT,
    GITHUB_JSON_LOGIN,
    GITHUB_JSON_NAME,
    GITHUB_JSON_PERMISSIONS,
    GITHUB_JSON_REPO_ROLE,
    GITHUB_JSON_ROLE,
    GITHUB_LABEL_ADDED_MSG,
    GITHUB_LIST_COLLABORATOR_ENDPOINT,
    GITHUB_LIST_COLLABORATOR_PENDING_INVITATIONS_ENDPOINT,
    GITHUB_LIST_MEMBERS_PENDING_INVITATIONS_ENDPOINT,
    GITHUB_LIST_ORGANIZATIONS_ENDPOINT,
    GITHUB_LIST_REPOS_ENDPOINT,
    GITHUB_LIST_TEAMS_ENDPOINT,
    GITHUB_LIST_USERS_ENDPOINT,
    GITHUB_MEMBER_REMOVAL_MSG,
    GITHUB_ORGANIZATION_REQUIRED_MSG,
    GITHUB_PAGINATION_MAX_SIZE,
    GITHUB_PARAM_AFFILIATION,
    GITHUB_PARAM_AFFILIATION_DIRECT,
    GITHUB_REPO_ROLE_ADMIN,
    GITHUB_REPO_ROLE_PULL,
    GITHUB_REPO_ROLE_PUSH,
    GITHUB_REPO_ROLE_READ,
    GITHUB_REPO_ROLE_WRITE,
    GITHUB_REQUEST_DELETE,
    GITHUB_REQUEST_PATCH,
    GITHUB_REQUEST_POST,
    GITHUB_REQUEST_PUT,
    GITHUB_TEST_CONNECTIVITY_FAILED_MSG,
    GITHUB_UPDATE_DELETE_COLLABORATOR_INVITATION_ENDPOINT,
    GITHUB_USER_NOT_COLLABORATOR_MSG,
    GITHUB_USER_NOT_TEAM_MEMBER_MSG,
)
from .views import display_view


logger = getLogger()


class Asset(BaseAsset):
    personal_access_token: str | None = AssetField(
        description="Personal Access Token (PAT)", sensitive=True
    )
    client_id: str | None = AssetField(description="OAuth App Client ID")
    client_secret: str | None = AssetField(
        description="OAuth App Client Secret", sensitive=True
    )


app = App(
    name="GitHub",
    app_type="information",
    logo="logo_github.svg",
    logo_dark="logo_github_dark.svg",
    product_vendor="Microsoft",
    product_name="GitHub",
    publisher="Splunk",
    appid="5553a13b-ca44-4d03-ac48-293fce874001",
    fips_compliant=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Validate the asset configuration for connectivity using supplied configuration."""

    if not asset.personal_access_token:
        raise ActionFailure(GITHUB_CONFIG_PARAMS_REQUIRED_CONNECTIVITY)

    # GET /user is the canonical connectivity probe.
    endpoint = GITHUB_CURRENT_USER_ENDPOINT

    response = call_github("GET", endpoint, asset)
    if response.status_code == 401:
        raise ActionFailure(
            f"{GITHUB_TEST_CONNECTIVITY_FAILED_MSG}: "
            "HTTP 401 — check your Personal Access Token."
        )
    _check_response(response)


class ListEventsParams(Params):
    username: str = Param(
        description="Username", primary=True, cef_types=["github username"]
    )


class ActorOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars.githubusercontent.com/u/41301719?"],
    )
    display_login: str | None = OutputField(
        cef_types=["github username"], example_values=["test"]
    )
    gravatar_id: str | None
    id: float = OutputField(example_values=[41301719])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/test"]
    )


class OrgOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars.githubusercontent.com/u/41301665?"],
    )
    gravatar_id: str | None
    id: float = OutputField(example_values=[41301665])
    login: str = OutputField(
        cef_types=["github organization name"], example_values=["test"]
    )
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/orgs/test"]
    )


class DismisserOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars1.githubusercontent.com/u/1032411?v=4"],
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
    id: float = OutputField(example_values=[1032411])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjEwMzI0MTE="]  # pragma: allowlist secret
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
        cef_types=["url"], example_values=["https://api.github.com/users/octocat"]
    )


class AlertOutput(ActionOutput):
    affected_package_name: str = OutputField(example_values=["many_versioned_gem"])
    affected_range: str = OutputField(example_values=["0.2.0"])
    dismiss_reason: str | None = OutputField(
        example_values=["No bandwidth to fix this"]
    )
    dismissed_at: str | None = OutputField(example_values=["2017-10-25T00:00:00+00:00"])
    dismisser: DismisserOutput | None
    external_identifier: str = OutputField(example_values=["CVE-2018-3728"])
    external_reference: str = OutputField(
        cef_types=["url"],
        example_values=["https://nvd.nist.gov/vuln/detail/CVE-2018-3728"],
    )
    fixed_in: str | None = OutputField(example_values=["0.2.5"])
    id: float = OutputField(example_values=[7649605])


class BlockedUserOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars2.githubusercontent.com/u/39652351?v=4"],
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
    id: float = OutputField(example_values=[406494157])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjM5NjUyMzUx"]  # pragma: allowlist secret
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


class BodyOutput(ActionOutput):
    from_: str = OutputField(alias="from")


class ColorOutput(ActionOutput):
    from_: str = OutputField(alias="from")


class DescriptionOutput(ActionOutput):
    from_: str = OutputField(alias="from")


class DueOnOutput(ActionOutput):
    from_: str = OutputField(alias="from")


class NameOutput(ActionOutput):
    from_: str = OutputField(alias="from")


class NoteOutput(ActionOutput):
    from_: str = OutputField(alias="from")


class PermissionOutput(ActionOutput):
    from_: str = OutputField(example_values=["write"], alias="from")


class PrivacyOutput(ActionOutput):
    from_: str = OutputField(alias="from")


class FromOutput(ActionOutput):
    admin: bool
    pull: bool
    push: bool


class PermissionsOutput(ActionOutput):
    contents: str = OutputField(example_values=["read"])
    issues: str = OutputField(example_values=["write"])
    metadata: str = OutputField(example_values=["read"])


class RepositoryOutput(ActionOutput):
    archive_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/{archive_format}{/ref}"
        ],
    )
    archived: bool
    assignees_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/assignees{/user}"],
    )
    blobs_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/blobs{/sha}"],
    )
    branches_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/branches{/branch}"
        ],
    )
    clone_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo.git"]
    )
    collaborators_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/collaborators{/collaborator}"
        ],
    )
    comments_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/comments{/number}"
        ],
    )
    commits_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/commits{/sha}"],
    )
    compare_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/compare/{base}...{head}"
        ],
    )
    contents_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/contents/{+path}"],
    )
    contributors_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/contributors"],
    )
    created_at: str = OutputField(example_values=["2018-05-30T20:18:04Z"])
    default_branch: str = OutputField(example_values=["master"])
    deployments_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/deployments"],
    )
    description: str | None
    downloads_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/downloads"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/events"],
    )
    fork: bool
    forks: float = OutputField(example_values=[0])
    forks_count: float = OutputField(example_values=[0])
    forks_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/forks"],
    )
    full_name: str = OutputField(example_values=["test/test-repo"])
    git_commits_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/git/commits{/sha}"
        ],
    )
    git_refs_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/refs{/sha}"],
    )
    git_tags_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/tags{/sha}"],
    )
    git_url: str = OutputField(example_values=["git://github.com/test/test-repo.git"])
    has_downloads: bool
    has_issues: bool
    has_pages: bool
    has_projects: bool
    has_wiki: bool
    homepage: str | None = OutputField(
        cef_types=["url"], example_values=["https://test.com"]
    )
    hooks_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/hooks"],
    )
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo"]
    )
    id: float = OutputField(example_values=[135493233])
    issue_comment_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/issues/comments{/number}"
        ],
    )
    issue_events_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/issues/events{/number}"
        ],
    )
    issues_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/issues{/number}"],
    )
    keys_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/keys{/key_id}"],
    )
    labels_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/labels{/name}"],
    )
    language: str | None
    languages_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/languages"],
    )
    license: "LicenseOutput | None"
    master_branch: str | None = OutputField(example_values=["master"])
    merges_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/merges"],
    )
    milestones_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/milestones{/number}"
        ],
    )
    mirror_url: str | None = OutputField(cef_types=["url"])
    name: str = OutputField(example_values=["test-repo"])
    node_id: str = OutputField(
        example_values=["MDEwOlJlcG9zaXRvcnkxMzU0OTMyMzM="]  # pragma: allowlist secret
    )
    notifications_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/notifications{?since,all,participating}"
        ],
    )
    open_issues: float = OutputField(example_values=[0])
    open_issues_count: float = OutputField(example_values=[0])
    owner: "OwnerOutput"
    private: bool
    pulls_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/pulls{/number}"],
    )
    pushed_at: str | None = OutputField(example_values=["2018-05-30T20:18:34Z"])
    releases_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/releases{/id}"],
    )
    size: float = OutputField(example_values=[0])
    ssh_url: str = OutputField(example_values=["git@github.com:test/test-repo.git"])
    stargazers: float | None = OutputField(example_values=[1])
    stargazers_count: float = OutputField(example_values=[0])
    stargazers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/stargazers"],
    )
    statuses_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/statuses/{sha}"],
    )
    subscribers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/subscribers"],
    )
    subscription_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/subscription"],
    )
    svn_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo"]
    )
    tags_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/tags"],
    )
    teams_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/teams"],
    )
    trees_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/trees{/sha}"],
    )
    updated_at: str = OutputField(example_values=["2018-05-30T20:18:44Z"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo"],
    )
    watchers: float = OutputField(example_values=[0])
    watchers_count: float = OutputField(example_values=[0])


class TitleOutput(ActionOutput):
    from_: str = OutputField(alias="from")


class ChangesOutput(ActionOutput):
    body: BodyOutput
    color: ColorOutput
    description: DescriptionOutput
    due_on: DueOnOutput
    name: NameOutput
    note: NoteOutput
    permission: PermissionOutput
    privacy: PrivacyOutput
    repository: RepositoryOutput
    title: TitleOutput


class OwnerOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/29939753?v=4"],
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


class AppOutput(ActionOutput):
    created_at: str = OutputField(example_values=["2018-04-25 20:42:10"])
    description: str | None
    external_url: str = OutputField(
        cef_types=["url"], example_values=["http://super-duper.example.com"]
    )
    html_url: str = OutputField(
        cef_types=["url"], example_values=["http://github.com/apps/super-duper"]
    )
    id: float = OutputField(example_values=[2])
    name: str = OutputField(example_values=["Super Duper"])
    node_id: str = OutputField(
        example_values=["MDExOkludGVncmF0aW9uMQ="]  # pragma: allowlist secret
    )
    owner: OwnerOutput
    updated_at: str = OutputField(example_values=["2018-04-25 20:42:10"])


class AuthorOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars0.githubusercontent.com/u/1?v=4"],
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
    id: float = OutputField(example_values=[1])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    node_id: str = OutputField(example_values=["MDQ6VXNlcjE="])
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


class CommitterOutput(ActionOutput):
    email: str = OutputField(cef_types=["email"], example_values=["test@user.com"])
    name: str = OutputField(cef_types=["github username"], example_values=["test"])


class HeadCommitOutput(ActionOutput):
    author: AuthorOutput
    committer: CommitterOutput
    id: str = OutputField(
        cef_types=["sha1"],
        example_values=[
            "d6fde92930d4715a2b49857d24b940956b26d2d3"  # pragma: allowlist secret
        ],
    )
    message: str = OutputField(example_values=["Sample message"])
    timestamp: str = OutputField(example_values=["2018-05-04T01:14:46Z"])
    tree_id: str = OutputField(
        cef_types=["sha1"],
        example_values=[
            "d6fde92930d4715a2b49857d24b940956b26d2d3"  # pragma: allowlist secret
        ],
    )


class CommentsOutput(ActionOutput):
    href: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test/issues/27999/comments"],
    )


class CommitsOutput(ActionOutput):
    href: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test/pulls/27999/commits"],
    )


class HtmlOutput(ActionOutput):
    href: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://github.com/test/test-repo/pull/1#pullrequestreview-124575911"
        ],
    )


class IssueOutput(ActionOutput):
    href: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test/issues/27999"],
    )


class ReviewCommentOutput(ActionOutput):
    href: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test/pulls/comments{/number}"
        ],
    )


class ReviewCommentsOutput(ActionOutput):
    href: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test/pulls/27999/comments"],
    )


class SelfOutput(ActionOutput):
    href: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test/pulls/27999"],
    )


class StatusesOutput(ActionOutput):
    href: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test/statuses/ee780f3c664f8e2846aba087c5e9653a92c64252"
        ],
    )


class LinksOutput(ActionOutput):
    html: HtmlOutput
    pull_request: "PullRequestOutput"


class AssigneeOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/29939753?v=4"],
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


class AssigneesOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/29939753?v=4"],
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


class LicenseOutput(ActionOutput):
    key: str = OutputField(example_values=["mit"])
    name: str = OutputField(example_values=["MIT License"])
    node_id: str = OutputField(example_values=["MDc6TGljZW5zZTEz"])
    spdx_id: str = OutputField(example_values=["MIT"])
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/licenses/mit"]
    )


class RepoOutput(ActionOutput):
    id: float = OutputField(example_values=[141531062])
    name: str = OutputField(cef_types=["github repo"], example_values=["test-repo"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo"],
    )


class UserOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars1.githubusercontent.com/u/1032411?v=4"],
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
    id: float = OutputField(example_values=[1032411])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjEwMzI0MTE="]  # pragma: allowlist secret
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


class BaseOutput(ActionOutput):
    label: str = OutputField(example_values=["test:2.8"])
    ref: str = OutputField(example_values=["2.8"])
    repo: RepoOutput
    sha: str = OutputField(
        cef_types=["sha1"],
        example_values=[
            "08a49bc5302de373bdb44e5c189133a7d5d5f12b"  # pragma: allowlist secret
        ],
    )
    user: UserOutput


class HeadOutput(ActionOutput):
    label: str = OutputField(example_values=["test:uuid-translations"])
    ref: str = OutputField(example_values=["uuid-translations"])
    repo: RepoOutput
    sha: str = OutputField(
        cef_types=["sha1"],
        example_values=[
            "ee780f3c664f8e2846aba087c5e9653a92c64252"  # pragma: allowlist secret
        ],
    )
    user: UserOutput


class LabelsOutput(ActionOutput):
    color: str = OutputField(example_values=["e10c02"])
    default: bool
    id: float = OutputField(example_values=[100079])
    name: str = OutputField(example_values=["Bug"])
    node_id: str = OutputField(
        example_values=["MDU6TGFiZWwxMDAwNzk="]  # pragma: allowlist secret
    )
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test/labels/Bug"],
    )


class MergedByOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/47313?v=4"],
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
    id: float = OutputField(example_values=[47313])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    node_id: str = OutputField(example_values=["MDQ6VXNlcjQ3MzEz"])
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


class CreatorOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/73419?v=4"],
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
    id: float = OutputField(example_values=[73419])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    node_id: str = OutputField(example_values=["MDQ6VXNlcjczNDE5"])
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


class MilestoneOutput(ActionOutput):
    closed_at: str | None = OutputField(example_values=["2018-07-20T11:26:15Z"])
    closed_issues: float = OutputField(example_values=[879])
    created_at: str = OutputField(example_values=["2016-11-06T20:24:23Z"])
    creator: CreatorOutput
    description: str | None = OutputField(example_values=["Sample description"])
    due_on: str | None = OutputField(example_values=["2020-11-30T08:00:00Z"])
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test/milestone/10"]
    )
    id: float = OutputField(example_values=[2117464])
    labels_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test/milestones/10/labels"],
    )
    node_id: str = OutputField(
        example_values=["MDk6TWlsZXN0b25lMjExNzQ2NA=="]  # pragma: allowlist secret
    )
    number: float = OutputField(example_values=[10])
    open_issues: float = OutputField(example_values=[15])
    state: str = OutputField(example_values=["open"])
    title: str = OutputField(example_values=["3.4"])
    updated_at: str = OutputField(example_values=["2018-07-19T07:12:02Z"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test/milestones/10"],
    )


class RequestedReviewersOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars2.githubusercontent.com/u/57224?v=4"],
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
    id: float = OutputField(example_values=[57224])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    node_id: str = OutputField(example_values=["MDQ6VXNlcjU3MjI0"])
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


class OrganizationOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars0.githubusercontent.com/u/41309665?v=4"],
    )
    created_at: str = OutputField(example_values=["2018-07-16T23:02:38Z"])
    description: str | None
    events_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/orgs/test/events"]
    )
    followers: float = OutputField(example_values=[3])
    following: float = OutputField(example_values=[3])
    has_organization_projects: bool
    has_repository_projects: bool
    hooks_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/orgs/test/hooks"]
    )
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test"]
    )
    id: float = OutputField(example_values=[41309665])
    issues_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/orgs/test/issues"]
    )
    login: str = OutputField(
        cef_types=["github organization name"], example_values=["test"]
    )
    members_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/orgs/test/members{/member}"],
    )
    node_id: str = OutputField(
        example_values=["MDEyOk9yZ2FuaXphdGlvbjQxMzA5NjY1"]  # pragma: allowlist secret
    )
    public_gists: float = OutputField(example_values=[3])
    public_members_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/orgs/test/public_members{/member}"],
    )
    public_repos: float = OutputField(example_values=[3])
    repos_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/orgs/test/repos"]
    )
    type: str = OutputField(example_values=["Organization"])
    updated_at: str = OutputField(example_values=["2018-07-16T23:02:38Z"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/orgs/test"]
    )


class RequestedTeamsOutput(ActionOutput):
    created_at: str = OutputField(example_values=["2018-07-16T23:08:17Z"])
    description: str | None = OutputField(example_values=["Everybody but Tony"])
    id: float = OutputField(example_values=[2826794])
    members_count: float = OutputField(example_values=[2])
    members_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/teams/2826794/members{/member}"],
    )
    name: str = OutputField(example_values=["not-tony-team"])
    node_id: str = OutputField(
        example_values=["MDQ6VGVhbTI4MjY3OTQ="]  # pragma: allowlist secret
    )
    organization: OrganizationOutput
    permission: str = OutputField(example_values=["pull"])
    privacy: str = OutputField(example_values=["closed"])
    repos_count: float = OutputField(example_values=[2])
    repositories_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/teams/test/repos"]
    )
    slug: str = OutputField(example_values=["not-tony-team"])
    updated_at: str = OutputField(example_values=["2018-07-16T23:08:17Z"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/teams/2826794"]
    )


class PullRequestsOutput(ActionOutput):
    diff_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://github.com/twigphp/Twig/pull/2721.diff"],
    )
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/twigphp/Twig/pull/2721"]
    )
    patch_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://github.com/twigphp/Twig/pull/2721.patch"],
    )
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/twigphp/Twig/pulls/2721"],
    )


class CheckSuiteOutput(ActionOutput):
    after: str | None = OutputField(
        cef_types=["sha1"],
        example_values=[
            "d6fde92930d4715a2b49857d24b940956b26d2d3"  # pragma: allowlist secret
        ],
    )
    app: AppOutput
    before: str | None = OutputField(
        cef_types=["sha1"],
        example_values=[
            "146e867f55c26428e5f9fade55a9bbf5e95a7912"  # pragma: allowlist secret
        ],
    )
    check_runs_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/check-suites/5/check-runs"
        ],
    )
    conclusion: str | None = OutputField(example_values=["neutral"])
    created_at: str = OutputField(example_values=["2018-04-25 20:42:10"])
    head_branch: str | None = OutputField(example_values=["master"])
    head_commit: HeadCommitOutput
    head_sha: str = OutputField(
        cef_types=["sha1"],
        example_values=[
            "d6fde92930d4715a2b49857d24b940956b26d2d3"  # pragma: allowlist secret
        ],
    )
    id: float = OutputField(example_values=[5])
    latest_check_runs_count: float = OutputField(example_values=[1])
    latest_check_runs_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/check-suites/5/check-runs"
        ],
    )
    pull_requests: list[PullRequestsOutput]
    status: str = OutputField(example_values=["completed"])
    updated_at: str = OutputField(example_values=["2018-04-25 20:42:10"])


class OutputOutput(ActionOutput):
    annotations_count: float = OutputField(example_values=[12])
    annotations_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/check-runs/4/annotations"
        ],
    )
    summary: str | None = OutputField(example_values=["It's all good"])
    text: str | None = OutputField(example_values=["Sample text"])
    title: str | None = OutputField(example_values=["Report"])


class CheckRunOutput(ActionOutput):
    pull_requests: list[PullRequestsOutput]


class PullRequestOutput(ActionOutput):
    href: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/pulls/1"],
    )


class CommentOutput(ActionOutput):
    links: LinksOutput | None = None
    author_association: str = OutputField(example_values=["CONTRIBUTOR"])
    body: str = OutputField(example_values=["LGTM. Can you add some tests?"])
    commit_id: str = OutputField(
        cef_types=["sha1"],
        example_values=[
            "329bd507c1123c1ab24e58b78fa8d32bd1c70639"  # pragma: allowlist secret
        ],
    )
    created_at: str = OutputField(example_values=["2018-07-20T05:36:22Z"])
    diff_hunk: str = OutputField(example_values=["Sample"])
    html_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://github.com/twigphp/Twig/pull/2721#issuecomment-406494157"
        ],
    )
    id: float = OutputField(example_values=[406494157])
    in_reply_to_id: float | None = OutputField(example_values=[203123149])
    issue_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/twigphp/Twig/issues/2721"],
    )
    line: str | None
    node_id: str = OutputField(
        example_values=[
            "MDEyOklzc3VlQ29tbWVudDQwNjQ5NDE1Nw=="  # pragma: allowlist secret
        ]
    )
    original_commit_id: str = OutputField(
        cef_types=["sha1"],
        example_values=[
            "329bd507c1123c1ab24e58b78fa8d32bd1c70639"  # pragma: allowlist secret
        ],
    )
    original_position: float = OutputField(example_values=[13])
    path: str = OutputField(example_values=["src/test/Component/Finder/Finder.php"])
    position: float | None = OutputField(example_values=[13])
    pull_request_review_id: float | None = OutputField(example_values=[138091767])
    pull_request_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test/pulls/27967"],
    )
    updated_at: str = OutputField(example_values=["2018-07-20T05:36:22Z"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/twigphp/Twig/issues/comments/406494157"
        ],
    )
    user: UserOutput


class ForkeeOutput(ActionOutput):
    archive_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-proj/{archive_format}{/ref}"
        ],
    )
    archived: bool
    assignees_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/assignees{/user}"],
    )
    blobs_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/git/blobs{/sha}"],
    )
    branches_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-proj/branches{/branch}"
        ],
    )
    clone_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-proj.git"]
    )
    collaborators_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-proj/collaborators{/collaborator}"
        ],
    )
    comments_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-proj/comments{/number}"
        ],
    )
    commits_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/commits{/sha}"],
    )
    compare_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-proj/compare/{base}...{head}"
        ],
    )
    contents_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/contents/{+path}"],
    )
    contributors_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/contributors"],
    )
    created_at: str = OutputField(example_values=["2018-07-20T06:03:13Z"])
    default_branch: str = OutputField(example_values=["master"])
    deployments_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/deployments"],
    )
    description: str | None
    downloads_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/downloads"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/events"],
    )
    fork: bool
    forks: float = OutputField(example_values=[0])
    forks_count: float = OutputField(example_values=[0])
    forks_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/forks"],
    )
    full_name: str = OutputField(example_values=["test/test-repo"])
    git_commits_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-proj/git/commits{/sha}"
        ],
    )
    git_refs_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/git/refs{/sha}"],
    )
    git_tags_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/git/tags{/sha}"],
    )
    git_url: str = OutputField(example_values=["git://github.com/test/test-proj.git"])
    has_downloads: bool
    has_issues: bool
    has_pages: bool
    has_projects: bool
    has_wiki: bool
    homepage: str | None = OutputField(
        cef_types=["url"], example_values=["https://test.com"]
    )
    hooks_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/hooks"],
    )
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-proj"]
    )
    id: float = OutputField(example_values=[141670240])
    issue_comment_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-proj/issues/comments{/number}"
        ],
    )
    issue_events_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-proj/issues/events{/number}"
        ],
    )
    issues_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/issues{/number}"],
    )
    keys_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/keys{/key_id}"],
    )
    labels_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/labels{/name}"],
    )
    language: str | None = OutputField(example_values=["PHP"])
    languages_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/languages"],
    )
    license: LicenseOutput | None
    merges_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/merges"],
    )
    milestones_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-proj/milestones{/number}"
        ],
    )
    mirror_url: str | None = OutputField(cef_types=["url"])
    name: str = OutputField(example_values=["test-proj"])
    node_id: str = OutputField(
        example_values=["MDEwOlJlcG9zaXRvcnkxNDE2NzAyNDA="]  # pragma: allowlist secret
    )
    notifications_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-proj/notifications{?since,all,participating}"
        ],
    )
    open_issues: float = OutputField(example_values=[0])
    open_issues_count: float = OutputField(example_values=[0])
    owner: OwnerOutput
    private: bool
    public: bool
    pulls_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/pulls{/number}"],
    )
    pushed_at: str | None = OutputField(example_values=["2018-07-20T06:02:31Z"])
    releases_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/releases{/id}"],
    )
    size: float = OutputField(example_values=[0])
    ssh_url: str = OutputField(example_values=["git@github.com:test/test-proj.git"])
    stargazers_count: float = OutputField(example_values=[0])
    stargazers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/stargazers"],
    )
    statuses_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/statuses/{sha}"],
    )
    subscribers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/subscribers"],
    )
    subscription_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/subscription"],
    )
    svn_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-proj"]
    )
    tags_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/tags"],
    )
    teams_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/teams"],
    )
    trees_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj/git/trees{/sha}"],
    )
    updated_at: str = OutputField(example_values=["2018-07-20T06:02:33Z"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-proj"],
    )
    watchers: float = OutputField(example_values=[0])
    watchers_count: float = OutputField(example_values=[0])


class AccountOutput(ActionOutput):
    id: float = OutputField(example_values=[18404719])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    organization_billing_email: str = OutputField(
        cef_types=["email"], example_values=["username@email.com"]
    )
    type: str = OutputField(example_values=["Organization"])


class InstallationOutput(ActionOutput):
    access_tokens_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/installations/2/access_tokens"],
    )
    account: AccountOutput
    app_id: float = OutputField(example_values=[5725])
    created_at: float = OutputField(example_values=[1525109898])
    events: str = OutputField(example_values=["User"])
    html_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://github.com/settings/installations/2"],
    )
    id: float = OutputField(example_values=[2])
    permissions: PermissionsOutput
    repositories_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/installation/repositories"],
    )
    repository_selection: str = OutputField(example_values=["selected"])
    single_file_name: str | None = OutputField(
        cef_types=["file name"], example_values=["config.yml"]
    )
    target_id: float = OutputField(example_values=[3880403])
    target_type: str = OutputField(example_values=["User"])
    updated_at: float = OutputField(example_values=[1525109899])


class PlanOutput(ActionOutput):
    bullets: str = OutputField(example_values=["Is Basic"])
    description: str = OutputField(example_values=["Basic Plan"])
    has_free_trial: bool
    id: float = OutputField(example_values=[435])
    monthly_price_in_cents: float = OutputField(example_values=[1000])
    name: str = OutputField(example_values=["Basic Plan"])
    price_model: str = OutputField(example_values=["per-unit"])
    unit_name: str = OutputField(example_values=["seat"])
    yearly_price_in_cents: float = OutputField(example_values=[10000])


class MarketplacePurchaseOutput(ActionOutput):
    account: AccountOutput
    billing_cycle: str = OutputField(example_values=["monthly"])
    free_trial_ends_on: str | None
    next_billing_date: str = OutputField(example_values=["2017-11-05T00:00:00+00:00"])
    on_free_trial: bool
    plan: PlanOutput
    unit_count: float = OutputField(example_values=[1])


class MemberOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars1.githubusercontent.com/u/41301719?v=4"],
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
    id: float = OutputField(example_values=[41301719])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjQxMzA5NzE5"]  # pragma: allowlist secret
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


class PagesOutput(ActionOutput):
    action: str = OutputField(example_values=["created"])
    creator: CreatorOutput
    html_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://github.com/test/test-proj/wiki/Home"],
    )
    page_name: str = OutputField(example_values=["Home"])
    sha: str = OutputField(
        cef_types=["sha1"],
        example_values=[
            "75c7614e23cb40511d9cb3eb00d20e5cadc0d0e6"  # pragma: allowlist secret
        ],
    )
    summary: str | None
    title: str = OutputField(example_values=["Home"])


class ProjectOutput(ActionOutput):
    body: str | None = OutputField(example_values=["Project tasks for a trip to Space"])
    columns_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/projects/1547122/columns"],
    )
    created_at: str = OutputField(example_values=["2018-05-30T20:18:51Z"])
    creator: CreatorOutput
    html_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://github.com/test/test-repo/projects/1"],
    )
    id: float = OutputField(example_values=[1547122])
    name: str = OutputField(example_values=["Space 2.0"])
    node_id: str = OutputField(
        example_values=["MDc6UHJvamVjdDE1NDcxMjI="]  # pragma: allowlist secret
    )
    number: float = OutputField(example_values=[1])
    owner_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo"],
    )
    state: str = OutputField(example_values=["open"])
    updated_at: str = OutputField(example_values=["2018-05-30T20:18:51Z"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/projects/1547122"]
    )


class ProjectCardOutput(ActionOutput):
    column_id: float = OutputField(example_values=[2803722])
    column_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/projects/columns/2803722"],
    )
    created_at: str = OutputField(example_values=["2018-05-30T20:18:52Z"])
    creator: CreatorOutput
    id: float = OutputField(example_values=[10189042])
    node_id: str = OutputField(
        example_values=["MDExOlByb2plY3RDYXJkMTAxODkwNDI="]  # pragma: allowlist secret
    )
    note: str | None = OutputField(
        example_values=["Work that can be completed in one hour or less"]
    )
    updated_at: str = OutputField(example_values=["2018-05-30T20:18:52Z"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/projects/columns/cards/10189042"],
    )


class ProjectColumnOutput(ActionOutput):
    cards_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/projects/columns/2803722/cards"],
    )
    created_at: str = OutputField(example_values=["2018-05-30T20:18:52Z"])
    id: float = OutputField(example_values=[2803722])
    name: str = OutputField(example_values=["Small bugfixes"])
    node_id: str = OutputField(
        example_values=["MDEzOlByb2plY3RDb2x1bW4yODAzNzIy"]  # pragma: allowlist secret
    )
    project_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/projects/1547122"]
    )
    updated_at: str = OutputField(example_values=["2018-05-30T20:18:52Z"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/projects/columns/2803722"],
    )


class UploaderOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars1.githubusercontent.com/u/41309719?v=4"],
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
    id: float = OutputField(example_values=[41309719])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjQxMzA5NzE5"]  # pragma: allowlist secret
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


class AssetsOutput(ActionOutput):
    browser_download_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://github.com/test/test-proj/releases/download/1.1.1.1.1/phapp_code42.tgz"
        ],
    )
    content_type: str = OutputField(example_values=["application/x-compressed"])
    created_at: str = OutputField(example_values=["2018-07-20T13:12:10Z"])
    download_count: float = OutputField(example_values=[0])
    id: float = OutputField(example_values=[7946908])
    label: str | None
    name: str = OutputField(example_values=["phapp_code42.tgz"])
    node_id: str = OutputField(
        example_values=["MDEyOlJlbGVhc2VBc3NldDc5NDY5MDg="]  # pragma: allowlist secret
    )
    size: float = OutputField(example_values=[91097])
    state: str = OutputField(example_values=["uploaded"])
    updated_at: str = OutputField(example_values=["2018-07-20T13:12:16Z"])
    uploader: UploaderOutput
    url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-proj/releases/assets/8946908"
        ],
    )


class ReleaseOutput(ActionOutput):
    assets: list[AssetsOutput]
    assets_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/toml-lang/toml/releases/11865985/assets"
        ],
    )
    author: AuthorOutput
    body: str | None = OutputField(example_values=["Sample body"])
    created_at: str = OutputField(example_values=["2018-07-10T21:44:12Z"])
    draft: bool
    html_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://github.com/toml-lang/toml/releases/tag/v0.5.0"],
    )
    id: float = OutputField(example_values=[11865985])
    name: str | None = OutputField(example_values=["v0.5.0"])
    node_id: str = OutputField(
        example_values=["MDc6UmVsZWFzZTExODY1OTg1"]  # pragma: allowlist secret
    )
    prerelease: bool
    published_at: str = OutputField(example_values=["2018-07-10T21:58:13Z"])
    tag_name: str = OutputField(example_values=["v0.5.0"])
    tarball_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/toml-lang/toml/tarball/v0.5.0"],
    )
    target_commitish: str = OutputField(example_values=["master"])
    upload_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://uploads.github.com/repos/toml-lang/toml/releases/11865985/assets{?name,label}"
        ],
    )
    url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/toml-lang/toml/releases/11865985"
        ],
    )
    zipball_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/toml-lang/toml/zipball/v0.5.0"],
    )


class RepositoriesAddedOutput(ActionOutput):
    archive_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/{archive_format}{/ref}"
        ],
    )
    archived: bool
    assignees_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/assignees{/user}"],
    )
    blobs_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/blobs{/sha}"],
    )
    branches_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/branches{/branch}"
        ],
    )
    clone_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo.git"]
    )
    collaborators_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/collaborators{/collaborator}"
        ],
    )
    comments_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/comments{/number}"
        ],
    )
    commits_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/commits{/sha}"],
    )
    compare_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/compare/{base}...{head}"
        ],
    )
    contents_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/contents/{+path}"],
    )
    contributors_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/contributors"],
    )
    created_at: str = OutputField(example_values=["2018-05-30T20:18:04Z"])
    default_branch: str = OutputField(example_values=["master"])
    deployments_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/deployments"],
    )
    description: str | None
    downloads_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/downloads"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/events"],
    )
    fork: bool
    forks: float = OutputField(example_values=[0])
    forks_count: float = OutputField(example_values=[0])
    forks_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/forks"],
    )
    full_name: str = OutputField(example_values=["test/test-repo"])
    git_commits_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/git/commits{/sha}"
        ],
    )
    git_refs_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/refs{/sha}"],
    )
    git_tags_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/tags{/sha}"],
    )
    git_url: str = OutputField(example_values=["git://github.com/test/test-repo.git"])
    has_downloads: bool
    has_issues: bool
    has_pages: bool
    has_projects: bool
    has_wiki: bool
    homepage: str | None = OutputField(
        cef_types=["url"], example_values=["https://test.com"]
    )
    hooks_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/hooks"],
    )
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo"]
    )
    id: float = OutputField(example_values=[135493233])
    issue_comment_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/issues/comments{/number}"
        ],
    )
    issue_events_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/issues/events{/number}"
        ],
    )
    issues_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/issues{/number}"],
    )
    keys_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/keys{/key_id}"],
    )
    labels_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/labels{/name}"],
    )
    language: str | None
    languages_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/languages"],
    )
    license: LicenseOutput | None
    merges_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/merges"],
    )
    milestones_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/milestones{/number}"
        ],
    )
    mirror_url: str | None = OutputField(cef_types=["url"])
    name: str = OutputField(example_values=["test-repo"])
    node_id: str = OutputField(
        example_values=["MDEwOlJlcG9zaXRvcnkxMzU0OTMyMzM="]  # pragma: allowlist secret
    )
    notifications_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/notifications{?since,all,participating}"
        ],
    )
    open_issues: float = OutputField(example_values=[0])
    open_issues_count: float = OutputField(example_values=[0])
    owner: OwnerOutput
    private: bool
    pulls_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/pulls{/number}"],
    )
    pushed_at: str | None = OutputField(example_values=["2018-05-30T20:18:34Z"])
    releases_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/releases{/id}"],
    )
    size: float = OutputField(example_values=[0])
    ssh_url: str = OutputField(example_values=["git@github.com:test/test-repo.git"])
    stargazers_count: float = OutputField(example_values=[0])
    stargazers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/stargazers"],
    )
    statuses_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/statuses/{sha}"],
    )
    subscribers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/subscribers"],
    )
    subscription_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/subscription"],
    )
    svn_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo"]
    )
    tags_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/tags"],
    )
    teams_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/teams"],
    )
    trees_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/trees{/sha}"],
    )
    updated_at: str = OutputField(example_values=["2018-05-30T20:18:44Z"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo"],
    )
    watchers: float = OutputField(example_values=[0])
    watchers_count: float = OutputField(example_values=[0])


class RepositoriesRemovedOutput(ActionOutput):
    archive_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/{archive_format}{/ref}"
        ],
    )
    archived: bool
    assignees_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/assignees{/user}"],
    )
    blobs_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/blobs{/sha}"],
    )
    branches_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/branches{/branch}"
        ],
    )
    clone_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo.git"]
    )
    collaborators_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/collaborators{/collaborator}"
        ],
    )
    comments_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/comments{/number}"
        ],
    )
    commits_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/commits{/sha}"],
    )
    compare_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/compare/{base}...{head}"
        ],
    )
    contents_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/contents/{+path}"],
    )
    contributors_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/contributors"],
    )
    created_at: str = OutputField(example_values=["2018-05-30T20:18:04Z"])
    default_branch: str = OutputField(example_values=["master"])
    deployments_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/deployments"],
    )
    description: str | None
    downloads_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/downloads"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/events"],
    )
    fork: bool
    forks: float = OutputField(example_values=[0])
    forks_count: float = OutputField(example_values=[0])
    forks_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/forks"],
    )
    full_name: str = OutputField(example_values=["test/test-repo"])
    git_commits_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/git/commits{/sha}"
        ],
    )
    git_refs_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/refs{/sha}"],
    )
    git_tags_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/tags{/sha}"],
    )
    git_url: str = OutputField(example_values=["git://github.com/test/test-repo.git"])
    has_downloads: bool
    has_issues: bool
    has_pages: bool
    has_projects: bool
    has_wiki: bool
    homepage: str | None = OutputField(
        cef_types=["url"], example_values=["https://test.com"]
    )
    hooks_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/hooks"],
    )
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo"]
    )
    id: float = OutputField(example_values=[135493233])
    issue_comment_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/issues/comments{/number}"
        ],
    )
    issue_events_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/issues/events{/number}"
        ],
    )
    issues_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/issues{/number}"],
    )
    keys_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/keys{/key_id}"],
    )
    labels_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/labels{/name}"],
    )
    language: str | None
    languages_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/languages"],
    )
    license: LicenseOutput | None
    merges_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/merges"],
    )
    milestones_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/milestones{/number}"
        ],
    )
    mirror_url: str | None = OutputField(cef_types=["url"])
    name: str = OutputField(example_values=["test-repo"])
    node_id: str = OutputField(
        example_values=["MDEwOlJlcG9zaXRvcnkxMzU0OTMyMzM="]  # pragma: allowlist secret
    )
    notifications_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/notifications{?since,all,participating}"
        ],
    )
    open_issues: float = OutputField(example_values=[0])
    open_issues_count: float = OutputField(example_values=[0])
    owner: OwnerOutput
    private: bool
    pulls_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/pulls{/number}"],
    )
    pushed_at: str | None = OutputField(example_values=["2018-05-30T20:18:34Z"])
    releases_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/releases{/id}"],
    )
    size: float = OutputField(example_values=[0])
    ssh_url: str = OutputField(example_values=["git@github.com:test/test-repo.git"])
    stargazers_count: float = OutputField(example_values=[0])
    stargazers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/stargazers"],
    )
    statuses_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/statuses/{sha}"],
    )
    subscribers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/subscribers"],
    )
    subscription_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/subscription"],
    )
    svn_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo"]
    )
    tags_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/tags"],
    )
    teams_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/teams"],
    )
    trees_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/trees{/sha}"],
    )
    updated_at: str = OutputField(example_values=["2018-05-30T20:18:44Z"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo"],
    )
    watchers: float = OutputField(example_values=[0])
    watchers_count: float = OutputField(example_values=[0])


class ReviewOutput(ActionOutput):
    links: LinksOutput | None = None
    author_association: str = OutputField(example_values=["OWNER"])
    body: str | None
    commit_id: str = OutputField(
        example_values=[
            "34c5c7793cb3b279e22454cb6750c80560547b3a"  # pragma: allowlist secret
        ]  # pragma: allowlist secret
    )
    html_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://github.com/test/test-repo/pull/1#pullrequestreview-124575911"
        ],
    )
    id: float = OutputField(example_values=[124575911])
    node_id: str = OutputField(
        example_values=[
            "MDE3OlB1bGxSZXF1ZXN0UmV2aWV3MTI0NTc1OTEx"  # pragma: allowlist secret
        ]  # pragma: allowlist secret
    )
    pull_request_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/pulls/1"],
    )
    state: str = OutputField(example_values=["commented"])
    submitted_at: str = OutputField(example_values=["2018-05-30T20:18:31Z"])
    user: UserOutput


class SenderOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars2.githubusercontent.com/u/39652351?v=4"],
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
    id: float = OutputField(example_values=[406494157])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjM5NjUyMzUx"]  # pragma: allowlist secret
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


class PayloadOutput(ActionOutput):
    action: str | None = OutputField(example_values=["added"])
    after: str | None = OutputField(
        cef_types=["sha1"],
        example_values=[
            "286996c9d9bf535e9e2de7cb3bb11a7a67dc1c61"  # pragma: allowlist secret
        ],
    )
    alert: AlertOutput | None = None
    base_ref: str | None = None
    before: str | None = OutputField(
        cef_types=["sha1"],
        example_values=[
            "286996c9d9bf535e9ebde7cb3bb11a7a67dcbc6b"  # pragma: allowlist secret
        ],
    )
    blocked_user: BlockedUserOutput | None = None
    changes: ChangesOutput | None = None
    check_run: CheckRunOutput | None = None
    check_suite: CheckSuiteOutput | None = None
    comment: CommentOutput | None = None
    commits: list[CommitsOutput] | None = None
    compare: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://github.com/test/test-repo/compare/a10867b14bb7...000000000000"
        ],
    )
    created: bool | None = None
    deleted: bool | None = None
    description: str | None = OutputField(example_values=["test-repo-Description"])
    distinct_size: float | None = OutputField(example_values=[100])
    effective_date: str | None = OutputField(
        example_values=["2017-10-25T00:00:00+00:00"]
    )
    forced: bool | None = None
    forkee: ForkeeOutput | None = None
    head: str | None = OutputField(
        cef_types=["sha1"],
        example_values=[
            "9bfa971bc5662a6f90408b58a7b2453d7dae4f83"  # pragma: allowlist secret
        ],
    )
    head_commit: HeadCommitOutput | None = None
    installation: InstallationOutput | None = None
    issue: IssueOutput | None = None
    marketplace_purchase: MarketplacePurchaseOutput | None = None
    master_branch: str | None = OutputField(example_values=["master"])
    member: MemberOutput | None = None
    number: float | None = OutputField(example_values=[27999])
    organization: OrganizationOutput | None = None
    pages: list[PagesOutput] | None = None
    project: ProjectOutput | None = None
    project_card: ProjectCardOutput | None = None
    project_column: ProjectColumnOutput | None = None
    pull_request: PullRequestOutput | None = None
    push_id: float | None = OutputField(example_values=[2731668591])
    pusher_type: str | None = OutputField(example_values=["user"])
    ref: str | None = OutputField(example_values=["refs/heads/2.8"])
    ref_type: str | None = OutputField(example_values=["repository"])
    release: ReleaseOutput | None = None
    repositories_added: list[RepositoriesAddedOutput] | None = None
    repositories_removed: list[RepositoriesRemovedOutput] | None = None
    repository: RepositoryOutput | None = None
    repository_selection: str | None = OutputField(example_values=["selected"])
    review: ReviewOutput | None = None
    sender: SenderOutput | None = None
    size: float | None = OutputField(example_values=[2])


class ListEventsOutput(ActionOutput):
    actor: ActorOutput
    created_at: str = OutputField(example_values=["2018-07-19T06:26:57Z"])
    id: str = OutputField(example_values=["7987124418"])
    org: OrgOutput | None
    payload: PayloadOutput
    public: bool
    repo: RepoOutput
    type: str = OutputField(example_values=["CreateEvent"])


class ListEventsSummary(ActionOutput):
    total_events: int = OutputField(example_values=[10])


@app.action(
    description="List events performed by a user",
    action_type="investigate",
    verbose="Action will list a maximum of 300 events. Only events from the past 90 days will be listed.",
    view_handler=display_view,
)
def list_events(
    params: ListEventsParams, soar: SOARClient, asset: Asset
) -> list[ListEventsOutput]:
    endpoint = GITHUB_EVENTS_ENDPOINT.format(username=params.username)
    results = []
    page = 1

    while True:
        response = call_github(
            "GET",
            endpoint,
            asset,
            params={"per_page": GITHUB_PAGINATION_MAX_SIZE, "page": page},
        )
        _check_response(response)
        page_items = response.json()
        results.extend(page_items)

        if len(page_items) < GITHUB_PAGINATION_MAX_SIZE or page >= 3:
            break
        page += 1

    output = [ListEventsOutput(**item) for item in results]
    soar.set_summary(ListEventsSummary(total_events=len(output)))
    return output


class ListUsersParams(Params):
    organization_name: str = Param(
        description="Organization name",
        primary=True,
        cef_types=["github organization name"],
    )
    limit: float | None = Param(description="Maximum number of users to be fetched")


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


class ListUsersSummary(ActionOutput):
    total_users: int = OutputField(example_values=[10])


@app.action(description="List users of an organization", action_type="investigate")
def list_users(
    params: ListUsersParams, soar: SOARClient, asset: Asset
) -> list[ListUsersOutput]:
    limit = int(params.limit) if params.limit is not None else None
    if limit is not None and limit <= 0:
        raise ActionFailure("limit must be a positive integer")
    endpoint = GITHUB_LIST_USERS_ENDPOINT.format(
        organization_name=params.organization_name
    )
    output = [ListUsersOutput(**u) for u in _paginate_all(endpoint, asset, limit=limit)]
    soar.set_summary(ListUsersSummary(total_users=len(output)))
    return output


def _paginate_all(
    endpoint: str,
    asset: Asset,
    extra_params: dict | None = None,
    limit: int | None = None,
) -> list:
    """Exhaust all pages of a GitHub list endpoint and return every item, up to limit."""
    page, results = 1, []
    while True:
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
            break
        page += 1
    return results


def _resolve_team_id(team: str, org_name: str | None, asset: Asset) -> int:
    """Return a numeric team ID from either a numeric string or a team name.

    Mirrors legacy _verify_and_get_team_id: numeric input is used directly;
    a name requires org_name and triggers a search across GET /orgs/{org}/teams.
    Raises ActionFailure when the team cannot be found.
    """
    if team.isdigit():
        return int(team)

    if not org_name:
        raise ActionFailure(GITHUB_ORGANIZATION_REQUIRED_MSG)

    teams = _paginate_all(GITHUB_LIST_TEAMS_ENDPOINT.format(org_name=org_name), asset)
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


@app.action(
    description="Remove user as a collaborator from the repo",
    action_type="generic",
    read_only=False,
    verbose="If the user is not a direct collaborator to the repo, any pending invitations to the user will also be deleted.",
    view_handler=display_view,
)
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


@app.action(
    description="Remove user from the team",
    action_type="generic",
    read_only=False,
    verbose="Parameter 'organization name' is mandatory if the team name is provided instead of team ID.",
    view_handler=display_view,
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


class ListReposParams(Params):
    organization_name: str = Param(
        description="Organization name",
        primary=True,
        cef_types=["github organization name"],
        column_name="Organization Name",
    )
    limit: float | None = Param(
        description="Maximum number of repositories to be fetched"
    )


class LicenseOutput(ActionOutput):
    key: str = OutputField(example_values=["apache-2.0"])
    name: str = OutputField(example_values=["Apache License 2.0"])
    node_id: str = OutputField(example_values=["MDc6TGljZW5zZIT="])
    spdx_id: str = OutputField(example_values=["Apache-2.0"])
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/licenses/apache-2.0"]
    )


class OwnerOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars0.githubusercontent.com/u/41409665?v=4"],
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
    id: float = OutputField(example_values=[41309165])
    login: str = OutputField(cef_types=["github username"], example_values=["test"])
    node_id: str = OutputField(
        example_values=["MDEyOk9yZ2FuaX1hdGl1bjQxMzA5NjY1"]  # pragma: allowlist secret
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
    type: str = OutputField(example_values=["Organization"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/test"]
    )


class PermissionsOutput(ActionOutput):
    admin: bool
    pull: bool
    push: bool


class ListReposOutput(ActionOutput):
    # Column fields in widget display order
    id: float = OutputField(example_values=[141304012], column_name="Repo Id")
    full_name: str = OutputField(
        example_values=["test/test-repo"], column_name="Repo Full Name"
    )
    description: str | None = OutputField(
        example_values=["Test Repo 1"], column_name="Repo Description"
    )
    repo_owner: str | None = OutputField(
        cef_types=["github username"], example_values=["test"], column_name="Repo Owner"
    )
    created_at: str = OutputField(
        example_values=["2018-07-16T23:05:00Z"], column_name="Created At"
    )
    updated_at: str = OutputField(
        example_values=["2018-07-16T23:03:00Z"], column_name="Updated At"
    )
    private: bool = OutputField(column_name="Is Private")
    # Non-column fields
    archive_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/{archive_format}{/ref}"
        ],
    )
    archived: bool
    assignees_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/assignees{/user}"],
    )
    blobs_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/blobs{/sha}"],
    )
    branches_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/branches{/branch}"
        ],
    )
    clone_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo.git"]
    )
    collaborators_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/collaborators{/collaborator}"
        ],
    )
    comments_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/comments{/number}"
        ],
    )
    commits_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/commits{/sha}"],
    )
    compare_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/compare/{base}...{head}"
        ],
    )
    contents_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/contents/{+path}"],
    )
    contributors_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/contributors"],
    )
    default_branch: str = OutputField(example_values=["master"])
    deployments_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/deployments"],
    )
    downloads_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/downloads"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/events"],
    )
    fork: bool
    forks: float = OutputField(example_values=[0])
    forks_count: float = OutputField(example_values=[0])
    forks_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/forks"],
    )
    git_commits_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/git/commits{/sha}"
        ],
    )
    git_refs_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/refs{/sha}"],
    )
    git_tags_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/tags{/sha}"],
    )
    git_url: str = OutputField(example_values=["git://github.com/test/test-repo.git"])
    has_downloads: bool
    has_issues: bool
    has_pages: bool
    has_projects: bool
    has_wiki: bool
    homepage: str | None = OutputField(cef_types=["url"])
    hooks_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/hooks"],
    )
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo"]
    )
    issue_comment_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/issues/comments{/number}"
        ],
    )
    issue_events_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/issues/events{/number}"
        ],
    )
    issues_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/issues{/number}"],
    )
    keys_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/keys{/key_id}"],
    )
    labels_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/labels{/name}"],
    )
    language: str | None
    languages_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/languages"],
    )
    license: LicenseOutput | None
    merges_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/merges"],
    )
    milestones_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/milestones{/number}"
        ],
    )
    mirror_url: str | None = OutputField(cef_types=["url"])
    name: str = OutputField(example_values=["test-repo"])
    node_id: str = OutputField(
        example_values=["MDEwOlJlcG9zaXRvnckxNDEyMDQwMDA="]  # pragma: allowlist secret
    )
    notifications_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/test/test-repo/notifications{?since,all,participating}"
        ],
    )
    open_issues: float = OutputField(example_values=[0])
    open_issues_count: float = OutputField(example_values=[0])
    owner: OwnerOutput
    permissions: PermissionsOutput | None
    pulls_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/pulls{/number}"],
    )
    pushed_at: str | None = OutputField(example_values=["2018-07-16T23:03:58Z"])
    releases_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/releases{/id}"],
    )
    size: float = OutputField(example_values=[0])
    ssh_url: str = OutputField(example_values=["git@github.com:test/test-repo.git"])
    stargazers_count: float = OutputField(example_values=[0])
    stargazers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/stargazers"],
    )
    statuses_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/statuses/{sha}"],
    )
    subscribers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/subscribers"],
    )
    subscription_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/subscription"],
    )
    svn_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo"]
    )
    tags_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/tags"],
    )
    teams_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/teams"],
    )
    trees_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo/git/trees{/sha}"],
    )
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/test/test-repo"],
    )
    watchers: float = OutputField(example_values=[0])
    watchers_count: float = OutputField(example_values=[0])

    @model_validator(mode="before")
    @classmethod
    def _flatten_owner(cls, values):
        if isinstance(values, dict) and "owner" in values:
            owner = values["owner"]
            if isinstance(owner, dict):
                values.setdefault("repo_owner", owner.get("login"))
        return values


class ListReposSummary(ActionOutput):
    total_repos: int = OutputField(example_values=[10])


@app.action(
    description="List all repos of an organization",
    action_type="investigate",
    view_handler=display_view,
)
def list_repos(
    params: ListReposParams, soar: SOARClient, asset: Asset
) -> list[ListReposOutput]:
    limit = int(params.limit) if params.limit is not None else None
    if limit is not None and limit <= 0:
        raise ActionFailure("limit must be a positive integer")
    endpoint = GITHUB_LIST_REPOS_ENDPOINT.format(org_name=params.organization_name)
    output = [ListReposOutput(**r) for r in _paginate_all(endpoint, asset, limit=limit)]
    soar.set_summary(ListReposSummary(total_repos=len(output)))
    return output


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


class ListIssuesParams(Params):
    repo_owner: str = Param(
        description="Owner of the repository",
        primary=True,
        cef_types=["github repo owner", "github username"],
    )
    repo_name: str = Param(
        description="Name of the repository", primary=True, cef_types=["github repo"]
    )
    limit: float | None = Param(description="Maximum number of issues to be fetched")


class AssigneeOutput(ActionOutput):  # noqa: F811
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars0.githubusercontent.com/u/id"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/following{/other_user}"],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/username"]
    )
    id: float = OutputField(example_values=[7614131])
    login: str = OutputField(
        cef_types=["github username"], example_values=["testusername"]
    )
    node_id: str = OutputField(example_values=["LAKSJDOIWsase="])
    organizations_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/username/orgs"]
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/repos"],
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/starred{/owner}{/repo}"],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/username"]
    )


class AssigneesOutput(ActionOutput):  # noqa: F811
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars0.githubusercontent.com/u/7614131?v=4"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/following{/other_user}"],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/username"]
    )
    id: float = OutputField(example_values=[7614131])
    login: str = OutputField(cef_types=["github username"], example_values=["username"])
    node_id: str = OutputField(example_values=["LAKSJDOIWsase="])
    organizations_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/username/orgs"]
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/repos"],
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/starred{/owner}{/repo}"],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/username"]
    )


class LabelsOutput(ActionOutput):  # noqa: F811
    color: str = OutputField(example_values=["a2eeef"])
    default: bool
    id: float = OutputField(example_values=[864962287])
    name: str = OutputField(example_values=["enhancement"])
    node_id: str = OutputField(example_values=["LAKSJDOIWsase="])
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/owner/repo/labels/enhancement"],
    )


class UserOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars0.githubusercontent.com/u/avatarid"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/following{/other_user}"],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/username"]
    )
    id: float = OutputField(example_values=[99999])
    login: str = OutputField(cef_types=["github username"], example_values=["username"])
    node_id: str = OutputField(example_values=["LAKSJDOIWsase="])
    organizations_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/username/orgs"]
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/repos"],
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/starred{/owner}{/repo}"],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/username/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/username"]
    )


class ListIssuesOutput(ActionOutput):
    assignee: AssigneeOutput | None
    assignees: list[AssigneesOutput]
    author_association: str = OutputField(example_values=["COLLABORATOR"])
    body: str | None = OutputField(example_values=["Test issue body right here"])
    closed_at: str | None
    comments: float = OutputField(example_values=[0])
    comments_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/username/testrepo/issues/4/comments"
        ],
    )
    created_at: str = OutputField(example_values=["2018-04-23T01:15:25Z"])
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/username/testrepo/issues/4/events"
        ],
    )
    html_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://github.com/username/testrepo/issues/4"],
    )
    id: float = OutputField(example_values=[316631564])
    labels: list[LabelsOutput]
    labels_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/username/testrepo/issues/4/labels{/name}"
        ],
    )
    locked: bool
    milestone: MilestoneOutput | None
    node_id: str = OutputField(example_values=["LAKSJDOIWsase="])
    number: float = OutputField(cef_types=["github issue id"], example_values=[4])
    repository_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/username/testrepo"],
    )
    state: str = OutputField(example_values=["open"])
    title: str = OutputField(example_values=["Test issue title here"])
    updated_at: str = OutputField(example_values=["2018-04-23T01:15:25Z"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/username/testrepo/issues/4"],
    )
    user: UserOutput


class ListIssuesSummary(ActionOutput):
    total_issues: int = OutputField(example_values=[10])


@app.action(
    description="Get a list of issues for the GitHub repository",
    action_type="investigate",
    view_handler=display_view,
)
def list_issues(
    params: ListIssuesParams, soar: SOARClient, asset: Asset
) -> list[ListIssuesOutput]:
    limit = int(params.limit) if params.limit is not None else None
    if limit is not None and limit <= 0:
        raise ActionFailure("limit must be a positive integer")
    endpoint = GITHUB_ENDPOINT_ISSUES.format(
        repo_owner=params.repo_owner, repo_name=params.repo_name
    )
    output = [
        ListIssuesOutput(**i) for i in _paginate_all(endpoint, asset, limit=limit)
    ]
    soar.set_summary(ListIssuesSummary(total_issues=len(output)))
    return output


class ListCommentsParams(Params):
    repo_owner: str = Param(
        description="Owner of the repository",
        primary=True,
        cef_types=["github repo owner", "github username"],
    )
    repo_name: str = Param(
        description="Name of the repository", primary=True, cef_types=["github repo"]
    )
    issue_number: float = Param(
        description="Issue ID", primary=True, cef_types=["github issue id"]
    )
    limit: float | None = Param(description="Maximum number of comments to be fetched")


class UserOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/52245234"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/following{/other_user}"
        ],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/repoowner"]
    )
    id: float = OutputField(example_values=[99999999])
    login: str = OutputField(
        cef_types=["github username"], example_values=["repoowner"]
    )
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjExODkwNzA5"]  # pragma: allowlist secret
    )
    organizations_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/orgs"],
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/repos"],
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/starred{/owner}{/repo}"
        ],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/repoowner"]
    )


class ListCommentsOutput(ActionOutput):
    author_association: str = OutputField(example_values=["OWNER"])
    body: str | None = OutputField(
        example_values=["I am writing a comment to this issue"]
    )
    created_at: str = OutputField(example_values=["2019-07-16T19:52:27Z"])
    html_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://github.com/repoowner/TestingAPI/issues/1#issuecomment-511961016"
        ],
    )
    id: float = OutputField(example_values=[511961016])
    issue_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/repoowner/TestingAPI/issues/1"],
    )
    node_id: str = OutputField(
        example_values=[
            "MDEyOklzc3VlQ29tbWVudDUxMTk2MTAxNg=="  # pragma: allowlist secret
        ]
    )
    updated_at: str = OutputField(example_values=["2019-07-16T19:52:27Z"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/repoowner/TestingAPI/issues/comments/511961016"
        ],
    )
    user: UserOutput


class ListCommentsSummary(ActionOutput):
    total_comments: int = OutputField(example_values=[10])


@app.action(
    description="List comments for an issue on the GitHub repository",
    action_type="investigate",
)
def list_comments(
    params: ListCommentsParams, soar: SOARClient, asset: Asset
) -> list[ListCommentsOutput]:
    limit = int(params.limit) if params.limit is not None else None
    if limit is not None and limit <= 0:
        raise ActionFailure("limit must be a positive integer")
    endpoint = GITHUB_ENDPOINT_COMMENTS.format(
        repo_owner=params.repo_owner,
        repo_name=params.repo_name,
        issue_number=int(params.issue_number),
    )
    output = [
        ListCommentsOutput(**c) for c in _paginate_all(endpoint, asset, limit=limit)
    ]
    soar.set_summary(ListCommentsSummary(total_comments=len(output)))
    return output


class GetIssueParams(Params):
    repo_owner: str = Param(
        description="Owner of the repository",
        primary=True,
        cef_types=["github repo owner", "github username"],
    )
    repo_name: str = Param(
        description="Name of the repository", primary=True, cef_types=["github repo"]
    )
    issue_number: float = Param(
        description="Issue ID", primary=True, cef_types=["github issue id"]
    )


class AssigneeOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/11890709?v=4"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/following{/other_user}"
        ],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/repoowner"]
    )
    id: float = OutputField(example_values=[11890709])
    login: str = OutputField(
        cef_types=["github username"], example_values=["repoowner"]
    )
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjExODkwNzA5"]  # pragma: allowlist secret
    )
    organizations_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/orgs"],
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/repos"],
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/starred{/owner}{/repo}"
        ],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/repoowner"]
    )


class AssigneesOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/11890709?v=4"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/following{/other_user}"
        ],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/repoowner"]
    )
    id: float = OutputField(example_values=[11890709])
    login: str = OutputField(
        cef_types=["github username"], example_values=["repoowner"]
    )
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjExODkwNzA5"]  # pragma: allowlist secret
    )
    organizations_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/orgs"],
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/repos"],
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/starred{/owner}{/repo}"
        ],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/repoowner"]
    )


class UserOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/11890709?v=4"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/following{/other_user}"
        ],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/repoowner"]
    )
    id: float = OutputField(example_values=[11890709])
    login: str = OutputField(
        cef_types=["github username"], example_values=["repoowner"]
    )
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjExODkwNzA5"]  # pragma: allowlist secret
    )
    organizations_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/orgs"],
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/repos"],
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/starred{/owner}{/repo}"
        ],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/repoowner"]
    )


class ClosedByOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/53362718?v=4"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/following{/other_user}"],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/testbg11"]
    )
    id: float = OutputField(example_values=[53362718])
    login: str = OutputField(cef_types=["github username"], example_values=["testbg11"])
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjUzMzYyNzE4"]  # pragma: allowlist secret
    )
    organizations_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/testbg11/orgs"]
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/repos"],
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/starred{/owner}{/repo}"],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/testbg11"]
    )


class GetIssueOutput(ActionOutput):
    assignee: AssigneeOutput | None
    assignees: list[AssigneesOutput]
    author_association: str = OutputField(example_values=["OWNER"])
    body: str | None = OutputField(
        example_values=["This is the body I believe of the issue"]
    )
    closed_at: str | None
    closed_by: ClosedByOutput | None
    comments: float = OutputField(example_values=[1])
    comments_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/repoowner/TestingAPI/issues/1/comments"
        ],
    )
    created_at: str = OutputField(example_values=["2019-07-16T19:52:15Z"])
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/repoowner/TestingAPI/issues/1/events"
        ],
    )
    html_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://github.com/repoowner/TestingAPI/issues/1"],
    )
    id: float = OutputField(example_values=[468834090])
    labels_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/repoowner/TestingAPI/issues/1/labels{/name}"
        ],
    )
    locked: bool
    milestone: MilestoneOutput | None
    node_id: str = OutputField(
        example_values=["MDU6SXNzdWU0Njg4MzQwOTA="]  # pragma: allowlist secret
    )
    number: float = OutputField(cef_types=["github issue id"], example_values=[1])
    repository_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/repoowner/TestingAPI"],
    )
    state: str = OutputField(example_values=["open"])
    title: str = OutputField(example_values=["This is a Test Issue"])
    updated_at: str = OutputField(example_values=["2019-07-16T20:00:23Z"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/repoowner/TestingAPI/issues/1"],
    )
    user: UserOutput


class GetIssueSummary(ActionOutput):
    issue_number: float | None = OutputField(example_values=[1])
    issue_url: str | None = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo/issues/1"]
    )


@app.action(
    description="Retrieve an issue for the GitHub repository", action_type="investigate"
)
def get_issue(params: GetIssueParams, soar: SOARClient, asset: Asset) -> GetIssueOutput:
    endpoint = GITHUB_ENDPOINT_GET_ISSUE.format(
        repo_owner=params.repo_owner,
        repo_name=params.repo_name,
        issue_number=int(params.issue_number),
    )
    response = call_github("GET", endpoint, asset)
    _check_response(response)
    data = response.json()
    soar.set_summary(
        GetIssueSummary(issue_number=data.get("number"), issue_url=data.get("html_url"))
    )
    return GetIssueOutput(**data)


class CreateIssueParams(Params):
    repo_owner: str = Param(
        description="Owner of the repository",
        primary=True,
        cef_types=["github repo owner", "github username"],
    )
    repo_name: str = Param(
        description="Name of the repository", primary=True, cef_types=["github repo"]
    )
    issue_title: str = Param(description="Title of the issue")
    issue_body: str | None = Param(description="Contents of the issue")
    assignees: str | None = Param(
        description="Comma-separated list of logins (usernames) for the users to assign to this issue",
        primary=True,
        cef_types=["github username"],
    )
    labels: str | None = Param(
        description="Comma-separated list of labels to associate with this issue"
    )


class AssigneeOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/11890709?v=4"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/following{/other_user}"
        ],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/repoowner"]
    )
    id: float = OutputField(example_values=[11890709])
    login: str = OutputField(
        cef_types=["github username"], example_values=["repoowner"]
    )
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjExODkwNzA5"]  # pragma: allowlist secret
    )
    organizations_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/orgs"],
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/repos"],
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/starred{/owner}{/repo}"
        ],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/repoowner"]
    )


class AssigneesOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/11890709?v=4"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/following{/other_user}"
        ],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/repoowner"]
    )
    id: float = OutputField(example_values=[11890709])
    login: str = OutputField(
        cef_types=["github username"], example_values=["repoowner"]
    )
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjExODkwNzA5"]  # pragma: allowlist secret
    )
    organizations_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/orgs"],
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/repos"],
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/starred{/owner}{/repo}"
        ],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/repoowner"]
    )


class LabelsOutput(ActionOutput):
    color: str = OutputField(example_values=["ededed"])
    default: bool
    id: float = OutputField(example_values=[1454469929])
    name: str = OutputField(example_values=["test"])
    node_id: str = OutputField(
        example_values=["MDU6TGFiZWwxNDU0NDY5OTI5"]  # pragma: allowlist secret
    )
    url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/repoowner/TestingAPI/labels/test"
        ],
    )


class UserOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/11890709?v=4"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/following{/other_user}"
        ],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/repoowner"]
    )
    id: float = OutputField(example_values=[11890709])
    login: str = OutputField(
        cef_types=["github username"], example_values=["repoowner"]
    )
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjExODkwNzA5"]  # pragma: allowlist secret
    )
    organizations_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/orgs"],
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/repos"],
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/starred{/owner}{/repo}"
        ],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/repoowner"]
    )


class CreateIssueOutput(ActionOutput):
    assignee: AssigneeOutput | None
    assignees: list[AssigneesOutput]
    author_association: str = OutputField(example_values=["OWNER"])
    body: str | None = OutputField(
        example_values=["This is what the body looks like when testing from the app"]
    )
    closed_at: str | None
    closed_by: ClosedByOutput | None
    comments: float = OutputField(example_values=[0])
    comments_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/repoowner/TestingAPI/issues/2/comments"
        ],
    )
    created_at: str = OutputField(example_values=["2019-07-16T20:07:26Z"])
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/repoowner/TestingAPI/issues/2/events"
        ],
    )
    html_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://github.com/repoowner/TestingAPI/issues/2"],
    )
    id: float = OutputField(example_values=[468840014])
    labels: list[LabelsOutput]
    labels_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/repoowner/TestingAPI/issues/2/labels{/name}"
        ],
    )
    locked: bool
    milestone: MilestoneOutput | None
    node_id: str = OutputField(
        example_values=["MDU6SXNzdWU0Njg4NDAwMTQ="]  # pragma: allowlist secret
    )
    number: float = OutputField(cef_types=["github issue id"], example_values=[2])
    repository_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/repoowner/TestingAPI"],
    )
    state: str = OutputField(example_values=["open"])
    title: str = OutputField(example_values=["I am testing from the app"])
    updated_at: str = OutputField(example_values=["2019-07-16T20:07:27Z"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/repoowner/TestingAPI/issues/2"],
    )
    user: UserOutput


class CreateIssueSummary(ActionOutput):
    issue_number: float | None = OutputField(example_values=[1])
    issue_url: str | None = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo/issues/1"]
    )


@app.action(
    description="Create an issue for the GitHub repository",
    action_type="generic",
    read_only=False,
    verbose="Only users with push access can set assignees/labels for the issues. \nAssignees/labels are silently dropped otherwise.",
    view_handler=display_view,
)
def create_issue(
    params: CreateIssueParams, soar: SOARClient, asset: Asset
) -> CreateIssueOutput:
    assignees = [x.strip() for x in (params.assignees or "").split(",") if x.strip()]
    labels = [x.strip() for x in (params.labels or "").split(",") if x.strip()]
    body = {
        "title": params.issue_title,
        "body": params.issue_body or "",
        "assignees": assignees,
        "labels": labels,
    }
    endpoint = GITHUB_ENDPOINT_ISSUES.format(
        repo_owner=params.repo_owner, repo_name=params.repo_name
    )
    response = call_github(GITHUB_REQUEST_POST.upper(), endpoint, asset, json=body)
    _check_response(response)
    data = response.json()
    soar.set_summary(
        CreateIssueSummary(
            issue_number=data.get("number"), issue_url=data.get("html_url")
        )
    )
    return CreateIssueOutput(**data)


class UpdateIssueParams(Params):
    repo_owner: str = Param(
        description="Owner of the repository",
        primary=True,
        cef_types=["github repo owner", "github username"],
    )
    repo_name: str = Param(
        description="Name of the repository", primary=True, cef_types=["github repo"]
    )
    issue_number: float = Param(
        description="Issue ID", primary=True, cef_types=["github issue id"]
    )
    state: str | None = Param(
        description="State of the issue", value_list=["open", "closed"]
    )
    issue_title: str | None = Param(description="Title of the issue")
    issue_body: str | None = Param(description="Contents of the issue")
    assignees: str | None = Param(
        description="Comma-separated list of logins (usernames) for the users to assign to this issue",
        primary=True,
        cef_types=["github username"],
    )
    labels: str | None = Param(
        description="Comma-separated list of labels to associate with this issue"
    )
    to_empty: bool | None = Param(
        description="Empty the field values of the issue for which the parameter values are not provided",
        default=False,
    )


class AssigneeOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/53362718?v=4"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/following{/other_user}"],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/testbg11"]
    )
    id: float = OutputField(example_values=[53362718])
    login: str = OutputField(cef_types=["github username"], example_values=["testbg11"])
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjUzMzYyNzE4"]  # pragma: allowlist secret
    )
    organizations_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/testbg11/orgs"]
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/repos"],
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/starred{/owner}{/repo}"],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/testbg11"]
    )


class AssigneesOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/53362718?v=4"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/following{/other_user}"],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/testbg11"]
    )
    id: float = OutputField(example_values=[53362718])
    login: str = OutputField(cef_types=["github username"], example_values=["testbg11"])
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjUzMzYyNzE4"]  # pragma: allowlist secret
    )
    organizations_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/testbg11/orgs"]
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/repos"],
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/starred{/owner}{/repo}"],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/testbg11"]
    )


class LabelsOutput(ActionOutput):
    color: str = OutputField(example_values=["ededed"])
    default: bool
    id: float = OutputField(example_values=[1474194162])
    name: str = OutputField(example_values=["demo_update"])
    node_id: str = OutputField(
        example_values=["MDU6TGFiZWwxNDc0MTk0MTYy"]  # pragma: allowlist secret
    )
    url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/testbg11/Testing1/labels/demo_update"
        ],
    )


class UserOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/53362718?v=4"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/following{/other_user}"],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/testbg11"]
    )
    id: float = OutputField(example_values=[53362718])
    login: str = OutputField(cef_types=["github username"], example_values=["testbg11"])
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjUzMzYyNzE4"]  # pragma: allowlist secret
    )
    organizations_url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/testbg11/orgs"]
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/repos"],
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/starred{/owner}{/repo}"],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/testbg11/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/testbg11"]
    )


class UpdateIssueOutput(ActionOutput):
    assignee: AssigneeOutput | None
    assignees: list[AssigneesOutput]
    author_association: str = OutputField(example_values=["OWNER"])
    body: str | None = OutputField(example_values=["test update body"])
    closed_at: str | None = OutputField(example_values=["2019-07-29T11:24:09Z"])
    closed_by: ClosedByOutput | None
    comments: float = OutputField(example_values=[1])
    comments_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/testbg11/Testing1/issues/1/comments"
        ],
    )
    created_at: str = OutputField(example_values=["2019-07-27T05:42:57Z"])
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/testbg11/Testing1/issues/1/events"
        ],
    )
    html_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://github.com/testbg11/Testing1/issues/1"],
    )
    id: float = OutputField(example_values=[473601979])
    labels: list[LabelsOutput]
    labels_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/testbg11/Testing1/issues/1/labels{/name}"
        ],
    )
    locked: bool
    milestone: MilestoneOutput | None
    node_id: str = OutputField(
        example_values=["MDU6SXNzdWU0NzM2MDE5Nzk="]  # pragma: allowlist secret
    )
    number: float = OutputField(cef_types=["github issue id"], example_values=[1])
    repository_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/testbg11/Testing1"],
    )
    state: str = OutputField(example_values=["closed"])
    title: str = OutputField(example_values=["update test title"])
    updated_at: str = OutputField(example_values=["2019-07-29T11:27:10Z"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/testbg11/Testing1/issues/1"],
    )
    user: UserOutput


class UpdateIssueSummary(ActionOutput):
    issue_number: float | None = OutputField(example_values=[1])
    issue_url: str | None = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo/issues/1"]
    )


@app.action(
    description="Update an issue for the GitHub repository",
    action_type="generic",
    read_only=False,
    verbose="Only users with push access can set assignees/labels for new issues. \nAssignees/labels are silently dropped otherwise. The existing labels and assignees of the issue will be replaced with the labels and assignees provided in the respective input parameters by the user. If the to_empty parameter is checked, then, it will empty the field values of the issue (except for the title and the state of the issue) for which the parameter values are not provided or kept empty. If the to_empty parameter is not checked, then, it will simply ignore the empty parameter values from being updated on the issue.",
    view_handler=display_view,
)
def update_issue(
    params: UpdateIssueParams, soar: SOARClient, asset: Asset
) -> UpdateIssueOutput:
    assignees = [x.strip() for x in (params.assignees or "").split(",") if x.strip()]
    labels = [x.strip() for x in (params.labels or "").split(",") if x.strip()]
    to_empty = params.to_empty or False

    if to_empty:
        body: dict = {
            "body": params.issue_body,
            "assignees": assignees,
            "labels": labels,
        }
    else:
        body = {}
        if params.issue_body:
            body["body"] = params.issue_body
        if assignees:
            body["assignees"] = assignees
        if labels:
            body["labels"] = labels

    if params.issue_title:
        body["title"] = params.issue_title
    if params.state:
        body["state"] = params.state

    endpoint = GITHUB_ENDPOINT_GET_ISSUE.format(
        repo_owner=params.repo_owner,
        repo_name=params.repo_name,
        issue_number=int(params.issue_number),
    )
    response = call_github(GITHUB_REQUEST_PATCH.upper(), endpoint, asset, json=body)
    _check_response(response)
    data = response.json()
    soar.set_summary(
        UpdateIssueSummary(
            issue_number=data.get("number"), issue_url=data.get("html_url")
        )
    )
    return UpdateIssueOutput(**data)


class CreateCommentParams(Params):
    repo_owner: str = Param(
        description="Owner of the repository",
        primary=True,
        cef_types=["github repo owner", "github username"],
    )
    repo_name: str = Param(
        description="Name of the repository", primary=True, cef_types=["github repo"]
    )
    issue_number: float = Param(
        description="Issue ID", primary=True, cef_types=["github issue id"]
    )
    comment_body: str = Param(description="Contents of a comment to add to the issue")


class UserOutput(ActionOutput):
    avatar_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://avatars3.githubusercontent.com/u/11890709?v=4"],
    )
    events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/events{/privacy}"],
    )
    followers_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/followers"],
    )
    following_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/following{/other_user}"
        ],
    )
    gists_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/gists{/gist_id}"],
    )
    gravatar_id: str | None
    html_url: str = OutputField(
        cef_types=["url"], example_values=["https://github.com/repoowner"]
    )
    id: float = OutputField(example_values=[11890709])
    login: str = OutputField(
        cef_types=["github username"], example_values=["repoowner"]
    )
    node_id: str = OutputField(
        example_values=["MDQ6VXNlcjExODkwNzA5"]  # pragma: allowlist secret
    )
    organizations_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/orgs"],
    )
    received_events_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/received_events"],
    )
    repos_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/repos"],
    )
    site_admin: bool
    starred_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/users/repoowner/starred{/owner}{/repo}"
        ],
    )
    subscriptions_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/users/repoowner/subscriptions"],
    )
    type: str = OutputField(example_values=["User"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://api.github.com/users/repoowner"]
    )


class CreateCommentOutput(ActionOutput):
    author_association: str = OutputField(example_values=["OWNER"])
    body: str = OutputField(example_values=["I am adding a comment from the app"])
    created_at: str = OutputField(example_values=["2019-07-16T20:11:38Z"])
    html_url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://github.com/repoowner/TestingAPI/issues/2#issuecomment-511967194"
        ],
    )
    id: float = OutputField(example_values=[511967194])
    issue_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/repoowner/TestingAPI/issues/2"],
    )
    node_id: str = OutputField(
        example_values=[
            "MDEyOklzc3VlQ29tbWVudDUxMTk2NzE5NA=="  # pragma: allowlist secret
        ]
    )
    updated_at: str = OutputField(example_values=["2019-07-16T20:11:38Z"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/repoowner/TestingAPI/issues/comments/511967194"
        ],
    )
    user: UserOutput


class CreateCommentSummary(ActionOutput):
    comment_id: float | None = OutputField(example_values=[1])
    comment_url: str | None = OutputField(
        cef_types=["url"],
        example_values=["https://github.com/test/test-repo/issues/1#issuecomment-1"],
    )


@app.action(
    description="Create a comment for an issue on the GitHub repository",
    action_type="generic",
    read_only=False,
)
def create_comment(
    params: CreateCommentParams, soar: SOARClient, asset: Asset
) -> CreateCommentOutput:
    endpoint = GITHUB_ENDPOINT_COMMENTS.format(
        repo_owner=params.repo_owner,
        repo_name=params.repo_name,
        issue_number=int(params.issue_number),
    )
    response = call_github(
        GITHUB_REQUEST_POST.upper(), endpoint, asset, json={"body": params.comment_body}
    )
    _check_response(response)
    data = response.json()
    soar.set_summary(
        CreateCommentSummary(
            comment_id=data.get("id"), comment_url=data.get("html_url")
        )
    )
    return CreateCommentOutput(**data)


class AddLabelsParams(Params):
    repo_owner: str = Param(
        description="Owner of the repository",
        primary=True,
        cef_types=["github repo owner", "github username"],
    )
    repo_name: str = Param(
        description="Name of the repository", primary=True, cef_types=["github repo"]
    )
    issue_number: float = Param(
        description="Issue ID", primary=True, cef_types=["github issue id"]
    )
    labels: str = Param(
        description="Comma-separated list of labels to add to the issue"
    )


class AddLabelsOutput(ActionOutput):
    color: str = OutputField(example_values=["ededed"])
    default: bool
    id: float = OutputField(example_values=[1454479580])
    name: str = OutputField(example_values=["app-testing"])
    node_id: str = OutputField(
        example_values=["MDU6TGFiZWwxNDU0NDc5NTgw"]  # pragma: allowlist secret
    )
    url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/repoowner/TestingAPI/labels/app-testing"
        ],
    )


@app.action(
    description="Add label(s) to an issue on the GitHub repository",
    action_type="generic",
    read_only=False,
    verbose="Only users with push access can set labels for the issues.",
)
def add_labels(
    params: AddLabelsParams, soar: SOARClient, asset: Asset
) -> list[AddLabelsOutput]:
    labels = [label.strip() for label in params.labels.split(",") if label.strip()]

    endpoint = GITHUB_ENDPOINT_LABELS.format(
        repo_owner=params.repo_owner,
        repo_name=params.repo_name,
        issue_number=int(params.issue_number),
    )
    response = call_github(
        GITHUB_REQUEST_POST.upper(), endpoint, asset, json={"labels": labels}
    )
    _check_response(response)
    soar.set_message(
        GITHUB_LABEL_ADDED_MSG.format(
            labels=",".join(labels), issue_number=int(params.issue_number)
        )
    )
    return [AddLabelsOutput(**label) for label in response.json()]


RepositoryOutput.model_rebuild()
LinksOutput.model_rebuild()

if __name__ == "__main__":
    app.cli()
