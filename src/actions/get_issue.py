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
from soar_sdk.action_results import (
    ActionOutput,
    OutputField,
    PermissiveActionOutput,
)
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..client import call_github
from ..consts import (
    GITHUB_ENDPOINT_GET_ISSUE,
)
from ._helpers import _check_response

logger = getLogger()


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


class GetIssueParams(Params):
    repo_owner: str = Param(
        description="Owner of the repository",
        primary=True,
        cef_types=["github repo owner", "github username"],
    )
    repo_name: str = Param(
        description="Name of the repository", primary=True, cef_types=["github repo"]
    )
    issue_number: int = Param(
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


class GetIssueOutput(PermissiveActionOutput):
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
    number: int = OutputField(cef_types=["github issue id"], example_values=[1])
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
    issue_number: int | None = OutputField(example_values=[1])
    issue_url: str | None = OutputField(
        cef_types=["url"], example_values=["https://github.com/test/test-repo/issues/1"]
    )


def get_issue(params: GetIssueParams, soar: SOARClient, asset: Asset) -> GetIssueOutput:
    endpoint = GITHUB_ENDPOINT_GET_ISSUE.format(
        repo_owner=params.repo_owner,
        repo_name=params.repo_name,
        issue_number=params.issue_number,
    )
    response = call_github("GET", endpoint, asset)
    _check_response(response)
    data = response.json()
    soar.set_summary(
        GetIssueSummary(issue_number=data.get("number"), issue_url=data.get("html_url"))
    )
    return GetIssueOutput(**data)
