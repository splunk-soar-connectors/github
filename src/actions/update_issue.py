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
    GITHUB_ENDPOINT_GET_ISSUE,
    GITHUB_REQUEST_PATCH,
)
from ..views import display_view
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

