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
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..consts import (
    GITHUB_ENDPOINT_ISSUES,
)
from ._helpers import _paginate_all

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


class ListIssuesParams(Params):
    repo_owner: str = Param(
        description="Owner of the repository",
        primary=True,
        cef_types=["github repo owner", "github username"],
    )
    repo_name: str = Param(
        description="Name of the repository", primary=True, cef_types=["github repo"]
    )
    limit: int | None = Param(description="Maximum number of issues to be fetched")


class AssigneeOutput(ActionOutput):
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


class AssigneesOutput(ActionOutput):
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


class LabelsOutput(ActionOutput):
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


class ListIssuesOutput(PermissiveActionOutput):
    # Column fields in widget display order
    number: int = OutputField(
        cef_types=["github issue id"], example_values=[4], column_name="Issue Number"
    )
    title: str = OutputField(
        example_values=["Test issue title here"], column_name="Issue Title"
    )
    body: str | None = OutputField(
        example_values=["Test issue body right here"], column_name="Issue Body"
    )
    state: str = OutputField(example_values=["open"], column_name="Issue State")
    assignee_login: str | None = OutputField(
        cef_types=["github username"],
        example_values=["testusername"],
        column_name="Assignee",
    )
    # Non-column fields
    assignee: AssigneeOutput | None
    assignees: list[AssigneesOutput]
    author_association: str = OutputField(example_values=["COLLABORATOR"])
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
    repository_url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/username/testrepo"],
    )
    updated_at: str = OutputField(example_values=["2018-04-23T01:15:25Z"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=["https://api.github.com/repos/username/testrepo/issues/4"],
    )
    user: UserOutput


class ListIssuesSummary(ActionOutput):
    total_issues: int = OutputField(example_values=[10])


def _flatten_assignee(item: dict) -> dict:
    """Promote the nested assignee's login to the top-level ``assignee_login``
    column. Done here rather than in a validator because PermissiveActionOutput
    serializes the raw input dict, so the column value must be present in it."""
    if isinstance(item, dict) and isinstance(item.get("assignee"), dict):
        item.setdefault("assignee_login", item["assignee"].get("login"))
    return item


def list_issues(
    params: ListIssuesParams, soar: SOARClient, asset: Asset
) -> list[ListIssuesOutput]:
    if params.limit is not None and params.limit <= 0:
        raise ActionFailure("limit must be a positive integer")
    endpoint = GITHUB_ENDPOINT_ISSUES.format(
        repo_owner=params.repo_owner, repo_name=params.repo_name
    )
    output = [
        ListIssuesOutput(**_flatten_assignee(i))
        for i in _paginate_all(endpoint, asset, limit=params.limit)
    ]
    soar.set_summary(ListIssuesSummary(total_issues=len(output)))
    return output
