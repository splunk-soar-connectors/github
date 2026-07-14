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
    GITHUB_ENDPOINT_COMMENTS,
    GITHUB_REQUEST_POST,
)
from ._helpers import _check_response

logger = getLogger()


class CreateCommentParams(Params):
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


class CreateCommentOutput(PermissiveActionOutput):
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


def create_comment(
    params: CreateCommentParams, soar: SOARClient, asset: Asset
) -> CreateCommentOutput:
    endpoint = GITHUB_ENDPOINT_COMMENTS.format(
        repo_owner=params.repo_owner,
        repo_name=params.repo_name,
        issue_number=params.issue_number,
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
