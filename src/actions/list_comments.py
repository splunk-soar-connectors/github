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
    GITHUB_ENDPOINT_COMMENTS,
)
from ._helpers import _paginate_all

logger = getLogger()

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

