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
    GITHUB_LIST_REPOS_ENDPOINT,
)
from ._helpers import _paginate_all

logger = getLogger()


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


class ListReposOutput(PermissiveActionOutput):
    # PermissiveActionOutput so that every field GitHub returns for a repository
    # is passed through to the client. The repository object is the largest and
    # most volatile object in the API (GitHub keeps adding fields like
    # security_and_analysis, custom_properties, topics, visibility), and
    # playbooks may key off fields we don't model. Declared fields drive the
    # widget columns and CEF pivots; unknown fields flow through instead of
    # being dropped.
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


class ListReposSummary(ActionOutput):
    total_repos: int = OutputField(example_values=[10])


def _flatten_owner(item: dict) -> dict:
    """Promote the nested owner's login to the top-level ``repo_owner`` column.
    Done here rather than in a validator because PermissiveActionOutput
    serializes the raw input dict, so the column value must be present in it."""
    if isinstance(item, dict) and isinstance(item.get("owner"), dict):
        item.setdefault("repo_owner", item["owner"].get("login"))
    return item


def list_repos(
    params: ListReposParams, soar: SOARClient, asset: Asset
) -> list[ListReposOutput]:
    limit = int(params.limit) if params.limit is not None else None
    if limit is not None and limit <= 0:
        raise ActionFailure("limit must be a positive integer")
    endpoint = GITHUB_LIST_REPOS_ENDPOINT.format(org_name=params.organization_name)
    output = [
        ListReposOutput(**_flatten_owner(r))
        for r in _paginate_all(endpoint, asset, limit=limit)
    ]
    soar.set_summary(ListReposSummary(total_repos=len(output)))
    return output
