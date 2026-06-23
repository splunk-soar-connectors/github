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
    GITHUB_EVENTS_ENDPOINT,
    GITHUB_PAGINATION_MAX_SIZE,
)
from ..views import display_view
from ._helpers import _check_response

logger = getLogger()

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


class ChangesRepositoryPermissionsOutput(ActionOutput):
    from_: FromOutput = OutputField(alias="from")


class ChangesRepositoryOutput(ActionOutput):
    permissions: ChangesRepositoryPermissionsOutput | None = None


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
    repository: ChangesRepositoryOutput | None = None
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

RepositoryOutput.model_rebuild()
LinksOutput.model_rebuild()
