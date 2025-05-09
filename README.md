# GitHub

Publisher: Splunk \
Connector Version: 2.1.1 \
Product Vendor: Microsoft \
Product Name: GitHub \
Minimum Product Version: 5.5.0

This app integrates with GitHub to support various investigative and issue-based actions

### Configuration variables

This table lists the configuration variables required to operate GitHub. These variables are specified when configuring a GitHub asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**username** | optional | string | Username |
**password** | optional | password | Password |
**client_id** | optional | string | Client ID |
**client_secret** | optional | password | Client secret |
**personal_access_token** | optional | password | Personal access token |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[list events](#action-list-events) - List events performed by a user \
[list users](#action-list-users) - List users of an organization \
[remove collaborator](#action-remove-collaborator) - Remove user as a collaborator from the repo \
[add collaborator](#action-add-collaborator) - Add user as a collaborator to repo \
[remove member](#action-remove-member) - Remove user from the team \
[add member](#action-add-member) - Add user in a team \
[list teams](#action-list-teams) - List all teams of an organization \
[list repos](#action-list-repos) - List all repos of an organization \
[list organizations](#action-list-organizations) - List all organizations \
[list issues](#action-list-issues) - Get a list of issues for the GitHub repository \
[list comments](#action-list-comments) - List comments for an issue on the GitHub repository \
[get issue](#action-get-issue) - Retrieve an issue for the GitHub repository \
[create issue](#action-create-issue) - Create an issue for the GitHub repository \
[update issue](#action-update-issue) - Update an issue for the GitHub repository \
[create comment](#action-create-comment) - Create a comment for an issue on the GitHub repository \
[add labels](#action-add-labels) - Add label(s) to an issue on the GitHub repository

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'list events'

List events performed by a user

Type: **investigate** \
Read only: **True**

Action will list a maximum of 300 events. Only events from the past 90 days will be listed.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**username** | required | Username | string | `github username` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.username | string | `github username` | test |
action_result.data.\*.actor.avatar_url | string | `url` | https://avatars.githubusercontent.com/u/41301719? |
action_result.data.\*.actor.display_login | string | `github username` | test |
action_result.data.\*.actor.gravatar_id | string | | |
action_result.data.\*.actor.id | numeric | | 41301719 |
action_result.data.\*.actor.login | string | `github username` | test |
action_result.data.\*.actor.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.created_at | string | | 2018-07-19T06:26:57Z |
action_result.data.\*.id | string | | 7987124418 |
action_result.data.\*.org.avatar_url | string | `url` | https://avatars.githubusercontent.com/u/41301665? |
action_result.data.\*.org.gravatar_id | string | | |
action_result.data.\*.org.id | numeric | | 41301665 |
action_result.data.\*.org.login | string | `github organization name` | test |
action_result.data.\*.org.url | string | `url` | https://api.github.com/orgs/test |
action_result.data.\*.payload.action | string | | added |
action_result.data.\*.payload.after | string | `sha1` | 286996c9d9bf535e9e2de7cb3bb11a7a67dc1c61 |
action_result.data.\*.payload.alert.affected_package_name | string | | many_versioned_gem |
action_result.data.\*.payload.alert.affected_range | string | | 0.2.0 |
action_result.data.\*.payload.alert.dismiss_reason | string | | No bandwidth to fix this |
action_result.data.\*.payload.alert.dismissed_at | string | | 2017-10-25T00:00:00+00:00 |
action_result.data.\*.payload.alert.dismisser.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.alert.dismisser.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.alert.dismisser.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.alert.dismisser.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.alert.dismisser.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.alert.dismisser.gravatar_id | string | | |
action_result.data.\*.payload.alert.dismisser.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.alert.dismisser.id | numeric | | 1032411 |
action_result.data.\*.payload.alert.dismisser.login | string | `github username` | test |
action_result.data.\*.payload.alert.dismisser.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.alert.dismisser.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.alert.dismisser.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.alert.dismisser.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.alert.dismisser.site_admin | boolean | | True False |
action_result.data.\*.payload.alert.dismisser.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.alert.dismisser.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.alert.dismisser.type | string | | User |
action_result.data.\*.payload.alert.dismisser.url | string | `url` | https://api.github.com/users/octocat |
action_result.data.\*.payload.alert.external_identifier | string | | CVE-2018-3728 |
action_result.data.\*.payload.alert.external_reference | string | `url` | https://nvd.nist.gov/vuln/detail/CVE-2018-3728 |
action_result.data.\*.payload.alert.fixed_in | string | | 0.2.5 |
action_result.data.\*.payload.alert.id | numeric | | 7649605 |
action_result.data.\*.payload.base_ref | string | | |
action_result.data.\*.payload.before | string | `sha1` | 286996c9d9bf535e9ebde7cb3bb11a7a67dcbc6b |
action_result.data.\*.payload.blocked_user.avatar_url | string | `url` | https://avatars2.githubusercontent.com/u/39652351?v=4 |
action_result.data.\*.payload.blocked_user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.blocked_user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.blocked_user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.blocked_user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.blocked_user.gravatar_id | string | | |
action_result.data.\*.payload.blocked_user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.blocked_user.id | numeric | | 406494157 |
action_result.data.\*.payload.blocked_user.login | string | `github username` | test |
action_result.data.\*.payload.blocked_user.node_id | string | | MDQ6VXNlcjM5NjUyMzUx |
action_result.data.\*.payload.blocked_user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.blocked_user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.blocked_user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.blocked_user.site_admin | boolean | | True False |
action_result.data.\*.payload.blocked_user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.blocked_user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.blocked_user.type | string | | User |
action_result.data.\*.payload.blocked_user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.changes.body.from | string | | |
action_result.data.\*.payload.changes.color.from | string | | |
action_result.data.\*.payload.changes.description.from | string | | |
action_result.data.\*.payload.changes.due_on.from | string | | |
action_result.data.\*.payload.changes.name.from | string | | |
action_result.data.\*.payload.changes.name.from | string | | |
action_result.data.\*.payload.changes.note.from | string | | |
action_result.data.\*.payload.changes.permission.from | string | | write |
action_result.data.\*.payload.changes.privacy.from | string | | |
action_result.data.\*.payload.changes.repository.permissions.from.admin | boolean | | True False |
action_result.data.\*.payload.changes.repository.permissions.from.pull | boolean | | True False |
action_result.data.\*.payload.changes.repository.permissions.from.push | boolean | | True False |
action_result.data.\*.payload.changes.title.from | string | | |
action_result.data.\*.payload.check_run.app.created_at | string | | |
action_result.data.\*.payload.check_run.app.description | string | | |
action_result.data.\*.payload.check_run.app.external_url | string | `url` | http://super-duper.example.com |
action_result.data.\*.payload.check_run.app.html_url | string | `url` | http://github.com/apps/super-duper |
action_result.data.\*.payload.check_run.app.id | numeric | | 2 |
action_result.data.\*.payload.check_run.app.name | string | | Super Duper |
action_result.data.\*.payload.check_run.app.node_id | string | | MDExOkludGVncmF0aW9uMQ= |
action_result.data.\*.payload.check_run.app.owner.avatar_url | string | `url` | http://alambic.github.com/avatars/u/340? |
action_result.data.\*.payload.check_run.app.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.app.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.app.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.app.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.app.owner.gravatar_id | string | | |
action_result.data.\*.payload.check_run.app.owner.html_url | string | `url` | http://github.com/test |
action_result.data.\*.payload.check_run.app.owner.id | numeric | | 340 |
action_result.data.\*.payload.check_run.app.owner.login | string | `github username` | test |
action_result.data.\*.payload.check_run.app.owner.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjE= |
action_result.data.\*.payload.check_run.app.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.app.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.app.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.app.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.app.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.app.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.app.owner.type | string | | Organization |
action_result.data.\*.payload.check_run.app.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.app.updated_at | string | | 2018-04-25 20:42:10 |
action_result.data.\*.payload.check_run.check_suite.after | string | `sha1` | d6fde92930d4715a2b49857d24b940956b26d2d3 |
action_result.data.\*.payload.check_run.check_suite.app.created_at | string | | 2018-04-25 20:42:10 |
action_result.data.\*.payload.check_run.check_suite.app.description | string | | |
action_result.data.\*.payload.check_run.check_suite.app.external_url | string | `url` | http://super-duper.example.com |
action_result.data.\*.payload.check_run.check_suite.app.html_url | string | `url` | http://github.com/apps/super-duper |
action_result.data.\*.payload.check_run.check_suite.app.id | numeric | | 2 |
action_result.data.\*.payload.check_run.check_suite.app.name | string | | Super Duper |
action_result.data.\*.payload.check_run.check_suite.app.node_id | string | | MDExOkludGVncmF0aW9uMQ= |
action_result.data.\*.payload.check_run.check_suite.app.owner.avatar_url | string | `url` | http://api.github.com/avatars/u/340? |
action_result.data.\*.payload.check_run.check_suite.app.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.check_suite.app.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.check_suite.app.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.check_suite.app.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.check_suite.app.owner.gravatar_id | string | | |
action_result.data.\*.payload.check_run.check_suite.app.owner.html_url | string | `url` | http://github.com/test |
action_result.data.\*.payload.check_run.check_suite.app.owner.id | numeric | | 340 |
action_result.data.\*.payload.check_run.check_suite.app.owner.login | string | `github username` | test |
action_result.data.\*.payload.check_run.check_suite.app.owner.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjE= |
action_result.data.\*.payload.check_run.check_suite.app.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.check_suite.app.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.check_suite.app.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.check_suite.app.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.app.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.check_suite.app.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.check_suite.app.owner.type | string | | Organization |
action_result.data.\*.payload.check_run.check_suite.app.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.check_suite.app.updated_at | string | | 2018-04-25 20:42:10 |
action_result.data.\*.payload.check_run.check_suite.before | string | `sha1` | 146e867f55c26428e5f9fade55a9bbf5e95a7912 |
action_result.data.\*.payload.check_run.check_suite.check_runs_url | string | `url` | https://api.github.com/repos/test/test-repo/check-suites/5/check-runs |
action_result.data.\*.payload.check_run.check_suite.conclusion | string | | neutral |
action_result.data.\*.payload.check_run.check_suite.created_at | string | | 2018-04-25 20:42:10 |
action_result.data.\*.payload.check_run.check_suite.head_branch | string | | master |
action_result.data.\*.payload.check_run.check_suite.head_commit.author.email | string | `email` | test@user.com |
action_result.data.\*.payload.check_run.check_suite.head_commit.author.name | string | `github username` | test |
action_result.data.\*.payload.check_run.check_suite.head_commit.committer.email | string | `email` | test@user.com |
action_result.data.\*.payload.check_run.check_suite.head_commit.committer.name | string | `github username` | test |
action_result.data.\*.payload.check_run.check_suite.head_commit.id | string | `sha1` | d6fde92930d4715a2b49857d24b940956b26d2d3 |
action_result.data.\*.payload.check_run.check_suite.head_commit.message | string | | Sample message |
action_result.data.\*.payload.check_run.check_suite.head_commit.timestamp | string | | 2018-05-04T01:14:46Z |
action_result.data.\*.payload.check_run.check_suite.head_commit.tree_id | string | `sha1` | d6fde92930d4715a2b49857d24b940956b26d2d3 |
action_result.data.\*.payload.check_run.check_suite.head_sha | string | `sha1` | d6fde92930d4715a2b49857d24b940956b26d2d3 |
action_result.data.\*.payload.check_run.check_suite.id | numeric | | 5 |
action_result.data.\*.payload.check_run.check_suite.latest_check_runs_count | numeric | | 1 |
action_result.data.\*.payload.check_run.check_suite.latest_check_runs_url | string | `url` | https://api.github.com/repos/test/test-repo/check-suites/5/check-runs |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.\_links.comments.href | string | `url` | https://api.github.com/repos/test/test/issues/27999/comments |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.\_links.commits.href | string | `url` | https://api.github.com/repos/test/test/pulls/27999/commits |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.\_links.html.href | string | `url` | https://github.com/test/test/pull/27999 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.\_links.issue.href | string | `url` | https://api.github.com/repos/test/test/issues/27999 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.\_links.review_comment.href | string | `url` | https://api.github.com/repos/test/test/pulls/comments{/number} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.\_links.review_comments.href | string | `url` | https://api.github.com/repos/test/test/pulls/27999/comments |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.\_links.self.href | string | `url` | https://api.github.com/repos/test/test/pulls/27999 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.\_links.statuses.href | string | `url` | https://api.github.com/repos/test/test/statuses/ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.additions | numeric | | 24 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/29939753?v=4 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.gravatar_id | string | | |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.id | numeric | | 29939753 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.login | string | `github username` | test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.node_id | string | | MDQ6VXNlcjI5OTM5NzUz |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.type | string | | User |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignee.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/29939753?v=4 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.gravatar_id | string | | |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.id | numeric | | 29939753 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.login | string | `github username` | test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.node_id | string | | MDQ6VXNlcjI5OTM5NzUz |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.type | string | | User |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.assignees.\*.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.author_association | string | | CONTRIBUTOR |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.label | string | | test:2.8 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.ref | string | | 2.8 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.archive_url | string | `url` | https://api.github.com/repos/test/test/{archive_format}{/ref} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.archived | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.assignees_url | string | `url` | https://api.github.com/repos/test/test/assignees{/user} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.blobs_url | string | `url` | https://api.github.com/repos/test/test/git/blobs{/sha} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.branches_url | string | `url` | https://api.github.com/repos/test/test/branches{/branch} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.clone_url | string | `url` | https://github.com/test/test.git |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.collaborators_url | string | `url` | https://api.github.com/repos/test/test/collaborators{/collaborator} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.comments_url | string | `url` | https://api.github.com/repos/test/test/comments{/number} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.commits_url | string | `url` | https://api.github.com/repos/test/test/commits{/sha} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.compare_url | string | `url` | https://api.github.com/repos/test/test/compare/{base}..{head} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.contents_url | string | `url` | https://api.github.com/repos/test/test/contents/{+path} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.contributors_url | string | `url` | https://api.github.com/repos/test/test/contributors |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.created_at | string | | 2010-01-04T14:21:21Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.default_branch | string | | master |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.deployments_url | string | `url` | https://api.github.com/repos/test/test/deployments |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.description | string | | The test PHP framework |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.downloads_url | string | `url` | https://api.github.com/repos/test/test/downloads |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.events_url | string | `url` | https://api.github.com/repos/test/test/events |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.fork | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.forks | numeric | | 6330 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.forks_count | numeric | | 6330 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.forks_url | string | `url` | https://api.github.com/repos/test/test/forks |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.full_name | string | | test/test-repo |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.git_commits_url | string | `url` | https://api.github.com/repos/test/test/git/commits{/sha} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.git_refs_url | string | `url` | https://api.github.com/repos/test/test/git/refs{/sha} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.git_tags_url | string | `url` | https://api.github.com/repos/test/test/git/tags{/sha} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.git_url | string | | git://github.com/test/test.git |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.has_downloads | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.has_issues | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.has_pages | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.has_projects | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.has_wiki | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.homepage | string | `url` | https://test.com |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.hooks_url | string | `url` | https://api.github.com/repos/test/test/hooks |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.html_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.id | numeric | | 458058 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.issue_comment_url | string | `url` | https://api.github.com/repos/test/test/issues/comments{/number} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.issue_events_url | string | `url` | https://api.github.com/repos/test/test/issues/events{/number} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.issues_url | string | `url` | https://api.github.com/repos/test/test/issues{/number} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.keys_url | string | `url` | https://api.github.com/repos/test/test/keys{/key_id} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.labels_url | string | `url` | https://api.github.com/repos/test/test/labels{/name} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.language | string | | PHP |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.languages_url | string | `url` | https://api.github.com/repos/test/test/languages |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.license.key | string | | mit |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.license.name | string | | MIT License |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.license.node_id | string | | MDc6TGljZW5zZTEz |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.license.spdx_id | string | | MIT |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.license.url | string | `url` | https://api.github.com/licenses/mit |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.merges_url | string | `url` | https://api.github.com/repos/test/test/merges |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.milestones_url | string | `url` | https://api.github.com/repos/test/test/milestones{/number} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.mirror_url | string | `url` | |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.name | string | | test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.node_id | string | | MDEwOlJlcG9zaXRvcnk0NTgwNTg= |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.notifications_url | string | `url` | https://api.github.com/repos/test/test/notifications{?since,all,participating} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.open_issues | numeric | | 893 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.open_issues_count | numeric | | 893 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/143937?v=4 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.gravatar_id | string | | |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.id | numeric | | 143937 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.login | string | `github username` | test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjE0MzkzNw== |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.type | string | | Organization |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.private | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.pulls_url | string | `url` | https://api.github.com/repos/test/test/pulls{/number} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.pushed_at | string | | 2018-07-19T12:14:02Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.releases_url | string | `url` | https://api.github.com/repos/test/test/releases{/id} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.size | numeric | | 120647 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.ssh_url | string | | git@github.com:test/test.git |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.stargazers_count | numeric | | 18086 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.stargazers_url | string | `url` | https://api.github.com/repos/test/test/stargazers |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.statuses_url | string | `url` | https://api.github.com/repos/test/test/statuses/{sha} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.subscribers_url | string | `url` | https://api.github.com/repos/test/test/subscribers |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.subscription_url | string | `url` | https://api.github.com/repos/test/test/subscription |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.svn_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.tags_url | string | `url` | https://api.github.com/repos/test/test/tags |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.teams_url | string | `url` | https://api.github.com/repos/test/test/teams |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.trees_url | string | `url` | https://api.github.com/repos/test/test/git/trees{/sha} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.updated_at | string | | 2018-07-19T11:54:19Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.url | string | `url` | https://api.github.com/repos/test/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.watchers | numeric | | 18086 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.repo.watchers_count | numeric | | 18086 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.sha | string | `sha1` | 08a49bc5302de373bdb44e5c189133a7d5d5f12b |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/143937?v=4 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.gravatar_id | string | | |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.id | numeric | | 143937 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.login | string | `github username` | test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjE0MzkzNw== |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.type | string | | Organization |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.base.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.body | string | | pull requests sample body |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.changed_files | numeric | | 6 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.closed_at | string | | 2018-07-19T12:14:03Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.comments | numeric | | 1 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.comments_url | string | `url` | https://api.github.com/repos/test/test/issues/27999/comments |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.commits | numeric | | 1 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.commits_url | string | `url` | https://api.github.com/repos/test/test/pulls/27999/commits |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.created_at | string | | 2018-07-19T12:12:54Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.deletions | numeric | | 0 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.diff_url | string | `url` | https://github.com/test/test/pull/27999.diff |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.label | string | | test:uuid-translations |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.ref | string | | uuid-translations |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.archive_url | string | `url` | https://api.github.com/repos/test/test/{archive_format}{/ref} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.archived | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.assignees_url | string | `url` | https://api.github.com/repos/test/test/assignees{/user} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.blobs_url | string | `url` | https://api.github.com/repos/test/test/git/blobs{/sha} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.branches_url | string | `url` | https://api.github.com/repos/test/test/branches{/branch} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.clone_url | string | `url` | https://github.com/test/test.git |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.collaborators_url | string | `url` | https://api.github.com/repos/test/test/collaborators{/collaborator} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.comments_url | string | `url` | https://api.github.com/repos/test/test/comments{/number} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.commits_url | string | `url` | https://api.github.com/repos/test/test/commits{/sha} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.compare_url | string | `url` | https://api.github.com/repos/test/test/compare/{base}..{head} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.contents_url | string | `url` | https://api.github.com/repos/test/test/contents/{+path} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.contributors_url | string | `url` | https://api.github.com/repos/test/test/contributors |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.created_at | string | | 2017-02-01T16:32:59Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.default_branch | string | | master |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.deployments_url | string | `url` | https://api.github.com/repos/test/test/deployments |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.description | string | | The test PHP framework |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.downloads_url | string | `url` | https://api.github.com/repos/test/test/downloads |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.events_url | string | `url` | https://api.github.com/repos/test/test/events |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.fork | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.forks | numeric | | 1 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.forks_count | numeric | | 1 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.forks_url | string | `url` | https://api.github.com/repos/test/test/forks |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.full_name | string | | test/test-repo |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.git_commits_url | string | `url` | https://api.github.com/repos/test/test/git/commits{/sha} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.git_refs_url | string | `url` | https://api.github.com/repos/test/test/git/refs{/sha} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.git_tags_url | string | `url` | https://api.github.com/repos/test/test/git/tags{/sha} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.git_url | string | | git://github.com/test/test.git |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.has_downloads | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.has_issues | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.has_pages | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.has_projects | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.has_wiki | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.homepage | string | `url` | https://test.com |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.hooks_url | string | `url` | https://api.github.com/repos/test/test/hooks |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.html_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.id | numeric | | 80639758 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.issue_comment_url | string | `url` | https://api.github.com/repos/test/test/issues/comments{/number} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.issue_events_url | string | `url` | https://api.github.com/repos/test/test/issues/events{/number} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.issues_url | string | `url` | https://api.github.com/repos/test/test/issues{/number} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.keys_url | string | `url` | https://api.github.com/repos/test/test/keys{/key_id} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.labels_url | string | `url` | https://api.github.com/repos/test/test/labels{/name} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.language | string | | PHP |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.languages_url | string | `url` | https://api.github.com/repos/test/test/languages |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.license.key | string | | mit |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.license.name | string | | MIT License |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.license.node_id | string | | MDc6TGljZW5zZTEz |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.license.spdx_id | string | | MIT |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.license.url | string | `url` | https://api.github.com/licenses/mit |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.merges_url | string | `url` | https://api.github.com/repos/test/test/merges |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.milestones_url | string | `url` | https://api.github.com/repos/test/test/milestones{/number} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.mirror_url | string | `url` | |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.name | string | | test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.node_id | string | | MDEwOlJlcG9zaXRvcnk4MDYzOTc1OA== |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.notifications_url | string | `url` | https://api.github.com/repos/test/test/notifications{?since,all,participating} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.open_issues | numeric | | 0 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.open_issues_count | numeric | | 0 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.gravatar_id | string | | |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.id | numeric | | 1032411 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.login | string | `github username` | test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.type | string | | User |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.private | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.pulls_url | string | `url` | https://api.github.com/repos/test/test/pulls{/number} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.pushed_at | string | | 2018-07-19T12:11:30Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.releases_url | string | `url` | https://api.github.com/repos/test/test/releases{/id} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.size | numeric | | 112468 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.ssh_url | string | | git@github.com:test/test.git |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.stargazers_count | numeric | | 0 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.stargazers_url | string | `url` | https://api.github.com/repos/test/test/stargazers |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.statuses_url | string | `url` | https://api.github.com/repos/test/test/statuses/{sha} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.subscribers_url | string | `url` | https://api.github.com/repos/test/test/subscribers |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.subscription_url | string | `url` | https://api.github.com/repos/test/test/subscription |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.svn_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.tags_url | string | `url` | https://api.github.com/repos/test/test/tags |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.teams_url | string | `url` | https://api.github.com/repos/test/test/teams |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.trees_url | string | `url` | https://api.github.com/repos/test/test/git/trees{/sha} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.updated_at | string | | 2017-02-01T16:33:18Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.url | string | `url` | https://api.github.com/repos/test/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.watchers | numeric | | 0 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.repo.watchers_count | numeric | | 0 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.sha | string | `sha1` | ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.gravatar_id | string | | |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.id | numeric | | 1032411 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.login | string | `github username` | test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.type | string | | User |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.head.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.html_url | string | `url` | https://github.com/test/test/pull/27999 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.id | numeric | | 202539219 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.issue_url | string | `url` | https://api.github.com/repos/test/test/issues/27999 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.labels.\*.color | string | | e10c02 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.labels.\*.default | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.labels.\*.id | numeric | | 100079 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.labels.\*.name | string | | Bug |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.labels.\*.node_id | string | | MDU6TGFiZWwxMDAwNzk= |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.labels.\*.url | string | `url` | https://api.github.com/repos/test/test/labels/Bug |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.locked | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.maintainer_can_modify | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merge_commit_sha | string | `sha1` | ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.mergeable | boolean | | False True |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.mergeable_state | string | | unknown |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_at | string | | 2018-07-19T12:14:03Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/47313?v=4 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.gravatar_id | string | | |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.id | numeric | | 47313 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.login | string | `github username` | test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.node_id | string | | MDQ6VXNlcjQ3MzEz |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.type | string | | User |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.merged_by.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.closed_at | string | | 2018-07-20T11:26:15Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.closed_issues | numeric | | 879 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.created_at | string | | 2016-11-06T20:24:23Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/73419?v=4 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.gravatar_id | string | | |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.id | numeric | | 73419 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.login | string | `github username` | test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.node_id | string | | MDQ6VXNlcjczNDE5 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.type | string | | User |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.creator.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.description | string | `url` | https://test.com/roadmap?version=3.4#checker |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.due_on | string | | 2020-11-30T08:00:00Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.html_url | string | `url` | https://github.com/test/test/milestone/10 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.id | numeric | | 2117464 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.labels_url | string | `url` | https://api.github.com/repos/test/test/milestones/10/labels |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.node_id | string | | MDk6TWlsZXN0b25lMjExNzQ2NA== |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.number | numeric | | 10 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.open_issues | numeric | | 15 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.state | string | | open |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.title | string | | 3.4 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.updated_at | string | | 2018-07-19T07:12:02Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.milestone.url | string | `url` | https://api.github.com/repos/test/test/milestones/10 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.node_id | string | | MDExOlB1bGxSZXF1ZXN0MjAyNTM5MjE5 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.number | numeric | | 27999 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.patch_url | string | `url` | https://github.com/test/test/pull/27999.patch |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.rebaseable | boolean | | False True |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.avatar_url | string | `url` | https://avatars2.githubusercontent.com/u/57224?v=4 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.gravatar_id | string | | |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.id | numeric | | 57224 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.login | string | `github username` | test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.node_id | string | | MDQ6VXNlcjU3MjI0 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.type | string | | User |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_reviewers.\*.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.created_at | string | | 2018-07-16T23:08:17Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.description | string | | Everybody but Tony |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.id | numeric | `github team id` | 2826794 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.members_count | numeric | | 2 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.members_url | string | `url` | https://api.github.com/teams/2826794/members{/member} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.name | string | `github team name` | not-tony-team |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.node_id | string | | MDQ6VGVhbTI4MjY3OTQ= |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.avatar_url | string | `url` | https://avatars0.githubusercontent.com/u/41309665?v=4 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.created_at | string | | 2018-07-16T23:02:38Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.description | string | | |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.events_url | string | `url` | https://api.github.com/orgs/test/events |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.followers | numeric | | 3 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.following | numeric | | 3 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.has_organization_projects | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.has_repository_projects | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.hooks_url | string | `url` | https://api.github.com/orgs/test/hooks |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.id | numeric | | 41309665 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.issues_url | string | `url` | https://api.github.com/orgs/test/issues |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.login | string | `github username` | test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.members_url | string | `url` | https://api.github.com/orgs/test/members{/member} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjQxMzA5NjY1 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.public_gists | numeric | | 3 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.public_members_url | string | `url` | https://api.github.com/orgs/test/public_members{/member} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.public_repos | numeric | | 3 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.repos_url | string | `url` | https://api.github.com/orgs/test/repos |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.type | string | | Organization |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.updated_at | string | | 2018-07-16T23:02:38Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.organization.url | string | `url` | https://api.github.com/orgs/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.permission | string | | pull |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.privacy | string | | closed |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.repos_count | numeric | | 2 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.repositories_url | string | `url` | https://api.github.com/teams/test/repos |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.slug | string | | not-tony-team |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.updated_at | string | | 2018-07-16T23:08:17Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.requested_teams.\*.url | string | `url` | https://api.github.com/teams/2826794 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.review_comment_url | string | `url` | https://api.github.com/repos/test/test/pulls/comments{/number} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.review_comments | numeric | | 0 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.review_comments_url | string | `url` | https://api.github.com/repos/test/test/pulls/27999/comments |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.state | string | | closed |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.statuses_url | string | `url` | https://api.github.com/repos/test/test/statuses/ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.title | string | | Sample title |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.updated_at | string | | 2018-07-19T12:14:03Z |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.url | string | `url` | https://api.github.com/repos/test/test/pulls/27999 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.gravatar_id | string | | |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.id | numeric | | 1032411 |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.login | string | `github username` | test |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.type | string | | User |
action_result.data.\*.payload.check_run.check_suite.pull_requests.\*.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.check_suite.status | string | | completed |
action_result.data.\*.payload.check_run.check_suite.updated_at | string | | 2018-04-25 20:42:10 |
action_result.data.\*.payload.check_run.check_suite.url | string | `url` | https://api.github.com/repos/test/test-repo/check-suites/5 |
action_result.data.\*.payload.check_run.completed_at | string | | 2018-05-04T01:14:52Z |
action_result.data.\*.payload.check_run.conclusion | string | | neutral |
action_result.data.\*.payload.check_run.external_id | string | | |
action_result.data.\*.payload.check_run.head_sha | string | `sha1` | d6fde92930d4715a2b49857d24b940956b26d2d3 |
action_result.data.\*.payload.check_run.html_url | string | `url` | http://github.com/test/test-repo/runs/4 |
action_result.data.\*.payload.check_run.id | numeric | | 4 |
action_result.data.\*.payload.check_run.name | string | | randscape |
action_result.data.\*.payload.check_run.output.annotations_count | numeric | | 12 |
action_result.data.\*.payload.check_run.output.annotations_url | string | `url` | https://api.github.com/repos/test/test-repo/check-runs/4/annotations |
action_result.data.\*.payload.check_run.output.summary | string | | It's all good |
action_result.data.\*.payload.check_run.output.text | string | | Sample text |
action_result.data.\*.payload.check_run.output.title | string | | Report |
action_result.data.\*.payload.check_run.pull_requests.\*.\_links.comments.href | string | `url` | https://api.github.com/repos/test/test/issues/27999/comments |
action_result.data.\*.payload.check_run.pull_requests.\*.\_links.commits.href | string | `url` | https://api.github.com/repos/test/test/pulls/27999/commits |
action_result.data.\*.payload.check_run.pull_requests.\*.\_links.html.href | string | `url` | https://github.com/test/test/pull/27999 |
action_result.data.\*.payload.check_run.pull_requests.\*.\_links.issue.href | string | `url` | https://api.github.com/repos/test/test/issues/27999 |
action_result.data.\*.payload.check_run.pull_requests.\*.\_links.review_comment.href | string | `url` | https://api.github.com/repos/test/test/pulls/comments{/number} |
action_result.data.\*.payload.check_run.pull_requests.\*.\_links.review_comments.href | string | `url` | https://api.github.com/repos/test/test/pulls/27999/comments |
action_result.data.\*.payload.check_run.pull_requests.\*.\_links.self.href | string | `url` | https://api.github.com/repos/test/test/pulls/27999 |
action_result.data.\*.payload.check_run.pull_requests.\*.\_links.statuses.href | string | `url` | https://api.github.com/repos/test/test/statuses/ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.check_run.pull_requests.\*.additions | numeric | | 24 |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/29939753?v=4 |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.gravatar_id | string | | |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.id | numeric | | 29939753 |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.login | string | `github username` | test |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.node_id | string | | MDQ6VXNlcjI5OTM5NzUz |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.type | string | | User |
action_result.data.\*.payload.check_run.pull_requests.\*.assignee.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/29939753?v=4 |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.gravatar_id | string | | |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.id | numeric | | 29939753 |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.login | string | `github username` | test |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.node_id | string | | MDQ6VXNlcjI5OTM5NzUz |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.type | string | | User |
action_result.data.\*.payload.check_run.pull_requests.\*.assignees.\*.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.pull_requests.\*.author_association | string | | CONTRIBUTOR |
action_result.data.\*.payload.check_run.pull_requests.\*.base.label | string | | test:2.8 |
action_result.data.\*.payload.check_run.pull_requests.\*.base.ref | string | | 2.8 |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.archive_url | string | `url` | https://api.github.com/repos/test/test/{archive_format}{/ref} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.archived | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.assignees_url | string | `url` | https://api.github.com/repos/test/test/assignees{/user} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.blobs_url | string | `url` | https://api.github.com/repos/test/test/git/blobs{/sha} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.branches_url | string | `url` | https://api.github.com/repos/test/test/branches{/branch} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.clone_url | string | `url` | https://github.com/test/test.git |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.collaborators_url | string | `url` | https://api.github.com/repos/test/test/collaborators{/collaborator} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.comments_url | string | `url` | https://api.github.com/repos/test/test/comments{/number} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.commits_url | string | `url` | https://api.github.com/repos/test/test/commits{/sha} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.compare_url | string | `url` | https://api.github.com/repos/test/test/compare/{base}...{head} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.contents_url | string | `url` | https://api.github.com/repos/test/test/contents/{+path} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.contributors_url | string | `url` | https://api.github.com/repos/test/test/contributors |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.created_at | string | | 2010-01-04T14:21:21Z |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.default_branch | string | | master |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.deployments_url | string | `url` | https://api.github.com/repos/test/test/deployments |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.description | string | | The test PHP framework |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.downloads_url | string | `url` | https://api.github.com/repos/test/test/downloads |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.events_url | string | `url` | https://api.github.com/repos/test/test/events |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.fork | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.forks | numeric | | 6330 |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.forks_count | numeric | | 6330 |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.forks_url | string | `url` | https://api.github.com/repos/test/test/forks |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.full_name | string | | test/test-repo |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.git_commits_url | string | `url` | https://api.github.com/repos/test/test/git/commits{/sha} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.git_refs_url | string | `url` | https://api.github.com/repos/test/test/git/refs{/sha} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.git_tags_url | string | `url` | https://api.github.com/repos/test/test/git/tags{/sha} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.git_url | string | | git://github.com/test/test.git |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.has_downloads | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.has_issues | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.has_pages | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.has_projects | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.has_wiki | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.homepage | string | `url` | https://test.com |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.hooks_url | string | `url` | https://api.github.com/repos/test/test/hooks |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.html_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.id | numeric | | 458058 |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.issue_comment_url | string | `url` | https://api.github.com/repos/test/test/issues/comments{/number} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.issue_events_url | string | `url` | https://api.github.com/repos/test/test/issues/events{/number} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.issues_url | string | `url` | https://api.github.com/repos/test/test/issues{/number} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.keys_url | string | `url` | https://api.github.com/repos/test/test/keys{/key_id} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.labels_url | string | `url` | https://api.github.com/repos/test/test/labels{/name} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.language | string | | PHP |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.languages_url | string | `url` | https://api.github.com/repos/test/test/languages |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.license.key | string | | mit |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.license.name | string | | MIT License |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.license.node_id | string | | MDc6TGljZW5zZTEz |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.license.spdx_id | string | | MIT |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.license.url | string | `url` | https://api.github.com/licenses/mit |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.merges_url | string | `url` | https://api.github.com/repos/test/test/merges |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.milestones_url | string | `url` | https://api.github.com/repos/test/test/milestones{/number} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.mirror_url | string | `url` | |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.name | string | | test |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.node_id | string | | MDEwOlJlcG9zaXRvcnk0NTgwNTg= |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.notifications_url | string | `url` | https://api.github.com/repos/test/test/notifications{?since,all,participating} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.open_issues | numeric | | 893 |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.open_issues_count | numeric | | 893 |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/143937?v=4 |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.gravatar_id | string | | |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.id | numeric | | 143937 |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.login | string | `github username` | test |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjE0MzkzNw== |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.type | string | | Organization |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.private | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.pulls_url | string | `url` | https://api.github.com/repos/test/test/pulls{/number} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.pushed_at | string | | 2018-07-19T12:14:02Z |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.releases_url | string | `url` | https://api.github.com/repos/test/test/releases{/id} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.size | numeric | | 120647 |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.ssh_url | string | | git@github.com:test/test.git |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.stargazers_count | numeric | | 18086 |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.stargazers_url | string | `url` | https://api.github.com/repos/test/test/stargazers |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.statuses_url | string | `url` | https://api.github.com/repos/test/test/statuses/{sha} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.subscribers_url | string | `url` | https://api.github.com/repos/test/test/subscribers |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.subscription_url | string | `url` | https://api.github.com/repos/test/test/subscription |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.svn_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.tags_url | string | `url` | https://api.github.com/repos/test/test/tags |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.teams_url | string | `url` | https://api.github.com/repos/test/test/teams |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.trees_url | string | `url` | https://api.github.com/repos/test/test/git/trees{/sha} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.updated_at | string | | 2018-07-19T11:54:19Z |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.url | string | `url` | https://api.github.com/repos/test/test |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.watchers | numeric | | 18086 |
action_result.data.\*.payload.check_run.pull_requests.\*.base.repo.watchers_count | numeric | | 18086 |
action_result.data.\*.payload.check_run.pull_requests.\*.base.sha | string | `sha1` | 08a49bc5302de373bdb44e5c189133a7d5d5f12b |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/143937?v=4 |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.gravatar_id | string | | |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.id | numeric | | 143937 |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.login | string | `github username` | test |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjE0MzkzNw== |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.type | string | | Organization |
action_result.data.\*.payload.check_run.pull_requests.\*.base.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.pull_requests.\*.body | string | | Sample body |
action_result.data.\*.payload.check_run.pull_requests.\*.changed_files | numeric | | 6 |
action_result.data.\*.payload.check_run.pull_requests.\*.closed_at | string | | 2018-07-19T12:14:03Z |
action_result.data.\*.payload.check_run.pull_requests.\*.comments | numeric | | 1 |
action_result.data.\*.payload.check_run.pull_requests.\*.comments_url | string | `url` | https://api.github.com/repos/test/test/issues/27999/comments |
action_result.data.\*.payload.check_run.pull_requests.\*.commits | numeric | | 1 |
action_result.data.\*.payload.check_run.pull_requests.\*.commits_url | string | `url` | https://api.github.com/repos/test/test/pulls/27999/commits |
action_result.data.\*.payload.check_run.pull_requests.\*.created_at | string | | 2018-07-19T12:12:54Z |
action_result.data.\*.payload.check_run.pull_requests.\*.deletions | numeric | | 0 |
action_result.data.\*.payload.check_run.pull_requests.\*.diff_url | string | `url` | https://github.com/test/test/pull/27999.diff |
action_result.data.\*.payload.check_run.pull_requests.\*.head.label | string | | test:uuid-translations |
action_result.data.\*.payload.check_run.pull_requests.\*.head.ref | string | | uuid-translations |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.archive_url | string | `url` | https://api.github.com/repos/test/test/{archive_format}{/ref} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.archived | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.assignees_url | string | `url` | https://api.github.com/repos/test/test/assignees{/user} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.blobs_url | string | `url` | https://api.github.com/repos/test/test/git/blobs{/sha} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.branches_url | string | `url` | https://api.github.com/repos/test/test/branches{/branch} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.clone_url | string | `url` | https://github.com/test/test.git |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.collaborators_url | string | `url` | https://api.github.com/repos/test/test/collaborators{/collaborator} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.comments_url | string | `url` | https://api.github.com/repos/test/test/comments{/number} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.commits_url | string | `url` | https://api.github.com/repos/test/test/commits{/sha} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.compare_url | string | `url` | https://api.github.com/repos/test/test/compare/{base}...{head} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.contents_url | string | `url` | https://api.github.com/repos/test/test/contents/{+path} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.contributors_url | string | `url` | https://api.github.com/repos/test/test/contributors |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.created_at | string | | 2017-02-01T16:32:59Z |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.default_branch | string | | master |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.deployments_url | string | `url` | https://api.github.com/repos/test/test/deployments |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.description | string | | The test PHP framework |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.downloads_url | string | `url` | https://api.github.com/repos/test/test/downloads |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.events_url | string | `url` | https://api.github.com/repos/test/test/events |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.fork | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.forks | numeric | | 1 |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.forks_count | numeric | | 1 |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.forks_url | string | `url` | https://api.github.com/repos/test/test/forks |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.full_name | string | | test/test-repo |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.git_commits_url | string | `url` | https://api.github.com/repos/test/test/git/commits{/sha} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.git_refs_url | string | `url` | https://api.github.com/repos/test/test/git/refs{/sha} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.git_tags_url | string | `url` | https://api.github.com/repos/test/test/git/tags{/sha} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.git_url | string | | git://github.com/test/test.git |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.has_downloads | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.has_issues | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.has_pages | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.has_projects | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.has_wiki | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.homepage | string | `url` | https://test.com |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.hooks_url | string | `url` | https://api.github.com/repos/test/test/hooks |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.html_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.id | numeric | | 80639758 |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.issue_comment_url | string | `url` | https://api.github.com/repos/test/test/issues/comments{/number} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.issue_events_url | string | `url` | https://api.github.com/repos/test/test/issues/events{/number} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.issues_url | string | `url` | https://api.github.com/repos/test/test/issues{/number} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.keys_url | string | `url` | https://api.github.com/repos/test/test/keys{/key_id} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.labels_url | string | `url` | https://api.github.com/repos/test/test/labels{/name} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.language | string | | PHP |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.languages_url | string | `url` | https://api.github.com/repos/test/test/languages |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.license.key | string | | mit |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.license.name | string | | MIT License |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.license.node_id | string | | MDc6TGljZW5zZTEz |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.license.spdx_id | string | | MIT |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.license.url | string | `url` | https://api.github.com/licenses/mit |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.merges_url | string | `url` | https://api.github.com/repos/test/test/merges |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.milestones_url | string | `url` | https://api.github.com/repos/test/test/milestones{/number} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.mirror_url | string | `url` | |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.name | string | | test |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.node_id | string | | MDEwOlJlcG9zaXRvcnk4MDYzOTc1OA== |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.notifications_url | string | `url` | https://api.github.com/repos/test/test/notifications{?since,all,participating} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.open_issues | numeric | | 0 |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.open_issues_count | numeric | | 0 |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.gravatar_id | string | | |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.id | numeric | | 1032411 |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.login | string | `github username` | test |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.type | string | | User |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.private | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.pulls_url | string | `url` | https://api.github.com/repos/test/test/pulls{/number} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.pushed_at | string | | 2018-07-19T12:11:30Z |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.releases_url | string | `url` | https://api.github.com/repos/test/test/releases{/id} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.size | numeric | | 112468 |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.ssh_url | string | | git@github.com:test/test.git |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.stargazers_count | numeric | | 0 |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.stargazers_url | string | `url` | https://api.github.com/repos/test/test/stargazers |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.statuses_url | string | `url` | https://api.github.com/repos/test/test/statuses/{sha} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.subscribers_url | string | `url` | https://api.github.com/repos/test/test/subscribers |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.subscription_url | string | `url` | https://api.github.com/repos/test/test/subscription |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.svn_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.tags_url | string | `url` | https://api.github.com/repos/test/test/tags |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.teams_url | string | `url` | https://api.github.com/repos/test/test/teams |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.trees_url | string | `url` | https://api.github.com/repos/test/test/git/trees{/sha} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.updated_at | string | | 2017-02-01T16:33:18Z |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.url | string | `url` | https://api.github.com/repos/test/test |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.watchers | numeric | | 0 |
action_result.data.\*.payload.check_run.pull_requests.\*.head.repo.watchers_count | numeric | | 0 |
action_result.data.\*.payload.check_run.pull_requests.\*.head.sha | string | `sha1` | ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.gravatar_id | string | | |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.id | numeric | | 1032411 |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.login | string | `github username` | test |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.type | string | | User |
action_result.data.\*.payload.check_run.pull_requests.\*.head.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.pull_requests.\*.html_url | string | `url` | https://github.com/test/test/pull/27999 |
action_result.data.\*.payload.check_run.pull_requests.\*.id | numeric | | 202539219 |
action_result.data.\*.payload.check_run.pull_requests.\*.issue_url | string | `url` | https://api.github.com/repos/test/test/issues/27999 |
action_result.data.\*.payload.check_run.pull_requests.\*.labels.\*.color | string | | e10c02 |
action_result.data.\*.payload.check_run.pull_requests.\*.labels.\*.default | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.labels.\*.id | numeric | | 100079 |
action_result.data.\*.payload.check_run.pull_requests.\*.labels.\*.name | string | | Bug |
action_result.data.\*.payload.check_run.pull_requests.\*.labels.\*.node_id | string | | MDU6TGFiZWwxMDAwNzk= |
action_result.data.\*.payload.check_run.pull_requests.\*.labels.\*.url | string | `url` | https://api.github.com/repos/test/test/labels/Bug |
action_result.data.\*.payload.check_run.pull_requests.\*.locked | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.maintainer_can_modify | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.merge_commit_sha | string | `sha1` | ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.check_run.pull_requests.\*.mergeable | boolean | | False True |
action_result.data.\*.payload.check_run.pull_requests.\*.mergeable_state | string | | unknown |
action_result.data.\*.payload.check_run.pull_requests.\*.merged | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_at | string | | 2018-07-19T12:14:03Z |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/47313?v=4 |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.gravatar_id | string | | |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.id | numeric | | 47313 |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.login | string | `github username` | test |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.node_id | string | | MDQ6VXNlcjQ3MzEz |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.type | string | | User |
action_result.data.\*.payload.check_run.pull_requests.\*.merged_by.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.closed_at | string | | 2018-07-20T11:26:15Z |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.closed_issues | numeric | | 879 |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.created_at | string | | 2016-11-06T20:24:23Z |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/73419?v=4 |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.gravatar_id | string | | |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.id | numeric | | 73419 |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.login | string | `github username` | test |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.node_id | string | | MDQ6VXNlcjczNDE5 |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.type | string | | User |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.creator.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.description | string | `url` | https://test.com/roadmap?version=3.4#checker |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.due_on | string | | 2020-11-30T08:00:00Z |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.html_url | string | `url` | https://github.com/test/test/milestone/10 |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.id | numeric | | 2117464 |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.labels_url | string | `url` | https://api.github.com/repos/test/test/milestones/10/labels |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.node_id | string | | MDk6TWlsZXN0b25lMjExNzQ2NA== |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.number | numeric | | 10 |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.open_issues | numeric | | 15 |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.state | string | | open |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.title | string | | 3.4 |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.updated_at | string | | 2018-07-19T07:12:02Z |
action_result.data.\*.payload.check_run.pull_requests.\*.milestone.url | string | `url` | https://api.github.com/repos/test/test/milestones/10 |
action_result.data.\*.payload.check_run.pull_requests.\*.node_id | string | | MDExOlB1bGxSZXF1ZXN0MjAyNTM5MjE5 |
action_result.data.\*.payload.check_run.pull_requests.\*.number | numeric | | 27999 |
action_result.data.\*.payload.check_run.pull_requests.\*.patch_url | string | `url` | https://github.com/test/test/pull/27999.patch |
action_result.data.\*.payload.check_run.pull_requests.\*.rebaseable | boolean | | False True |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.avatar_url | string | `url` | https://avatars2.githubusercontent.com/u/57224?v=4 |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.gravatar_id | string | | |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.id | numeric | | 57224 |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.login | string | `github username` | test |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.node_id | string | | MDQ6VXNlcjU3MjI0 |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.type | string | | User |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_reviewers.\*.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.created_at | string | | 2018-07-16T23:08:17Z |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.description | string | | Everybody but Tony |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.id | numeric | | 2826794 |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.members_count | numeric | | 2 |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.members_url | string | `url` | https://api.github.com/teams/2826794/members{/member} |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.name | string | | not-tony-team |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.node_id | string | | MDQ6VGVhbTI4MjY3OTQ= |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.avatar_url | string | `url` | https://avatars0.githubusercontent.com/u/41309665?v=4 |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.created_at | string | | 2018-07-16T23:02:38Z |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.description | string | | |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.events_url | string | `url` | https://api.github.com/orgs/test/events |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.followers | numeric | | 3 |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.following | numeric | | 3 |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.has_organization_projects | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.has_repository_projects | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.hooks_url | string | `url` | https://api.github.com/orgs/test/hooks |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.id | numeric | | 41309665 |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.issues_url | string | `url` | https://api.github.com/orgs/test/issues |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.login | string | `github username` | test |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.members_url | string | `url` | https://api.github.com/orgs/test/members{/member} |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjQxMzA5NjY1 |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.public_gists | numeric | | 3 |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.public_members_url | string | `url` | https://api.github.com/orgs/test/public_members{/member} |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.public_repos | numeric | | 3 |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.repos_url | string | `url` | https://api.github.com/orgs/test/repos |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.type | string | | Organization |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.updated_at | string | | 2018-07-16T23:02:38Z |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.organization.url | string | `url` | https://api.github.com/orgs/test |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.permission | string | | pull |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.privacy | string | | closed |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.repos_count | numeric | | 2 |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.repositories_url | string | `url` | https://api.github.com/teams/test/repos |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.slug | string | | not-tony-team |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.updated_at | string | | 2018-07-16T23:08:17Z |
action_result.data.\*.payload.check_run.pull_requests.\*.requested_teams.\*.url | string | `url` | https://api.github.com/teams/2826794 |
action_result.data.\*.payload.check_run.pull_requests.\*.review_comment_url | string | `url` | https://api.github.com/repos/test/test/pulls/comments{/number} |
action_result.data.\*.payload.check_run.pull_requests.\*.review_comments | numeric | | 0 |
action_result.data.\*.payload.check_run.pull_requests.\*.review_comments_url | string | `url` | https://api.github.com/repos/test/test/pulls/27999/comments |
action_result.data.\*.payload.check_run.pull_requests.\*.state | string | | closed |
action_result.data.\*.payload.check_run.pull_requests.\*.statuses_url | string | `url` | https://api.github.com/repos/test/test/statuses/ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.check_run.pull_requests.\*.title | string | | Sample title |
action_result.data.\*.payload.check_run.pull_requests.\*.updated_at | string | | 2018-07-19T12:14:03Z |
action_result.data.\*.payload.check_run.pull_requests.\*.url | string | `url` | https://api.github.com/repos/test/test/pulls/27999 |
action_result.data.\*.payload.check_run.pull_requests.\*.user.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.check_run.pull_requests.\*.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_run.pull_requests.\*.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_run.pull_requests.\*.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_run.pull_requests.\*.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_run.pull_requests.\*.user.gravatar_id | string | | |
action_result.data.\*.payload.check_run.pull_requests.\*.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_run.pull_requests.\*.user.id | numeric | | 1032411 |
action_result.data.\*.payload.check_run.pull_requests.\*.user.login | string | `github username` | test |
action_result.data.\*.payload.check_run.pull_requests.\*.user.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.check_run.pull_requests.\*.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_run.pull_requests.\*.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_run.pull_requests.\*.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_run.pull_requests.\*.user.site_admin | boolean | | True False |
action_result.data.\*.payload.check_run.pull_requests.\*.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_run.pull_requests.\*.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_run.pull_requests.\*.user.type | string | | User |
action_result.data.\*.payload.check_run.pull_requests.\*.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_run.started_at | string | | 2018-05-04T01:14:52Z |
action_result.data.\*.payload.check_run.status | string | | completed |
action_result.data.\*.payload.check_run.url | string | `url` | https://api.github.com/repos/test/test-repo/check-runs/4 |
action_result.data.\*.payload.check_suite.after | string | `sha1` | d6fde92930d4715a2b49857d24b940956b26d2d3 |
action_result.data.\*.payload.check_suite.app.created_at | string | | 2018-04-25 20:42:10 |
action_result.data.\*.payload.check_suite.app.description | string | | |
action_result.data.\*.payload.check_suite.app.external_url | string | `url` | http://super-duper.example.com |
action_result.data.\*.payload.check_suite.app.html_url | string | `url` | http://github.com/apps/super-duper |
action_result.data.\*.payload.check_suite.app.id | numeric | | 2 |
action_result.data.\*.payload.check_suite.app.name | string | | Super Duper |
action_result.data.\*.payload.check_suite.app.node_id | string | | MDExOkludGVncmF0aW9uMQ= |
action_result.data.\*.payload.check_suite.app.owner.avatar_url | string | `url` | http://alambic.github.com/avatars/u/340? |
action_result.data.\*.payload.check_suite.app.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_suite.app.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_suite.app.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_suite.app.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_suite.app.owner.gravatar_id | string | | |
action_result.data.\*.payload.check_suite.app.owner.html_url | string | `url` | http://github.com/test |
action_result.data.\*.payload.check_suite.app.owner.id | numeric | | 340 |
action_result.data.\*.payload.check_suite.app.owner.login | string | `github username` | test |
action_result.data.\*.payload.check_suite.app.owner.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjE= |
action_result.data.\*.payload.check_suite.app.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_suite.app.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_suite.app.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_suite.app.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.check_suite.app.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_suite.app.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_suite.app.owner.type | string | | Organization |
action_result.data.\*.payload.check_suite.app.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_suite.app.updated_at | string | | 2018-04-25 20:42:10 |
action_result.data.\*.payload.check_suite.before | string | `sha1` | 146e867f55c26428e5f9fade55a9bbf5e95a7912 |
action_result.data.\*.payload.check_suite.check_runs_url | string | `url` | https://api.github.com/repos/test/test-repo/check-suites/5/check-runs |
action_result.data.\*.payload.check_suite.conclusion | string | | neutral |
action_result.data.\*.payload.check_suite.created_at | string | | 2018-04-25 20:42:10 |
action_result.data.\*.payload.check_suite.head_branch | string | | master |
action_result.data.\*.payload.check_suite.head_commit.author.email | string | `email` | test@user.com |
action_result.data.\*.payload.check_suite.head_commit.author.name | string | `github username` | test |
action_result.data.\*.payload.check_suite.head_commit.committer.email | string | `email` | test@user.com |
action_result.data.\*.payload.check_suite.head_commit.committer.name | string | `github username` | test |
action_result.data.\*.payload.check_suite.head_commit.id | string | `sha1` | d6fde92930d4715a2b49857d24b940956b26d2d3 |
action_result.data.\*.payload.check_suite.head_commit.message | string | | Sample message |
action_result.data.\*.payload.check_suite.head_commit.timestamp | string | | 2018-05-04T01:14:46Z |
action_result.data.\*.payload.check_suite.head_commit.tree_id | string | `sha1` | d6fde92930d4715a2b49857d24b940956b26d2d3 |
action_result.data.\*.payload.check_suite.head_sha | string | `sha1` | d6fde92930d4715a2b49857d24b940956b26d2d3 |
action_result.data.\*.payload.check_suite.id | numeric | | 5 |
action_result.data.\*.payload.check_suite.latest_check_runs_count | numeric | | 1 |
action_result.data.\*.payload.check_suite.latest_check_runs_url | string | `url` | https://api.github.com/repos/test/test-repo/check-suites/5/check-runs |
action_result.data.\*.payload.check_suite.pull_requests.\*.\_links.comments.href | string | `url` | https://api.github.com/repos/test/test/issues/27999/comments |
action_result.data.\*.payload.check_suite.pull_requests.\*.\_links.commits.href | string | `url` | https://api.github.com/repos/test/test/pulls/27999/commits |
action_result.data.\*.payload.check_suite.pull_requests.\*.\_links.html.href | string | `url` | https://github.com/test/test/pull/27999 |
action_result.data.\*.payload.check_suite.pull_requests.\*.\_links.issue.href | string | `url` | https://api.github.com/repos/test/test/issues/27999 |
action_result.data.\*.payload.check_suite.pull_requests.\*.\_links.review_comment.href | string | `url` | https://api.github.com/repos/test/test/pulls/comments{/number} |
action_result.data.\*.payload.check_suite.pull_requests.\*.\_links.review_comments.href | string | `url` | https://api.github.com/repos/test/test/pulls/27999/comments |
action_result.data.\*.payload.check_suite.pull_requests.\*.\_links.self.href | string | `url` | https://api.github.com/repos/test/test/pulls/27999 |
action_result.data.\*.payload.check_suite.pull_requests.\*.\_links.statuses.href | string | `url` | https://api.github.com/repos/test/test/statuses/ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.check_suite.pull_requests.\*.additions | numeric | | 24 |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/29939753?v=4 |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.gravatar_id | string | | |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.id | numeric | | 29939753 |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.login | string | `github username` | test |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.node_id | string | | MDQ6VXNlcjI5OTM5NzUz |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.site_admin | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.type | string | | User |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignee.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/29939753?v=4 |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.gravatar_id | string | | |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.id | numeric | | 29939753 |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.login | string | `github username` | test |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.node_id | string | | MDQ6VXNlcjI5OTM5NzUz |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.site_admin | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.type | string | | User |
action_result.data.\*.payload.check_suite.pull_requests.\*.assignees.\*.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.author_association | string | | CONTRIBUTOR |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.label | string | | test:2.8 |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.ref | string | | 2.8 |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.archive_url | string | `url` | https://api.github.com/repos/test/test/{archive_format}{/ref} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.archived | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.assignees_url | string | `url` | https://api.github.com/repos/test/test/assignees{/user} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.blobs_url | string | `url` | https://api.github.com/repos/test/test/git/blobs{/sha} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.branches_url | string | `url` | https://api.github.com/repos/test/test/branches{/branch} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.clone_url | string | `url` | https://github.com/test/test.git |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.collaborators_url | string | `url` | https://api.github.com/repos/test/test/collaborators{/collaborator} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.comments_url | string | `url` | https://api.github.com/repos/test/test/comments{/number} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.commits_url | string | `url` | https://api.github.com/repos/test/test/commits{/sha} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.compare_url | string | `url` | https://api.github.com/repos/test/test/compare/{base}..{head} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.contents_url | string | `url` | https://api.github.com/repos/test/test/contents/{+path} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.contributors_url | string | `url` | https://api.github.com/repos/test/test/contributors |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.created_at | string | | 2010-01-04T14:21:21Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.default_branch | string | | master |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.deployments_url | string | `url` | https://api.github.com/repos/test/test/deployments |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.description | string | | The test PHP framework |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.downloads_url | string | `url` | https://api.github.com/repos/test/test/downloads |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.events_url | string | `url` | https://api.github.com/repos/test/test/events |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.fork | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.forks | numeric | | 6330 |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.forks_count | numeric | | 6330 |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.forks_url | string | `url` | https://api.github.com/repos/test/test/forks |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.full_name | string | | test/test-repo |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.git_commits_url | string | `url` | https://api.github.com/repos/test/test/git/commits{/sha} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.git_refs_url | string | `url` | https://api.github.com/repos/test/test/git/refs{/sha} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.git_tags_url | string | `url` | https://api.github.com/repos/test/test/git/tags{/sha} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.git_url | string | | git://github.com/test/test.git |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.has_downloads | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.has_issues | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.has_pages | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.has_projects | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.has_wiki | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.homepage | string | `url` | https://test.com |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.hooks_url | string | `url` | https://api.github.com/repos/test/test/hooks |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.html_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.id | numeric | | 458058 |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.issue_comment_url | string | `url` | https://api.github.com/repos/test/test/issues/comments{/number} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.issue_events_url | string | `url` | https://api.github.com/repos/test/test/issues/events{/number} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.issues_url | string | `url` | https://api.github.com/repos/test/test/issues{/number} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.keys_url | string | `url` | https://api.github.com/repos/test/test/keys{/key_id} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.labels_url | string | `url` | https://api.github.com/repos/test/test/labels{/name} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.language | string | | PHP |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.languages_url | string | `url` | https://api.github.com/repos/test/test/languages |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.license.key | string | | mit |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.license.name | string | | MIT License |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.license.node_id | string | | MDc6TGljZW5zZTEz |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.license.spdx_id | string | | MIT |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.license.url | string | `url` | https://api.github.com/licenses/mit |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.merges_url | string | `url` | https://api.github.com/repos/test/test/merges |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.milestones_url | string | `url` | https://api.github.com/repos/test/test/milestones{/number} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.mirror_url | string | `url` | |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.name | string | | test |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.node_id | string | | MDEwOlJlcG9zaXRvcnk0NTgwNTg= |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.notifications_url | string | `url` | https://api.github.com/repos/test/test/notifications{?since,all,participating} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.open_issues | numeric | | 893 |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.open_issues_count | numeric | | 893 |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/143937?v=4 |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.gravatar_id | string | | |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.id | numeric | | 143937 |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.login | string | `github username` | test |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjE0MzkzNw== |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.type | string | | Organization |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.private | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.pulls_url | string | `url` | https://api.github.com/repos/test/test/pulls{/number} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.pushed_at | string | | 2018-07-19T12:14:02Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.releases_url | string | `url` | https://api.github.com/repos/test/test/releases{/id} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.size | numeric | | 120647 |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.ssh_url | string | | git@github.com:test/test.git |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.stargazers_count | numeric | | 18086 |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.stargazers_url | string | `url` | https://api.github.com/repos/test/test/stargazers |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.statuses_url | string | `url` | https://api.github.com/repos/test/test/statuses/{sha} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.subscribers_url | string | `url` | https://api.github.com/repos/test/test/subscribers |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.subscription_url | string | `url` | https://api.github.com/repos/test/test/subscription |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.svn_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.tags_url | string | `url` | https://api.github.com/repos/test/test/tags |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.teams_url | string | `url` | https://api.github.com/repos/test/test/teams |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.trees_url | string | `url` | https://api.github.com/repos/test/test/git/trees{/sha} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.updated_at | string | | 2018-07-19T11:54:19Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.url | string | `url` | https://api.github.com/repos/test/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.watchers | numeric | | 18086 |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.repo.watchers_count | numeric | | 18086 |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.sha | string | `sha1` | 08a49bc5302de373bdb44e5c189133a7d5d5f12b |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/143937?v=4 |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.gravatar_id | string | | |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.id | numeric | | 143937 |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.login | string | `github username` | test |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjE0MzkzNw== |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.site_admin | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.type | string | | Organization |
action_result.data.\*.payload.check_suite.pull_requests.\*.base.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.body | string | | Sample body |
action_result.data.\*.payload.check_suite.pull_requests.\*.changed_files | numeric | | 6 |
action_result.data.\*.payload.check_suite.pull_requests.\*.closed_at | string | | 2018-07-19T12:14:03Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.comments | numeric | | 1 |
action_result.data.\*.payload.check_suite.pull_requests.\*.comments_url | string | `url` | https://api.github.com/repos/test/test/issues/27999/comments |
action_result.data.\*.payload.check_suite.pull_requests.\*.commits | numeric | | 1 |
action_result.data.\*.payload.check_suite.pull_requests.\*.commits_url | string | `url` | https://api.github.com/repos/test/test/pulls/27999/commits |
action_result.data.\*.payload.check_suite.pull_requests.\*.created_at | string | | 2018-07-19T12:12:54Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.deletions | numeric | | 0 |
action_result.data.\*.payload.check_suite.pull_requests.\*.diff_url | string | `url` | https://github.com/test/test/pull/27999.diff |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.label | string | | test:uuid-translations |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.ref | string | | uuid-translations |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.archive_url | string | `url` | https://api.github.com/repos/test/test/{archive_format}{/ref} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.archived | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.assignees_url | string | `url` | https://api.github.com/repos/test/test/assignees{/user} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.blobs_url | string | `url` | https://api.github.com/repos/test/test/git/blobs{/sha} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.branches_url | string | `url` | https://api.github.com/repos/test/test/branches{/branch} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.clone_url | string | `url` | https://github.com/test/test.git |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.collaborators_url | string | `url` | https://api.github.com/repos/test/test/collaborators{/collaborator} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.comments_url | string | `url` | https://api.github.com/repos/test/test/comments{/number} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.commits_url | string | `url` | https://api.github.com/repos/test/test/commits{/sha} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.compare_url | string | `url` | https://api.github.com/repos/test/test/compare/{base}..{head} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.contents_url | string | `url` | https://api.github.com/repos/test/test/contents/{+path} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.contributors_url | string | `url` | https://api.github.com/repos/test/test/contributors |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.created_at | string | | 2017-02-01T16:32:59Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.default_branch | string | | master |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.deployments_url | string | `url` | https://api.github.com/repos/test/test/deployments |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.description | string | | The test PHP framework |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.downloads_url | string | `url` | https://api.github.com/repos/test/test/downloads |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.events_url | string | `url` | https://api.github.com/repos/test/test/events |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.fork | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.forks | numeric | | 1 |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.forks_count | numeric | | 1 |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.forks_url | string | `url` | https://api.github.com/repos/test/test/forks |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.full_name | string | | test/test-repo |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.git_commits_url | string | `url` | https://api.github.com/repos/test/test/git/commits{/sha} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.git_refs_url | string | `url` | https://api.github.com/repos/test/test/git/refs{/sha} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.git_tags_url | string | `url` | https://api.github.com/repos/test/test/git/tags{/sha} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.git_url | string | | git://github.com/test/test.git |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.has_downloads | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.has_issues | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.has_pages | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.has_projects | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.has_wiki | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.homepage | string | `url` | https://test.com |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.hooks_url | string | `url` | https://api.github.com/repos/test/test/hooks |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.html_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.id | numeric | | 80639758 |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.issue_comment_url | string | `url` | https://api.github.com/repos/test/test/issues/comments{/number} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.issue_events_url | string | `url` | https://api.github.com/repos/test/test/issues/events{/number} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.issues_url | string | `url` | https://api.github.com/repos/test/test/issues{/number} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.keys_url | string | `url` | https://api.github.com/repos/test/test/keys{/key_id} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.labels_url | string | `url` | https://api.github.com/repos/test/test/labels{/name} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.language | string | | PHP |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.languages_url | string | `url` | https://api.github.com/repos/test/test/languages |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.license.key | string | | mit |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.license.name | string | | MIT License |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.license.node_id | string | | MDc6TGljZW5zZTEz |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.license.spdx_id | string | | MIT |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.license.url | string | `url` | https://api.github.com/licenses/mit |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.merges_url | string | `url` | https://api.github.com/repos/test/test/merges |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.milestones_url | string | `url` | https://api.github.com/repos/test/test/milestones{/number} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.mirror_url | string | `url` | |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.name | string | `github repo` | test |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.node_id | string | | MDEwOlJlcG9zaXRvcnk4MDYzOTc1OA== |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.notifications_url | string | `url` | https://api.github.com/repos/test/test/notifications{?since,all,participating} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.open_issues | numeric | | 0 |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.open_issues_count | numeric | | 0 |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.gravatar_id | string | | |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.id | numeric | | 1032411 |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.login | string | `github username` | test |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.type | string | | User |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.private | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.pulls_url | string | `url` | https://api.github.com/repos/test/test/pulls{/number} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.pushed_at | string | | 2018-07-19T12:11:30Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.releases_url | string | `url` | https://api.github.com/repos/test/test/releases{/id} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.size | numeric | | 112468 |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.ssh_url | string | | git@github.com:test/test.git |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.stargazers_count | numeric | | 0 |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.stargazers_url | string | `url` | https://api.github.com/repos/test/test/stargazers |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.statuses_url | string | `url` | https://api.github.com/repos/test/test/statuses/{sha} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.subscribers_url | string | `url` | https://api.github.com/repos/test/test/subscribers |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.subscription_url | string | `url` | https://api.github.com/repos/test/test/subscription |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.svn_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.tags_url | string | `url` | https://api.github.com/repos/test/test/tags |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.teams_url | string | `url` | https://api.github.com/repos/test/test/teams |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.trees_url | string | `url` | https://api.github.com/repos/test/test/git/trees{/sha} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.updated_at | string | | 2017-02-01T16:33:18Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.url | string | `url` | https://api.github.com/repos/test/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.watchers | numeric | | 0 |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.repo.watchers_count | numeric | | 0 |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.sha | string | `sha1` | ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.gravatar_id | string | | |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.id | numeric | | 1032411 |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.login | string | `github username` | test |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.site_admin | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.type | string | | User |
action_result.data.\*.payload.check_suite.pull_requests.\*.head.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.html_url | string | `url` | https://github.com/test/test/pull/27999 |
action_result.data.\*.payload.check_suite.pull_requests.\*.id | numeric | | 202539219 |
action_result.data.\*.payload.check_suite.pull_requests.\*.issue_url | string | `url` | https://api.github.com/repos/test/test/issues/27999 |
action_result.data.\*.payload.check_suite.pull_requests.\*.labels.\*.color | string | | e10c02 |
action_result.data.\*.payload.check_suite.pull_requests.\*.labels.\*.default | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.labels.\*.id | numeric | | 100079 |
action_result.data.\*.payload.check_suite.pull_requests.\*.labels.\*.name | string | | Bug |
action_result.data.\*.payload.check_suite.pull_requests.\*.labels.\*.node_id | string | | MDU6TGFiZWwxMDAwNzk= |
action_result.data.\*.payload.check_suite.pull_requests.\*.labels.\*.url | string | `url` | https://api.github.com/repos/test/test/labels/Bug |
action_result.data.\*.payload.check_suite.pull_requests.\*.locked | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.maintainer_can_modify | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.merge_commit_sha | string | `sha1` | ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.check_suite.pull_requests.\*.mergeable | boolean | | False True |
action_result.data.\*.payload.check_suite.pull_requests.\*.mergeable_state | string | | unknown |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_at | string | | 2018-07-19T12:14:03Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/47313?v=4 |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.gravatar_id | string | | |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.id | numeric | | 47313 |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.login | string | `github username` | test |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.node_id | string | | MDQ6VXNlcjQ3MzEz |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.site_admin | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.type | string | | User |
action_result.data.\*.payload.check_suite.pull_requests.\*.merged_by.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.closed_at | string | | 2016-11-06T21:24:23Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.closed_issues | numeric | | 879 |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.created_at | string | | 2016-11-06T20:24:23Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/73419?v=4 |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.gravatar_id | string | | |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.id | numeric | | 73419 |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.login | string | `github username` | test |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.node_id | string | | MDQ6VXNlcjczNDE5 |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.site_admin | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.type | string | | User |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.creator.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.description | string | `url` | https://test.com/roadmap?version=3.4#checker |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.due_on | string | | 2020-11-30T08:00:00Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.html_url | string | `url` | https://github.com/test/test/milestone/10 |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.id | numeric | | 2117464 |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.labels_url | string | `url` | https://api.github.com/repos/test/test/milestones/10/labels |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.node_id | string | | MDk6TWlsZXN0b25lMjExNzQ2NA== |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.number | numeric | | 10 |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.open_issues | numeric | | 15 |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.state | string | | open |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.title | string | | 3.4 |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.updated_at | string | | 2018-07-19T07:12:02Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.milestone.url | string | `url` | https://api.github.com/repos/test/test/milestones/10 |
action_result.data.\*.payload.check_suite.pull_requests.\*.node_id | string | | MDExOlB1bGxSZXF1ZXN0MjAyNTM5MjE5 |
action_result.data.\*.payload.check_suite.pull_requests.\*.number | numeric | | 27999 |
action_result.data.\*.payload.check_suite.pull_requests.\*.patch_url | string | `url` | https://github.com/test/test/pull/27999.patch |
action_result.data.\*.payload.check_suite.pull_requests.\*.rebaseable | boolean | | False True |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.avatar_url | string | `url` | https://avatars2.githubusercontent.com/u/57224?v=4 |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.gravatar_id | string | | |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.id | numeric | | 57224 |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.login | string | `github username` | test |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.node_id | string | | MDQ6VXNlcjU3MjI0 |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.site_admin | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.type | string | | User |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_reviewers.\*.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.created_at | string | | 2018-07-16T23:08:17Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.description | string | | Everybody but Tony |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.id | numeric | | 2826794 |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.members_count | numeric | | 2 |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.members_url | string | `url` | https://api.github.com/teams/2826794/members{/member} |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.name | string | | not-tony-team |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.node_id | string | | MDQ6VGVhbTI4MjY3OTQ= |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.avatar_url | string | `url` | https://avatars0.githubusercontent.com/u/41309665?v=4 |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.created_at | string | | 2018-07-16T23:02:38Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.description | string | | |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.events_url | string | `url` | https://api.github.com/orgs/test/events |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.followers | numeric | | 3 |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.following | numeric | | 3 |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.has_organization_projects | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.has_repository_projects | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.hooks_url | string | `url` | https://api.github.com/orgs/test/hooks |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.id | numeric | | 41309665 |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.issues_url | string | `url` | https://api.github.com/orgs/test/issues |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.login | string | `github organization name` | test |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.members_url | string | `url` | https://api.github.com/orgs/test/members{/member} |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjQxMzA5NjY1 |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.public_gists | numeric | | 3 |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.public_members_url | string | `url` | https://api.github.com/orgs/test/public_members{/member} |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.public_repos | numeric | | 3 |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.repos_url | string | `url` | https://api.github.com/orgs/test/repos |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.type | string | | Organization |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.updated_at | string | | 2018-07-16T23:02:38Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.organization.url | string | `url` | https://api.github.com/orgs/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.permission | string | | pull |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.privacy | string | | closed |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.repos_count | numeric | | 2 |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.repositories_url | string | `url` | https://api.github.com/teams/test/repos |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.slug | string | | not-tony-team |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.updated_at | string | | 2018-07-16T23:08:17Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.requested_teams.\*.url | string | `url` | https://api.github.com/teams/2826794 |
action_result.data.\*.payload.check_suite.pull_requests.\*.review_comment_url | string | `url` | https://api.github.com/repos/test/test/pulls/comments{/number} |
action_result.data.\*.payload.check_suite.pull_requests.\*.review_comments | numeric | | 0 |
action_result.data.\*.payload.check_suite.pull_requests.\*.review_comments_url | string | `url` | https://api.github.com/repos/test/test/pulls/27999/comments |
action_result.data.\*.payload.check_suite.pull_requests.\*.state | string | | closed |
action_result.data.\*.payload.check_suite.pull_requests.\*.statuses_url | string | `url` | https://api.github.com/repos/test/test/statuses/ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.check_suite.pull_requests.\*.title | string | | Sample title |
action_result.data.\*.payload.check_suite.pull_requests.\*.updated_at | string | | 2018-07-19T12:14:03Z |
action_result.data.\*.payload.check_suite.pull_requests.\*.url | string | `url` | https://api.github.com/repos/test/test/pulls/27999 |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.gravatar_id | string | | |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.id | numeric | | 1032411 |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.login | string | `github username` | test |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.site_admin | boolean | | True False |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.type | string | | User |
action_result.data.\*.payload.check_suite.pull_requests.\*.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_suite.status | string | | completed |
action_result.data.\*.payload.check_suite.updated_at | string | | 2018-04-25 20:42:10 |
action_result.data.\*.payload.comment.\_links.check_run.pull_requests.\*.href | string | `url` | https://api.github.com/repos/test/test/pulls/27967 |
action_result.data.\*.payload.comment.\_links.html.href | string | `url` | https://github.com/test/test/pull/27967#discussion_r203241551 |
action_result.data.\*.payload.comment.\_links.pull_request.href | string | `url` | https://api.github.com/repos/test/test/pulls/27967 |
action_result.data.\*.payload.comment.\_links.pull_request.href | string | `url` | https://api.github.com/repos/test/test/pulls/27967 |
action_result.data.\*.payload.comment.\_links.self.href | string | `url` | https://api.github.com/repos/test/test/pulls/comments/203241551 |
action_result.data.\*.payload.comment.author_association | string | | CONTRIBUTOR |
action_result.data.\*.payload.comment.body | string | | LGTM. Can you add some tests? |
action_result.data.\*.payload.comment.commit_id | string | `sha1` | 329bd507c1123c1ab24e58b78fa8d32bd1c70639 |
action_result.data.\*.payload.comment.created_at | string | | 2018-07-20T05:36:22Z |
action_result.data.\*.payload.comment.diff_hunk | string | | Sample |
action_result.data.\*.payload.comment.html_url | string | `url` | https://github.com/twigphp/Twig/pull/2721#issuecomment-406494157 |
action_result.data.\*.payload.comment.id | numeric | | 406494157 |
action_result.data.\*.payload.comment.in_reply_to_id | numeric | | 203123149 |
action_result.data.\*.payload.comment.issue_url | string | `url` | https://api.github.com/repos/twigphp/Twig/issues/2721 |
action_result.data.\*.payload.comment.line | string | | |
action_result.data.\*.payload.comment.node_id | string | | MDEyOklzc3VlQ29tbWVudDQwNjQ5NDE1Nw== |
action_result.data.\*.payload.comment.original_commit_id | string | `sha1` | 329bd507c1123c1ab24e58b78fa8d32bd1c70639 |
action_result.data.\*.payload.comment.original_position | numeric | | 13 |
action_result.data.\*.payload.comment.path | string | | src/test/Component/Finder/Finder.php |
action_result.data.\*.payload.comment.position | numeric | | 13 |
action_result.data.\*.payload.comment.pull_request_review_id | numeric | | 138091767 |
action_result.data.\*.payload.comment.pull_request_url | string | `url` | https://api.github.com/repos/test/test/pulls/27967 |
action_result.data.\*.payload.comment.updated_at | string | | 2018-07-20T05:36:22Z |
action_result.data.\*.payload.comment.url | string | `url` | https://api.github.com/repos/twigphp/Twig/issues/comments/406494157 |
action_result.data.\*.payload.comment.user.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/47313?v=4 |
action_result.data.\*.payload.comment.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.comment.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.comment.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.comment.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.comment.user.gravatar_id | string | | |
action_result.data.\*.payload.comment.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.comment.user.id | numeric | | 47313 |
action_result.data.\*.payload.comment.user.login | string | `github username` | test |
action_result.data.\*.payload.comment.user.node_id | string | | MDQ6VXNlcjQ3MzEz |
action_result.data.\*.payload.comment.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.comment.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.comment.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.comment.user.site_admin | boolean | | True False |
action_result.data.\*.payload.comment.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.comment.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.comment.user.type | string | | User |
action_result.data.\*.payload.comment.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.commits.\*.author.email | string | `email` | jz@becklyn.com |
action_result.data.\*.payload.commits.\*.author.name | string | `github username` | Jannik Zschiesche |
action_result.data.\*.payload.commits.\*.distinct | boolean | | True False |
action_result.data.\*.payload.commits.\*.message | string | | Add several missing translations of the UUID validation message |
action_result.data.\*.payload.commits.\*.sha | string | `sha1` | ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.commits.\*.url | string | `url` | https://api.github.com/repos/test/test/commits/ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.compare | string | `url` | https://github.com/test/test-repo/compare/a10867b14bb7...000000000000 |
action_result.data.\*.payload.created | boolean | | True False |
action_result.data.\*.payload.deleted | boolean | | True False |
action_result.data.\*.payload.description | string | | test-repo-Description |
action_result.data.\*.payload.distinct_size | numeric | | 100 |
action_result.data.\*.payload.distinct_size | numeric | | 2 |
action_result.data.\*.payload.effective_date | string | | 2017-10-25T00:00:00+00:00 |
action_result.data.\*.payload.forced | boolean | | True False |
action_result.data.\*.payload.forkee.archive_url | string | `url` | https://api.github.com/repos/test/test-proj/{archive_format}{/ref} |
action_result.data.\*.payload.forkee.archived | boolean | | True False |
action_result.data.\*.payload.forkee.assignees_url | string | `url` | https://api.github.com/repos/test/test-proj/assignees{/user} |
action_result.data.\*.payload.forkee.blobs_url | string | `url` | https://api.github.com/repos/test/test-proj/git/blobs{/sha} |
action_result.data.\*.payload.forkee.branches_url | string | `url` | https://api.github.com/repos/test/test-proj/branches{/branch} |
action_result.data.\*.payload.forkee.clone_url | string | `url` | https://github.com/test/test-proj.git |
action_result.data.\*.payload.forkee.collaborators_url | string | `url` | https://api.github.com/repos/test/test-proj/collaborators{/collaborator} |
action_result.data.\*.payload.forkee.comments_url | string | `url` | https://api.github.com/repos/test/test-proj/comments{/number} |
action_result.data.\*.payload.forkee.commits_url | string | `url` | https://api.github.com/repos/test/test-proj/commits{/sha} |
action_result.data.\*.payload.forkee.compare_url | string | `url` | https://api.github.com/repos/test/test-proj/compare/{base}...{head} |
action_result.data.\*.payload.forkee.contents_url | string | `url` | https://api.github.com/repos/test/test-proj/contents/{+path} |
action_result.data.\*.payload.forkee.contributors_url | string | `url` | https://api.github.com/repos/test/test-proj/contributors |
action_result.data.\*.payload.forkee.created_at | string | | 2018-07-20T06:03:13Z |
action_result.data.\*.payload.forkee.default_branch | string | | master |
action_result.data.\*.payload.forkee.deployments_url | string | `url` | https://api.github.com/repos/test/test-proj/deployments |
action_result.data.\*.payload.forkee.description | string | | |
action_result.data.\*.payload.forkee.downloads_url | string | `url` | https://api.github.com/repos/test/test-proj/downloads |
action_result.data.\*.payload.forkee.events_url | string | `url` | https://api.github.com/repos/test/test-proj/events |
action_result.data.\*.payload.forkee.fork | boolean | | True False |
action_result.data.\*.payload.forkee.forks | numeric | | 0 |
action_result.data.\*.payload.forkee.forks_count | numeric | | 0 |
action_result.data.\*.payload.forkee.forks_url | string | `url` | https://api.github.com/repos/test/test-proj/forks |
action_result.data.\*.payload.forkee.full_name | string | | test/test-repo |
action_result.data.\*.payload.forkee.git_commits_url | string | `url` | https://api.github.com/repos/test/test-proj/git/commits{/sha} |
action_result.data.\*.payload.forkee.git_refs_url | string | `url` | https://api.github.com/repos/test/test-proj/git/refs{/sha} |
action_result.data.\*.payload.forkee.git_tags_url | string | `url` | https://api.github.com/repos/test/test-proj/git/tags{/sha} |
action_result.data.\*.payload.forkee.git_url | string | | git://github.com/test/test-proj.git |
action_result.data.\*.payload.forkee.has_downloads | boolean | | True False |
action_result.data.\*.payload.forkee.has_issues | boolean | | True False |
action_result.data.\*.payload.forkee.has_pages | boolean | | True False |
action_result.data.\*.payload.forkee.has_projects | boolean | | True False |
action_result.data.\*.payload.forkee.has_wiki | boolean | | True False |
action_result.data.\*.payload.forkee.homepage | string | `url` | https://test.com |
action_result.data.\*.payload.forkee.hooks_url | string | `url` | https://api.github.com/repos/test/test-proj/hooks |
action_result.data.\*.payload.forkee.html_url | string | `url` | https://github.com/test/test-proj |
action_result.data.\*.payload.forkee.id | numeric | | 141670240 |
action_result.data.\*.payload.forkee.issue_comment_url | string | `url` | https://api.github.com/repos/test/test-proj/issues/comments{/number} |
action_result.data.\*.payload.forkee.issue_events_url | string | `url` | https://api.github.com/repos/test/test-proj/issues/events{/number} |
action_result.data.\*.payload.forkee.issues_url | string | `url` | https://api.github.com/repos/test/test-proj/issues{/number} |
action_result.data.\*.payload.forkee.keys_url | string | `url` | https://api.github.com/repos/test/test-proj/keys{/key_id} |
action_result.data.\*.payload.forkee.labels_url | string | `url` | https://api.github.com/repos/test/test-proj/labels{/name} |
action_result.data.\*.payload.forkee.language | string | | PHP |
action_result.data.\*.payload.forkee.languages_url | string | `url` | https://api.github.com/repos/test/test-proj/languages |
action_result.data.\*.payload.forkee.license.key | string | | mit |
action_result.data.\*.payload.forkee.license.name | string | | MIT License |
action_result.data.\*.payload.forkee.license.node_id | string | | MDc6TGljZW5zZTEz |
action_result.data.\*.payload.forkee.license.spdx_id | string | | MIT |
action_result.data.\*.payload.forkee.license.url | string | `url` | https://api.github.com/licenses/mit |
action_result.data.\*.payload.forkee.merges_url | string | `url` | https://api.github.com/repos/test/test-proj/merges |
action_result.data.\*.payload.forkee.milestones_url | string | `url` | https://api.github.com/repos/test/test-proj/milestones{/number} |
action_result.data.\*.payload.forkee.mirror_url | string | `url` | |
action_result.data.\*.payload.forkee.name | string | | test-proj |
action_result.data.\*.payload.forkee.node_id | string | | MDEwOlJlcG9zaXRvcnkxNDE2NzAyNDA= |
action_result.data.\*.payload.forkee.notifications_url | string | `url` | https://api.github.com/repos/test/test-proj/notifications{?since,all,participating} |
action_result.data.\*.payload.forkee.open_issues | numeric | | 0 |
action_result.data.\*.payload.forkee.open_issues_count | numeric | | 0 |
action_result.data.\*.payload.forkee.owner.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/29939753?v=4 |
action_result.data.\*.payload.forkee.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.forkee.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.forkee.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.forkee.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.forkee.owner.gravatar_id | string | | |
action_result.data.\*.payload.forkee.owner.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.forkee.owner.id | numeric | | 29939753 |
action_result.data.\*.payload.forkee.owner.login | string | `github username` | test |
action_result.data.\*.payload.forkee.owner.node_id | string | | MDQ6VXNlcjI5OTM5NzUz |
action_result.data.\*.payload.forkee.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.forkee.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.forkee.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.forkee.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.forkee.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.forkee.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.forkee.owner.type | string | | User |
action_result.data.\*.payload.forkee.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.forkee.private | boolean | | True False |
action_result.data.\*.payload.forkee.public | boolean | | True False |
action_result.data.\*.payload.forkee.pulls_url | string | `url` | https://api.github.com/repos/test/test-proj/pulls{/number} |
action_result.data.\*.payload.forkee.pushed_at | string | | 2018-07-20T06:02:31Z |
action_result.data.\*.payload.forkee.releases_url | string | `url` | https://api.github.com/repos/test/test-proj/releases{/id} |
action_result.data.\*.payload.forkee.size | numeric | | 0 |
action_result.data.\*.payload.forkee.ssh_url | string | | git@github.com:test/test-proj.git |
action_result.data.\*.payload.forkee.stargazers_count | numeric | | 0 |
action_result.data.\*.payload.forkee.stargazers_url | string | `url` | https://api.github.com/repos/test/test-proj/stargazers |
action_result.data.\*.payload.forkee.statuses_url | string | `url` | https://api.github.com/repos/test/test-proj/statuses/{sha} |
action_result.data.\*.payload.forkee.subscribers_url | string | `url` | https://api.github.com/repos/test/test-proj/subscribers |
action_result.data.\*.payload.forkee.subscription_url | string | `url` | https://api.github.com/repos/test/test-proj/subscription |
action_result.data.\*.payload.forkee.svn_url | string | `url` | https://github.com/test/test-proj |
action_result.data.\*.payload.forkee.tags_url | string | `url` | https://api.github.com/repos/test/test-proj/tags |
action_result.data.\*.payload.forkee.teams_url | string | `url` | https://api.github.com/repos/test/test-proj/teams |
action_result.data.\*.payload.forkee.trees_url | string | `url` | https://api.github.com/repos/test/test-proj/git/trees{/sha} |
action_result.data.\*.payload.forkee.updated_at | string | | 2018-07-20T06:02:33Z |
action_result.data.\*.payload.forkee.url | string | `url` | https://api.github.com/repos/test/test-proj |
action_result.data.\*.payload.forkee.watchers | numeric | | 0 |
action_result.data.\*.payload.forkee.watchers_count | numeric | | 0 |
action_result.data.\*.payload.head | string | `sha1` | 9bfa971bc5662a6f90408b58a7b2453d7dae4f83 |
action_result.data.\*.payload.head_commit.author.email | string | `email` | test@user.com |
action_result.data.\*.payload.head_commit.author.name | string | `github username` | test |
action_result.data.\*.payload.head_commit.committer.email | string | `email` | test@user.com |
action_result.data.\*.payload.head_commit.committer.name | string | `github username` | test |
action_result.data.\*.payload.head_commit.id | string | `sha1` | d6fde92930d4715a2b49857d24b940956b26d2d3 |
action_result.data.\*.payload.head_commit.message | string | | Sample message |
action_result.data.\*.payload.head_commit.timestamp | string | | 2018-05-04T01:14:46Z |
action_result.data.\*.payload.head_commit.tree_id | string | `sha1` | d6fde92930d4715a2b49857d24b940956b26d2d3 |
action_result.data.\*.payload.installation.access_tokens_url | string | `url` | https://api.github.com/installations/2/access_tokens |
action_result.data.\*.payload.installation.account.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.installation.account.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.installation.account.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.installation.account.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.installation.account.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.installation.account.gravatar_id | string | | |
action_result.data.\*.payload.installation.account.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.installation.account.id | numeric | | 1032411 |
action_result.data.\*.payload.installation.account.login | string | `github username` | test |
action_result.data.\*.payload.installation.account.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.installation.account.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.installation.account.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.installation.account.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.installation.account.site_admin | boolean | | True False |
action_result.data.\*.payload.installation.account.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.installation.account.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.installation.account.type | string | | User |
action_result.data.\*.payload.installation.account.url | string | `url` | https://api.github.com/users/octocat |
action_result.data.\*.payload.installation.app_id | numeric | | 5725 |
action_result.data.\*.payload.installation.created_at | numeric | | 1525109898 |
action_result.data.\*.payload.installation.events | string | | User |
action_result.data.\*.payload.installation.html_url | string | `url` | https://github.com/settings/installations/2 |
action_result.data.\*.payload.installation.id | numeric | | 2 |
action_result.data.\*.payload.installation.permissions.contents | string | | read |
action_result.data.\*.payload.installation.permissions.issues | string | | write |
action_result.data.\*.payload.installation.permissions.metadata | string | | read |
action_result.data.\*.payload.installation.repositories_url | string | `url` | https://api.github.com/installation/repositories |
action_result.data.\*.payload.installation.repository_selection | string | | selected |
action_result.data.\*.payload.installation.single_file_name | string | `file name` | config.yml |
action_result.data.\*.payload.installation.target_id | numeric | | 3880403 |
action_result.data.\*.payload.installation.target_type | string | | User |
action_result.data.\*.payload.installation.updated_at | numeric | | 1525109899 |
action_result.data.\*.payload.issue.assignee.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/243674?v=4 |
action_result.data.\*.payload.issue.assignee.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.issue.assignee.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.issue.assignee.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.issue.assignee.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.issue.assignee.gravatar_id | string | | |
action_result.data.\*.payload.issue.assignee.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.issue.assignee.id | numeric | | 243674 |
action_result.data.\*.payload.issue.assignee.login | string | `github username` | test |
action_result.data.\*.payload.issue.assignee.node_id | string | | MDQ6VXNlcjI0MzY3NA== |
action_result.data.\*.payload.issue.assignee.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.issue.assignee.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.issue.assignee.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.issue.assignee.site_admin | boolean | | True False |
action_result.data.\*.payload.issue.assignee.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.issue.assignee.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.issue.assignee.type | string | | User |
action_result.data.\*.payload.issue.assignee.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.issue.assignees.\*.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/243674?v=4 |
action_result.data.\*.payload.issue.assignees.\*.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.issue.assignees.\*.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.issue.assignees.\*.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.issue.assignees.\*.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.issue.assignees.\*.gravatar_id | string | | |
action_result.data.\*.payload.issue.assignees.\*.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.issue.assignees.\*.id | numeric | | 243674 |
action_result.data.\*.payload.issue.assignees.\*.login | string | `github username` | test |
action_result.data.\*.payload.issue.assignees.\*.node_id | string | | MDQ6VXNlcjI0MzY3NA== |
action_result.data.\*.payload.issue.assignees.\*.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.issue.assignees.\*.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.issue.assignees.\*.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.issue.assignees.\*.site_admin | boolean | | True False |
action_result.data.\*.payload.issue.assignees.\*.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.issue.assignees.\*.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.issue.assignees.\*.type | string | | User |
action_result.data.\*.payload.issue.assignees.\*.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.issue.author_association | string | | CONTRIBUTOR |
action_result.data.\*.payload.issue.body | string | | As spotted here https://github.com/test/test/issues/28001 `$loader->exists('@foo')` shouldn't throw an exception. e.g.: https://github.com/test/test/blob/9bfa971bc5662a6f90408b58a7b2453d7dae4f83/src/test/Component/HttpKernel/Fragment/HIncludeFragmentRenderer.php#L145 |
action_result.data.\*.payload.issue.check_run.pull_requests.\*.diff_url | string | `url` | https://github.com/twigphp/Twig/pull/2721.diff |
action_result.data.\*.payload.issue.check_run.pull_requests.\*.html_url | string | `url` | https://github.com/twigphp/Twig/pull/2721 |
action_result.data.\*.payload.issue.check_run.pull_requests.\*.patch_url | string | `url` | https://github.com/twigphp/Twig/pull/2721.patch |
action_result.data.\*.payload.issue.check_run.pull_requests.\*.url | string | `url` | https://api.github.com/repos/twigphp/Twig/pulls/2721 |
action_result.data.\*.payload.issue.closed_at | string | | 2018-07-19T19:18:50Z |
action_result.data.\*.payload.issue.comments | numeric | | 0 |
action_result.data.\*.payload.issue.comments_url | string | `url` | https://api.github.com/repos/twigphp/Twig/issues/2721/comments |
action_result.data.\*.payload.issue.created_at | string | | 2018-07-19T18:18:50Z |
action_result.data.\*.payload.issue.events_url | string | `url` | https://api.github.com/repos/twigphp/Twig/issues/2721/events |
action_result.data.\*.payload.issue.html_url | string | `url` | https://github.com/twigphp/Twig/pull/2721 |
action_result.data.\*.payload.issue.id | numeric | | 342837096 |
action_result.data.\*.payload.issue.labels.\*.color | string | | e10c02 |
action_result.data.\*.payload.issue.labels.\*.default | boolean | | True False |
action_result.data.\*.payload.issue.labels.\*.id | numeric | | 100079 |
action_result.data.\*.payload.issue.labels.\*.name | string | | Bug |
action_result.data.\*.payload.issue.labels.\*.node_id | string | | MDU6TGFiZWwxMDAwNzk= |
action_result.data.\*.payload.issue.labels.\*.url | string | `url` | https://api.github.com/repos/test/test/labels/Bug |
action_result.data.\*.payload.issue.labels_url | string | `url` | https://api.github.com/repos/twigphp/Twig/issues/2721/labels{/name} |
action_result.data.\*.payload.issue.locked | boolean | | True False |
action_result.data.\*.payload.issue.milestone.closed_at | string | | 2016-12-06T13:03:12Z |
action_result.data.\*.payload.issue.milestone.closed_issues | numeric | | 146 |
action_result.data.\*.payload.issue.milestone.created_at | string | | 2016-12-06T12:03:12Z |
action_result.data.\*.payload.issue.milestone.creator.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/243674?v=4 |
action_result.data.\*.payload.issue.milestone.creator.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.issue.milestone.creator.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.issue.milestone.creator.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.issue.milestone.creator.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.issue.milestone.creator.gravatar_id | string | | |
action_result.data.\*.payload.issue.milestone.creator.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.issue.milestone.creator.id | numeric | | 243674 |
action_result.data.\*.payload.issue.milestone.creator.login | string | `github username` | test |
action_result.data.\*.payload.issue.milestone.creator.node_id | string | | MDQ6VXNlcjI0MzY3NA== |
action_result.data.\*.payload.issue.milestone.creator.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.issue.milestone.creator.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.issue.milestone.creator.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.issue.milestone.creator.site_admin | boolean | | True False |
action_result.data.\*.payload.issue.milestone.creator.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.issue.milestone.creator.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.issue.milestone.creator.type | string | | User |
action_result.data.\*.payload.issue.milestone.creator.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.issue.milestone.description | string | `url` | https://test.com/roadmap?version=2.8#checker |
action_result.data.\*.payload.issue.milestone.due_on | string | | 2018-11-30T08:00:00Z |
action_result.data.\*.payload.issue.milestone.html_url | string | `url` | https://github.com/test/test/milestone/14 |
action_result.data.\*.payload.issue.milestone.id | numeric | | 2178740 |
action_result.data.\*.payload.issue.milestone.labels_url | string | `url` | https://api.github.com/repos/test/test/milestones/14/labels |
action_result.data.\*.payload.issue.milestone.node_id | string | | MDk6TWlsZXN0b25lMjE3ODc0MA== |
action_result.data.\*.payload.issue.milestone.number | numeric | | 14 |
action_result.data.\*.payload.issue.milestone.open_issues | numeric | | 14 |
action_result.data.\*.payload.issue.milestone.state | string | | open |
action_result.data.\*.payload.issue.milestone.title | string | | 2.8 |
action_result.data.\*.payload.issue.milestone.updated_at | string | | 2018-07-13T20:20:34Z |
action_result.data.\*.payload.issue.milestone.url | string | `url` | https://api.github.com/repos/test/test/milestones/14 |
action_result.data.\*.payload.issue.node_id | string | | MDExOlB1bGxSZXF1ZXN0MjAyNjQzNTEy |
action_result.data.\*.payload.issue.number | numeric | | 2721 |
action_result.data.\*.payload.issue.pull_request.diff_url | string | `url` | https://github.com/twigphp/Twig/pull/2721.diff |
action_result.data.\*.payload.issue.pull_request.html_url | string | `url` | https://github.com/twigphp/Twig/pull/2721 |
action_result.data.\*.payload.issue.pull_request.patch_url | string | `url` | https://github.com/twigphp/Twig/pull/2721.patch |
action_result.data.\*.payload.issue.pull_request.url | string | `url` | https://api.github.com/repos/twigphp/Twig/pulls/2721 |
action_result.data.\*.payload.issue.repository_url | string | `url` | https://api.github.com/repos/twigphp/Twig |
action_result.data.\*.payload.issue.state | string | | open |
action_result.data.\*.payload.issue.title | string | | Don't throw error on validate or parse name if throw var is false |
action_result.data.\*.payload.issue.updated_at | string | | 2018-07-20T05:36:22Z |
action_result.data.\*.payload.issue.url | string | `url` | https://api.github.com/repos/twigphp/Twig/issues/2721 |
action_result.data.\*.payload.issue.user.avatar_url | string | `url` | https://avatars0.githubusercontent.com/u/2028198?v=4 |
action_result.data.\*.payload.issue.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.issue.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.issue.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.issue.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.issue.user.gravatar_id | string | | |
action_result.data.\*.payload.issue.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.issue.user.id | numeric | | 2028198 |
action_result.data.\*.payload.issue.user.login | string | `github username` | test |
action_result.data.\*.payload.issue.user.node_id | string | | MDQ6VXNlcjIwMjgxOTg= |
action_result.data.\*.payload.issue.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.issue.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.issue.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.issue.user.site_admin | boolean | | True False |
action_result.data.\*.payload.issue.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.issue.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.issue.user.type | string | | User |
action_result.data.\*.payload.issue.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.marketplace_purchase.account.id | numeric | | 18404719 |
action_result.data.\*.payload.marketplace_purchase.account.login | string | `github username` | test |
action_result.data.\*.payload.marketplace_purchase.account.organization_billing_email | string | `email` | username@email.com |
action_result.data.\*.payload.marketplace_purchase.account.type | string | | Organization |
action_result.data.\*.payload.marketplace_purchase.billing_cycle | string | | monthly |
action_result.data.\*.payload.marketplace_purchase.free_trial_ends_on | string | | |
action_result.data.\*.payload.marketplace_purchase.next_billing_date | string | | 2017-11-05T00:00:00+00:00 |
action_result.data.\*.payload.marketplace_purchase.on_free_trial | boolean | | True False |
action_result.data.\*.payload.marketplace_purchase.plan.bullets | string | | Is Basic |
action_result.data.\*.payload.marketplace_purchase.plan.description | string | | Basic Plan |
action_result.data.\*.payload.marketplace_purchase.plan.has_free_trial | boolean | | True False |
action_result.data.\*.payload.marketplace_purchase.plan.id | numeric | | 435 |
action_result.data.\*.payload.marketplace_purchase.plan.monthly_price_in_cents | numeric | | 1000 |
action_result.data.\*.payload.marketplace_purchase.plan.name | string | | Basic Plan |
action_result.data.\*.payload.marketplace_purchase.plan.price_model | string | | per-unit |
action_result.data.\*.payload.marketplace_purchase.plan.unit_name | string | | seat |
action_result.data.\*.payload.marketplace_purchase.plan.yearly_price_in_cents | numeric | | 10000 |
action_result.data.\*.payload.marketplace_purchase.unit_count | numeric | | 1 |
action_result.data.\*.payload.master_branch | string | | master |
action_result.data.\*.payload.member.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/41301719?v=4 |
action_result.data.\*.payload.member.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.member.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.member.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.member.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.member.gravatar_id | string | | |
action_result.data.\*.payload.member.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.member.id | numeric | | 41301719 |
action_result.data.\*.payload.member.login | string | `github username` | test |
action_result.data.\*.payload.member.node_id | string | | MDQ6VXNlcjQxMzA5NzE5 |
action_result.data.\*.payload.member.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.member.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.member.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.member.site_admin | boolean | | True False |
action_result.data.\*.payload.member.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.member.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.member.type | string | | User |
action_result.data.\*.payload.member.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.number | numeric | | 27999 |
action_result.data.\*.payload.organization.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/38302899?v=4 |
action_result.data.\*.payload.organization.description | string | | sample description |
action_result.data.\*.payload.organization.events_url | string | `url` | https://api.github.com/orgs/Octocoders/events |
action_result.data.\*.payload.organization.hooks_url | string | `url` | https://api.github.com/orgs/Octocoders/hooks |
action_result.data.\*.payload.organization.id | numeric | | 406494157 |
action_result.data.\*.payload.organization.issues_url | string | `url` | https://api.github.com/orgs/Octocoders/issues |
action_result.data.\*.payload.organization.login | string | `github organization name` | test |
action_result.data.\*.payload.organization.members_url | string | `url` | https://api.github.com/orgs/Octocoders/members{/member} |
action_result.data.\*.payload.organization.node_id | string | | MDQ6VXNlcjM5NjUyMzUx |
action_result.data.\*.payload.organization.public_members_url | string | `url` | https://api.github.com/orgs/Octocoders/public_members{/member} |
action_result.data.\*.payload.organization.repos_url | string | `url` | https://api.github.com/users/Octocoders/repos |
action_result.data.\*.payload.organization.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.pages.\*.action | string | | created |
action_result.data.\*.payload.pages.\*.creator.html_url | string | `url` | https://github.com/test/test-proj/wiki/Home |
action_result.data.\*.payload.pages.\*.html_url | string | `url` | https://github.com/test/test-proj/wiki/Home |
action_result.data.\*.payload.pages.\*.page_name | string | | Home |
action_result.data.\*.payload.pages.\*.sha | string | `sha1` | 75c7614e23cb40511d9cb3eb00d20e5cadc0d0e6 |
action_result.data.\*.payload.pages.\*.summary | string | | |
action_result.data.\*.payload.pages.\*.title | string | | Home |
action_result.data.\*.payload.project.body | string | | Project tasks for a trip to Space |
action_result.data.\*.payload.project.columns_url | string | `url` | https://api.github.com/projects/1547122/columns |
action_result.data.\*.payload.project.created_at | string | | 2018-05-30T20:18:51Z |
action_result.data.\*.payload.project.creator.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/21031067?v=4 |
action_result.data.\*.payload.project.creator.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.project.creator.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.project.creator.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.project.creator.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.project.creator.gravatar_id | string | | |
action_result.data.\*.payload.project.creator.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.project.creator.id | numeric | | 73419 |
action_result.data.\*.payload.project.creator.login | string | `github username` | test |
action_result.data.\*.payload.project.creator.node_id | string | | MDQ6VXNlcjczNDE5 |
action_result.data.\*.payload.project.creator.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.project.creator.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.project.creator.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.project.creator.site_admin | boolean | | True False |
action_result.data.\*.payload.project.creator.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.project.creator.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.project.creator.type | string | | User |
action_result.data.\*.payload.project.creator.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.project.html_url | string | `url` | https://github.com/test/test-repo/projects/1 |
action_result.data.\*.payload.project.id | numeric | | 1547122 |
action_result.data.\*.payload.project.name | string | | Space 2.0 |
action_result.data.\*.payload.project.node_id | string | | MDc6UHJvamVjdDE1NDcxMjI= |
action_result.data.\*.payload.project.number | numeric | | 1 |
action_result.data.\*.payload.project.owner_url | string | `url` | https://api.github.com/repos/test/test-repo |
action_result.data.\*.payload.project.state | string | | open |
action_result.data.\*.payload.project.updated_at | string | | 2018-05-30T20:18:51Z |
action_result.data.\*.payload.project.url | string | `url` | https://api.github.com/projects/1547122 |
action_result.data.\*.payload.project_card.column_id | numeric | | 2803722 |
action_result.data.\*.payload.project_card.column_url | string | `url` | https://api.github.com/projects/columns/2803722 |
action_result.data.\*.payload.project_card.created_at | string | | 2018-05-30T20:18:52Z |
action_result.data.\*.payload.project_card.creator.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/243674?v=4 |
action_result.data.\*.payload.project_card.creator.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.project_card.creator.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.project_card.creator.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.project_card.creator.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.project_card.creator.gravatar_id | string | | |
action_result.data.\*.payload.project_card.creator.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.project_card.creator.id | numeric | | 243674 |
action_result.data.\*.payload.project_card.creator.login | string | `github username` | test |
action_result.data.\*.payload.project_card.creator.node_id | string | | MDQ6VXNlcjI0MzY3NA== |
action_result.data.\*.payload.project_card.creator.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.project_card.creator.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.project_card.creator.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.project_card.creator.site_admin | boolean | | True False |
action_result.data.\*.payload.project_card.creator.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.project_card.creator.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.project_card.creator.type | string | | User |
action_result.data.\*.payload.project_card.creator.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.project_card.id | numeric | | 10189042 |
action_result.data.\*.payload.project_card.node_id | string | | MDExOlByb2plY3RDYXJkMTAxODkwNDI= |
action_result.data.\*.payload.project_card.note | string | | Work that can be completed in one hour or less |
action_result.data.\*.payload.project_card.updated_at | string | | 2018-05-30T20:18:52Z |
action_result.data.\*.payload.project_card.url | string | `url` | https://api.github.com/projects/columns/cards/10189042 |
action_result.data.\*.payload.project_column.cards_url | string | `url` | https://api.github.com/projects/columns/2803722/cards |
action_result.data.\*.payload.project_column.created_at | string | | 2018-05-30T20:18:52Z |
action_result.data.\*.payload.project_column.id | numeric | | 2803722 |
action_result.data.\*.payload.project_column.name | string | | Small bugfixes |
action_result.data.\*.payload.project_column.node_id | string | | MDEzOlByb2plY3RDb2x1bW4yODAzNzIy |
action_result.data.\*.payload.project_column.project_url | string | `url` | https://api.github.com/projects/1547122 |
action_result.data.\*.payload.project_column.updated_at | string | | 2018-05-30T20:18:52Z |
action_result.data.\*.payload.project_column.url | string | `url` | https://api.github.com/projects/columns/2803722 |
action_result.data.\*.payload.pull_request.\_links.comments.href | string | `url` | https://api.github.com/repos/test/test/issues/27999/comments |
action_result.data.\*.payload.pull_request.\_links.commits.href | string | `url` | https://api.github.com/repos/test/test/pulls/27999/commits |
action_result.data.\*.payload.pull_request.\_links.html.href | string | `url` | https://github.com/test/test/pull/27999 |
action_result.data.\*.payload.pull_request.\_links.issue.href | string | `url` | https://api.github.com/repos/test/test/issues/27999 |
action_result.data.\*.payload.pull_request.\_links.review_comment.href | string | `url` | https://api.github.com/repos/test/test/pulls/comments{/number} |
action_result.data.\*.payload.pull_request.\_links.review_comments.href | string | `url` | https://api.github.com/repos/test/test/pulls/27999/comments |
action_result.data.\*.payload.pull_request.\_links.self.href | string | `url` | https://api.github.com/repos/test/test/pulls/27999 |
action_result.data.\*.payload.pull_request.\_links.statuses.href | string | `url` | https://api.github.com/repos/test/test/statuses/ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.pull_request.additions | numeric | | 24 |
action_result.data.\*.payload.pull_request.assignee.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/29939753?v=4 |
action_result.data.\*.payload.pull_request.assignee.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.pull_request.assignee.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.pull_request.assignee.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.pull_request.assignee.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.pull_request.assignee.gravatar_id | string | | |
action_result.data.\*.payload.pull_request.assignee.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.pull_request.assignee.id | numeric | | 29939753 |
action_result.data.\*.payload.pull_request.assignee.login | string | `github username` | test |
action_result.data.\*.payload.pull_request.assignee.node_id | string | | MDQ6VXNlcjI5OTM5NzUz |
action_result.data.\*.payload.pull_request.assignee.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.pull_request.assignee.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.pull_request.assignee.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.pull_request.assignee.site_admin | boolean | | True False |
action_result.data.\*.payload.pull_request.assignee.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.pull_request.assignee.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.pull_request.assignee.type | string | | User |
action_result.data.\*.payload.pull_request.assignee.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.pull_request.assignees.\*.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/29939753?v=4 |
action_result.data.\*.payload.pull_request.assignees.\*.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.pull_request.assignees.\*.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.pull_request.assignees.\*.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.pull_request.assignees.\*.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.pull_request.assignees.\*.gravatar_id | string | | |
action_result.data.\*.payload.pull_request.assignees.\*.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.pull_request.assignees.\*.id | numeric | | 29939753 |
action_result.data.\*.payload.pull_request.assignees.\*.login | string | `github username` | test |
action_result.data.\*.payload.pull_request.assignees.\*.node_id | string | | MDQ6VXNlcjI5OTM5NzUz |
action_result.data.\*.payload.pull_request.assignees.\*.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.pull_request.assignees.\*.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.pull_request.assignees.\*.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.pull_request.assignees.\*.site_admin | boolean | | True False |
action_result.data.\*.payload.pull_request.assignees.\*.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.pull_request.assignees.\*.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.pull_request.assignees.\*.type | string | | User |
action_result.data.\*.payload.pull_request.assignees.\*.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.pull_request.author_association | string | | CONTRIBUTOR |
action_result.data.\*.payload.pull_request.base.label | string | | test:2.8 |
action_result.data.\*.payload.pull_request.base.ref | string | | 2.8 |
action_result.data.\*.payload.pull_request.base.repo.archive_url | string | `url` | https://api.github.com/repos/test/test/{archive_format}{/ref} |
action_result.data.\*.payload.pull_request.base.repo.archived | boolean | | True False |
action_result.data.\*.payload.pull_request.base.repo.assignees_url | string | `url` | https://api.github.com/repos/test/test/assignees{/user} |
action_result.data.\*.payload.pull_request.base.repo.blobs_url | string | `url` | https://api.github.com/repos/test/test/git/blobs{/sha} |
action_result.data.\*.payload.pull_request.base.repo.branches_url | string | `url` | https://api.github.com/repos/test/test/branches{/branch} |
action_result.data.\*.payload.pull_request.base.repo.clone_url | string | `url` | https://github.com/test/test.git |
action_result.data.\*.payload.pull_request.base.repo.collaborators_url | string | `url` | https://api.github.com/repos/test/test/collaborators{/collaborator} |
action_result.data.\*.payload.pull_request.base.repo.comments_url | string | `url` | https://api.github.com/repos/test/test/comments{/number} |
action_result.data.\*.payload.pull_request.base.repo.commits_url | string | `url` | https://api.github.com/repos/test/test/commits{/sha} |
action_result.data.\*.payload.pull_request.base.repo.compare_url | string | `url` | https://api.github.com/repos/test/test/compare/{base}...{head} |
action_result.data.\*.payload.pull_request.base.repo.contents_url | string | `url` | https://api.github.com/repos/test/test/contents/{+path} |
action_result.data.\*.payload.pull_request.base.repo.contributors_url | string | `url` | https://api.github.com/repos/test/test/contributors |
action_result.data.\*.payload.pull_request.base.repo.created_at | string | | 2010-01-04T14:21:21Z |
action_result.data.\*.payload.pull_request.base.repo.default_branch | string | | master |
action_result.data.\*.payload.pull_request.base.repo.deployments_url | string | `url` | https://api.github.com/repos/test/test/deployments |
action_result.data.\*.payload.pull_request.base.repo.description | string | | The test PHP framework |
action_result.data.\*.payload.pull_request.base.repo.downloads_url | string | `url` | https://api.github.com/repos/test/test/downloads |
action_result.data.\*.payload.pull_request.base.repo.events_url | string | `url` | https://api.github.com/repos/test/test/events |
action_result.data.\*.payload.pull_request.base.repo.fork | boolean | | True False |
action_result.data.\*.payload.pull_request.base.repo.forks | numeric | | 6330 |
action_result.data.\*.payload.pull_request.base.repo.forks_count | numeric | | 6330 |
action_result.data.\*.payload.pull_request.base.repo.forks_url | string | `url` | https://api.github.com/repos/test/test/forks |
action_result.data.\*.payload.pull_request.base.repo.full_name | string | | test/test-repo |
action_result.data.\*.payload.pull_request.base.repo.git_commits_url | string | `url` | https://api.github.com/repos/test/test/git/commits{/sha} |
action_result.data.\*.payload.pull_request.base.repo.git_refs_url | string | `url` | https://api.github.com/repos/test/test/git/refs{/sha} |
action_result.data.\*.payload.pull_request.base.repo.git_tags_url | string | `url` | https://api.github.com/repos/test/test/git/tags{/sha} |
action_result.data.\*.payload.pull_request.base.repo.git_url | string | | git://github.com/test/test.git |
action_result.data.\*.payload.pull_request.base.repo.has_downloads | boolean | | True False |
action_result.data.\*.payload.pull_request.base.repo.has_issues | boolean | | True False |
action_result.data.\*.payload.pull_request.base.repo.has_pages | boolean | | True False |
action_result.data.\*.payload.pull_request.base.repo.has_projects | boolean | | True False |
action_result.data.\*.payload.pull_request.base.repo.has_wiki | boolean | | True False |
action_result.data.\*.payload.pull_request.base.repo.homepage | string | `url` | https://test.com |
action_result.data.\*.payload.pull_request.base.repo.hooks_url | string | `url` | https://api.github.com/repos/test/test/hooks |
action_result.data.\*.payload.pull_request.base.repo.html_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.pull_request.base.repo.id | numeric | | 458058 |
action_result.data.\*.payload.pull_request.base.repo.issue_comment_url | string | `url` | https://api.github.com/repos/test/test/issues/comments{/number} |
action_result.data.\*.payload.pull_request.base.repo.issue_events_url | string | `url` | https://api.github.com/repos/test/test/issues/events{/number} |
action_result.data.\*.payload.pull_request.base.repo.issues_url | string | `url` | https://api.github.com/repos/test/test/issues{/number} |
action_result.data.\*.payload.pull_request.base.repo.keys_url | string | `url` | https://api.github.com/repos/test/test/keys{/key_id} |
action_result.data.\*.payload.pull_request.base.repo.labels_url | string | `url` | https://api.github.com/repos/test/test/labels{/name} |
action_result.data.\*.payload.pull_request.base.repo.language | string | | PHP |
action_result.data.\*.payload.pull_request.base.repo.languages_url | string | `url` | https://api.github.com/repos/test/test/languages |
action_result.data.\*.payload.pull_request.base.repo.license.key | string | | mit |
action_result.data.\*.payload.pull_request.base.repo.license.name | string | | MIT License |
action_result.data.\*.payload.pull_request.base.repo.license.node_id | string | | MDc6TGljZW5zZTEz |
action_result.data.\*.payload.pull_request.base.repo.license.spdx_id | string | | MIT |
action_result.data.\*.payload.pull_request.base.repo.license.url | string | `url` | https://api.github.com/licenses/mit |
action_result.data.\*.payload.pull_request.base.repo.merges_url | string | `url` | https://api.github.com/repos/test/test/merges |
action_result.data.\*.payload.pull_request.base.repo.milestones_url | string | `url` | https://api.github.com/repos/test/test/milestones{/number} |
action_result.data.\*.payload.pull_request.base.repo.mirror_url | string | `url` | |
action_result.data.\*.payload.pull_request.base.repo.name | string | | test |
action_result.data.\*.payload.pull_request.base.repo.node_id | string | | MDEwOlJlcG9zaXRvcnk0NTgwNTg= |
action_result.data.\*.payload.pull_request.base.repo.notifications_url | string | `url` | https://api.github.com/repos/test/test/notifications{?since,all,participating} |
action_result.data.\*.payload.pull_request.base.repo.open_issues | numeric | | 893 |
action_result.data.\*.payload.pull_request.base.repo.open_issues_count | numeric | | 893 |
action_result.data.\*.payload.pull_request.base.repo.owner.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/143937?v=4 |
action_result.data.\*.payload.pull_request.base.repo.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.pull_request.base.repo.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.pull_request.base.repo.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.pull_request.base.repo.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.pull_request.base.repo.owner.gravatar_id | string | | |
action_result.data.\*.payload.pull_request.base.repo.owner.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.pull_request.base.repo.owner.id | numeric | | 143937 |
action_result.data.\*.payload.pull_request.base.repo.owner.login | string | `github username` | test |
action_result.data.\*.payload.pull_request.base.repo.owner.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjE0MzkzNw== |
action_result.data.\*.payload.pull_request.base.repo.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.pull_request.base.repo.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.pull_request.base.repo.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.pull_request.base.repo.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.pull_request.base.repo.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.pull_request.base.repo.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.pull_request.base.repo.owner.type | string | | Organization |
action_result.data.\*.payload.pull_request.base.repo.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.pull_request.base.repo.private | boolean | | True False |
action_result.data.\*.payload.pull_request.base.repo.pulls_url | string | `url` | https://api.github.com/repos/test/test/pulls{/number} |
action_result.data.\*.payload.pull_request.base.repo.pushed_at | string | | 2018-07-19T12:14:02Z |
action_result.data.\*.payload.pull_request.base.repo.releases_url | string | `url` | https://api.github.com/repos/test/test/releases{/id} |
action_result.data.\*.payload.pull_request.base.repo.size | numeric | | 120647 |
action_result.data.\*.payload.pull_request.base.repo.ssh_url | string | | git@github.com:test/test.git |
action_result.data.\*.payload.pull_request.base.repo.stargazers_count | numeric | | 18086 |
action_result.data.\*.payload.pull_request.base.repo.stargazers_url | string | `url` | https://api.github.com/repos/test/test/stargazers |
action_result.data.\*.payload.pull_request.base.repo.statuses_url | string | `url` | https://api.github.com/repos/test/test/statuses/{sha} |
action_result.data.\*.payload.pull_request.base.repo.subscribers_url | string | `url` | https://api.github.com/repos/test/test/subscribers |
action_result.data.\*.payload.pull_request.base.repo.subscription_url | string | `url` | https://api.github.com/repos/test/test/subscription |
action_result.data.\*.payload.pull_request.base.repo.svn_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.pull_request.base.repo.tags_url | string | `url` | https://api.github.com/repos/test/test/tags |
action_result.data.\*.payload.pull_request.base.repo.teams_url | string | `url` | https://api.github.com/repos/test/test/teams |
action_result.data.\*.payload.pull_request.base.repo.trees_url | string | `url` | https://api.github.com/repos/test/test/git/trees{/sha} |
action_result.data.\*.payload.pull_request.base.repo.updated_at | string | | 2018-07-19T11:54:19Z |
action_result.data.\*.payload.pull_request.base.repo.url | string | `url` | https://api.github.com/repos/test/test |
action_result.data.\*.payload.pull_request.base.repo.watchers | numeric | | 18086 |
action_result.data.\*.payload.pull_request.base.repo.watchers_count | numeric | | 18086 |
action_result.data.\*.payload.pull_request.base.sha | string | `sha1` | 08a49bc5302de373bdb44e5c189133a7d5d5f12b |
action_result.data.\*.payload.pull_request.base.user.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/143937?v=4 |
action_result.data.\*.payload.pull_request.base.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.pull_request.base.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.pull_request.base.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.pull_request.base.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.pull_request.base.user.gravatar_id | string | | |
action_result.data.\*.payload.pull_request.base.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.pull_request.base.user.id | numeric | | 143937 |
action_result.data.\*.payload.pull_request.base.user.login | string | `github username` | test |
action_result.data.\*.payload.pull_request.base.user.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjE0MzkzNw== |
action_result.data.\*.payload.pull_request.base.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.pull_request.base.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.pull_request.base.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.pull_request.base.user.site_admin | boolean | | True False |
action_result.data.\*.payload.pull_request.base.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.pull_request.base.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.pull_request.base.user.type | string | | Organization |
action_result.data.\*.payload.pull_request.base.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.pull_request.body | string | | Sample body |
action_result.data.\*.payload.pull_request.changed_files | numeric | | 6 |
action_result.data.\*.payload.pull_request.closed_at | string | | 2018-07-19T12:14:03Z |
action_result.data.\*.payload.pull_request.comments | numeric | | 1 |
action_result.data.\*.payload.pull_request.comments_url | string | `url` | https://api.github.com/repos/test/test/issues/27999/comments |
action_result.data.\*.payload.pull_request.commits | numeric | | 1 |
action_result.data.\*.payload.pull_request.commits_url | string | `url` | https://api.github.com/repos/test/test/pulls/27999/commits |
action_result.data.\*.payload.pull_request.created_at | string | | 2018-07-19T12:12:54Z |
action_result.data.\*.payload.pull_request.deletions | numeric | | 0 |
action_result.data.\*.payload.pull_request.diff_url | string | `url` | https://github.com/test/test/pull/27999.diff |
action_result.data.\*.payload.pull_request.head.label | string | | test:uuid-translations |
action_result.data.\*.payload.pull_request.head.ref | string | | uuid-translations |
action_result.data.\*.payload.pull_request.head.repo.archive_url | string | `url` | https://api.github.com/repos/test/test/{archive_format}{/ref} |
action_result.data.\*.payload.pull_request.head.repo.archived | boolean | | True False |
action_result.data.\*.payload.pull_request.head.repo.assignees_url | string | `url` | https://api.github.com/repos/test/test/assignees{/user} |
action_result.data.\*.payload.pull_request.head.repo.blobs_url | string | `url` | https://api.github.com/repos/test/test/git/blobs{/sha} |
action_result.data.\*.payload.pull_request.head.repo.branches_url | string | `url` | https://api.github.com/repos/test/test/branches{/branch} |
action_result.data.\*.payload.pull_request.head.repo.clone_url | string | `url` | https://github.com/test/test.git |
action_result.data.\*.payload.pull_request.head.repo.collaborators_url | string | `url` | https://api.github.com/repos/test/test/collaborators{/collaborator} |
action_result.data.\*.payload.pull_request.head.repo.comments_url | string | `url` | https://api.github.com/repos/test/test/comments{/number} |
action_result.data.\*.payload.pull_request.head.repo.commits_url | string | `url` | https://api.github.com/repos/test/test/commits{/sha} |
action_result.data.\*.payload.pull_request.head.repo.compare_url | string | `url` | https://api.github.com/repos/test/test/compare/{base}...{head} |
action_result.data.\*.payload.pull_request.head.repo.contents_url | string | `url` | https://api.github.com/repos/test/test/contents/{+path} |
action_result.data.\*.payload.pull_request.head.repo.contributors_url | string | `url` | https://api.github.com/repos/test/test/contributors |
action_result.data.\*.payload.pull_request.head.repo.created_at | string | | 2017-02-01T16:32:59Z |
action_result.data.\*.payload.pull_request.head.repo.default_branch | string | | master |
action_result.data.\*.payload.pull_request.head.repo.deployments_url | string | `url` | https://api.github.com/repos/test/test/deployments |
action_result.data.\*.payload.pull_request.head.repo.description | string | | The test PHP framework |
action_result.data.\*.payload.pull_request.head.repo.downloads_url | string | `url` | https://api.github.com/repos/test/test/downloads |
action_result.data.\*.payload.pull_request.head.repo.events_url | string | `url` | https://api.github.com/repos/test/test/events |
action_result.data.\*.payload.pull_request.head.repo.fork | boolean | | True False |
action_result.data.\*.payload.pull_request.head.repo.forks | numeric | | 1 |
action_result.data.\*.payload.pull_request.head.repo.forks_count | numeric | | 1 |
action_result.data.\*.payload.pull_request.head.repo.forks_url | string | `url` | https://api.github.com/repos/test/test/forks |
action_result.data.\*.payload.pull_request.head.repo.full_name | string | | test/test-repo |
action_result.data.\*.payload.pull_request.head.repo.git_commits_url | string | `url` | https://api.github.com/repos/test/test/git/commits{/sha} |
action_result.data.\*.payload.pull_request.head.repo.git_refs_url | string | `url` | https://api.github.com/repos/test/test/git/refs{/sha} |
action_result.data.\*.payload.pull_request.head.repo.git_tags_url | string | `url` | https://api.github.com/repos/test/test/git/tags{/sha} |
action_result.data.\*.payload.pull_request.head.repo.git_url | string | | git://github.com/test/test.git |
action_result.data.\*.payload.pull_request.head.repo.has_downloads | boolean | | True False |
action_result.data.\*.payload.pull_request.head.repo.has_issues | boolean | | True False |
action_result.data.\*.payload.pull_request.head.repo.has_pages | boolean | | True False |
action_result.data.\*.payload.pull_request.head.repo.has_projects | boolean | | True False |
action_result.data.\*.payload.pull_request.head.repo.has_wiki | boolean | | True False |
action_result.data.\*.payload.pull_request.head.repo.homepage | string | `url` | https://test.com |
action_result.data.\*.payload.pull_request.head.repo.hooks_url | string | `url` | https://api.github.com/repos/test/test/hooks |
action_result.data.\*.payload.pull_request.head.repo.html_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.pull_request.head.repo.id | numeric | | 80639758 |
action_result.data.\*.payload.pull_request.head.repo.issue_comment_url | string | `url` | https://api.github.com/repos/test/test/issues/comments{/number} |
action_result.data.\*.payload.pull_request.head.repo.issue_events_url | string | `url` | https://api.github.com/repos/test/test/issues/events{/number} |
action_result.data.\*.payload.pull_request.head.repo.issues_url | string | `url` | https://api.github.com/repos/test/test/issues{/number} |
action_result.data.\*.payload.pull_request.head.repo.keys_url | string | `url` | https://api.github.com/repos/test/test/keys{/key_id} |
action_result.data.\*.payload.pull_request.head.repo.labels_url | string | `url` | https://api.github.com/repos/test/test/labels{/name} |
action_result.data.\*.payload.pull_request.head.repo.language | string | | PHP |
action_result.data.\*.payload.pull_request.head.repo.languages_url | string | `url` | https://api.github.com/repos/test/test/languages |
action_result.data.\*.payload.pull_request.head.repo.license.key | string | | mit |
action_result.data.\*.payload.pull_request.head.repo.license.name | string | | MIT License |
action_result.data.\*.payload.pull_request.head.repo.license.node_id | string | | MDc6TGljZW5zZTEz |
action_result.data.\*.payload.pull_request.head.repo.license.spdx_id | string | | MIT |
action_result.data.\*.payload.pull_request.head.repo.license.url | string | `url` | https://api.github.com/licenses/mit |
action_result.data.\*.payload.pull_request.head.repo.merges_url | string | `url` | https://api.github.com/repos/test/test/merges |
action_result.data.\*.payload.pull_request.head.repo.milestones_url | string | `url` | https://api.github.com/repos/test/test/milestones{/number} |
action_result.data.\*.payload.pull_request.head.repo.mirror_url | string | `url` | |
action_result.data.\*.payload.pull_request.head.repo.name | string | | test |
action_result.data.\*.payload.pull_request.head.repo.node_id | string | | MDEwOlJlcG9zaXRvcnk4MDYzOTc1OA== |
action_result.data.\*.payload.pull_request.head.repo.notifications_url | string | `url` | https://api.github.com/repos/test/test/notifications{?since,all,participating} |
action_result.data.\*.payload.pull_request.head.repo.open_issues | numeric | | 0 |
action_result.data.\*.payload.pull_request.head.repo.open_issues_count | numeric | | 0 |
action_result.data.\*.payload.pull_request.head.repo.owner.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.pull_request.head.repo.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.pull_request.head.repo.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.pull_request.head.repo.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.pull_request.head.repo.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.pull_request.head.repo.owner.gravatar_id | string | | |
action_result.data.\*.payload.pull_request.head.repo.owner.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.pull_request.head.repo.owner.id | numeric | | 1032411 |
action_result.data.\*.payload.pull_request.head.repo.owner.login | string | `github username` | test |
action_result.data.\*.payload.pull_request.head.repo.owner.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.pull_request.head.repo.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.pull_request.head.repo.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.pull_request.head.repo.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.pull_request.head.repo.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.pull_request.head.repo.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.pull_request.head.repo.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.pull_request.head.repo.owner.type | string | | User |
action_result.data.\*.payload.pull_request.head.repo.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.pull_request.head.repo.private | boolean | | True False |
action_result.data.\*.payload.pull_request.head.repo.pulls_url | string | `url` | https://api.github.com/repos/test/test/pulls{/number} |
action_result.data.\*.payload.pull_request.head.repo.pushed_at | string | | 2018-07-19T12:11:30Z |
action_result.data.\*.payload.pull_request.head.repo.releases_url | string | `url` | https://api.github.com/repos/test/test/releases{/id} |
action_result.data.\*.payload.pull_request.head.repo.size | numeric | | 112468 |
action_result.data.\*.payload.pull_request.head.repo.ssh_url | string | | git@github.com:test/test.git |
action_result.data.\*.payload.pull_request.head.repo.stargazers_count | numeric | | 0 |
action_result.data.\*.payload.pull_request.head.repo.stargazers_url | string | `url` | https://api.github.com/repos/test/test/stargazers |
action_result.data.\*.payload.pull_request.head.repo.statuses_url | string | `url` | https://api.github.com/repos/test/test/statuses/{sha} |
action_result.data.\*.payload.pull_request.head.repo.subscribers_url | string | `url` | https://api.github.com/repos/test/test/subscribers |
action_result.data.\*.payload.pull_request.head.repo.subscription_url | string | `url` | https://api.github.com/repos/test/test/subscription |
action_result.data.\*.payload.pull_request.head.repo.svn_url | string | `url` | https://github.com/test/test |
action_result.data.\*.payload.pull_request.head.repo.tags_url | string | `url` | https://api.github.com/repos/test/test/tags |
action_result.data.\*.payload.pull_request.head.repo.teams_url | string | `url` | https://api.github.com/repos/test/test/teams |
action_result.data.\*.payload.pull_request.head.repo.trees_url | string | `url` | https://api.github.com/repos/test/test/git/trees{/sha} |
action_result.data.\*.payload.pull_request.head.repo.updated_at | string | | 2017-02-01T16:33:18Z |
action_result.data.\*.payload.pull_request.head.repo.url | string | `url` | https://api.github.com/repos/test/test |
action_result.data.\*.payload.pull_request.head.repo.watchers | numeric | | 0 |
action_result.data.\*.payload.pull_request.head.repo.watchers_count | numeric | | 0 |
action_result.data.\*.payload.pull_request.head.sha | string | `sha1` | ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.pull_request.head.user.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.pull_request.head.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.pull_request.head.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.pull_request.head.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.pull_request.head.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.pull_request.head.user.gravatar_id | string | | |
action_result.data.\*.payload.pull_request.head.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.pull_request.head.user.id | numeric | | 1032411 |
action_result.data.\*.payload.pull_request.head.user.login | string | `github username` | test |
action_result.data.\*.payload.pull_request.head.user.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.pull_request.head.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.pull_request.head.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.pull_request.head.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.pull_request.head.user.site_admin | boolean | | True False |
action_result.data.\*.payload.pull_request.head.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.pull_request.head.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.pull_request.head.user.type | string | | User |
action_result.data.\*.payload.pull_request.head.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.pull_request.html_url | string | `url` | https://github.com/test/test/pull/27999 |
action_result.data.\*.payload.pull_request.id | numeric | | 202539219 |
action_result.data.\*.payload.pull_request.issue_url | string | `url` | https://api.github.com/repos/test/test/issues/27999 |
action_result.data.\*.payload.pull_request.labels.\*.color | string | | e10c02 |
action_result.data.\*.payload.pull_request.labels.\*.default | boolean | | True False |
action_result.data.\*.payload.pull_request.labels.\*.id | numeric | | 100079 |
action_result.data.\*.payload.pull_request.labels.\*.name | string | | Bug |
action_result.data.\*.payload.pull_request.labels.\*.node_id | string | | MDU6TGFiZWwxMDAwNzk= |
action_result.data.\*.payload.pull_request.labels.\*.url | string | `url` | https://api.github.com/repos/test/test/labels/Bug |
action_result.data.\*.payload.pull_request.locked | boolean | | True False |
action_result.data.\*.payload.pull_request.maintainer_can_modify | boolean | | True False |
action_result.data.\*.payload.pull_request.merge_commit_sha | string | `sha1` | ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.pull_request.mergeable | boolean | | False True |
action_result.data.\*.payload.pull_request.mergeable_state | string | | unknown |
action_result.data.\*.payload.pull_request.merged | boolean | | True False |
action_result.data.\*.payload.pull_request.merged_at | string | | 2018-07-19T12:14:03Z |
action_result.data.\*.payload.pull_request.merged_by.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/47313?v=4 |
action_result.data.\*.payload.pull_request.merged_by.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.pull_request.merged_by.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.pull_request.merged_by.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.pull_request.merged_by.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.pull_request.merged_by.gravatar_id | string | | |
action_result.data.\*.payload.pull_request.merged_by.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.pull_request.merged_by.id | numeric | | 47313 |
action_result.data.\*.payload.pull_request.merged_by.login | string | `github username` | test |
action_result.data.\*.payload.pull_request.merged_by.node_id | string | | MDQ6VXNlcjQ3MzEz |
action_result.data.\*.payload.pull_request.merged_by.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.pull_request.merged_by.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.pull_request.merged_by.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.pull_request.merged_by.site_admin | boolean | | True False |
action_result.data.\*.payload.pull_request.merged_by.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.pull_request.merged_by.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.pull_request.merged_by.type | string | | User |
action_result.data.\*.payload.pull_request.merged_by.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.pull_request.milestone.closed_at | string | | 2018-07-20T11:26:15Z |
action_result.data.\*.payload.pull_request.milestone.closed_issues | numeric | | 879 |
action_result.data.\*.payload.pull_request.milestone.created_at | string | | 2016-11-06T20:24:23Z |
action_result.data.\*.payload.pull_request.milestone.creator.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/73419?v=4 |
action_result.data.\*.payload.pull_request.milestone.creator.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.pull_request.milestone.creator.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.pull_request.milestone.creator.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.pull_request.milestone.creator.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.pull_request.milestone.creator.gravatar_id | string | | |
action_result.data.\*.payload.pull_request.milestone.creator.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.pull_request.milestone.creator.id | numeric | | 73419 |
action_result.data.\*.payload.pull_request.milestone.creator.login | string | `github username` | test |
action_result.data.\*.payload.pull_request.milestone.creator.node_id | string | | MDQ6VXNlcjczNDE5 |
action_result.data.\*.payload.pull_request.milestone.creator.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.pull_request.milestone.creator.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.pull_request.milestone.creator.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.pull_request.milestone.creator.site_admin | boolean | | True False |
action_result.data.\*.payload.pull_request.milestone.creator.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.pull_request.milestone.creator.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.pull_request.milestone.creator.type | string | | User |
action_result.data.\*.payload.pull_request.milestone.creator.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.pull_request.milestone.description | string | | Sample description |
action_result.data.\*.payload.pull_request.milestone.due_on | string | | 2020-11-30T08:00:00Z |
action_result.data.\*.payload.pull_request.milestone.html_url | string | `url` | https://github.com/test/test/milestone/10 |
action_result.data.\*.payload.pull_request.milestone.id | numeric | | 2117464 |
action_result.data.\*.payload.pull_request.milestone.labels_url | string | `url` | https://api.github.com/repos/test/test/milestones/10/labels |
action_result.data.\*.payload.pull_request.milestone.node_id | string | | MDk6TWlsZXN0b25lMjExNzQ2NA== |
action_result.data.\*.payload.pull_request.milestone.number | numeric | | 10 |
action_result.data.\*.payload.pull_request.milestone.open_issues | numeric | | 15 |
action_result.data.\*.payload.pull_request.milestone.state | string | | open |
action_result.data.\*.payload.pull_request.milestone.title | string | | 3.4 |
action_result.data.\*.payload.pull_request.milestone.updated_at | string | | 2018-07-19T07:12:02Z |
action_result.data.\*.payload.pull_request.milestone.url | string | `url` | https://api.github.com/repos/test/test/milestones/10 |
action_result.data.\*.payload.pull_request.node_id | string | | MDExOlB1bGxSZXF1ZXN0MjAyNTM5MjE5 |
action_result.data.\*.payload.pull_request.number | numeric | | 27999 |
action_result.data.\*.payload.pull_request.patch_url | string | `url` | https://github.com/test/test/pull/27999.patch |
action_result.data.\*.payload.pull_request.rebaseable | boolean | | False True |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.avatar_url | string | `url` | https://avatars2.githubusercontent.com/u/57224?v=4 |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.gravatar_id | string | | |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.id | numeric | | 57224 |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.login | string | `github username` | test |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.node_id | string | | MDQ6VXNlcjU3MjI0 |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.site_admin | boolean | | True False |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.type | string | | User |
action_result.data.\*.payload.pull_request.requested_reviewers.\*.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.pull_request.requested_teams.\*.created_at | string | | 2018-07-16T23:08:17Z |
action_result.data.\*.payload.pull_request.requested_teams.\*.description | string | | Everybody but Tony |
action_result.data.\*.payload.pull_request.requested_teams.\*.id | numeric | | 2826794 |
action_result.data.\*.payload.pull_request.requested_teams.\*.members_count | numeric | | 2 |
action_result.data.\*.payload.pull_request.requested_teams.\*.members_url | string | `url` | https://api.github.com/teams/2826794/members{/member} |
action_result.data.\*.payload.pull_request.requested_teams.\*.name | string | | not-tony-team |
action_result.data.\*.payload.pull_request.requested_teams.\*.node_id | string | | MDQ6VGVhbTI4MjY3OTQ= |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.avatar_url | string | `url` | https://avatars0.githubusercontent.com/u/41309665?v=4 |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.created_at | string | | 2018-07-16T23:02:38Z |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.description | string | | |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.events_url | string | `url` | https://api.github.com/orgs/test/events |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.followers | numeric | | 3 |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.following | numeric | | 3 |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.has_organization_projects | boolean | | True False |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.has_repository_projects | boolean | | True False |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.hooks_url | string | `url` | https://api.github.com/orgs/test/hooks |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.id | numeric | | 41309665 |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.issues_url | string | `url` | https://api.github.com/orgs/test/issues |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.login | string | `github organization name` | test |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.members_url | string | `url` | https://api.github.com/orgs/test/members{/member} |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjQxMzA5NjY1 |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.public_gists | numeric | | 3 |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.public_members_url | string | `url` | https://api.github.com/orgs/test/public_members{/member} |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.public_repos | numeric | | 3 |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.repos_url | string | `url` | https://api.github.com/orgs/test/repos |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.type | string | | Organization |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.updated_at | string | | 2018-07-16T23:02:38Z |
action_result.data.\*.payload.pull_request.requested_teams.\*.organization.url | string | `url` | https://api.github.com/orgs/test |
action_result.data.\*.payload.pull_request.requested_teams.\*.permission | string | | pull |
action_result.data.\*.payload.pull_request.requested_teams.\*.privacy | string | | closed |
action_result.data.\*.payload.pull_request.requested_teams.\*.repos_count | numeric | | 2 |
action_result.data.\*.payload.pull_request.requested_teams.\*.repositories_url | string | `url` | https://api.github.com/teams/test/repos |
action_result.data.\*.payload.pull_request.requested_teams.\*.slug | string | | not-tony-team |
action_result.data.\*.payload.pull_request.requested_teams.\*.updated_at | string | | 2018-07-16T23:08:17Z |
action_result.data.\*.payload.pull_request.requested_teams.\*.url | string | `url` | https://api.github.com/teams/2826794 |
action_result.data.\*.payload.pull_request.review_comment_url | string | `url` | https://api.github.com/repos/test/test/pulls/comments{/number} |
action_result.data.\*.payload.pull_request.review_comments | numeric | | 0 |
action_result.data.\*.payload.pull_request.review_comments_url | string | `url` | https://api.github.com/repos/test/test/pulls/27999/comments |
action_result.data.\*.payload.pull_request.state | string | | closed |
action_result.data.\*.payload.pull_request.statuses_url | string | `url` | https://api.github.com/repos/test/test/statuses/ee780f3c664f8e2846aba087c5e9653a92c64252 |
action_result.data.\*.payload.pull_request.title | string | | Sample title |
action_result.data.\*.payload.pull_request.updated_at | string | | 2018-07-19T12:14:03Z |
action_result.data.\*.payload.pull_request.url | string | `url` | https://api.github.com/repos/test/test/pulls/27999 |
action_result.data.\*.payload.pull_request.user.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.pull_request.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.pull_request.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.pull_request.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.pull_request.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.pull_request.user.gravatar_id | string | | |
action_result.data.\*.payload.pull_request.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.pull_request.user.id | numeric | | 1032411 |
action_result.data.\*.payload.pull_request.user.login | string | `github username` | test |
action_result.data.\*.payload.pull_request.user.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.pull_request.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.pull_request.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.pull_request.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.pull_request.user.site_admin | boolean | | True False |
action_result.data.\*.payload.pull_request.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.pull_request.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.pull_request.user.type | string | | User |
action_result.data.\*.payload.pull_request.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.push_id | numeric | | 2731668591 |
action_result.data.\*.payload.pusher_type | string | | user |
action_result.data.\*.payload.ref | string | | refs/heads/2.8 |
action_result.data.\*.payload.ref_type | string | | repository |
action_result.data.\*.payload.release.assets.\*.browser_download_url | string | `url` | https://github.com/test/test-proj/releases/download/1.1.1.1.1/phapp_code42.tgz |
action_result.data.\*.payload.release.assets.\*.content_type | string | | application/x-compressed |
action_result.data.\*.payload.release.assets.\*.created_at | string | | 2018-07-20T13:12:10Z |
action_result.data.\*.payload.release.assets.\*.download_count | numeric | | 0 |
action_result.data.\*.payload.release.assets.\*.id | numeric | | 7946908 |
action_result.data.\*.payload.release.assets.\*.label | string | | |
action_result.data.\*.payload.release.assets.\*.name | string | | phapp_code42.tgz |
action_result.data.\*.payload.release.assets.\*.node_id | string | | MDEyOlJlbGVhc2VBc3NldDc5NDY5MDg= |
action_result.data.\*.payload.release.assets.\*.size | numeric | | 91097 |
action_result.data.\*.payload.release.assets.\*.state | string | | uploaded |
action_result.data.\*.payload.release.assets.\*.updated_at | string | | 2018-07-20T13:12:16Z |
action_result.data.\*.payload.release.assets.\*.uploader.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/41309719?v=4 |
action_result.data.\*.payload.release.assets.\*.uploader.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.release.assets.\*.uploader.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.release.assets.\*.uploader.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.release.assets.\*.uploader.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.release.assets.\*.uploader.gravatar_id | string | | |
action_result.data.\*.payload.release.assets.\*.uploader.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.release.assets.\*.uploader.id | numeric | | 41309719 |
action_result.data.\*.payload.release.assets.\*.uploader.login | string | `github username` | test |
action_result.data.\*.payload.release.assets.\*.uploader.node_id | string | | MDQ6VXNlcjQxMzA5NzE5 |
action_result.data.\*.payload.release.assets.\*.uploader.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.release.assets.\*.uploader.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.release.assets.\*.uploader.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.release.assets.\*.uploader.site_admin | boolean | | True False |
action_result.data.\*.payload.release.assets.\*.uploader.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.release.assets.\*.uploader.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.release.assets.\*.uploader.type | string | | User |
action_result.data.\*.payload.release.assets.\*.uploader.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.release.assets.\*.url | string | `url` | https://api.github.com/repos/test/test-proj/releases/assets/8946908 |
action_result.data.\*.payload.release.assets_url | string | `url` | https://api.github.com/repos/toml-lang/toml/releases/11865985/assets |
action_result.data.\*.payload.release.author.avatar_url | string | `url` | https://avatars0.githubusercontent.com/u/1?v=4 |
action_result.data.\*.payload.release.author.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.release.author.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.release.author.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.release.author.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.release.author.gravatar_id | string | | |
action_result.data.\*.payload.release.author.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.release.author.id | numeric | | 1 |
action_result.data.\*.payload.release.author.login | string | `github username` | test |
action_result.data.\*.payload.release.author.node_id | string | | MDQ6VXNlcjE= |
action_result.data.\*.payload.release.author.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.release.author.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.release.author.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.release.author.site_admin | boolean | | True False |
action_result.data.\*.payload.release.author.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.release.author.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.release.author.type | string | | User |
action_result.data.\*.payload.release.author.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.release.body | string | | Sample body |
action_result.data.\*.payload.release.created_at | string | | 2018-07-10T21:44:12Z |
action_result.data.\*.payload.release.draft | boolean | | True False |
action_result.data.\*.payload.release.html_url | string | `url` | https://github.com/toml-lang/toml/releases/tag/v0.5.0 |
action_result.data.\*.payload.release.id | numeric | | 11865985 |
action_result.data.\*.payload.release.name | string | | v0.5.0 |
action_result.data.\*.payload.release.node_id | string | | MDc6UmVsZWFzZTExODY1OTg1 |
action_result.data.\*.payload.release.prerelease | boolean | | True False |
action_result.data.\*.payload.release.published_at | string | | 2018-07-10T21:58:13Z |
action_result.data.\*.payload.release.tag_name | string | | v0.5.0 |
action_result.data.\*.payload.release.tarball_url | string | `url` | https://api.github.com/repos/toml-lang/toml/tarball/v0.5.0 |
action_result.data.\*.payload.release.target_commitish | string | | master |
action_result.data.\*.payload.release.upload_url | string | `url` | https://uploads.github.com/repos/toml-lang/toml/releases/11865985/assets{?name,label} |
action_result.data.\*.payload.release.url | string | `url` | https://api.github.com/repos/toml-lang/toml/releases/11865985 |
action_result.data.\*.payload.release.zipball_url | string | `url` | https://api.github.com/repos/toml-lang/toml/zipball/v0.5.0 |
action_result.data.\*.payload.repositories_added.\*.archive_url | string | `url` | https://api.github.com/repos/test/test-repo/{archive_format}{/ref} |
action_result.data.\*.payload.repositories_added.\*.archived | boolean | | True False |
action_result.data.\*.payload.repositories_added.\*.assignees_url | string | `url` | https://api.github.com/repos/test/test-repo/assignees{/user} |
action_result.data.\*.payload.repositories_added.\*.blobs_url | string | `url` | https://api.github.com/repos/test/test-repo/git/blobs{/sha} |
action_result.data.\*.payload.repositories_added.\*.branches_url | string | `url` | https://api.github.com/repos/test/test-repo/branches{/branch} |
action_result.data.\*.payload.repositories_added.\*.clone_url | string | `url` | https://github.com/test/test-repo.git |
action_result.data.\*.payload.repositories_added.\*.collaborators_url | string | `url` | https://api.github.com/repos/test/test-repo/collaborators{/collaborator} |
action_result.data.\*.payload.repositories_added.\*.comments_url | string | `url` | https://api.github.com/repos/test/test-repo/comments{/number} |
action_result.data.\*.payload.repositories_added.\*.commits_url | string | `url` | https://api.github.com/repos/test/test-repo/commits{/sha} |
action_result.data.\*.payload.repositories_added.\*.compare_url | string | `url` | https://api.github.com/repos/test/test-repo/compare/{base}...{head} |
action_result.data.\*.payload.repositories_added.\*.contents_url | string | `url` | https://api.github.com/repos/test/test-repo/contents/{+path} |
action_result.data.\*.payload.repositories_added.\*.contributors_url | string | `url` | https://api.github.com/repos/test/test-repo/contributors |
action_result.data.\*.payload.repositories_added.\*.created_at | string | | 2018-05-30T20:18:04Z |
action_result.data.\*.payload.repositories_added.\*.default_branch | string | | master |
action_result.data.\*.payload.repositories_added.\*.deployments_url | string | `url` | https://api.github.com/repos/test/test-repo/deployments |
action_result.data.\*.payload.repositories_added.\*.description | string | | |
action_result.data.\*.payload.repositories_added.\*.downloads_url | string | `url` | https://api.github.com/repos/test/test-repo/downloads |
action_result.data.\*.payload.repositories_added.\*.events_url | string | `url` | https://api.github.com/repos/test/test-repo/events |
action_result.data.\*.payload.repositories_added.\*.fork | boolean | | True False |
action_result.data.\*.payload.repositories_added.\*.forks | numeric | | 0 |
action_result.data.\*.payload.repositories_added.\*.forks_count | numeric | | 0 |
action_result.data.\*.payload.repositories_added.\*.forks_url | string | `url` | https://api.github.com/repos/test/test-repo/forks |
action_result.data.\*.payload.repositories_added.\*.full_name | string | | test/test-repo |
action_result.data.\*.payload.repositories_added.\*.git_commits_url | string | `url` | https://api.github.com/repos/test/test-repo/git/commits{/sha} |
action_result.data.\*.payload.repositories_added.\*.git_refs_url | string | `url` | https://api.github.com/repos/test/test-repo/git/refs{/sha} |
action_result.data.\*.payload.repositories_added.\*.git_tags_url | string | `url` | https://api.github.com/repos/test/test-repo/git/tags{/sha} |
action_result.data.\*.payload.repositories_added.\*.git_url | string | | git://github.com/test/test-repo.git |
action_result.data.\*.payload.repositories_added.\*.has_downloads | boolean | | True False |
action_result.data.\*.payload.repositories_added.\*.has_issues | boolean | | True False |
action_result.data.\*.payload.repositories_added.\*.has_pages | boolean | | True False |
action_result.data.\*.payload.repositories_added.\*.has_projects | boolean | | True False |
action_result.data.\*.payload.repositories_added.\*.has_wiki | boolean | | True False |
action_result.data.\*.payload.repositories_added.\*.homepage | string | `url` | https://test.com |
action_result.data.\*.payload.repositories_added.\*.hooks_url | string | `url` | https://api.github.com/repos/test/test-repo/hooks |
action_result.data.\*.payload.repositories_added.\*.html_url | string | `url` | https://github.com/test/test-repo |
action_result.data.\*.payload.repositories_added.\*.id | numeric | | 135493233 |
action_result.data.\*.payload.repositories_added.\*.issue_comment_url | string | `url` | https://api.github.com/repos/test/test-repo/issues/comments{/number} |
action_result.data.\*.payload.repositories_added.\*.issue_events_url | string | `url` | https://api.github.com/repos/test/test-repo/issues/events{/number} |
action_result.data.\*.payload.repositories_added.\*.issues_url | string | `url` | https://api.github.com/repos/test/test-repo/issues{/number} |
action_result.data.\*.payload.repositories_added.\*.keys_url | string | `url` | https://api.github.com/repos/test/test-repo/keys{/key_id} |
action_result.data.\*.payload.repositories_added.\*.labels_url | string | `url` | https://api.github.com/repos/test/test-repo/labels{/name} |
action_result.data.\*.payload.repositories_added.\*.language | string | | |
action_result.data.\*.payload.repositories_added.\*.languages_url | string | `url` | https://api.github.com/repos/test/test-repo/languages |
action_result.data.\*.payload.repositories_added.\*.license.key | string | | mit |
action_result.data.\*.payload.repositories_added.\*.license.name | string | | MIT License |
action_result.data.\*.payload.repositories_added.\*.license.node_id | string | | MDc6TGljZW5zZTEz |
action_result.data.\*.payload.repositories_added.\*.license.spdx_id | string | | MIT |
action_result.data.\*.payload.repositories_added.\*.license.url | string | `url` | https://api.github.com/licenses/mit |
action_result.data.\*.payload.repositories_added.\*.merges_url | string | `url` | https://api.github.com/repos/test/test-repo/merges |
action_result.data.\*.payload.repositories_added.\*.milestones_url | string | `url` | https://api.github.com/repos/test/test-repo/milestones{/number} |
action_result.data.\*.payload.repositories_added.\*.mirror_url | string | `url` | |
action_result.data.\*.payload.repositories_added.\*.name | string | | test-repo |
action_result.data.\*.payload.repositories_added.\*.node_id | string | | MDEwOlJlcG9zaXRvcnkxMzU0OTMyMzM= |
action_result.data.\*.payload.repositories_added.\*.notifications_url | string | `url` | https://api.github.com/repos/test/test-repo/notifications{?since,all,participating} |
action_result.data.\*.payload.repositories_added.\*.open_issues | numeric | | 0 |
action_result.data.\*.payload.repositories_added.\*.open_issues_count | numeric | | 0 |
action_result.data.\*.payload.repositories_added.\*.owner.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/29939753?v=4 |
action_result.data.\*.payload.repositories_added.\*.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.repositories_added.\*.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.repositories_added.\*.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.repositories_added.\*.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.repositories_added.\*.owner.gravatar_id | string | | |
action_result.data.\*.payload.repositories_added.\*.owner.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.repositories_added.\*.owner.id | numeric | | 29939753 |
action_result.data.\*.payload.repositories_added.\*.owner.login | string | `github username` | test |
action_result.data.\*.payload.repositories_added.\*.owner.node_id | string | | MDQ6VXNlcjI5OTM5NzUz |
action_result.data.\*.payload.repositories_added.\*.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.repositories_added.\*.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.repositories_added.\*.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.repositories_added.\*.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.repositories_added.\*.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.repositories_added.\*.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.repositories_added.\*.owner.type | string | | User |
action_result.data.\*.payload.repositories_added.\*.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.repositories_added.\*.private | boolean | | True False |
action_result.data.\*.payload.repositories_added.\*.pulls_url | string | `url` | https://api.github.com/repos/test/test-repo/pulls{/number} |
action_result.data.\*.payload.repositories_added.\*.pushed_at | string | | 2018-05-30T20:18:34Z |
action_result.data.\*.payload.repositories_added.\*.releases_url | string | `url` | https://api.github.com/repos/test/test-repo/releases{/id} |
action_result.data.\*.payload.repositories_added.\*.size | numeric | | 0 |
action_result.data.\*.payload.repositories_added.\*.ssh_url | string | | git@github.com:test/test-repo.git |
action_result.data.\*.payload.repositories_added.\*.stargazers_count | numeric | | 0 |
action_result.data.\*.payload.repositories_added.\*.stargazers_url | string | `url` | https://api.github.com/repos/test/test-repo/stargazers |
action_result.data.\*.payload.repositories_added.\*.statuses_url | string | `url` | https://api.github.com/repos/test/test-repo/statuses/{sha} |
action_result.data.\*.payload.repositories_added.\*.subscribers_url | string | `url` | https://api.github.com/repos/test/test-repo/subscribers |
action_result.data.\*.payload.repositories_added.\*.subscription_url | string | `url` | https://api.github.com/repos/test/test-repo/subscription |
action_result.data.\*.payload.repositories_added.\*.svn_url | string | `url` | https://github.com/test/test-repo |
action_result.data.\*.payload.repositories_added.\*.tags_url | string | `url` | https://api.github.com/repos/test/test-repo/tags |
action_result.data.\*.payload.repositories_added.\*.teams_url | string | `url` | https://api.github.com/repos/test/test-repo/teams |
action_result.data.\*.payload.repositories_added.\*.trees_url | string | `url` | https://api.github.com/repos/test/test-repo/git/trees{/sha} |
action_result.data.\*.payload.repositories_added.\*.updated_at | string | | 2018-05-30T20:18:44Z |
action_result.data.\*.payload.repositories_added.\*.url | string | `url` | https://api.github.com/repos/test/test-repo |
action_result.data.\*.payload.repositories_added.\*.watchers | numeric | | 0 |
action_result.data.\*.payload.repositories_added.\*.watchers_count | numeric | | 0 |
action_result.data.\*.payload.repositories_removed.\*.archive_url | string | `url` | https://api.github.com/repos/test/test-repo/{archive_format}{/ref} |
action_result.data.\*.payload.repositories_removed.\*.archived | boolean | | True False |
action_result.data.\*.payload.repositories_removed.\*.assignees_url | string | `url` | https://api.github.com/repos/test/test-repo/assignees{/user} |
action_result.data.\*.payload.repositories_removed.\*.blobs_url | string | `url` | https://api.github.com/repos/test/test-repo/git/blobs{/sha} |
action_result.data.\*.payload.repositories_removed.\*.branches_url | string | `url` | https://api.github.com/repos/test/test-repo/branches{/branch} |
action_result.data.\*.payload.repositories_removed.\*.clone_url | string | `url` | https://github.com/test/test-repo.git |
action_result.data.\*.payload.repositories_removed.\*.collaborators_url | string | `url` | https://api.github.com/repos/test/test-repo/collaborators{/collaborator} |
action_result.data.\*.payload.repositories_removed.\*.comments_url | string | `url` | https://api.github.com/repos/test/test-repo/comments{/number} |
action_result.data.\*.payload.repositories_removed.\*.commits_url | string | `url` | https://api.github.com/repos/test/test-repo/commits{/sha} |
action_result.data.\*.payload.repositories_removed.\*.compare_url | string | `url` | https://api.github.com/repos/test/test-repo/compare/{base}...{head} |
action_result.data.\*.payload.repositories_removed.\*.contents_url | string | `url` | https://api.github.com/repos/test/test-repo/contents/{+path} |
action_result.data.\*.payload.repositories_removed.\*.contributors_url | string | `url` | https://api.github.com/repos/test/test-repo/contributors |
action_result.data.\*.payload.repositories_removed.\*.created_at | string | | 2018-05-30T20:18:04Z |
action_result.data.\*.payload.repositories_removed.\*.default_branch | string | | master |
action_result.data.\*.payload.repositories_removed.\*.deployments_url | string | `url` | https://api.github.com/repos/test/test-repo/deployments |
action_result.data.\*.payload.repositories_removed.\*.description | string | | |
action_result.data.\*.payload.repositories_removed.\*.downloads_url | string | `url` | https://api.github.com/repos/test/test-repo/downloads |
action_result.data.\*.payload.repositories_removed.\*.events_url | string | `url` | https://api.github.com/repos/test/test-repo/events |
action_result.data.\*.payload.repositories_removed.\*.fork | boolean | | True False |
action_result.data.\*.payload.repositories_removed.\*.forks | numeric | | 0 |
action_result.data.\*.payload.repositories_removed.\*.forks_count | numeric | | 0 |
action_result.data.\*.payload.repositories_removed.\*.forks_url | string | `url` | https://api.github.com/repos/test/test-repo/forks |
action_result.data.\*.payload.repositories_removed.\*.full_name | string | | test/test-repo |
action_result.data.\*.payload.repositories_removed.\*.git_commits_url | string | `url` | https://api.github.com/repos/test/test-repo/git/commits{/sha} |
action_result.data.\*.payload.repositories_removed.\*.git_refs_url | string | `url` | https://api.github.com/repos/test/test-repo/git/refs{/sha} |
action_result.data.\*.payload.repositories_removed.\*.git_tags_url | string | `url` | https://api.github.com/repos/test/test-repo/git/tags{/sha} |
action_result.data.\*.payload.repositories_removed.\*.git_url | string | | git://github.com/test/test-repo.git |
action_result.data.\*.payload.repositories_removed.\*.has_downloads | boolean | | True False |
action_result.data.\*.payload.repositories_removed.\*.has_issues | boolean | | True False |
action_result.data.\*.payload.repositories_removed.\*.has_pages | boolean | | True False |
action_result.data.\*.payload.repositories_removed.\*.has_projects | boolean | | True False |
action_result.data.\*.payload.repositories_removed.\*.has_wiki | boolean | | True False |
action_result.data.\*.payload.repositories_removed.\*.homepage | string | `url` | https://test.com |
action_result.data.\*.payload.repositories_removed.\*.hooks_url | string | `url` | https://api.github.com/repos/test/test-repo/hooks |
action_result.data.\*.payload.repositories_removed.\*.html_url | string | `url` | https://github.com/test/test-repo |
action_result.data.\*.payload.repositories_removed.\*.id | numeric | | 135493233 |
action_result.data.\*.payload.repositories_removed.\*.issue_comment_url | string | `url` | https://api.github.com/repos/test/test-repo/issues/comments{/number} |
action_result.data.\*.payload.repositories_removed.\*.issue_events_url | string | `url` | https://api.github.com/repos/test/test-repo/issues/events{/number} |
action_result.data.\*.payload.repositories_removed.\*.issues_url | string | `url` | https://api.github.com/repos/test/test-repo/issues{/number} |
action_result.data.\*.payload.repositories_removed.\*.keys_url | string | `url` | https://api.github.com/repos/test/test-repo/keys{/key_id} |
action_result.data.\*.payload.repositories_removed.\*.labels_url | string | `url` | https://api.github.com/repos/test/test-repo/labels{/name} |
action_result.data.\*.payload.repositories_removed.\*.language | string | | |
action_result.data.\*.payload.repositories_removed.\*.languages_url | string | `url` | https://api.github.com/repos/test/test-repo/languages |
action_result.data.\*.payload.repositories_removed.\*.license.key | string | | mit |
action_result.data.\*.payload.repositories_removed.\*.license.name | string | | MIT License |
action_result.data.\*.payload.repositories_removed.\*.license.node_id | string | | MDc6TGljZW5zZTEz |
action_result.data.\*.payload.repositories_removed.\*.license.spdx_id | string | | MIT |
action_result.data.\*.payload.repositories_removed.\*.license.url | string | `url` | https://api.github.com/licenses/mit |
action_result.data.\*.payload.repositories_removed.\*.merges_url | string | `url` | https://api.github.com/repos/test/test-repo/merges |
action_result.data.\*.payload.repositories_removed.\*.milestones_url | string | `url` | https://api.github.com/repos/test/test-repo/milestones{/number} |
action_result.data.\*.payload.repositories_removed.\*.mirror_url | string | `url` | |
action_result.data.\*.payload.repositories_removed.\*.name | string | | test-repo |
action_result.data.\*.payload.repositories_removed.\*.node_id | string | | MDEwOlJlcG9zaXRvcnkxMzU0OTMyMzM= |
action_result.data.\*.payload.repositories_removed.\*.notifications_url | string | `url` | https://api.github.com/repos/test/test-repo/notifications{?since,all,participating} |
action_result.data.\*.payload.repositories_removed.\*.open_issues | numeric | | 0 |
action_result.data.\*.payload.repositories_removed.\*.open_issues_count | numeric | | 0 |
action_result.data.\*.payload.repositories_removed.\*.owner.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/29939753?v=4 |
action_result.data.\*.payload.repositories_removed.\*.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.repositories_removed.\*.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.repositories_removed.\*.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.repositories_removed.\*.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.repositories_removed.\*.owner.gravatar_id | string | | |
action_result.data.\*.payload.repositories_removed.\*.owner.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.repositories_removed.\*.owner.id | numeric | | 29939753 |
action_result.data.\*.payload.repositories_removed.\*.owner.login | string | `github username` | test |
action_result.data.\*.payload.repositories_removed.\*.owner.node_id | string | | MDQ6VXNlcjI5OTM5NzUz |
action_result.data.\*.payload.repositories_removed.\*.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.repositories_removed.\*.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.repositories_removed.\*.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.repositories_removed.\*.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.repositories_removed.\*.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.repositories_removed.\*.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.repositories_removed.\*.owner.type | string | | User |
action_result.data.\*.payload.repositories_removed.\*.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.repositories_removed.\*.private | boolean | | True False |
action_result.data.\*.payload.repositories_removed.\*.pulls_url | string | `url` | https://api.github.com/repos/test/test-repo/pulls{/number} |
action_result.data.\*.payload.repositories_removed.\*.pushed_at | string | | 2018-05-30T20:18:34Z |
action_result.data.\*.payload.repositories_removed.\*.releases_url | string | `url` | https://api.github.com/repos/test/test-repo/releases{/id} |
action_result.data.\*.payload.repositories_removed.\*.size | numeric | | 0 |
action_result.data.\*.payload.repositories_removed.\*.ssh_url | string | | git@github.com:test/test-repo.git |
action_result.data.\*.payload.repositories_removed.\*.stargazers_count | numeric | | 0 |
action_result.data.\*.payload.repositories_removed.\*.stargazers_url | string | `url` | https://api.github.com/repos/test/test-repo/stargazers |
action_result.data.\*.payload.repositories_removed.\*.statuses_url | string | `url` | https://api.github.com/repos/test/test-repo/statuses/{sha} |
action_result.data.\*.payload.repositories_removed.\*.subscribers_url | string | `url` | https://api.github.com/repos/test/test-repo/subscribers |
action_result.data.\*.payload.repositories_removed.\*.subscription_url | string | `url` | https://api.github.com/repos/test/test-repo/subscription |
action_result.data.\*.payload.repositories_removed.\*.svn_url | string | `url` | https://github.com/test/test-repo |
action_result.data.\*.payload.repositories_removed.\*.tags_url | string | `url` | https://api.github.com/repos/test/test-repo/tags |
action_result.data.\*.payload.repositories_removed.\*.teams_url | string | `url` | https://api.github.com/repos/test/test-repo/teams |
action_result.data.\*.payload.repositories_removed.\*.trees_url | string | `url` | https://api.github.com/repos/test/test-repo/git/trees{/sha} |
action_result.data.\*.payload.repositories_removed.\*.updated_at | string | | 2018-05-30T20:18:44Z |
action_result.data.\*.payload.repositories_removed.\*.url | string | `url` | https://api.github.com/repos/test/test-repo |
action_result.data.\*.payload.repositories_removed.\*.watchers | numeric | | 0 |
action_result.data.\*.payload.repositories_removed.\*.watchers_count | numeric | | 0 |
action_result.data.\*.payload.repository.archive_url | string | `url` | https://api.github.com/repos/test/test-repo/{archive_format}{/ref} |
action_result.data.\*.payload.repository.archived | boolean | | True False |
action_result.data.\*.payload.repository.assignees_url | string | `url` | https://api.github.com/repos/test/test-repo/assignees{/user} |
action_result.data.\*.payload.repository.blobs_url | string | `url` | https://api.github.com/repos/test/test-repo/git/blobs{/sha} |
action_result.data.\*.payload.repository.branches_url | string | `url` | https://api.github.com/repos/test/test-repo/branches{/branch} |
action_result.data.\*.payload.repository.clone_url | string | `url` | https://github.com/test/test-repo.git |
action_result.data.\*.payload.repository.collaborators_url | string | `url` | https://api.github.com/repos/test/test-repo/collaborators{/collaborator} |
action_result.data.\*.payload.repository.comments_url | string | `url` | https://api.github.com/repos/test/test-repo/comments{/number} |
action_result.data.\*.payload.repository.commits_url | string | `url` | https://api.github.com/repos/test/test-repo/commits{/sha} |
action_result.data.\*.payload.repository.compare_url | string | `url` | https://api.github.com/repos/test/test-repo/compare/{base}...{head} |
action_result.data.\*.payload.repository.contents_url | string | `url` | https://api.github.com/repos/test/test-repo/contents/{+path} |
action_result.data.\*.payload.repository.contributors_url | string | `url` | https://api.github.com/repos/test/test-repo/contributors |
action_result.data.\*.payload.repository.created_at | string | | 2018-05-30T20:18:04Z |
action_result.data.\*.payload.repository.default_branch | string | | master |
action_result.data.\*.payload.repository.deployments_url | string | `url` | https://api.github.com/repos/test/test-repo/deployments |
action_result.data.\*.payload.repository.description | string | | |
action_result.data.\*.payload.repository.downloads_url | string | `url` | https://api.github.com/repos/test/test-repo/downloads |
action_result.data.\*.payload.repository.events_url | string | `url` | https://api.github.com/repos/test/test-repo/events |
action_result.data.\*.payload.repository.fork | boolean | | True False |
action_result.data.\*.payload.repository.forks | numeric | | 0 |
action_result.data.\*.payload.repository.forks_count | numeric | | 0 |
action_result.data.\*.payload.repository.forks_url | string | `url` | https://api.github.com/repos/test/test-repo/forks |
action_result.data.\*.payload.repository.full_name | string | | test/test-repo |
action_result.data.\*.payload.repository.git_commits_url | string | `url` | https://api.github.com/repos/test/test-repo/git/commits{/sha} |
action_result.data.\*.payload.repository.git_refs_url | string | `url` | https://api.github.com/repos/test/test-repo/git/refs{/sha} |
action_result.data.\*.payload.repository.git_tags_url | string | `url` | https://api.github.com/repos/test/test-repo/git/tags{/sha} |
action_result.data.\*.payload.repository.git_url | string | | git://github.com/test/test-repo.git |
action_result.data.\*.payload.repository.has_downloads | boolean | | True False |
action_result.data.\*.payload.repository.has_issues | boolean | | True False |
action_result.data.\*.payload.repository.has_pages | boolean | | True False |
action_result.data.\*.payload.repository.has_projects | boolean | | True False |
action_result.data.\*.payload.repository.has_wiki | boolean | | True False |
action_result.data.\*.payload.repository.homepage | string | `url` | https://test.com |
action_result.data.\*.payload.repository.hooks_url | string | `url` | https://api.github.com/repos/test/test-repo/hooks |
action_result.data.\*.payload.repository.html_url | string | `url` | https://github.com/test/test-repo |
action_result.data.\*.payload.repository.id | numeric | | 135493233 |
action_result.data.\*.payload.repository.issue_comment_url | string | `url` | https://api.github.com/repos/test/test-repo/issues/comments{/number} |
action_result.data.\*.payload.repository.issue_events_url | string | `url` | https://api.github.com/repos/test/test-repo/issues/events{/number} |
action_result.data.\*.payload.repository.issues_url | string | `url` | https://api.github.com/repos/test/test-repo/issues{/number} |
action_result.data.\*.payload.repository.keys_url | string | `url` | https://api.github.com/repos/test/test-repo/keys{/key_id} |
action_result.data.\*.payload.repository.labels_url | string | `url` | https://api.github.com/repos/test/test-repo/labels{/name} |
action_result.data.\*.payload.repository.language | string | | |
action_result.data.\*.payload.repository.languages_url | string | `url` | https://api.github.com/repos/test/test-repo/languages |
action_result.data.\*.payload.repository.license.key | string | | mit |
action_result.data.\*.payload.repository.license.name | string | | MIT License |
action_result.data.\*.payload.repository.license.node_id | string | | MDc6TGljZW5zZTEz |
action_result.data.\*.payload.repository.license.spdx_id | string | | MIT |
action_result.data.\*.payload.repository.license.url | string | `url` | https://api.github.com/licenses/mit |
action_result.data.\*.payload.repository.master_branch | string | | master |
action_result.data.\*.payload.repository.merges_url | string | `url` | https://api.github.com/repos/test/test-repo/merges |
action_result.data.\*.payload.repository.milestones_url | string | `url` | https://api.github.com/repos/test/test-repo/milestones{/number} |
action_result.data.\*.payload.repository.mirror_url | string | `url` | |
action_result.data.\*.payload.repository.name | string | | test-repo |
action_result.data.\*.payload.repository.node_id | string | | MDEwOlJlcG9zaXRvcnkxMzU0OTMyMzM= |
action_result.data.\*.payload.repository.notifications_url | string | `url` | https://api.github.com/repos/test/test-repo/notifications{?since,all,participating} |
action_result.data.\*.payload.repository.open_issues | numeric | | 0 |
action_result.data.\*.payload.repository.open_issues_count | numeric | | 0 |
action_result.data.\*.payload.repository.owner.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/29939753?v=4 |
action_result.data.\*.payload.repository.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.repository.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.repository.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.repository.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.repository.owner.gravatar_id | string | | |
action_result.data.\*.payload.repository.owner.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.repository.owner.id | numeric | | 29939753 |
action_result.data.\*.payload.repository.owner.login | string | `github username` | test |
action_result.data.\*.payload.repository.owner.node_id | string | | MDQ6VXNlcjI5OTM5NzUz |
action_result.data.\*.payload.repository.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.repository.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.repository.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.repository.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.repository.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.repository.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.repository.owner.type | string | | User |
action_result.data.\*.payload.repository.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.repository.private | boolean | | True False |
action_result.data.\*.payload.repository.pulls_url | string | `url` | https://api.github.com/repos/test/test-repo/pulls{/number} |
action_result.data.\*.payload.repository.pushed_at | string | | 2018-05-30T20:18:34Z |
action_result.data.\*.payload.repository.releases_url | string | `url` | https://api.github.com/repos/test/test-repo/releases{/id} |
action_result.data.\*.payload.repository.size | numeric | | 0 |
action_result.data.\*.payload.repository.ssh_url | string | | git@github.com:test/test-repo.git |
action_result.data.\*.payload.repository.stargazers | numeric | | 1 |
action_result.data.\*.payload.repository.stargazers_count | numeric | | 0 |
action_result.data.\*.payload.repository.stargazers_url | string | `url` | https://api.github.com/repos/test/test-repo/stargazers |
action_result.data.\*.payload.repository.statuses_url | string | `url` | https://api.github.com/repos/test/test-repo/statuses/{sha} |
action_result.data.\*.payload.repository.subscribers_url | string | `url` | https://api.github.com/repos/test/test-repo/subscribers |
action_result.data.\*.payload.repository.subscription_url | string | `url` | https://api.github.com/repos/test/test-repo/subscription |
action_result.data.\*.payload.repository.svn_url | string | `url` | https://github.com/test/test-repo |
action_result.data.\*.payload.repository.tags_url | string | `url` | https://api.github.com/repos/test/test-repo/tags |
action_result.data.\*.payload.repository.teams_url | string | `url` | https://api.github.com/repos/test/test-repo/teams |
action_result.data.\*.payload.repository.trees_url | string | `url` | https://api.github.com/repos/test/test-repo/git/trees{/sha} |
action_result.data.\*.payload.repository.updated_at | string | | 2018-05-30T20:18:44Z |
action_result.data.\*.payload.repository.url | string | `url` | https://api.github.com/repos/test/test-repo |
action_result.data.\*.payload.repository.watchers | numeric | | 0 |
action_result.data.\*.payload.repository.watchers_count | numeric | | 0 |
action_result.data.\*.payload.repository_selection | string | | selected |
action_result.data.\*.payload.review.\_links.html.href | string | `url` | https://github.com/test/test-repo/pull/1#pullrequestreview-124575911 |
action_result.data.\*.payload.review.\_links.pull_request.href | string | `url` | https://api.github.com/repos/test/test-repo/pulls/1 |
action_result.data.\*.payload.review.author_association | string | | OWNER |
action_result.data.\*.payload.review.body | string | | |
action_result.data.\*.payload.review.commit_id | string | | 34c5c7793cb3b279e22454cb6750c80560547b3a |
action_result.data.\*.payload.review.html_url | string | `url` | https://github.com/test/test-repo/pull/1#pullrequestreview-124575911 |
action_result.data.\*.payload.review.id | numeric | | 124575911 |
action_result.data.\*.payload.review.node_id | string | | MDE3OlB1bGxSZXF1ZXN0UmV2aWV3MTI0NTc1OTEx |
action_result.data.\*.payload.review.pull_request_url | string | `url` | https://api.github.com/repos/test/test-repo/pulls/1 |
action_result.data.\*.payload.review.state | string | | commented |
action_result.data.\*.payload.review.submitted_at | string | | 2018-05-30T20:18:31Z |
action_result.data.\*.payload.review.user.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.review.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.review.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.review.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.review.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.review.user.gravatar_id | string | | |
action_result.data.\*.payload.review.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.review.user.id | numeric | | 1032411 |
action_result.data.\*.payload.review.user.login | string | `github username` | test |
action_result.data.\*.payload.review.user.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.review.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.review.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.review.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.review.user.site_admin | boolean | | True False |
action_result.data.\*.payload.review.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.review.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.review.user.type | string | | User |
action_result.data.\*.payload.review.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.sender.avatar_url | string | `url` | https://avatars2.githubusercontent.com/u/39652351?v=4 |
action_result.data.\*.payload.sender.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.sender.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.sender.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.sender.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.sender.gravatar_id | string | | |
action_result.data.\*.payload.sender.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.sender.id | numeric | | 406494157 |
action_result.data.\*.payload.sender.login | string | `github username` | test |
action_result.data.\*.payload.sender.node_id | string | | MDQ6VXNlcjM5NjUyMzUx |
action_result.data.\*.payload.sender.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.sender.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.sender.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.sender.site_admin | boolean | | True False |
action_result.data.\*.payload.sender.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.sender.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.sender.type | string | | User |
action_result.data.\*.payload.sender.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.size | numeric | | 2 |
action_result.data.\*.public | boolean | | True False |
action_result.data.\*.repo.id | numeric | | 141531062 |
action_result.data.\*.repo.name | string | `github repo` | test-repo |
action_result.data.\*.repo.url | string | `url` | https://api.github.com/repos/test/test-repo |
action_result.data.\*.type | string | | CreateEvent |
action_result.summary.total_events | numeric | | 153 |
action_result.message | string | | Total events: 153 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list users'

List users of an organization

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**organization_name** | required | Organization name | string | `github organization name` |
**limit** | optional | Maximum number of users to be fetched | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.limit | numeric | | |
action_result.parameter.organization_name | string | `github organization name` | test organization |
action_result.data.\*.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/29919753?v=4 |
action_result.data.\*.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.gravatar_id | string | | |
action_result.data.\*.html_url | string | `url` | https://github.com/test |
action_result.data.\*.id | numeric | | 29939753 |
action_result.data.\*.login | string | `github username` | test |
action_result.data.\*.node_id | string | | MDQ6VXNlcjI5OTM5NzUz |
action_result.data.\*.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.site_admin | boolean | | True False |
action_result.data.\*.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.type | string | | User |
action_result.data.\*.url | string | `url` | https://api.github.com/users/test |
action_result.summary.total_users | numeric | | 5 |
action_result.message | string | | Total users: 5 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'remove collaborator'

Remove user as a collaborator from the repo

Type: **generic** \
Read only: **False**

If the user is not a direct collaborator to the repo, any pending invitations to the user will also be deleted.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**repo_owner** | required | Owner of the repository | string | `github repo owner` `github username` |
**repo_name** | required | Name of the repository | string | `github repo` |
**user** | required | Username | string | `github username` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.repo_name | string | `github repo` | testrepo |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | Splunk |
action_result.parameter.user | string | `github username` | test |
action_result.data.\*.invite_deleted | boolean | | True False |
action_result.summary | string | | |
action_result.message | string | | User test is not a collaborator to repo test/test-repo and any pending invitations deleted |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add collaborator'

Add user as a collaborator to repo

Type: **generic** \
Read only: **False**

For repo whose owner is an organization, if the user is not a member of the organization, GitHub will send an email invite to the user to join as a collaborator. Otherwise, he will be directly added as a collaborator. For repo whose owner is a user, GitHub will always send an email invite to the user to join as a collaborator. If an invite is already sent to the user, re-invite will not be sent. If the user is already a collaborator, his role will be updated.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**repo_owner** | required | Owner of the repository | string | `github repo owner` `github username` |
**repo_name** | required | Name of the repository | string | `github repo` |
**user** | required | Username | string | `github username` |
**role** | optional | Role of the user (Default: Push) | string | |
**override** | optional | Override existing role of collaborator | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.override | boolean | | True False |
action_result.parameter.repo_name | string | `github repo` | testrepo |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | Splunk |
action_result.parameter.role | string | | Pull Push Admin |
action_result.parameter.user | string | `github username` | test |
action_result.data.\*.collaborator_added | boolean | | True False |
action_result.data.\*.created_at | string | | 2018-07-25T12:47:00Z |
action_result.data.\*.html_url | string | `url` | https://github.com/test/test-repo/invitations |
action_result.data.\*.id | numeric | | 10200401 |
action_result.data.\*.invite_sent | boolean | | True False |
action_result.data.\*.invitee.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/29930053?v=4 |
action_result.data.\*.invitee.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.invitee.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.invitee.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.invitee.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.invitee.gravatar_id | string | | |
action_result.data.\*.invitee.html_url | string | `url` | https://github.com/test |
action_result.data.\*.invitee.id | numeric | | 29900753 |
action_result.data.\*.invitee.login | string | `github username` | test |
action_result.data.\*.invitee.node_id | string | | MDQ6VXlNcjI5OTM5NzUz |
action_result.data.\*.invitee.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.invitee.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.invitee.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.invitee.site_admin | boolean | | True False |
action_result.data.\*.invitee.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.invitee.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.invitee.type | string | | User |
action_result.data.\*.invitee.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.inviter.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/41300385?v=4 |
action_result.data.\*.inviter.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.inviter.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.inviter.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.inviter.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.inviter.gravatar_id | string | | |
action_result.data.\*.inviter.html_url | string | `url` | https://github.com/test |
action_result.data.\*.inviter.id | numeric | | 41300385 |
action_result.data.\*.inviter.login | string | `github username` | test |
action_result.data.\*.inviter.node_id | string | | MDQ6VXlNcjQxMzMxMzg1 |
action_result.data.\*.inviter.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.inviter.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.inviter.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.inviter.site_admin | boolean | | True False |
action_result.data.\*.inviter.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.inviter.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.inviter.type | string | | User |
action_result.data.\*.inviter.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.node_id | string | | MDIwOlJlGc9zaXRvcnlJbnZpdGF0aW9uMTAyNDU0MDE= |
action_result.data.\*.permissions | string | | admin |
action_result.data.\*.url | string | `url` | https://api.github.com/user/repository_invitations/10245401 |
action_result.summary | string | | |
action_result.message | string | | User test added successfully as a collaborator to repo test-organization/test-repo |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'remove member'

Remove user from the team

Type: **generic** \
Read only: **False**

Parameter 'organization name' is mandatory if the team name is provided instead of team ID.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**team** | required | Team name or team ID | string | `github team name` `github team id` |
**user** | required | Username | string | `github username` |
**organization_name** | optional | Organization name | string | `github organization name` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.organization_name | string | `github organization name` | test |
action_result.parameter.team | string | `github team name` `github team id` | 2800753 test team |
action_result.parameter.user | string | `github username` | test |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | Member with username test successfully removed from Team 2800753 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 0 1 |

## action: 'add member'

Add user in a team

Type: **generic** \
Read only: **False**

Parameter 'organization name' is mandatory if the team name is provided instead of team ID.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**team** | required | Team name or team ID | string | `github team name` `github team id` |
**user** | required | Username | string | `github username` |
**role** | optional | Role of the user (Default: Member) | string | |
**organization_name** | optional | Organization name | string | `github organization name` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.organization_name | string | `github organization name` | test-org |
action_result.parameter.role | string | | Member Maintainer |
action_result.parameter.team | string | `github team name` `github team id` | new test team 2830072 |
action_result.parameter.user | string | `github username` | test |
action_result.data.\*.role | string | | member maintainer |
action_result.data.\*.state | string | | active pending |
action_result.data.\*.url | string | `url` | https://api.github.com/teams/2830072/memberships/test |
action_result.summary | string | | |
action_result.message | string | | Member with username test123456 successfully added in Team 2800260 with role of maintainer |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list teams'

List all teams of an organization

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**organization_name** | required | Organization name | string | `github organization name` |
**limit** | optional | Maximum number of teams to be fetched | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.limit | numeric | | |
action_result.parameter.organization_name | string | `github organization name` | test |
action_result.data.\*.description | string | | New team |
action_result.data.\*.id | numeric | `github team id` | 2825460 |
action_result.data.\*.members_url | string | `url` | https://api.github.com/teams/2825460/members{/member} |
action_result.data.\*.name | string | `github team name` | new team |
action_result.data.\*.node_id | string | | MDQ6VGVhbTI4JmcyNjA= |
action_result.data.\*.permission | string | | pull |
action_result.data.\*.privacy | string | | closed |
action_result.data.\*.repositories_url | string | `url` | https://api.github.com/teams/2825460/repos |
action_result.data.\*.slug | string | | new-team |
action_result.data.\*.url | string | `url` | https://api.github.com/teams/2825460 |
action_result.summary.total_teams | numeric | | 3 |
action_result.message | string | | Total teams: 3 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list repos'

List all repos of an organization

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**organization_name** | required | Organization name | string | `github organization name` |
**limit** | optional | Maximum number of repositories to be fetched | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.limit | numeric | | |
action_result.parameter.organization_name | string | `github organization name` | test |
action_result.data.\*.archive_url | string | `url` | https://api.github.com/repos/test/test-repo/{archive_format}{/ref} |
action_result.data.\*.archived | boolean | | True False |
action_result.data.\*.assignees_url | string | `url` | https://api.github.com/repos/test/test-repo/assignees{/user} |
action_result.data.\*.blobs_url | string | `url` | https://api.github.com/repos/test/test-repo/git/blobs{/sha} |
action_result.data.\*.branches_url | string | `url` | https://api.github.com/repos/test/test-repo/branches{/branch} |
action_result.data.\*.clone_url | string | `url` | https://github.com/test/test-repo.git |
action_result.data.\*.collaborators_url | string | `url` | https://api.github.com/repos/test/test-repo/collaborators{/collaborator} |
action_result.data.\*.comments_url | string | `url` | https://api.github.com/repos/test/test-repo/comments{/number} |
action_result.data.\*.commits_url | string | `url` | https://api.github.com/repos/test/test-repo/commits{/sha} |
action_result.data.\*.compare_url | string | `url` | https://api.github.com/repos/test/test-repo/compare/{base}...{head} |
action_result.data.\*.contents_url | string | `url` | https://api.github.com/repos/test/test-repo/contents/{+path} |
action_result.data.\*.contributors_url | string | `url` | https://api.github.com/repos/test/test-repo/contributors |
action_result.data.\*.created_at | string | | 2018-07-16T23:05:00Z |
action_result.data.\*.default_branch | string | | master |
action_result.data.\*.deployments_url | string | `url` | https://api.github.com/repos/test/test-repo/deployments |
action_result.data.\*.description | string | | Test Repo 1 |
action_result.data.\*.downloads_url | string | `url` | https://api.github.com/repos/test/test-repo/downloads |
action_result.data.\*.events_url | string | `url` | https://api.github.com/repos/test/test-repo/events |
action_result.data.\*.fork | boolean | | True False |
action_result.data.\*.forks | numeric | | 0 |
action_result.data.\*.forks_count | numeric | | 0 |
action_result.data.\*.forks_url | string | `url` | https://api.github.com/repos/test/test-repo/forks |
action_result.data.\*.full_name | string | | test/test-repo |
action_result.data.\*.git_commits_url | string | `url` | https://api.github.com/repos/test/test-repo/git/commits{/sha} |
action_result.data.\*.git_refs_url | string | `url` | https://api.github.com/repos/test/test-repo/git/refs{/sha} |
action_result.data.\*.git_tags_url | string | `url` | https://api.github.com/repos/test/test-repo/git/tags{/sha} |
action_result.data.\*.git_url | string | | git://github.com/test/test-repo.git |
action_result.data.\*.has_downloads | boolean | | True False |
action_result.data.\*.has_issues | boolean | | True False |
action_result.data.\*.has_pages | boolean | | True False |
action_result.data.\*.has_projects | boolean | | True False |
action_result.data.\*.has_wiki | boolean | | True False |
action_result.data.\*.homepage | string | `url` | |
action_result.data.\*.hooks_url | string | `url` | https://api.github.com/repos/test/test-repo/hooks |
action_result.data.\*.html_url | string | `url` | https://github.com/test/test-repo |
action_result.data.\*.id | numeric | | 141304012 |
action_result.data.\*.issue_comment_url | string | `url` | https://api.github.com/repos/test/test-repo/issues/comments{/number} |
action_result.data.\*.issue_events_url | string | `url` | https://api.github.com/repos/test/test-repo/issues/events{/number} |
action_result.data.\*.issues_url | string | `url` | https://api.github.com/repos/test/test-repo/issues{/number} |
action_result.data.\*.keys_url | string | `url` | https://api.github.com/repos/test/test-repo/keys{/key_id} |
action_result.data.\*.labels_url | string | `url` | https://api.github.com/repos/test/test-repo/labels{/name} |
action_result.data.\*.language | string | | |
action_result.data.\*.languages_url | string | `url` | https://api.github.com/repos/test/test-repo/languages |
action_result.data.\*.license.key | string | | apache-2.0 |
action_result.data.\*.license.name | string | | Apache License 2.0 |
action_result.data.\*.license.node_id | string | | MDc6TGljZW5zZIT= |
action_result.data.\*.license.spdx_id | string | | Apache-2.0 |
action_result.data.\*.license.url | string | `url` | https://api.github.com/licenses/apache-2.0 |
action_result.data.\*.merges_url | string | `url` | https://api.github.com/repos/test/test-repo/merges |
action_result.data.\*.milestones_url | string | `url` | https://api.github.com/repos/test/test-repo/milestones{/number} |
action_result.data.\*.mirror_url | string | `url` | |
action_result.data.\*.name | string | | test-repo |
action_result.data.\*.node_id | string | | MDEwOlJlcG9zaXRvnckxNDEyMDQwMDA= |
action_result.data.\*.notifications_url | string | `url` | https://api.github.com/repos/test/test-repo/notifications{?since,all,participating} |
action_result.data.\*.open_issues | numeric | | 0 |
action_result.data.\*.open_issues_count | numeric | | 0 |
action_result.data.\*.owner.avatar_url | string | `url` | https://avatars0.githubusercontent.com/u/41409665?v=4 |
action_result.data.\*.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.owner.gravatar_id | string | | |
action_result.data.\*.owner.html_url | string | `url` | https://github.com/test |
action_result.data.\*.owner.id | numeric | | 41309165 |
action_result.data.\*.owner.login | string | `github username` | test |
action_result.data.\*.owner.node_id | string | | MDEyOk9yZ2FuaX1hdGl1bjQxMzA5NjY1 |
action_result.data.\*.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.owner.site_admin | boolean | | True False |
action_result.data.\*.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.owner.type | string | | Organization |
action_result.data.\*.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.permissions.admin | boolean | | True False |
action_result.data.\*.permissions.pull | boolean | | True False |
action_result.data.\*.permissions.push | boolean | | True False |
action_result.data.\*.private | boolean | | True False |
action_result.data.\*.pulls_url | string | `url` | https://api.github.com/repos/test/test-repo/pulls{/number} |
action_result.data.\*.pushed_at | string | | 2018-07-16T23:03:58Z |
action_result.data.\*.releases_url | string | `url` | https://api.github.com/repos/test/test-repo/releases{/id} |
action_result.data.\*.size | numeric | | 0 |
action_result.data.\*.ssh_url | string | | git@github.com:test/test-repo.git |
action_result.data.\*.stargazers_count | numeric | | 0 |
action_result.data.\*.stargazers_url | string | `url` | https://api.github.com/repos/test/test-repo/stargazers |
action_result.data.\*.statuses_url | string | `url` | https://api.github.com/repos/test/test-repo/statuses/{sha} |
action_result.data.\*.subscribers_url | string | `url` | https://api.github.com/repos/test/test-repo/subscribers |
action_result.data.\*.subscription_url | string | `url` | https://api.github.com/repos/test/test-repo/subscription |
action_result.data.\*.svn_url | string | `url` | https://github.com/test/test-repo |
action_result.data.\*.tags_url | string | `url` | https://api.github.com/repos/test/test-repo/tags |
action_result.data.\*.teams_url | string | `url` | https://api.github.com/repos/test/test-repo/teams |
action_result.data.\*.trees_url | string | `url` | https://api.github.com/repos/test/test-repo/git/trees{/sha} |
action_result.data.\*.updated_at | string | | 2018-07-16T23:03:00Z |
action_result.data.\*.url | string | `url` | https://api.github.com/repos/test/test-repo |
action_result.data.\*.watchers | numeric | | 0 |
action_result.data.\*.watchers_count | numeric | | 0 |
action_result.summary.total_repos | numeric | | 3 |
action_result.message | string | | Total repos: 3 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list organizations'

List all organizations

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum number of organizations to be fetched | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.limit | numeric | | |
action_result.data.\*.avatar_url | string | `url` | https://avatars0.githubusercontent.com/u/41301665?v=4 |
action_result.data.\*.description | string | | |
action_result.data.\*.events_url | string | `url` | https://api.github.com/orgs/test/events |
action_result.data.\*.hooks_url | string | `url` | https://api.github.com/orgs/test/hooks |
action_result.data.\*.id | numeric | | 41301665 |
action_result.data.\*.issues_url | string | `url` | https://api.github.com/orgs/test/issues |
action_result.data.\*.login | string | `github organization name` | test |
action_result.data.\*.members_url | string | `url` | https://api.github.com/orgs/test/members{/member} |
action_result.data.\*.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjQxMzA5NjY1 |
action_result.data.\*.public_members_url | string | `url` | https://api.github.com/orgs/test/public_members{/member} |
action_result.data.\*.repos_url | string | `url` | https://api.github.com/orgs/test/repos |
action_result.data.\*.url | string | `url` | https://api.github.com/orgs/test |
action_result.summary.total_organizations | numeric | | 2 |
action_result.message | string | | Total organizations: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list issues'

Get a list of issues for the GitHub repository

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**repo_owner** | required | Owner of the repository | string | `github repo owner` `github username` |
**repo_name** | required | Name of the repository | string | `github repo` |
**limit** | optional | Maximum number of issues to be fetched | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.limit | numeric | | |
action_result.parameter.repo_name | string | `github repo` | testrepo |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | Splunk |
action_result.data.\*.assignee.avatar_url | string | `url` | https://avatars0.githubusercontent.com/u/id |
action_result.data.\*.assignee.events_url | string | `url` | https://api.github.com/users/username/events{/privacy} |
action_result.data.\*.assignee.followers_url | string | `url` | https://api.github.com/users/username/followers |
action_result.data.\*.assignee.following_url | string | `url` | https://api.github.com/users/username/following{/other_user} |
action_result.data.\*.assignee.gists_url | string | `url` | https://api.github.com/users/username/gists{/gist_id} |
action_result.data.\*.assignee.gravatar_id | string | | |
action_result.data.\*.assignee.html_url | string | `url` | https://github.com/username |
action_result.data.\*.assignee.id | numeric | | 7614131 |
action_result.data.\*.assignee.login | string | `github username` | testusername |
action_result.data.\*.assignee.node_id | string | | LAKSJDOIWsase= |
action_result.data.\*.assignee.organizations_url | string | `url` | https://api.github.com/users/username/orgs |
action_result.data.\*.assignee.received_events_url | string | `url` | https://api.github.com/users/username/received_events |
action_result.data.\*.assignee.repos_url | string | `url` | https://api.github.com/users/username/repos |
action_result.data.\*.assignee.site_admin | boolean | | True False |
action_result.data.\*.assignee.starred_url | string | `url` | https://api.github.com/users/username/starred{/owner}{/repo} |
action_result.data.\*.assignee.subscriptions_url | string | `url` | https://api.github.com/users/username/subscriptions |
action_result.data.\*.assignee.type | string | | User |
action_result.data.\*.assignee.url | string | `url` | https://api.github.com/users/username |
action_result.data.\*.assignees.\*.avatar_url | string | `url` | https://avatars0.githubusercontent.com/u/7614131?v=4 |
action_result.data.\*.assignees.\*.events_url | string | `url` | https://api.github.com/users/username/events{/privacy} |
action_result.data.\*.assignees.\*.followers_url | string | `url` | https://api.github.com/users/username/followers |
action_result.data.\*.assignees.\*.following_url | string | `url` | https://api.github.com/users/username/following{/other_user} |
action_result.data.\*.assignees.\*.gists_url | string | `url` | https://api.github.com/users/username/gists{/gist_id} |
action_result.data.\*.assignees.\*.gravatar_id | string | | |
action_result.data.\*.assignees.\*.html_url | string | `url` | https://github.com/username |
action_result.data.\*.assignees.\*.id | numeric | | 7614131 |
action_result.data.\*.assignees.\*.login | string | `github username` | username |
action_result.data.\*.assignees.\*.node_id | string | | LAKSJDOIWsase= |
action_result.data.\*.assignees.\*.organizations_url | string | `url` | https://api.github.com/users/username/orgs |
action_result.data.\*.assignees.\*.received_events_url | string | `url` | https://api.github.com/users/username/received_events |
action_result.data.\*.assignees.\*.repos_url | string | `url` | https://api.github.com/users/username/repos |
action_result.data.\*.assignees.\*.site_admin | boolean | | True False |
action_result.data.\*.assignees.\*.starred_url | string | `url` | https://api.github.com/users/username/starred{/owner}{/repo} |
action_result.data.\*.assignees.\*.subscriptions_url | string | `url` | https://api.github.com/users/username/subscriptions |
action_result.data.\*.assignees.\*.type | string | | User |
action_result.data.\*.assignees.\*.url | string | `url` | https://api.github.com/users/username |
action_result.data.\*.author_association | string | | COLLABORATOR |
action_result.data.\*.body | string | | Test issue body right here |
action_result.data.\*.closed_at | string | | |
action_result.data.\*.comments | numeric | | 0 |
action_result.data.\*.comments_url | string | `url` | https://api.github.com/repos/username/testrepo/issues/4/comments |
action_result.data.\*.created_at | string | | 2018-04-23T01:15:25Z |
action_result.data.\*.events_url | string | `url` | https://api.github.com/repos/username/testrepo/issues/4/events |
action_result.data.\*.html_url | string | `url` | https://github.com/username/testrepo/issues/4 |
action_result.data.\*.id | numeric | | 316631564 |
action_result.data.\*.labels.\*.color | string | | a2eeef |
action_result.data.\*.labels.\*.default | boolean | | True False |
action_result.data.\*.labels.\*.id | numeric | | 864962287 |
action_result.data.\*.labels.\*.name | string | | enhancement |
action_result.data.\*.labels.\*.node_id | string | | LAKSJDOIWsase= |
action_result.data.\*.labels.\*.url | string | `url` | https://api.github.com/repos/owner/repo/labels/enhancement |
action_result.data.\*.labels_url | string | `url` | https://api.github.com/repos/username/testrepo/issues/4/labels{/name} |
action_result.data.\*.locked | boolean | | True False |
action_result.data.\*.milestone | string | | |
action_result.data.\*.node_id | string | | LAKSJDOIWsase= |
action_result.data.\*.number | numeric | `github issue id` | 4 |
action_result.data.\*.repository_url | string | `url` | https://api.github.com/repos/username/testrepo |
action_result.data.\*.state | string | | open |
action_result.data.\*.title | string | | Test issue title here |
action_result.data.\*.updated_at | string | | 2018-04-23T01:15:25Z |
action_result.data.\*.url | string | `url` | https://api.github.com/repos/username/testrepo/issues/4 |
action_result.data.\*.user.avatar_url | string | `url` | https://avatars0.githubusercontent.com/u/avatarid |
action_result.data.\*.user.events_url | string | `url` | https://api.github.com/users/username/events{/privacy} |
action_result.data.\*.user.followers_url | string | `url` | https://api.github.com/users/username/followers |
action_result.data.\*.user.following_url | string | `url` | https://api.github.com/users/username/following{/other_user} |
action_result.data.\*.user.gists_url | string | `url` | https://api.github.com/users/username/gists{/gist_id} |
action_result.data.\*.user.gravatar_id | string | | |
action_result.data.\*.user.html_url | string | `url` | https://github.com/username |
action_result.data.\*.user.id | numeric | | 99999 |
action_result.data.\*.user.login | string | `github username` | username |
action_result.data.\*.user.node_id | string | | LAKSJDOIWsase= |
action_result.data.\*.user.organizations_url | string | `url` | https://api.github.com/users/username/orgs |
action_result.data.\*.user.received_events_url | string | `url` | https://api.github.com/users/username/received_events |
action_result.data.\*.user.repos_url | string | `url` | https://api.github.com/users/username/repos |
action_result.data.\*.user.site_admin | boolean | | True False |
action_result.data.\*.user.starred_url | string | `url` | https://api.github.com/users/username/starred{/owner}{/repo} |
action_result.data.\*.user.subscriptions_url | string | `url` | https://api.github.com/users/username/subscriptions |
action_result.data.\*.user.type | string | | User |
action_result.data.\*.user.url | string | `url` | https://api.github.com/users/username |
action_result.summary.total_issues | numeric | | 2 |
action_result.message | string | | Total issues: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list comments'

List comments for an issue on the GitHub repository

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**repo_owner** | required | Owner of the repository | string | `github repo owner` `github username` |
**repo_name** | required | Name of the repository | string | `github repo` |
**issue_number** | required | Issue ID | numeric | `github issue id` |
**limit** | optional | Maximum number of comments to be fetched | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.issue_number | numeric | `github issue id` | 1 |
action_result.parameter.limit | numeric | | |
action_result.parameter.repo_name | string | `github repo` | TestingAPI |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | repoowner |
action_result.data.\*.author_association | string | | OWNER |
action_result.data.\*.body | string | | I am writing a comment to this issue |
action_result.data.\*.created_at | string | | 2019-07-16T19:52:27Z |
action_result.data.\*.html_url | string | `url` | https://github.com/repoowner/TestingAPI/issues/1#issuecomment-511961016 |
action_result.data.\*.id | numeric | | 511961016 |
action_result.data.\*.issue_url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/issues/1 |
action_result.data.\*.node_id | string | | MDEyOklzc3VlQ29tbWVudDUxMTk2MTAxNg== |
action_result.data.\*.updated_at | string | | 2019-07-16T19:52:27Z |
action_result.data.\*.url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/issues/comments/511961016 |
action_result.data.\*.user.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/52245234 |
action_result.data.\*.user.events_url | string | `url` | https://api.github.com/users/repoowner/events{/privacy} |
action_result.data.\*.user.followers_url | string | `url` | https://api.github.com/users/repoowner/followers |
action_result.data.\*.user.following_url | string | `url` | https://api.github.com/users/repoowner/following{/other_user} |
action_result.data.\*.user.gists_url | string | `url` | https://api.github.com/users/repoowner/gists{/gist_id} |
action_result.data.\*.user.gravatar_id | string | | |
action_result.data.\*.user.html_url | string | `url` | https://github.com/repoowner |
action_result.data.\*.user.id | numeric | | 99999999 |
action_result.data.\*.user.login | string | `github username` | repoowner |
action_result.data.\*.user.node_id | string | | MDQ6VXNlcjExODkwNzA5 |
action_result.data.\*.user.organizations_url | string | `url` | https://api.github.com/users/repoowner/orgs |
action_result.data.\*.user.received_events_url | string | `url` | https://api.github.com/users/repoowner/received_events |
action_result.data.\*.user.repos_url | string | `url` | https://api.github.com/users/repoowner/repos |
action_result.data.\*.user.site_admin | boolean | | True False |
action_result.data.\*.user.starred_url | string | `url` | https://api.github.com/users/repoowner/starred{/owner}{/repo} |
action_result.data.\*.user.subscriptions_url | string | `url` | https://api.github.com/users/repoowner/subscriptions |
action_result.data.\*.user.type | string | | User |
action_result.data.\*.user.url | string | `url` | https://api.github.com/users/repoowner |
action_result.summary.total_comments | numeric | | 1 |
action_result.message | string | | Total comments: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get issue'

Retrieve an issue for the GitHub repository

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**repo_owner** | required | Owner of the repository | string | `github repo owner` `github username` |
**repo_name** | required | Name of the repository | string | `github repo` |
**issue_number** | required | Issue ID | numeric | `github issue id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.issue_number | numeric | `github issue id` | 1 |
action_result.parameter.repo_name | string | `github repo` | TestingAPI |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | repoowner |
action_result.data.\*.assignee.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/11890709?v=4 |
action_result.data.\*.assignee.events_url | string | `url` | https://api.github.com/users/repoowner/events{/privacy} |
action_result.data.\*.assignee.followers_url | string | `url` | https://api.github.com/users/repoowner/followers |
action_result.data.\*.assignee.following_url | string | `url` | https://api.github.com/users/repoowner/following{/other_user} |
action_result.data.\*.assignee.gists_url | string | `url` | https://api.github.com/users/repoowner/gists{/gist_id} |
action_result.data.\*.assignee.gravatar_id | string | | |
action_result.data.\*.assignee.html_url | string | `url` | https://github.com/repoowner |
action_result.data.\*.assignee.id | numeric | | 11890709 |
action_result.data.\*.assignee.login | string | `github username` | repoowner |
action_result.data.\*.assignee.node_id | string | | MDQ6VXNlcjExODkwNzA5 |
action_result.data.\*.assignee.organizations_url | string | `url` | https://api.github.com/users/repoowner/orgs |
action_result.data.\*.assignee.received_events_url | string | `url` | https://api.github.com/users/repoowner/received_events |
action_result.data.\*.assignee.repos_url | string | `url` | https://api.github.com/users/repoowner/repos |
action_result.data.\*.assignee.site_admin | boolean | | True False |
action_result.data.\*.assignee.starred_url | string | `url` | https://api.github.com/users/repoowner/starred{/owner}{/repo} |
action_result.data.\*.assignee.subscriptions_url | string | `url` | https://api.github.com/users/repoowner/subscriptions |
action_result.data.\*.assignee.type | string | | User |
action_result.data.\*.assignee.url | string | `url` | https://api.github.com/users/repoowner |
action_result.data.\*.assignees.\*.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/11890709?v=4 |
action_result.data.\*.assignees.\*.events_url | string | `url` | https://api.github.com/users/repoowner/events{/privacy} |
action_result.data.\*.assignees.\*.followers_url | string | `url` | https://api.github.com/users/repoowner/followers |
action_result.data.\*.assignees.\*.following_url | string | `url` | https://api.github.com/users/repoowner/following{/other_user} |
action_result.data.\*.assignees.\*.gists_url | string | `url` | https://api.github.com/users/repoowner/gists{/gist_id} |
action_result.data.\*.assignees.\*.gravatar_id | string | | |
action_result.data.\*.assignees.\*.html_url | string | `url` | https://github.com/repoowner |
action_result.data.\*.assignees.\*.id | numeric | | 11890709 |
action_result.data.\*.assignees.\*.login | string | `github username` | repoowner |
action_result.data.\*.assignees.\*.node_id | string | | MDQ6VXNlcjExODkwNzA5 |
action_result.data.\*.assignees.\*.organizations_url | string | `url` | https://api.github.com/users/repoowner/orgs |
action_result.data.\*.assignees.\*.received_events_url | string | `url` | https://api.github.com/users/repoowner/received_events |
action_result.data.\*.assignees.\*.repos_url | string | `url` | https://api.github.com/users/repoowner/repos |
action_result.data.\*.assignees.\*.site_admin | boolean | | True False |
action_result.data.\*.assignees.\*.starred_url | string | `url` | https://api.github.com/users/repoowner/starred{/owner}{/repo} |
action_result.data.\*.assignees.\*.subscriptions_url | string | `url` | https://api.github.com/users/repoowner/subscriptions |
action_result.data.\*.assignees.\*.type | string | | User |
action_result.data.\*.assignees.\*.url | string | `url` | https://api.github.com/users/repoowner |
action_result.data.\*.author_association | string | | OWNER |
action_result.data.\*.body | string | | This is the body I believe of the issue |
action_result.data.\*.closed_at | string | | |
action_result.data.\*.closed_by | string | | |
action_result.data.\*.comments | numeric | | 1 |
action_result.data.\*.comments_url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/issues/1/comments |
action_result.data.\*.created_at | string | | 2019-07-16T19:52:15Z |
action_result.data.\*.events_url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/issues/1/events |
action_result.data.\*.html_url | string | `url` | https://github.com/repoowner/TestingAPI/issues/1 |
action_result.data.\*.id | numeric | | 468834090 |
action_result.data.\*.labels_url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/issues/1/labels{/name} |
action_result.data.\*.locked | boolean | | True False |
action_result.data.\*.milestone | string | | |
action_result.data.\*.node_id | string | | MDU6SXNzdWU0Njg4MzQwOTA= |
action_result.data.\*.number | numeric | `github issue id` | 1 |
action_result.data.\*.repository_url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI |
action_result.data.\*.state | string | | open |
action_result.data.\*.title | string | | This is a Test Issue |
action_result.data.\*.updated_at | string | | 2019-07-16T20:00:23Z |
action_result.data.\*.url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/issues/1 |
action_result.data.\*.user.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/11890709?v=4 |
action_result.data.\*.user.events_url | string | `url` | https://api.github.com/users/repoowner/events{/privacy} |
action_result.data.\*.user.followers_url | string | `url` | https://api.github.com/users/repoowner/followers |
action_result.data.\*.user.following_url | string | `url` | https://api.github.com/users/repoowner/following{/other_user} |
action_result.data.\*.user.gists_url | string | `url` | https://api.github.com/users/repoowner/gists{/gist_id} |
action_result.data.\*.user.gravatar_id | string | | |
action_result.data.\*.user.html_url | string | `url` | https://github.com/repoowner |
action_result.data.\*.user.id | numeric | | 11890709 |
action_result.data.\*.user.login | string | `github username` | repoowner |
action_result.data.\*.user.node_id | string | | MDQ6VXNlcjExODkwNzA5 |
action_result.data.\*.user.organizations_url | string | `url` | https://api.github.com/users/repoowner/orgs |
action_result.data.\*.user.received_events_url | string | `url` | https://api.github.com/users/repoowner/received_events |
action_result.data.\*.user.repos_url | string | `url` | https://api.github.com/users/repoowner/repos |
action_result.data.\*.user.site_admin | boolean | | True False |
action_result.data.\*.user.starred_url | string | `url` | https://api.github.com/users/repoowner/starred{/owner}{/repo} |
action_result.data.\*.user.subscriptions_url | string | `url` | https://api.github.com/users/repoowner/subscriptions |
action_result.data.\*.user.type | string | | User |
action_result.data.\*.user.url | string | `url` | https://api.github.com/users/repoowner |
action_result.summary.issue_number | numeric | | 2 |
action_result.summary.issue_url | string | `url` | https://github.com/repoowner/TestingAPI/issues/2 |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create issue'

Create an issue for the GitHub repository

Type: **generic** \
Read only: **False**

Only users with push access can set assignees/labels for the issues.
Assignees/labels are silently dropped otherwise.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**repo_owner** | required | Owner of the repository | string | `github repo owner` `github username` |
**repo_name** | required | Name of the repository | string | `github repo` |
**issue_title** | required | Title of the issue | string | |
**issue_body** | optional | Contents of the issue | string | |
**assignees** | optional | Comma-separated list of logins (usernames) for the users to assign to this issue | string | `github username` |
**labels** | optional | Comma-separated list of labels to associate with this issue | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.assignees | string | `github username` | repoowner |
action_result.parameter.issue_body | string | | This is what the body looks like when testing from the app |
action_result.parameter.issue_title | string | | I am testing from the app |
action_result.parameter.labels | string | | test,multi-label,non-urgent |
action_result.parameter.repo_name | string | `github repo` | TestingAPI |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | repoowner |
action_result.data.\*.assignee.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/11890709?v=4 |
action_result.data.\*.assignee.events_url | string | `url` | https://api.github.com/users/repoowner/events{/privacy} |
action_result.data.\*.assignee.followers_url | string | `url` | https://api.github.com/users/repoowner/followers |
action_result.data.\*.assignee.following_url | string | `url` | https://api.github.com/users/repoowner/following{/other_user} |
action_result.data.\*.assignee.gists_url | string | `url` | https://api.github.com/users/repoowner/gists{/gist_id} |
action_result.data.\*.assignee.gravatar_id | string | | |
action_result.data.\*.assignee.html_url | string | `url` | https://github.com/repoowner |
action_result.data.\*.assignee.id | numeric | | 11890709 |
action_result.data.\*.assignee.login | string | `github username` | repoowner |
action_result.data.\*.assignee.node_id | string | | MDQ6VXNlcjExODkwNzA5 |
action_result.data.\*.assignee.organizations_url | string | `url` | https://api.github.com/users/repoowner/orgs |
action_result.data.\*.assignee.received_events_url | string | `url` | https://api.github.com/users/repoowner/received_events |
action_result.data.\*.assignee.repos_url | string | `url` | https://api.github.com/users/repoowner/repos |
action_result.data.\*.assignee.site_admin | boolean | | True False |
action_result.data.\*.assignee.starred_url | string | `url` | https://api.github.com/users/repoowner/starred{/owner}{/repo} |
action_result.data.\*.assignee.subscriptions_url | string | `url` | https://api.github.com/users/repoowner/subscriptions |
action_result.data.\*.assignee.type | string | | User |
action_result.data.\*.assignee.url | string | `url` | https://api.github.com/users/repoowner |
action_result.data.\*.assignees.\*.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/11890709?v=4 |
action_result.data.\*.assignees.\*.events_url | string | `url` | https://api.github.com/users/repoowner/events{/privacy} |
action_result.data.\*.assignees.\*.followers_url | string | `url` | https://api.github.com/users/repoowner/followers |
action_result.data.\*.assignees.\*.following_url | string | `url` | https://api.github.com/users/repoowner/following{/other_user} |
action_result.data.\*.assignees.\*.gists_url | string | `url` | https://api.github.com/users/repoowner/gists{/gist_id} |
action_result.data.\*.assignees.\*.gravatar_id | string | | |
action_result.data.\*.assignees.\*.html_url | string | `url` | https://github.com/repoowner |
action_result.data.\*.assignees.\*.id | numeric | | 11890709 |
action_result.data.\*.assignees.\*.login | string | `github username` | repoowner |
action_result.data.\*.assignees.\*.node_id | string | | MDQ6VXNlcjExODkwNzA5 |
action_result.data.\*.assignees.\*.organizations_url | string | `url` | https://api.github.com/users/repoowner/orgs |
action_result.data.\*.assignees.\*.received_events_url | string | `url` | https://api.github.com/users/repoowner/received_events |
action_result.data.\*.assignees.\*.repos_url | string | `url` | https://api.github.com/users/repoowner/repos |
action_result.data.\*.assignees.\*.site_admin | boolean | | True False |
action_result.data.\*.assignees.\*.starred_url | string | `url` | https://api.github.com/users/repoowner/starred{/owner}{/repo} |
action_result.data.\*.assignees.\*.subscriptions_url | string | `url` | https://api.github.com/users/repoowner/subscriptions |
action_result.data.\*.assignees.\*.type | string | | User |
action_result.data.\*.assignees.\*.url | string | `url` | https://api.github.com/users/repoowner |
action_result.data.\*.author_association | string | | OWNER |
action_result.data.\*.body | string | | This is what the body looks like when testing from the app |
action_result.data.\*.closed_at | string | | |
action_result.data.\*.closed_by | string | | |
action_result.data.\*.comments | numeric | | 0 |
action_result.data.\*.comments_url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/issues/2/comments |
action_result.data.\*.created_at | string | | 2019-07-16T20:07:26Z |
action_result.data.\*.events_url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/issues/2/events |
action_result.data.\*.html_url | string | `url` | https://github.com/repoowner/TestingAPI/issues/2 |
action_result.data.\*.id | numeric | | 468840014 |
action_result.data.\*.labels.\*.color | string | | ededed |
action_result.data.\*.labels.\*.default | boolean | | True False |
action_result.data.\*.labels.\*.id | numeric | | 1454469929 |
action_result.data.\*.labels.\*.name | string | | test |
action_result.data.\*.labels.\*.node_id | string | | MDU6TGFiZWwxNDU0NDY5OTI5 |
action_result.data.\*.labels.\*.url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/labels/test |
action_result.data.\*.labels_url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/issues/2/labels{/name} |
action_result.data.\*.locked | boolean | | True False |
action_result.data.\*.milestone | string | | |
action_result.data.\*.node_id | string | | MDU6SXNzdWU0Njg4NDAwMTQ= |
action_result.data.\*.number | numeric | `github issue id` | 2 |
action_result.data.\*.repository_url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI |
action_result.data.\*.state | string | | open |
action_result.data.\*.title | string | | I am testing from the app |
action_result.data.\*.updated_at | string | | 2019-07-16T20:07:27Z |
action_result.data.\*.url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/issues/2 |
action_result.data.\*.user.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/11890709?v=4 |
action_result.data.\*.user.events_url | string | `url` | https://api.github.com/users/repoowner/events{/privacy} |
action_result.data.\*.user.followers_url | string | `url` | https://api.github.com/users/repoowner/followers |
action_result.data.\*.user.following_url | string | `url` | https://api.github.com/users/repoowner/following{/other_user} |
action_result.data.\*.user.gists_url | string | `url` | https://api.github.com/users/repoowner/gists{/gist_id} |
action_result.data.\*.user.gravatar_id | string | | |
action_result.data.\*.user.html_url | string | `url` | https://github.com/repoowner |
action_result.data.\*.user.id | numeric | | 11890709 |
action_result.data.\*.user.login | string | `github username` | repoowner |
action_result.data.\*.user.node_id | string | | MDQ6VXNlcjExODkwNzA5 |
action_result.data.\*.user.organizations_url | string | `url` | https://api.github.com/users/repoowner/orgs |
action_result.data.\*.user.received_events_url | string | `url` | https://api.github.com/users/repoowner/received_events |
action_result.data.\*.user.repos_url | string | `url` | https://api.github.com/users/repoowner/repos |
action_result.data.\*.user.site_admin | boolean | | True False |
action_result.data.\*.user.starred_url | string | `url` | https://api.github.com/users/repoowner/starred{/owner}{/repo} |
action_result.data.\*.user.subscriptions_url | string | `url` | https://api.github.com/users/repoowner/subscriptions |
action_result.data.\*.user.type | string | | User |
action_result.data.\*.user.url | string | `url` | https://api.github.com/users/repoowner |
action_result.summary.issue_number | numeric | | 2 |
action_result.summary.issue_url | string | `url` | https://github.com/repoowner/TestingAPI/issues/2 |
action_result.message | string | | Issue number: 2, Issue url: https://github.com/repoowner/TestingAPI/issues/2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update issue'

Update an issue for the GitHub repository

Type: **generic** \
Read only: **False**

Only users with push access can set assignees/labels for new issues.
Assignees/labels are silently dropped otherwise. The existing labels and assignees of the issue will be replaced with the labels and assignees provided in the respective input parameters by the user. If the to_empty parameter is checked, then, it will empty the field values of the issue (except for the title and the state of the issue) for which the parameter values are not provided or kept empty. If the to_empty parameter is not checked, then, it will simply ignore the empty parameter values from being updated on the issue.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**repo_owner** | required | Owner of the repository | string | `github repo owner` `github username` |
**repo_name** | required | Name of the repository | string | `github repo` |
**issue_number** | required | Issue ID | numeric | `github issue id` |
**state** | optional | State of the issue | string | |
**issue_title** | optional | Title of the issue | string | |
**issue_body** | optional | Contents of the issue | string | |
**assignees** | optional | Comma-separated list of logins (usernames) for the users to assign to this issue | string | `github username` |
**labels** | optional | Comma-separated list of labels to associate with this issue | string | |
**to_empty** | optional | Empty the field values of the issue for which the parameter values are not provided | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.assignees | string | `github username` | testbg11 |
action_result.parameter.issue_body | string | | test update body |
action_result.parameter.issue_number | numeric | `github issue id` | 1 |
action_result.parameter.issue_title | string | | update test title |
action_result.parameter.labels | string | | demo_update |
action_result.parameter.repo_name | string | `github repo` | Testing1 |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | testbg11 |
action_result.parameter.state | string | | closed |
action_result.parameter.to_empty | boolean | | True False |
action_result.data.\*.assignee.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/53362718?v=4 |
action_result.data.\*.assignee.events_url | string | `url` | https://api.github.com/users/testbg11/events{/privacy} |
action_result.data.\*.assignee.followers_url | string | `url` | https://api.github.com/users/testbg11/followers |
action_result.data.\*.assignee.following_url | string | `url` | https://api.github.com/users/testbg11/following{/other_user} |
action_result.data.\*.assignee.gists_url | string | `url` | https://api.github.com/users/testbg11/gists{/gist_id} |
action_result.data.\*.assignee.gravatar_id | string | | |
action_result.data.\*.assignee.html_url | string | `url` | https://github.com/testbg11 |
action_result.data.\*.assignee.id | numeric | | 53362718 |
action_result.data.\*.assignee.login | string | `github username` | testbg11 |
action_result.data.\*.assignee.node_id | string | | MDQ6VXNlcjUzMzYyNzE4 |
action_result.data.\*.assignee.organizations_url | string | `url` | https://api.github.com/users/testbg11/orgs |
action_result.data.\*.assignee.received_events_url | string | `url` | https://api.github.com/users/testbg11/received_events |
action_result.data.\*.assignee.repos_url | string | `url` | https://api.github.com/users/testbg11/repos |
action_result.data.\*.assignee.site_admin | boolean | | True False |
action_result.data.\*.assignee.starred_url | string | `url` | https://api.github.com/users/testbg11/starred{/owner}{/repo} |
action_result.data.\*.assignee.subscriptions_url | string | `url` | https://api.github.com/users/testbg11/subscriptions |
action_result.data.\*.assignee.type | string | | User |
action_result.data.\*.assignee.url | string | `url` | https://api.github.com/users/testbg11 |
action_result.data.\*.assignees.\*.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/53362718?v=4 |
action_result.data.\*.assignees.\*.events_url | string | `url` | https://api.github.com/users/testbg11/events{/privacy} |
action_result.data.\*.assignees.\*.followers_url | string | `url` | https://api.github.com/users/testbg11/followers |
action_result.data.\*.assignees.\*.following_url | string | `url` | https://api.github.com/users/testbg11/following{/other_user} |
action_result.data.\*.assignees.\*.gists_url | string | `url` | https://api.github.com/users/testbg11/gists{/gist_id} |
action_result.data.\*.assignees.\*.gravatar_id | string | | |
action_result.data.\*.assignees.\*.html_url | string | `url` | https://github.com/testbg11 |
action_result.data.\*.assignees.\*.id | numeric | | 53362718 |
action_result.data.\*.assignees.\*.login | string | `github username` | testbg11 |
action_result.data.\*.assignees.\*.node_id | string | | MDQ6VXNlcjUzMzYyNzE4 |
action_result.data.\*.assignees.\*.organizations_url | string | `url` | https://api.github.com/users/testbg11/orgs |
action_result.data.\*.assignees.\*.received_events_url | string | `url` | https://api.github.com/users/testbg11/received_events |
action_result.data.\*.assignees.\*.repos_url | string | `url` | https://api.github.com/users/testbg11/repos |
action_result.data.\*.assignees.\*.site_admin | boolean | | True False |
action_result.data.\*.assignees.\*.starred_url | string | `url` | https://api.github.com/users/testbg11/starred{/owner}{/repo} |
action_result.data.\*.assignees.\*.subscriptions_url | string | `url` | https://api.github.com/users/testbg11/subscriptions |
action_result.data.\*.assignees.\*.type | string | | User |
action_result.data.\*.assignees.\*.url | string | `url` | https://api.github.com/users/testbg11 |
action_result.data.\*.author_association | string | | OWNER |
action_result.data.\*.body | string | | test update body |
action_result.data.\*.closed_at | string | | 2019-07-29T11:24:09Z |
action_result.data.\*.closed_by.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/53362718?v=4 |
action_result.data.\*.closed_by.events_url | string | `url` | https://api.github.com/users/testbg11/events{/privacy} |
action_result.data.\*.closed_by.followers_url | string | `url` | https://api.github.com/users/testbg11/followers |
action_result.data.\*.closed_by.following_url | string | `url` | https://api.github.com/users/testbg11/following{/other_user} |
action_result.data.\*.closed_by.gists_url | string | `url` | https://api.github.com/users/testbg11/gists{/gist_id} |
action_result.data.\*.closed_by.gravatar_id | string | | |
action_result.data.\*.closed_by.html_url | string | `url` | https://github.com/testbg11 |
action_result.data.\*.closed_by.id | numeric | | 53362718 |
action_result.data.\*.closed_by.login | string | `github username` | testbg11 |
action_result.data.\*.closed_by.node_id | string | | MDQ6VXNlcjUzMzYyNzE4 |
action_result.data.\*.closed_by.organizations_url | string | `url` | https://api.github.com/users/testbg11/orgs |
action_result.data.\*.closed_by.received_events_url | string | `url` | https://api.github.com/users/testbg11/received_events |
action_result.data.\*.closed_by.repos_url | string | `url` | https://api.github.com/users/testbg11/repos |
action_result.data.\*.closed_by.site_admin | boolean | | True False |
action_result.data.\*.closed_by.starred_url | string | `url` | https://api.github.com/users/testbg11/starred{/owner}{/repo} |
action_result.data.\*.closed_by.subscriptions_url | string | `url` | https://api.github.com/users/testbg11/subscriptions |
action_result.data.\*.closed_by.type | string | | User |
action_result.data.\*.closed_by.url | string | `url` | https://api.github.com/users/testbg11 |
action_result.data.\*.comments | numeric | | 1 |
action_result.data.\*.comments_url | string | `url` | https://api.github.com/repos/testbg11/Testing1/issues/1/comments |
action_result.data.\*.created_at | string | | 2019-07-27T05:42:57Z |
action_result.data.\*.events_url | string | `url` | https://api.github.com/repos/testbg11/Testing1/issues/1/events |
action_result.data.\*.html_url | string | `url` | https://github.com/testbg11/Testing1/issues/1 |
action_result.data.\*.id | numeric | | 473601979 |
action_result.data.\*.labels.\*.color | string | | ededed |
action_result.data.\*.labels.\*.default | boolean | | True False |
action_result.data.\*.labels.\*.id | numeric | | 1474194162 |
action_result.data.\*.labels.\*.name | string | | demo_update |
action_result.data.\*.labels.\*.node_id | string | | MDU6TGFiZWwxNDc0MTk0MTYy |
action_result.data.\*.labels.\*.url | string | `url` | https://api.github.com/repos/testbg11/Testing1/labels/demo_update |
action_result.data.\*.labels_url | string | `url` | https://api.github.com/repos/testbg11/Testing1/issues/1/labels{/name} |
action_result.data.\*.locked | boolean | | True False |
action_result.data.\*.milestone | string | | |
action_result.data.\*.node_id | string | | MDU6SXNzdWU0NzM2MDE5Nzk= |
action_result.data.\*.number | numeric | `github issue id` | 1 |
action_result.data.\*.repository_url | string | `url` | https://api.github.com/repos/testbg11/Testing1 |
action_result.data.\*.state | string | | closed |
action_result.data.\*.title | string | | update test title |
action_result.data.\*.updated_at | string | | 2019-07-29T11:27:10Z |
action_result.data.\*.url | string | `url` | https://api.github.com/repos/testbg11/Testing1/issues/1 |
action_result.data.\*.user.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/53362718?v=4 |
action_result.data.\*.user.events_url | string | `url` | https://api.github.com/users/testbg11/events{/privacy} |
action_result.data.\*.user.followers_url | string | `url` | https://api.github.com/users/testbg11/followers |
action_result.data.\*.user.following_url | string | `url` | https://api.github.com/users/testbg11/following{/other_user} |
action_result.data.\*.user.gists_url | string | `url` | https://api.github.com/users/testbg11/gists{/gist_id} |
action_result.data.\*.user.gravatar_id | string | | |
action_result.data.\*.user.html_url | string | `url` | https://github.com/testbg11 |
action_result.data.\*.user.id | numeric | | 53362718 |
action_result.data.\*.user.login | string | `github username` | testbg11 |
action_result.data.\*.user.node_id | string | | MDQ6VXNlcjUzMzYyNzE4 |
action_result.data.\*.user.organizations_url | string | `url` | https://api.github.com/users/testbg11/orgs |
action_result.data.\*.user.received_events_url | string | `url` | https://api.github.com/users/testbg11/received_events |
action_result.data.\*.user.repos_url | string | `url` | https://api.github.com/users/testbg11/repos |
action_result.data.\*.user.site_admin | boolean | | True False |
action_result.data.\*.user.starred_url | string | `url` | https://api.github.com/users/testbg11/starred{/owner}{/repo} |
action_result.data.\*.user.subscriptions_url | string | `url` | https://api.github.com/users/testbg11/subscriptions |
action_result.data.\*.user.type | string | | User |
action_result.data.\*.user.url | string | `url` | https://api.github.com/users/testbg11 |
action_result.summary.issue_number | numeric | | 1 |
action_result.summary.issue_url | string | `url` | https://github.com/testbg11/Testing1/issues/1 |
action_result.message | string | | Issue number: 1, Issue url: https://github.com/testbg11/Testing1/issues/1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create comment'

Create a comment for an issue on the GitHub repository

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**repo_owner** | required | Owner of the repository | string | `github repo owner` `github username` |
**repo_name** | required | Name of the repository | string | `github repo` |
**issue_number** | required | Issue ID | numeric | `github issue id` |
**comment_body** | required | Contents of a comment to add to the issue | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.comment_body | string | | I am adding a comment from the app |
action_result.parameter.issue_number | numeric | `github issue id` | 2 |
action_result.parameter.repo_name | string | `github repo` | TestingAPI |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | repoowner |
action_result.data.\*.author_association | string | | OWNER |
action_result.data.\*.body | string | | I am adding a comment from the app |
action_result.data.\*.created_at | string | | 2019-07-16T20:11:38Z |
action_result.data.\*.html_url | string | `url` | https://github.com/repoowner/TestingAPI/issues/2#issuecomment-511967194 |
action_result.data.\*.id | numeric | | 511967194 |
action_result.data.\*.issue_url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/issues/2 |
action_result.data.\*.node_id | string | | MDEyOklzc3VlQ29tbWVudDUxMTk2NzE5NA== |
action_result.data.\*.updated_at | string | | 2019-07-16T20:11:38Z |
action_result.data.\*.url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/issues/comments/511967194 |
action_result.data.\*.user.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/11890709?v=4 |
action_result.data.\*.user.events_url | string | `url` | https://api.github.com/users/repoowner/events{/privacy} |
action_result.data.\*.user.followers_url | string | `url` | https://api.github.com/users/repoowner/followers |
action_result.data.\*.user.following_url | string | `url` | https://api.github.com/users/repoowner/following{/other_user} |
action_result.data.\*.user.gists_url | string | `url` | https://api.github.com/users/repoowner/gists{/gist_id} |
action_result.data.\*.user.gravatar_id | string | | |
action_result.data.\*.user.html_url | string | `url` | https://github.com/repoowner |
action_result.data.\*.user.id | numeric | | 11890709 |
action_result.data.\*.user.login | string | `github username` | repoowner |
action_result.data.\*.user.node_id | string | | MDQ6VXNlcjExODkwNzA5 |
action_result.data.\*.user.organizations_url | string | `url` | https://api.github.com/users/repoowner/orgs |
action_result.data.\*.user.received_events_url | string | `url` | https://api.github.com/users/repoowner/received_events |
action_result.data.\*.user.repos_url | string | `url` | https://api.github.com/users/repoowner/repos |
action_result.data.\*.user.site_admin | boolean | | True False |
action_result.data.\*.user.starred_url | string | `url` | https://api.github.com/users/repoowner/starred{/owner}{/repo} |
action_result.data.\*.user.subscriptions_url | string | `url` | https://api.github.com/users/repoowner/subscriptions |
action_result.data.\*.user.type | string | | User |
action_result.data.\*.user.url | string | `url` | https://api.github.com/users/repoowner |
action_result.summary.comment_id | numeric | | 511967194 |
action_result.summary.comment_url | string | `url` | https://github.com/repoowner/TestingAPI/issues/2#issuecomment-511967194 |
action_result.message | string | | Comment id: 511967194, Comment url: https://github.com/repoowner/TestingAPI/issues/2#issuecomment-511967194 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add labels'

Add label(s) to an issue on the GitHub repository

Type: **generic** \
Read only: **False**

Only users with push access can set labels for the issues.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**repo_owner** | required | Owner of the repository | string | `github repo owner` `github username` |
**repo_name** | required | Name of the repository | string | `github repo` |
**issue_number** | required | Issue ID | numeric | `github issue id` |
**labels** | required | Comma-separated list of labels to add to the issue | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.issue_number | numeric | `github issue id` | 1 |
action_result.parameter.labels | string | | test,Splunk,app-testing |
action_result.parameter.repo_name | string | `github repo` | TestingAPI |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | repoowner |
action_result.data.\*.color | string | | ededed |
action_result.data.\*.default | boolean | | True False |
action_result.data.\*.id | numeric | | 1454479580 |
action_result.data.\*.name | string | | app-testing |
action_result.data.\*.node_id | string | | MDU6TGFiZWwxNDU0NDc5NTgw |
action_result.data.\*.url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/labels/app-testing |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
