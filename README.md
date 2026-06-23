# GitHub

Publisher: Splunk <br>
Connector Version: 3.0.0 <br>
Product Vendor: Microsoft <br>
Product Name: GitHub <br>
Minimum Product Version: 7.0.0

This app integrates with GitHub to support various investigative and issue-based actions

### Configuration variables

This table lists the configuration variables required to operate GitHub. These variables are specified when configuring a GitHub asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**personal_access_token** | optional | password | Personal Access Token (PAT) |
**client_id** | optional | string | OAuth App Client ID |
**client_secret** | optional | password | OAuth App Client Secret |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration. <br>
[add collaborator](#action-add-collaborator) - Add user as a collaborator to repo <br>
[add labels](#action-add-labels) - Add label(s) to an issue on the GitHub repository <br>
[add member](#action-add-member) - Add user in a team <br>
[create comment](#action-create-comment) - Create a comment for an issue on the GitHub repository <br>
[create issue](#action-create-issue) - Create an issue for the GitHub repository <br>
[get issue](#action-get-issue) - Retrieve an issue for the GitHub repository <br>
[list comments](#action-list-comments) - List comments for an issue on the GitHub repository <br>
[list events](#action-list-events) - List events performed by a user <br>
[list issues](#action-list-issues) - Get a list of issues for the GitHub repository <br>
[list organizations](#action-list-organizations) - List all organizations <br>
[list repos](#action-list-repos) - List all repos of an organization <br>
[list teams](#action-list-teams) - List all teams of an organization <br>
[list users](#action-list-users) - List users of an organization <br>
[make request](#action-make-request) - Execute an arbitrary HTTP request against the GitHub API.

Handles all three authentication modes configured on the asset:
username/password basic auth, personal access token, and OAuth Bearer token.
The endpoint is appended to https://api.github.com — do not include the base URL. <br>
[remove collaborator](#action-remove-collaborator) - Remove user as a collaborator from the repo <br>
[remove member](#action-remove-member) - Remove user from the team <br>
[update issue](#action-update-issue) - Update an issue for the GitHub repository

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration.

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add collaborator'

Add user as a collaborator to repo

Type: **generic** <br>
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
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | |
action_result.parameter.repo_name | string | `github repo` | |
action_result.parameter.user | string | `github username` | |
action_result.parameter.role | string | | |
action_result.parameter.override | boolean | | |
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
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add labels'

Add label(s) to an issue on the GitHub repository

Type: **generic** <br>
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
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | |
action_result.parameter.repo_name | string | `github repo` | |
action_result.parameter.issue_number | numeric | `github issue id` | |
action_result.parameter.labels | string | | |
action_result.data.\*.color | string | | ededed |
action_result.data.\*.default | boolean | | True False |
action_result.data.\*.id | numeric | | 1454479580 |
action_result.data.\*.name | string | | app-testing |
action_result.data.\*.node_id | string | | MDU6TGFiZWwxNDU0NDc5NTgw |
action_result.data.\*.url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/labels/app-testing |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add member'

Add user in a team

Type: **generic** <br>
Read only: **False**

Parameter 'organization name' is mandatory if the team name is provided instead of team ID.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**organization_name** | optional | Organization name | string | `github organization name` |
**team** | required | Team name or team ID | string | `github team name` `github team id` |
**user** | required | Username | string | `github username` |
**role** | optional | Role of the user (Default: Member) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.organization_name | string | `github organization name` | |
action_result.parameter.team | string | `github team name` `github team id` | |
action_result.parameter.user | string | `github username` | |
action_result.parameter.role | string | | |
action_result.data.\*.state | string | | active pending |
action_result.data.\*.status | string | | success failed |
action_result.data.\*.role | string | | member maintainer |
action_result.data.\*.url | string | `url` | https://api.github.com/teams/2830072/memberships/test |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create comment'

Create a comment for an issue on the GitHub repository

Type: **generic** <br>
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
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | |
action_result.parameter.repo_name | string | `github repo` | |
action_result.parameter.issue_number | numeric | `github issue id` | |
action_result.parameter.comment_body | string | | |
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
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create issue'

Create an issue for the GitHub repository

Type: **generic** <br>
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
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | |
action_result.parameter.repo_name | string | `github repo` | |
action_result.parameter.issue_title | string | | |
action_result.parameter.issue_body | string | | |
action_result.parameter.assignees | string | `github username` | |
action_result.parameter.labels | string | | |
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
action_result.data.\*.milestone.closed_at | string | | 2018-07-20T11:26:15Z |
action_result.data.\*.milestone.closed_issues | numeric | | 879 |
action_result.data.\*.milestone.created_at | string | | 2016-11-06T20:24:23Z |
action_result.data.\*.milestone.creator.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/73419?v=4 |
action_result.data.\*.milestone.creator.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.milestone.creator.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.milestone.creator.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.milestone.creator.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.milestone.creator.gravatar_id | string | | |
action_result.data.\*.milestone.creator.html_url | string | `url` | https://github.com/test |
action_result.data.\*.milestone.creator.id | numeric | | 73419 |
action_result.data.\*.milestone.creator.login | string | `github username` | test |
action_result.data.\*.milestone.creator.node_id | string | | MDQ6VXNlcjczNDE5 |
action_result.data.\*.milestone.creator.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.milestone.creator.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.milestone.creator.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.milestone.creator.site_admin | boolean | | True False |
action_result.data.\*.milestone.creator.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.milestone.creator.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.milestone.creator.type | string | | User |
action_result.data.\*.milestone.creator.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.milestone.description | string | | Sample description |
action_result.data.\*.milestone.due_on | string | | 2020-11-30T08:00:00Z |
action_result.data.\*.milestone.html_url | string | `url` | https://github.com/test/test/milestone/10 |
action_result.data.\*.milestone.id | numeric | | 2117464 |
action_result.data.\*.milestone.labels_url | string | `url` | https://api.github.com/repos/test/test/milestones/10/labels |
action_result.data.\*.milestone.node_id | string | | MDk6TWlsZXN0b25lMjExNzQ2NA== |
action_result.data.\*.milestone.number | numeric | | 10 |
action_result.data.\*.milestone.open_issues | numeric | | 15 |
action_result.data.\*.milestone.state | string | | open |
action_result.data.\*.milestone.title | string | | 3.4 |
action_result.data.\*.milestone.updated_at | string | | 2018-07-19T07:12:02Z |
action_result.data.\*.milestone.url | string | `url` | https://api.github.com/repos/test/test/milestones/10 |
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
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get issue'

Retrieve an issue for the GitHub repository

Type: **investigate** <br>
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
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | |
action_result.parameter.repo_name | string | `github repo` | |
action_result.parameter.issue_number | numeric | `github issue id` | |
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
action_result.data.\*.comments_url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/issues/1/comments |
action_result.data.\*.created_at | string | | 2019-07-16T19:52:15Z |
action_result.data.\*.events_url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/issues/1/events |
action_result.data.\*.html_url | string | `url` | https://github.com/repoowner/TestingAPI/issues/1 |
action_result.data.\*.id | numeric | | 468834090 |
action_result.data.\*.labels_url | string | `url` | https://api.github.com/repos/repoowner/TestingAPI/issues/1/labels{/name} |
action_result.data.\*.locked | boolean | | True False |
action_result.data.\*.milestone.closed_at | string | | 2018-07-20T11:26:15Z |
action_result.data.\*.milestone.closed_issues | numeric | | 879 |
action_result.data.\*.milestone.created_at | string | | 2016-11-06T20:24:23Z |
action_result.data.\*.milestone.creator.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/73419?v=4 |
action_result.data.\*.milestone.creator.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.milestone.creator.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.milestone.creator.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.milestone.creator.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.milestone.creator.gravatar_id | string | | |
action_result.data.\*.milestone.creator.html_url | string | `url` | https://github.com/test |
action_result.data.\*.milestone.creator.id | numeric | | 73419 |
action_result.data.\*.milestone.creator.login | string | `github username` | test |
action_result.data.\*.milestone.creator.node_id | string | | MDQ6VXNlcjczNDE5 |
action_result.data.\*.milestone.creator.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.milestone.creator.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.milestone.creator.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.milestone.creator.site_admin | boolean | | True False |
action_result.data.\*.milestone.creator.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.milestone.creator.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.milestone.creator.type | string | | User |
action_result.data.\*.milestone.creator.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.milestone.description | string | | Sample description |
action_result.data.\*.milestone.due_on | string | | 2020-11-30T08:00:00Z |
action_result.data.\*.milestone.html_url | string | `url` | https://github.com/test/test/milestone/10 |
action_result.data.\*.milestone.id | numeric | | 2117464 |
action_result.data.\*.milestone.labels_url | string | `url` | https://api.github.com/repos/test/test/milestones/10/labels |
action_result.data.\*.milestone.node_id | string | | MDk6TWlsZXN0b25lMjExNzQ2NA== |
action_result.data.\*.milestone.number | numeric | | 10 |
action_result.data.\*.milestone.open_issues | numeric | | 15 |
action_result.data.\*.milestone.state | string | | open |
action_result.data.\*.milestone.title | string | | 3.4 |
action_result.data.\*.milestone.updated_at | string | | 2018-07-19T07:12:02Z |
action_result.data.\*.milestone.url | string | `url` | https://api.github.com/repos/test/test/milestones/10 |
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
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list comments'

List comments for an issue on the GitHub repository

Type: **investigate** <br>
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
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | |
action_result.parameter.repo_name | string | `github repo` | |
action_result.parameter.issue_number | numeric | `github issue id` | |
action_result.parameter.limit | numeric | | |
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
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list events'

List events performed by a user

Type: **investigate** <br>
Read only: **True**

Action will list a maximum of 300 events. Only events from the past 90 days will be listed.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**username** | required | Username | string | `github username` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.username | string | `github username` | |
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
action_result.data.\*.payload.changes.note.from | string | | |
action_result.data.\*.payload.changes.permission.from | string | | write |
action_result.data.\*.payload.changes.privacy.from | string | | |
action_result.data.\*.payload.changes.repository.permissions.from.admin | boolean | | True False |
action_result.data.\*.payload.changes.repository.permissions.from.pull | boolean | | True False |
action_result.data.\*.payload.changes.repository.permissions.from.push | boolean | | True False |
action_result.data.\*.payload.changes.title.from | string | | |
action_result.data.\*.payload.check_run.pull_requests.\*.diff_url | string | `url` | https://github.com/twigphp/Twig/pull/2721.diff |
action_result.data.\*.payload.check_run.pull_requests.\*.html_url | string | `url` | https://github.com/twigphp/Twig/pull/2721 |
action_result.data.\*.payload.check_run.pull_requests.\*.patch_url | string | `url` | https://github.com/twigphp/Twig/pull/2721.patch |
action_result.data.\*.payload.check_run.pull_requests.\*.url | string | `url` | https://api.github.com/repos/twigphp/Twig/pulls/2721 |
action_result.data.\*.payload.check_suite.after | string | `sha1` | d6fde92930d4715a2b49857d24b940956b26d2d3 |
action_result.data.\*.payload.check_suite.app.created_at | string | | 2018-04-25 20:42:10 |
action_result.data.\*.payload.check_suite.app.description | string | | |
action_result.data.\*.payload.check_suite.app.external_url | string | `url` | http://super-duper.example.com |
action_result.data.\*.payload.check_suite.app.html_url | string | `url` | http://github.com/apps/super-duper |
action_result.data.\*.payload.check_suite.app.id | numeric | | 2 |
action_result.data.\*.payload.check_suite.app.name | string | | Super Duper |
action_result.data.\*.payload.check_suite.app.node_id | string | | MDExOkludGVncmF0aW9uMQ= |
action_result.data.\*.payload.check_suite.app.owner.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/29939753?v=4 |
action_result.data.\*.payload.check_suite.app.owner.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_suite.app.owner.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_suite.app.owner.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_suite.app.owner.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_suite.app.owner.gravatar_id | string | | |
action_result.data.\*.payload.check_suite.app.owner.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_suite.app.owner.id | numeric | | 29939753 |
action_result.data.\*.payload.check_suite.app.owner.login | string | `github username` | test |
action_result.data.\*.payload.check_suite.app.owner.node_id | string | | MDQ6VXNlcjI5OTM5NzUz |
action_result.data.\*.payload.check_suite.app.owner.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_suite.app.owner.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_suite.app.owner.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_suite.app.owner.site_admin | boolean | | True False |
action_result.data.\*.payload.check_suite.app.owner.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_suite.app.owner.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_suite.app.owner.type | string | | User |
action_result.data.\*.payload.check_suite.app.owner.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.check_suite.app.updated_at | string | | 2018-04-25 20:42:10 |
action_result.data.\*.payload.check_suite.before | string | `sha1` | 146e867f55c26428e5f9fade55a9bbf5e95a7912 |
action_result.data.\*.payload.check_suite.check_runs_url | string | `url` | https://api.github.com/repos/test/test-repo/check-suites/5/check-runs |
action_result.data.\*.payload.check_suite.conclusion | string | | neutral |
action_result.data.\*.payload.check_suite.created_at | string | | 2018-04-25 20:42:10 |
action_result.data.\*.payload.check_suite.head_branch | string | | master |
action_result.data.\*.payload.check_suite.head_commit.author.avatar_url | string | `url` | https://avatars0.githubusercontent.com/u/1?v=4 |
action_result.data.\*.payload.check_suite.head_commit.author.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.check_suite.head_commit.author.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.check_suite.head_commit.author.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.check_suite.head_commit.author.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.check_suite.head_commit.author.gravatar_id | string | | |
action_result.data.\*.payload.check_suite.head_commit.author.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.check_suite.head_commit.author.id | numeric | | 1 |
action_result.data.\*.payload.check_suite.head_commit.author.login | string | `github username` | test |
action_result.data.\*.payload.check_suite.head_commit.author.node_id | string | | MDQ6VXNlcjE= |
action_result.data.\*.payload.check_suite.head_commit.author.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.check_suite.head_commit.author.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.check_suite.head_commit.author.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.check_suite.head_commit.author.site_admin | boolean | | True False |
action_result.data.\*.payload.check_suite.head_commit.author.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.check_suite.head_commit.author.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.check_suite.head_commit.author.type | string | | User |
action_result.data.\*.payload.check_suite.head_commit.author.url | string | `url` | https://api.github.com/users/test |
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
action_result.data.\*.payload.check_suite.pull_requests.\*.diff_url | string | `url` | https://github.com/twigphp/Twig/pull/2721.diff |
action_result.data.\*.payload.check_suite.pull_requests.\*.html_url | string | `url` | https://github.com/twigphp/Twig/pull/2721 |
action_result.data.\*.payload.check_suite.pull_requests.\*.patch_url | string | `url` | https://github.com/twigphp/Twig/pull/2721.patch |
action_result.data.\*.payload.check_suite.pull_requests.\*.url | string | `url` | https://api.github.com/repos/twigphp/Twig/pulls/2721 |
action_result.data.\*.payload.check_suite.status | string | | completed |
action_result.data.\*.payload.check_suite.updated_at | string | | 2018-04-25 20:42:10 |
action_result.data.\*.payload.comment.links.html.href | string | `url` | https://github.com/test/test-repo/pull/1#pullrequestreview-124575911 |
action_result.data.\*.payload.comment.links.pull_request.href | string | `url` | https://api.github.com/repos/test/test-repo/pulls/1 |
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
action_result.data.\*.payload.comment.user.avatar_url | string | `url` | https://avatars1.githubusercontent.com/u/1032411?v=4 |
action_result.data.\*.payload.comment.user.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.comment.user.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.comment.user.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.comment.user.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.comment.user.gravatar_id | string | | |
action_result.data.\*.payload.comment.user.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.comment.user.id | numeric | | 1032411 |
action_result.data.\*.payload.comment.user.login | string | `github username` | test |
action_result.data.\*.payload.comment.user.node_id | string | | MDQ6VXNlcjEwMzI0MTE= |
action_result.data.\*.payload.comment.user.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.comment.user.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.comment.user.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.comment.user.site_admin | boolean | | True False |
action_result.data.\*.payload.comment.user.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.comment.user.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.comment.user.type | string | | User |
action_result.data.\*.payload.comment.user.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.commits.\*.href | string | `url` | https://api.github.com/repos/test/test/pulls/27999/commits |
action_result.data.\*.payload.compare | string | `url` | https://github.com/test/test-repo/compare/a10867b14bb7...000000000000 |
action_result.data.\*.payload.created | boolean | | True False |
action_result.data.\*.payload.deleted | boolean | | True False |
action_result.data.\*.payload.description | string | | test-repo-Description |
action_result.data.\*.payload.distinct_size | numeric | | 100 |
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
action_result.data.\*.payload.head_commit.author.avatar_url | string | `url` | https://avatars0.githubusercontent.com/u/1?v=4 |
action_result.data.\*.payload.head_commit.author.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.head_commit.author.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.head_commit.author.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.head_commit.author.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.head_commit.author.gravatar_id | string | | |
action_result.data.\*.payload.head_commit.author.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.head_commit.author.id | numeric | | 1 |
action_result.data.\*.payload.head_commit.author.login | string | `github username` | test |
action_result.data.\*.payload.head_commit.author.node_id | string | | MDQ6VXNlcjE= |
action_result.data.\*.payload.head_commit.author.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.head_commit.author.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.head_commit.author.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.head_commit.author.site_admin | boolean | | True False |
action_result.data.\*.payload.head_commit.author.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.head_commit.author.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.head_commit.author.type | string | | User |
action_result.data.\*.payload.head_commit.author.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.head_commit.committer.email | string | `email` | test@user.com |
action_result.data.\*.payload.head_commit.committer.name | string | `github username` | test |
action_result.data.\*.payload.head_commit.id | string | `sha1` | d6fde92930d4715a2b49857d24b940956b26d2d3 |
action_result.data.\*.payload.head_commit.message | string | | Sample message |
action_result.data.\*.payload.head_commit.timestamp | string | | 2018-05-04T01:14:46Z |
action_result.data.\*.payload.head_commit.tree_id | string | `sha1` | d6fde92930d4715a2b49857d24b940956b26d2d3 |
action_result.data.\*.payload.installation.access_tokens_url | string | `url` | https://api.github.com/installations/2/access_tokens |
action_result.data.\*.payload.installation.account.id | numeric | | 18404719 |
action_result.data.\*.payload.installation.account.login | string | `github username` | test |
action_result.data.\*.payload.installation.account.organization_billing_email | string | `email` | username@email.com |
action_result.data.\*.payload.installation.account.type | string | | Organization |
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
action_result.data.\*.payload.issue.href | string | `url` | https://api.github.com/repos/test/test/issues/27999 |
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
action_result.data.\*.payload.organization.avatar_url | string | `url` | https://avatars0.githubusercontent.com/u/41309665?v=4 |
action_result.data.\*.payload.organization.created_at | string | | 2018-07-16T23:02:38Z |
action_result.data.\*.payload.organization.description | string | | |
action_result.data.\*.payload.organization.events_url | string | `url` | https://api.github.com/orgs/test/events |
action_result.data.\*.payload.organization.followers | numeric | | 3 |
action_result.data.\*.payload.organization.following | numeric | | 3 |
action_result.data.\*.payload.organization.has_organization_projects | boolean | | True False |
action_result.data.\*.payload.organization.has_repository_projects | boolean | | True False |
action_result.data.\*.payload.organization.hooks_url | string | `url` | https://api.github.com/orgs/test/hooks |
action_result.data.\*.payload.organization.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.organization.id | numeric | | 41309665 |
action_result.data.\*.payload.organization.issues_url | string | `url` | https://api.github.com/orgs/test/issues |
action_result.data.\*.payload.organization.login | string | `github organization name` | test |
action_result.data.\*.payload.organization.members_url | string | `url` | https://api.github.com/orgs/test/members{/member} |
action_result.data.\*.payload.organization.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjQxMzA5NjY1 |
action_result.data.\*.payload.organization.public_gists | numeric | | 3 |
action_result.data.\*.payload.organization.public_members_url | string | `url` | https://api.github.com/orgs/test/public_members{/member} |
action_result.data.\*.payload.organization.public_repos | numeric | | 3 |
action_result.data.\*.payload.organization.repos_url | string | `url` | https://api.github.com/orgs/test/repos |
action_result.data.\*.payload.organization.type | string | | Organization |
action_result.data.\*.payload.organization.updated_at | string | | 2018-07-16T23:02:38Z |
action_result.data.\*.payload.organization.url | string | `url` | https://api.github.com/orgs/test |
action_result.data.\*.payload.pages.\*.action | string | | created |
action_result.data.\*.payload.pages.\*.creator.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/73419?v=4 |
action_result.data.\*.payload.pages.\*.creator.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.pages.\*.creator.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.pages.\*.creator.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.pages.\*.creator.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.pages.\*.creator.gravatar_id | string | | |
action_result.data.\*.payload.pages.\*.creator.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.pages.\*.creator.id | numeric | | 73419 |
action_result.data.\*.payload.pages.\*.creator.login | string | `github username` | test |
action_result.data.\*.payload.pages.\*.creator.node_id | string | | MDQ6VXNlcjczNDE5 |
action_result.data.\*.payload.pages.\*.creator.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.payload.pages.\*.creator.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.payload.pages.\*.creator.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.payload.pages.\*.creator.site_admin | boolean | | True False |
action_result.data.\*.payload.pages.\*.creator.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.payload.pages.\*.creator.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.payload.pages.\*.creator.type | string | | User |
action_result.data.\*.payload.pages.\*.creator.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.payload.pages.\*.html_url | string | `url` | https://github.com/test/test-proj/wiki/Home |
action_result.data.\*.payload.pages.\*.page_name | string | | Home |
action_result.data.\*.payload.pages.\*.sha | string | `sha1` | 75c7614e23cb40511d9cb3eb00d20e5cadc0d0e6 |
action_result.data.\*.payload.pages.\*.summary | string | | |
action_result.data.\*.payload.pages.\*.title | string | | Home |
action_result.data.\*.payload.project.body | string | | Project tasks for a trip to Space |
action_result.data.\*.payload.project.columns_url | string | `url` | https://api.github.com/projects/1547122/columns |
action_result.data.\*.payload.project.created_at | string | | 2018-05-30T20:18:51Z |
action_result.data.\*.payload.project.creator.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/73419?v=4 |
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
action_result.data.\*.payload.project_card.creator.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/73419?v=4 |
action_result.data.\*.payload.project_card.creator.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.payload.project_card.creator.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.payload.project_card.creator.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.payload.project_card.creator.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.payload.project_card.creator.gravatar_id | string | | |
action_result.data.\*.payload.project_card.creator.html_url | string | `url` | https://github.com/test |
action_result.data.\*.payload.project_card.creator.id | numeric | | 73419 |
action_result.data.\*.payload.project_card.creator.login | string | `github username` | test |
action_result.data.\*.payload.project_card.creator.node_id | string | | MDQ6VXNlcjczNDE5 |
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
action_result.data.\*.payload.pull_request.href | string | `url` | https://api.github.com/repos/test/test-repo/pulls/1 |
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
action_result.data.\*.payload.review.links.html.href | string | `url` | https://github.com/test/test-repo/pull/1#pullrequestreview-124575911 |
action_result.data.\*.payload.review.links.pull_request.href | string | `url` | https://api.github.com/repos/test/test-repo/pulls/1 |
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
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list issues'

Get a list of issues for the GitHub repository

Type: **investigate** <br>
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
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | |
action_result.parameter.repo_name | string | `github repo` | |
action_result.parameter.limit | numeric | | |
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
action_result.data.\*.milestone.closed_at | string | | 2018-07-20T11:26:15Z |
action_result.data.\*.milestone.closed_issues | numeric | | 879 |
action_result.data.\*.milestone.created_at | string | | 2016-11-06T20:24:23Z |
action_result.data.\*.milestone.creator.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/73419?v=4 |
action_result.data.\*.milestone.creator.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.milestone.creator.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.milestone.creator.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.milestone.creator.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.milestone.creator.gravatar_id | string | | |
action_result.data.\*.milestone.creator.html_url | string | `url` | https://github.com/test |
action_result.data.\*.milestone.creator.id | numeric | | 73419 |
action_result.data.\*.milestone.creator.login | string | `github username` | test |
action_result.data.\*.milestone.creator.node_id | string | | MDQ6VXNlcjczNDE5 |
action_result.data.\*.milestone.creator.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.milestone.creator.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.milestone.creator.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.milestone.creator.site_admin | boolean | | True False |
action_result.data.\*.milestone.creator.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.milestone.creator.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.milestone.creator.type | string | | User |
action_result.data.\*.milestone.creator.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.milestone.description | string | | Sample description |
action_result.data.\*.milestone.due_on | string | | 2020-11-30T08:00:00Z |
action_result.data.\*.milestone.html_url | string | `url` | https://github.com/test/test/milestone/10 |
action_result.data.\*.milestone.id | numeric | | 2117464 |
action_result.data.\*.milestone.labels_url | string | `url` | https://api.github.com/repos/test/test/milestones/10/labels |
action_result.data.\*.milestone.node_id | string | | MDk6TWlsZXN0b25lMjExNzQ2NA== |
action_result.data.\*.milestone.number | numeric | | 10 |
action_result.data.\*.milestone.open_issues | numeric | | 15 |
action_result.data.\*.milestone.state | string | | open |
action_result.data.\*.milestone.title | string | | 3.4 |
action_result.data.\*.milestone.updated_at | string | | 2018-07-19T07:12:02Z |
action_result.data.\*.milestone.url | string | `url` | https://api.github.com/repos/test/test/milestones/10 |
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
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list organizations'

List all organizations

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum number of organizations to be fetched | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.limit | numeric | | |
action_result.data.\*.id | numeric | | 41301665 |
action_result.data.\*.login | string | `github organization name` | test |
action_result.data.\*.description | string | | |
action_result.data.\*.url | string | `url` | https://api.github.com/orgs/test |
action_result.data.\*.avatar_url | string | `url` | https://avatars0.githubusercontent.com/u/41301665?v=4 |
action_result.data.\*.events_url | string | `url` | https://api.github.com/orgs/test/events |
action_result.data.\*.hooks_url | string | `url` | https://api.github.com/orgs/test/hooks |
action_result.data.\*.issues_url | string | `url` | https://api.github.com/orgs/test/issues |
action_result.data.\*.members_url | string | `url` | https://api.github.com/orgs/test/members{/member} |
action_result.data.\*.node_id | string | | MDEyOk9yZ2FuaXphdGlvbjQxMzA5NjY1 |
action_result.data.\*.public_members_url | string | `url` | https://api.github.com/orgs/test/public_members{/member} |
action_result.data.\*.repos_url | string | `url` | https://api.github.com/orgs/test/repos |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list repos'

List all repos of an organization

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**organization_name** | required | Organization name | string | `github organization name` |
**limit** | optional | Maximum number of repositories to be fetched | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.organization_name | string | `github organization name` | |
action_result.parameter.limit | numeric | | |
action_result.data.\*.id | numeric | | 141304012 |
action_result.data.\*.full_name | string | | test/test-repo |
action_result.data.\*.description | string | | Test Repo 1 |
action_result.data.\*.repo_owner | string | `github username` | test |
action_result.data.\*.created_at | string | | 2018-07-16T23:05:00Z |
action_result.data.\*.updated_at | string | | 2018-07-16T23:03:00Z |
action_result.data.\*.private | boolean | | True False |
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
action_result.data.\*.default_branch | string | | master |
action_result.data.\*.deployments_url | string | `url` | https://api.github.com/repos/test/test-repo/deployments |
action_result.data.\*.downloads_url | string | `url` | https://api.github.com/repos/test/test-repo/downloads |
action_result.data.\*.events_url | string | `url` | https://api.github.com/repos/test/test-repo/events |
action_result.data.\*.fork | boolean | | True False |
action_result.data.\*.forks | numeric | | 0 |
action_result.data.\*.forks_count | numeric | | 0 |
action_result.data.\*.forks_url | string | `url` | https://api.github.com/repos/test/test-repo/forks |
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
action_result.data.\*.url | string | `url` | https://api.github.com/repos/test/test-repo |
action_result.data.\*.watchers | numeric | | 0 |
action_result.data.\*.watchers_count | numeric | | 0 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list teams'

List all teams of an organization

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**organization_name** | required | Organization name | string | `github organization name` |
**limit** | optional | Maximum number of teams to be fetched | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.organization_name | string | `github organization name` | |
action_result.parameter.limit | numeric | | |
action_result.data.\*.id | numeric | `github team id` | 2825460 |
action_result.data.\*.name | string | `github team name` | new team |
action_result.data.\*.description | string | | New team |
action_result.data.\*.privacy | string | | closed |
action_result.data.\*.permission | string | | pull |
action_result.data.\*.members_url | string | `url` | https://api.github.com/teams/2825460/members{/member} |
action_result.data.\*.node_id | string | | MDQ6VGVhbTI4JmcyNjA= |
action_result.data.\*.repositories_url | string | `url` | https://api.github.com/teams/2825460/repos |
action_result.data.\*.slug | string | | new-team |
action_result.data.\*.url | string | `url` | https://api.github.com/teams/2825460 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list users'

List users of an organization

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**organization_name** | required | Organization name | string | `github organization name` |
**limit** | optional | Maximum number of users to be fetched | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.organization_name | string | `github organization name` | |
action_result.parameter.limit | numeric | | |
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
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'make request'

Execute an arbitrary HTTP request against the GitHub API.

Handles all three authentication modes configured on the asset:
username/password basic auth, personal access token, and OAuth Bearer token.
The endpoint is appended to https://api.github.com — do not include the base URL.

Type: **generic** <br>
Read only: **False**

'make request' action for the app. Used to handle arbitrary HTTP requests with the app's asset

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_method** | required | The HTTP method to use for the request. | string | |
**endpoint** | required | GitHub API endpoint path appended to https://api.github.com. Do not include the base URL. Examples: '/user', '/repos/owner/name/issues', '/orgs/my-org/teams', '/repos/owner/name/issues/1/labels'. | string | |
**headers** | optional | The headers to send with the request (JSON object). An example is {'Content-Type': 'application/json'} | string | |
**query_parameters** | optional | Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2 | string | |
**body** | optional | The body to send with the request (JSON object). An example is {'key': 'value', 'key2': 'value2'} | string | |
**timeout** | optional | The timeout for the request in seconds. | numeric | |
**verify_ssl** | optional | Whether to verify the SSL certificate. Default is False. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_method | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.headers | string | | |
action_result.parameter.query_parameters | string | | |
action_result.parameter.body | string | | |
action_result.parameter.timeout | numeric | | |
action_result.parameter.verify_ssl | boolean | | |
action_result.data.\*.status_code | numeric | | 200 404 500 |
action_result.data.\*.response_body | string | | {"key": "value"} |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'remove collaborator'

Remove user as a collaborator from the repo

Type: **generic** <br>
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
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | |
action_result.parameter.repo_name | string | `github repo` | |
action_result.parameter.user | string | `github username` | |
action_result.data.\*.invite_deleted | boolean | | True False |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'remove member'

Remove user from the team

Type: **generic** <br>
Read only: **False**

Parameter 'organization name' is mandatory if the team name is provided instead of team ID.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**organization_name** | optional | Organization name | string | `github organization name` |
**team** | required | Team name or team ID | string | `github team name` `github team id` |
**user** | required | Username | string | `github username` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.organization_name | string | `github organization name` | |
action_result.parameter.team | string | `github team name` `github team id` | |
action_result.parameter.user | string | `github username` | |
action_result.data.\*.status | string | | success failed |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update issue'

Update an issue for the GitHub repository

Type: **generic** <br>
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
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.repo_owner | string | `github repo owner` `github username` | |
action_result.parameter.repo_name | string | `github repo` | |
action_result.parameter.issue_number | numeric | `github issue id` | |
action_result.parameter.state | string | | |
action_result.parameter.issue_title | string | | |
action_result.parameter.issue_body | string | | |
action_result.parameter.assignees | string | `github username` | |
action_result.parameter.labels | string | | |
action_result.parameter.to_empty | boolean | | |
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
action_result.data.\*.milestone.closed_at | string | | 2018-07-20T11:26:15Z |
action_result.data.\*.milestone.closed_issues | numeric | | 879 |
action_result.data.\*.milestone.created_at | string | | 2016-11-06T20:24:23Z |
action_result.data.\*.milestone.creator.avatar_url | string | `url` | https://avatars3.githubusercontent.com/u/73419?v=4 |
action_result.data.\*.milestone.creator.events_url | string | `url` | https://api.github.com/users/test/events{/privacy} |
action_result.data.\*.milestone.creator.followers_url | string | `url` | https://api.github.com/users/test/followers |
action_result.data.\*.milestone.creator.following_url | string | `url` | https://api.github.com/users/test/following{/other_user} |
action_result.data.\*.milestone.creator.gists_url | string | `url` | https://api.github.com/users/test/gists{/gist_id} |
action_result.data.\*.milestone.creator.gravatar_id | string | | |
action_result.data.\*.milestone.creator.html_url | string | `url` | https://github.com/test |
action_result.data.\*.milestone.creator.id | numeric | | 73419 |
action_result.data.\*.milestone.creator.login | string | `github username` | test |
action_result.data.\*.milestone.creator.node_id | string | | MDQ6VXNlcjczNDE5 |
action_result.data.\*.milestone.creator.organizations_url | string | `url` | https://api.github.com/users/test/orgs |
action_result.data.\*.milestone.creator.received_events_url | string | `url` | https://api.github.com/users/test/received_events |
action_result.data.\*.milestone.creator.repos_url | string | `url` | https://api.github.com/users/test/repos |
action_result.data.\*.milestone.creator.site_admin | boolean | | True False |
action_result.data.\*.milestone.creator.starred_url | string | `url` | https://api.github.com/users/test/starred{/owner}{/repo} |
action_result.data.\*.milestone.creator.subscriptions_url | string | `url` | https://api.github.com/users/test/subscriptions |
action_result.data.\*.milestone.creator.type | string | | User |
action_result.data.\*.milestone.creator.url | string | `url` | https://api.github.com/users/test |
action_result.data.\*.milestone.description | string | | Sample description |
action_result.data.\*.milestone.due_on | string | | 2020-11-30T08:00:00Z |
action_result.data.\*.milestone.html_url | string | `url` | https://github.com/test/test/milestone/10 |
action_result.data.\*.milestone.id | numeric | | 2117464 |
action_result.data.\*.milestone.labels_url | string | `url` | https://api.github.com/repos/test/test/milestones/10/labels |
action_result.data.\*.milestone.node_id | string | | MDk6TWlsZXN0b25lMjExNzQ2NA== |
action_result.data.\*.milestone.number | numeric | | 10 |
action_result.data.\*.milestone.open_issues | numeric | | 15 |
action_result.data.\*.milestone.state | string | | open |
action_result.data.\*.milestone.title | string | | 3.4 |
action_result.data.\*.milestone.updated_at | string | | 2018-07-19T07:12:02Z |
action_result.data.\*.milestone.url | string | `url` | https://api.github.com/repos/test/test/milestones/10 |
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
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
