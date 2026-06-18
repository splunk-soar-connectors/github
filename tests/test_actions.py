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
"""Tests for implemented action handlers in src/app.py.

All GitHub API calls are mocked at the `client.call_github` boundary so no
real network traffic is made.

Strategy: call `action_fn.__wrapped__(params, asset)` directly.  The SDK
decorator wraps every handler with @wraps, so __wrapped__ is the original
function.  Calling it directly means:
  - ActionFailure propagates as a normal exception (not swallowed to a bool)
  - The return value is the actual ActionOutput, not True/False
  - The asset argument we pass is used as-is (no re-instantiation by the app)
"""

import contextlib
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from soar_sdk.exceptions import ActionFailure
import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_asset(
    *,
    personal_access_token=None,
    client_id=None,
    client_secret=None,
):
    """Return a real Asset built via model_construct (no validation, Pydantic v2)."""
    from app import Asset

    return Asset.model_construct(
        personal_access_token=personal_access_token,
        client_id=client_id,
        client_secret=client_secret,
    )


def make_response(status_code=200, json_body=None, content=True):
    resp = MagicMock()
    resp.status_code = status_code
    resp.is_success = 200 <= status_code < 300
    resp.json.return_value = json_body if json_body is not None else {}
    resp.text = str(json_body)
    resp.content = b"body" if content else b""
    return resp


def _pat_asset():
    return make_asset(personal_access_token="ghp_test")


# Minimal dicts that satisfy the Output models' required fields.
_MINIMAL_EVENT = {
    "id": "1",
    "type": "PushEvent",
    "actor": {},
    "repo": {},
    "payload": {},
    "public": True,
    "created_at": "2024-01-01T00:00:00Z",
}

_MINIMAL_USER = {
    "login": "octocat",
    "id": 1,
    "node_id": "abc",
    "avatar_url": "https://avatars.githubusercontent.com/u/1",
    "gravatar_id": "",
    "url": "https://api.github.com/users/octocat",
    "html_url": "https://github.com/octocat",
    "followers_url": "https://api.github.com/users/octocat/followers",
    "following_url": "https://api.github.com/users/octocat/following{/other_user}",
    "gists_url": "https://api.github.com/users/octocat/gists{/gist_id}",
    "starred_url": "https://api.github.com/users/octocat/starred{/owner}{/repo}",
    "subscriptions_url": "https://api.github.com/users/octocat/subscriptions",
    "organizations_url": "https://api.github.com/users/octocat/orgs",
    "repos_url": "https://api.github.com/users/octocat/repos",
    "events_url": "https://api.github.com/users/octocat/events{/privacy}",
    "received_events_url": "https://api.github.com/users/octocat/received_events",
    "type": "User",
    "site_admin": False,
}

_MINIMAL_TEAM = {
    "id": 42,
    "node_id": "abc",
    "name": "myteam",
    "slug": "myteam",
    "description": "",
    "privacy": "closed",
    "permission": "pull",
    "url": "https://api.github.com/teams/42",
    "members_url": "https://api.github.com/teams/42/members{/member}",
    "repositories_url": "https://api.github.com/teams/42/repos",
}

_MINIMAL_ISSUE = {
    "id": 100,
    "node_id": "abc",
    "url": "https://api.github.com/repos/owner/repo/issues/1",
    "repository_url": "https://api.github.com/repos/owner/repo",
    "labels_url": "https://api.github.com/repos/owner/repo/issues/1/labels{/name}",
    "comments_url": "https://api.github.com/repos/owner/repo/issues/1/comments",
    "events_url": "https://api.github.com/repos/owner/repo/issues/1/events",
    "html_url": "https://github.com/owner/repo/issues/1",
    "number": 1,
    "state": "open",
    "title": "Test issue",
    "body": "",
    "user": _MINIMAL_USER,
    "labels": [],
    "assignees": [],
    "locked": False,
    "comments": 0,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z",
    "author_association": "OWNER",
}

_MINIMAL_COMMENT = {
    "id": 1,
    "node_id": "abc",
    "url": "https://api.github.com/repos/owner/repo/issues/comments/1",
    "html_url": "https://github.com/owner/repo/issues/1#issuecomment-1",
    "body": "A comment",
    "user": _MINIMAL_USER,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z",
    "author_association": "OWNER",
}

_MINIMAL_LABEL = {
    "id": 1,
    "node_id": "abc",
    "url": "https://api.github.com/repos/owner/repo/labels/bug",
    "name": "bug",
    "color": "d73a4a",
    "default": True,
}

_MINIMAL_ADD_MEMBER_RESP = {
    "url": "https://api.github.com/teams/42/memberships/octocat",
    "role": "member",
    "state": "active",
}

_MINIMAL_COLLABORATOR = {
    **_MINIMAL_USER,
    "permissions": {"pull": True, "push": False, "admin": False},
}


# ---------------------------------------------------------------------------
# test_connectivity
# ---------------------------------------------------------------------------


class TestTestConnectivity(unittest.TestCase):
    def _run(self, asset):
        from app import test_connectivity

        # __wrapped__ is the original function before the SDK decorator
        return test_connectivity.__wrapped__(soar=MagicMock(), asset=asset)

    @patch("app.call_github")
    def test_pat_success(self, mock_call):
        mock_call.return_value = make_response(200)
        asset = make_asset(personal_access_token="ghp_x")
        self._run(asset)
        mock_call.assert_called_once_with("GET", "/user", asset)

    @patch("app.call_github")
    def test_no_credentials_raises(self, mock_call):
        asset = make_asset()
        with pytest.raises(ActionFailure):
            self._run(asset)
        mock_call.assert_not_called()

    @patch("app.call_github")
    def test_pat_401_raises(self, mock_call):
        mock_call.return_value = make_response(401)
        asset = make_asset(personal_access_token="ghp_bad")
        with pytest.raises(ActionFailure):
            self._run(asset)

    @patch("app.call_github")
    def test_github_error_response_raises(self, mock_call):
        mock_call.return_value = make_response(403)
        asset = make_asset(personal_access_token="ghp_x")
        with pytest.raises(ActionFailure):
            self._run(asset)


# ---------------------------------------------------------------------------
# list_events
# ---------------------------------------------------------------------------


class TestListEvents(unittest.TestCase):
    def _run(self, username, asset=None):
        asset = asset or _pat_asset()
        from app import ListEventsParams, list_events

        params = ListEventsParams(username=username)
        return list_events.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_calls_correct_endpoint(self, mock_call):
        asset = _pat_asset()
        mock_call.return_value = make_response(200, json_body=[])
        self._run("octocat", asset=asset)
        mock_call.assert_called_once_with(
            "GET",
            "/users/octocat/events",
            asset,
            params={"per_page": 100, "page": 1},
        )

    @patch("app.call_github")
    def test_paginates_up_to_3_pages(self, mock_call):
        # list_events stops after 3 pages regardless of fullness; assert call count
        # We don't construct ListEventsOutput — just count how many times the API was called
        full_page = [{}] * 100
        mock_call.return_value = make_response(200, json_body=full_page)
        with contextlib.suppress(Exception):
            self._run("octocat")
        assert mock_call.call_count == 3

    @patch("app.call_github")
    def test_stops_when_partial_page(self, mock_call):
        full_page = [{}] * 100
        partial_page = [{}] * 5
        mock_call.side_effect = [
            make_response(200, json_body=full_page),
            make_response(200, json_body=partial_page),
        ]
        with contextlib.suppress(Exception):
            self._run("octocat")
        assert mock_call.call_count == 2

    @patch("app.call_github")
    def test_api_error_raises(self, mock_call):
        mock_call.return_value = make_response(500, json_body={})
        with pytest.raises(ActionFailure):
            self._run("octocat")


# ---------------------------------------------------------------------------
# list_users
# ---------------------------------------------------------------------------


class TestListUsers(unittest.TestCase):
    def _run(self, org, limit=None, asset=None):
        asset = asset or _pat_asset()
        from app import ListUsersParams, list_users

        params = ListUsersParams(organization_name=org, limit=limit)
        return list_users.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_calls_correct_endpoint(self, mock_call):
        asset = _pat_asset()
        mock_call.return_value = make_response(200, json_body=[])
        self._run("myorg", asset=asset)
        mock_call.assert_called_once_with(
            "GET",
            "/orgs/myorg/members",
            asset,
            params={"per_page": 100, "page": 1},
        )

    @patch("app.call_github")
    def test_limit_respected(self, mock_call):
        mock_call.return_value = make_response(200, json_body=[_MINIMAL_USER] * 100)
        result = self._run("myorg", limit=3)
        assert len(result) == 3

    @patch("app.call_github")
    def test_api_error_raises(self, mock_call):
        mock_call.return_value = make_response(404)
        with pytest.raises(ActionFailure):
            self._run("noorg")


# ---------------------------------------------------------------------------
# list_teams
# ---------------------------------------------------------------------------


class TestListTeams(unittest.TestCase):
    def _run(self, org, limit=None, asset=None):
        asset = asset or _pat_asset()
        from app import ListTeamsParams, list_teams

        params = ListTeamsParams(organization_name=org, limit=limit)
        return list_teams.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_calls_correct_endpoint(self, mock_call):
        asset = _pat_asset()
        mock_call.return_value = make_response(200, json_body=[])
        self._run("myorg", asset=asset)
        mock_call.assert_called_once_with(
            "GET",
            "/orgs/myorg/teams",
            asset,
            params={"per_page": 100, "page": 1},
        )

    @patch("app.call_github")
    def test_returns_list_of_outputs(self, mock_call):
        mock_call.return_value = make_response(200, json_body=[_MINIMAL_TEAM])
        result = self._run("myorg")
        assert len(result) == 1
        assert result[0].name == "myteam"

    @patch("app.call_github")
    def test_limit_respected(self, mock_call):
        mock_call.return_value = make_response(200, json_body=[_MINIMAL_TEAM] * 100)
        result = self._run("myorg", limit=2)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# list_repos
# ---------------------------------------------------------------------------


class TestListRepos(unittest.TestCase):
    def _run(self, org, limit=None, asset=None):
        asset = asset or _pat_asset()
        from app import ListReposParams, list_repos

        params = ListReposParams(organization_name=org, limit=limit)
        return list_repos.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_calls_correct_endpoint(self, mock_call):
        asset = _pat_asset()
        mock_call.return_value = make_response(200, json_body=[])
        self._run("myorg", asset=asset)
        mock_call.assert_called_once_with(
            "GET",
            "/orgs/myorg/repos",
            asset,
            params={"per_page": 100, "page": 1},
        )

    @patch("app.call_github")
    def test_returns_empty_list(self, mock_call):
        mock_call.return_value = make_response(200, json_body=[])
        result = self._run("myorg")
        assert result == []


# ---------------------------------------------------------------------------
# list_organizations
# ---------------------------------------------------------------------------


class TestListOrganizations(unittest.TestCase):
    def _run(self, limit=None, asset=None):
        asset = asset or _pat_asset()
        from app import ListOrganizationsParams, list_organizations

        params = ListOrganizationsParams(limit=limit)
        return list_organizations.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_calls_correct_endpoint(self, mock_call):
        asset = _pat_asset()
        mock_call.return_value = make_response(200, json_body=[])
        self._run(asset=asset)
        mock_call.assert_called_once_with(
            "GET",
            "/user/orgs",
            asset,
            params={"per_page": 100, "page": 1},
        )


# ---------------------------------------------------------------------------
# list_issues
# ---------------------------------------------------------------------------


class TestListIssues(unittest.TestCase):
    def _run(self, owner="owner", repo="repo", limit=None, asset=None):
        asset = asset or _pat_asset()
        from app import ListIssuesParams, list_issues

        params = ListIssuesParams(repo_owner=owner, repo_name=repo, limit=limit)
        return list_issues.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_calls_correct_endpoint(self, mock_call):
        asset = _pat_asset()
        mock_call.return_value = make_response(200, json_body=[])
        self._run(asset=asset)
        mock_call.assert_called_once_with(
            "GET",
            "/repos/owner/repo/issues",
            asset,
            params={"per_page": 100, "page": 1},
        )

    @patch("app.call_github")
    def test_limit_respected(self, mock_call):
        mock_call.return_value = make_response(200, json_body=[{}] * 100)
        result = self._run(limit=1)
        assert len(result) == 1

    @patch("app.call_github")
    def test_api_error_raises(self, mock_call):
        mock_call.return_value = make_response(403)
        with pytest.raises(ActionFailure):
            self._run()


# ---------------------------------------------------------------------------
# list_comments
# ---------------------------------------------------------------------------


class TestListComments(unittest.TestCase):
    def _run(self, owner="owner", repo="repo", issue_number=1, limit=None, asset=None):
        asset = asset or _pat_asset()
        from app import ListCommentsParams, list_comments

        params = ListCommentsParams(
            repo_owner=owner, repo_name=repo, issue_number=issue_number, limit=limit
        )
        return list_comments.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_calls_correct_endpoint(self, mock_call):
        asset = _pat_asset()
        mock_call.return_value = make_response(200, json_body=[])
        self._run(issue_number=7, asset=asset)
        mock_call.assert_called_once_with(
            "GET",
            "/repos/owner/repo/issues/7/comments",
            asset,
            params={"per_page": 100, "page": 1},
        )

    @patch("app.call_github")
    def test_returns_list_of_outputs(self, mock_call):
        mock_call.return_value = make_response(200, json_body=[_MINIMAL_COMMENT])
        result = self._run()
        assert len(result) == 1
        assert result[0].body == "A comment"


# ---------------------------------------------------------------------------
# get_issue
# ---------------------------------------------------------------------------


class TestGetIssue(unittest.TestCase):
    def _run(self, owner="owner", repo="repo", issue_number=1, asset=None):
        asset = asset or _pat_asset()
        from app import GetIssueParams, get_issue

        params = GetIssueParams(
            repo_owner=owner, repo_name=repo, issue_number=issue_number
        )
        return get_issue.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_calls_correct_endpoint_and_method(self, mock_call):
        asset = _pat_asset()
        mock_call.return_value = make_response(200, json_body={})
        self._run(issue_number=42, asset=asset)
        mock_call.assert_called_once_with("GET", "/repos/owner/repo/issues/42", asset)

    @patch("app.call_github")
    def test_404_raises(self, mock_call):
        mock_call.return_value = make_response(404)
        with pytest.raises(ActionFailure):
            self._run()

    @patch("app.call_github")
    def test_issue_number_cast_to_int(self, mock_call):
        mock_call.return_value = make_response(200, json_body={})
        self._run(issue_number=5.0)
        args = mock_call.call_args
        assert "/issues/5" in args[0][1]


# ---------------------------------------------------------------------------
# create_issue
# ---------------------------------------------------------------------------


class TestCreateIssue(unittest.TestCase):
    def _run(
        self,
        owner="owner",
        repo="repo",
        title="T",
        body=None,
        assignees=None,
        labels=None,
        asset=None,
    ):
        asset = asset or _pat_asset()
        from app import CreateIssueParams, create_issue

        params = CreateIssueParams(
            repo_owner=owner,
            repo_name=repo,
            issue_title=title,
            issue_body=body,
            assignees=assignees,
            labels=labels,
        )
        return create_issue.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_uses_post_method(self, mock_call):
        mock_call.return_value = make_response(201, json_body={})
        self._run()
        assert mock_call.call_args[0][0] == "POST"

    @patch("app.call_github")
    def test_calls_correct_endpoint(self, mock_call):
        mock_call.return_value = make_response(201, json_body={})
        self._run()
        assert mock_call.call_args[0][1] == "/repos/owner/repo/issues"

    @patch("app.call_github")
    def test_payload_contains_title_and_empty_lists(self, mock_call):
        mock_call.return_value = make_response(201, json_body={})
        self._run(title="My Issue")
        _, kwargs = mock_call.call_args
        assert kwargs["json"]["title"] == "My Issue"
        assert kwargs["json"]["assignees"] == []
        assert kwargs["json"]["labels"] == []

    @patch("app.call_github")
    def test_assignees_and_labels_parsed_from_csv(self, mock_call):
        mock_call.return_value = make_response(201, json_body={})
        self._run(assignees="alice, bob", labels="bug, enhancement")
        _, kwargs = mock_call.call_args
        assert kwargs["json"]["assignees"] == ["alice", "bob"]
        assert kwargs["json"]["labels"] == ["bug", "enhancement"]

    @patch("app.call_github")
    def test_api_error_raises(self, mock_call):
        mock_call.return_value = make_response(422)
        with pytest.raises(ActionFailure):
            self._run()

    @patch("app.call_github")
    def test_called_exactly_once(self, mock_call):
        mock_call.return_value = make_response(201, json_body={})
        self._run()
        mock_call.assert_called_once()


# ---------------------------------------------------------------------------
# update_issue
# ---------------------------------------------------------------------------


class TestUpdateIssue(unittest.TestCase):
    def _run(
        self,
        owner="owner",
        repo="repo",
        issue_number=1,
        state=None,
        title=None,
        body=None,
        assignees=None,
        labels=None,
        to_empty=None,
        asset=None,
    ):
        asset = asset or _pat_asset()
        from app import UpdateIssueParams, update_issue

        params = UpdateIssueParams(
            repo_owner=owner,
            repo_name=repo,
            issue_number=issue_number,
            state=state,
            issue_title=title,
            issue_body=body,
            assignees=assignees,
            labels=labels,
            to_empty=to_empty,
        )
        return update_issue.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_uses_patch_method(self, mock_call):
        mock_call.return_value = make_response(200, json_body={})
        self._run()
        assert mock_call.call_args[0][0] == "PATCH"

    @patch("app.call_github")
    def test_calls_correct_endpoint(self, mock_call):
        mock_call.return_value = make_response(200, json_body={})
        self._run(issue_number=3)
        assert mock_call.call_args[0][1] == "/repos/owner/repo/issues/3"

    @patch("app.call_github")
    def test_state_included_in_payload(self, mock_call):
        mock_call.return_value = make_response(200, json_body={})
        self._run(state="closed")
        _, kwargs = mock_call.call_args
        assert kwargs["json"]["state"] == "closed"

    @patch("app.call_github")
    def test_empty_params_excluded_when_to_empty_false(self, mock_call):
        mock_call.return_value = make_response(200, json_body={})
        self._run(to_empty=False)
        _, kwargs = mock_call.call_args
        assert "body" not in kwargs["json"]
        assert "assignees" not in kwargs["json"]
        assert "labels" not in kwargs["json"]

    @patch("app.call_github")
    def test_empty_params_included_when_to_empty_true(self, mock_call):
        mock_call.return_value = make_response(200, json_body={})
        self._run(to_empty=True)
        _, kwargs = mock_call.call_args
        assert "body" in kwargs["json"]
        assert "assignees" in kwargs["json"]
        assert "labels" in kwargs["json"]

    @patch("app.call_github")
    def test_api_error_raises(self, mock_call):
        mock_call.return_value = make_response(404)
        with pytest.raises(ActionFailure):
            self._run()

    @patch("app.call_github")
    def test_title_always_included_when_provided(self, mock_call):
        mock_call.return_value = make_response(200, json_body={})
        self._run(title="New Title")
        _, kwargs = mock_call.call_args
        assert kwargs["json"]["title"] == "New Title"


# ---------------------------------------------------------------------------
# create_comment
# ---------------------------------------------------------------------------


class TestCreateComment(unittest.TestCase):
    def _run(
        self,
        owner="owner",
        repo="repo",
        issue_number=1,
        comment_body="hello",
        asset=None,
    ):
        asset = asset or _pat_asset()
        from app import CreateCommentParams, create_comment

        params = CreateCommentParams(
            repo_owner=owner,
            repo_name=repo,
            issue_number=issue_number,
            comment_body=comment_body,
        )
        return create_comment.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_uses_post_method(self, mock_call):
        mock_call.return_value = make_response(201, json_body=_MINIMAL_COMMENT)
        self._run()
        assert mock_call.call_args[0][0] == "POST"

    @patch("app.call_github")
    def test_calls_correct_endpoint(self, mock_call):
        mock_call.return_value = make_response(201, json_body=_MINIMAL_COMMENT)
        self._run(issue_number=9)
        assert mock_call.call_args[0][1] == "/repos/owner/repo/issues/9/comments"

    @patch("app.call_github")
    def test_payload_contains_body(self, mock_call):
        mock_call.return_value = make_response(201, json_body=_MINIMAL_COMMENT)
        self._run(comment_body="LGTM")
        _, kwargs = mock_call.call_args
        assert kwargs["json"] == {"body": "LGTM"}

    @patch("app.call_github")
    def test_called_exactly_once(self, mock_call):
        mock_call.return_value = make_response(201, json_body=_MINIMAL_COMMENT)
        self._run()
        mock_call.assert_called_once()

    @patch("app.call_github")
    def test_api_error_raises(self, mock_call):
        mock_call.return_value = make_response(403)
        with pytest.raises(ActionFailure):
            self._run()


# ---------------------------------------------------------------------------
# add_labels
# ---------------------------------------------------------------------------


class TestAddLabels(unittest.TestCase):
    def _run(
        self, owner="owner", repo="repo", issue_number=1, labels="bug", asset=None
    ):
        asset = asset or _pat_asset()
        from app import AddLabelsParams, add_labels

        params = AddLabelsParams(
            repo_owner=owner,
            repo_name=repo,
            issue_number=issue_number,
            labels=labels,
        )
        return add_labels.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_uses_post_method(self, mock_call):
        mock_call.return_value = make_response(200, json_body=[_MINIMAL_LABEL])
        self._run()
        assert mock_call.call_args[0][0] == "POST"

    @patch("app.call_github")
    def test_calls_correct_endpoint(self, mock_call):
        mock_call.return_value = make_response(200, json_body=[_MINIMAL_LABEL])
        self._run(issue_number=5)
        assert mock_call.call_args[0][1] == "/repos/owner/repo/issues/5/labels"

    @patch("app.call_github")
    def test_csv_labels_parsed_correctly(self, mock_call):
        mock_call.return_value = make_response(
            200, json_body=[_MINIMAL_LABEL, _MINIMAL_LABEL]
        )
        self._run(labels="bug, enhancement, help wanted")
        _, kwargs = mock_call.call_args
        assert kwargs["json"]["labels"] == ["bug", "enhancement", "help wanted"]

    @patch("app.call_github")
    def test_returns_list_of_label_outputs(self, mock_call):
        mock_call.return_value = make_response(200, json_body=[_MINIMAL_LABEL])
        result = self._run()
        assert len(result) == 1
        assert result[0].name == "bug"

    @patch("app.call_github")
    def test_api_error_raises(self, mock_call):
        mock_call.return_value = make_response(404)
        with pytest.raises(ActionFailure):
            self._run()


# ---------------------------------------------------------------------------
# add_member
# ---------------------------------------------------------------------------


class TestAddMember(unittest.TestCase):
    def _run(self, team="99", user="octocat", role=None, org=None, asset=None):
        asset = asset or _pat_asset()
        from app import AddMemberParams, add_member

        params = AddMemberParams(team=team, user=user, role=role, organization_name=org)
        return add_member.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_numeric_team_id_used_directly_no_resolve(self, mock_call):
        # First call: GET members (empty → user not found), second: PUT add member
        mock_call.side_effect = [
            make_response(200, json_body=[]),  # GET members
            make_response(200, json_body=_MINIMAL_ADD_MEMBER_RESP),  # PUT
        ]
        self._run(team="99")
        first_call = mock_call.call_args_list[0]
        assert first_call[0][0] == "GET"
        assert "/teams/99/members" in first_call[0][1]

    @patch("app.call_github")
    def test_put_to_add_member_endpoint(self, mock_call):
        mock_call.side_effect = [
            make_response(200, json_body=[]),
            make_response(200, json_body=_MINIMAL_ADD_MEMBER_RESP),
        ]
        self._run(team="42", user="octocat")
        put_call = mock_call.call_args_list[-1]
        assert put_call[0][0] == "PUT"
        assert "/teams/42/memberships/octocat" in put_call[0][1]

    @patch("app.call_github")
    def test_role_sent_in_payload(self, mock_call):
        mock_call.side_effect = [
            make_response(200, json_body=[]),
            make_response(200, json_body=_MINIMAL_ADD_MEMBER_RESP),
        ]
        self._run(team="42", role="Maintainer")
        put_call = mock_call.call_args_list[-1]
        assert put_call[1]["json"]["role"] == "maintainer"

    @patch("app.call_github")
    def test_member_already_exists_returns_without_put(self, mock_call):
        existing = {**_MINIMAL_USER, "role": "member", "state": "active"}
        mock_call.return_value = make_response(200, json_body=[existing])
        self._run(team="42", user="octocat")
        # Should not have issued a PUT
        for c in mock_call.call_args_list:
            assert c[0][0] != "PUT"

    @patch("app.call_github")
    def test_team_name_requires_org(self, mock_call):
        with pytest.raises(ActionFailure):
            self._run(team="myteam", org=None)

    @patch("app.call_github")
    def test_team_name_resolved_via_org(self, mock_call):
        teams_page = [_MINIMAL_TEAM]  # id=42, name="myteam"
        members_page = []
        put_resp = _MINIMAL_ADD_MEMBER_RESP
        mock_call.side_effect = [
            make_response(200, json_body=teams_page),  # paginate teams
            make_response(200, json_body=members_page),  # paginate members
            make_response(200, json_body=put_resp),  # PUT
        ]
        result = self._run(team="myteam", org="myorg")
        # Verify team resolution called teams endpoint
        first = mock_call.call_args_list[0]
        assert "/orgs/myorg/teams" in first[0][1]
        assert result.role == "member"

    @patch("app.call_github")
    def test_invalid_team_name_raises(self, mock_call):
        mock_call.return_value = make_response(200, json_body=[_MINIMAL_TEAM])
        with pytest.raises(ActionFailure):
            self._run(team="doesnotexist", org="myorg")


# ---------------------------------------------------------------------------
# remove_member
# ---------------------------------------------------------------------------


class TestRemoveMember(unittest.TestCase):
    def _run(self, team="42", user="octocat", org=None, asset=None):
        asset = asset or _pat_asset()
        from app import RemoveMemberParams, remove_member

        params = RemoveMemberParams(team=team, user=user, organization_name=org)
        return remove_member.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_deletes_direct_member(self, mock_call):
        member = {**_MINIMAL_USER, "login": "octocat"}
        mock_call.side_effect = [
            make_response(200, json_body=[member]),  # GET members
            make_response(204, json_body={}),  # DELETE
        ]
        self._run()
        delete_call = mock_call.call_args_list[-1]
        assert delete_call[0][0] == "DELETE"
        assert "/teams/42/memberships/octocat" in delete_call[0][1]

    @patch("app.call_github")
    def test_deletes_pending_invitation(self, mock_call):
        invite = {**_MINIMAL_USER, "login": "octocat"}
        mock_call.side_effect = [
            make_response(200, json_body=[]),  # GET members (empty)
            make_response(200, json_body=[invite]),  # GET invitations
            make_response(204, json_body={}),  # DELETE
        ]
        self._run()
        delete_call = mock_call.call_args_list[-1]
        assert delete_call[0][0] == "DELETE"

    @patch("app.call_github")
    def test_user_not_found_returns_without_delete(self, mock_call):
        mock_call.side_effect = [
            make_response(200, json_body=[]),  # members empty
            make_response(200, json_body=[]),  # invitations empty
        ]
        self._run()
        for c in mock_call.call_args_list:
            assert c[0][0] != "DELETE"


# ---------------------------------------------------------------------------
# remove_collaborator
# ---------------------------------------------------------------------------


class TestRemoveCollaborator(unittest.TestCase):
    def _run(self, owner="owner", repo="repo", user="octocat", asset=None):
        asset = asset or _pat_asset()
        from app import RemoveCollaboratorParams, remove_collaborator

        params = RemoveCollaboratorParams(repo_owner=owner, repo_name=repo, user=user)
        return remove_collaborator.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_removes_direct_collaborator(self, mock_call):
        collab = {**_MINIMAL_COLLABORATOR, "login": "octocat"}
        mock_call.side_effect = [
            make_response(200, json_body=[collab]),  # list collaborators
            make_response(204, json_body={}),  # DELETE
        ]
        result = self._run()
        delete_call = mock_call.call_args_list[-1]
        assert delete_call[0][0] == "DELETE"
        assert "/repos/owner/repo/collaborators/octocat" in delete_call[0][1]
        assert not result.invite_deleted

    @patch("app.call_github")
    def test_deletes_pending_invitation(self, mock_call):
        invite = {"id": 7, "invitee": {"login": "octocat"}}
        mock_call.side_effect = [
            make_response(200, json_body=[]),  # no direct collaborators
            make_response(200, json_body=[invite]),  # pending invitations
            make_response(204, json_body={}),  # DELETE invitation
        ]
        result = self._run()
        assert result.invite_deleted
        delete_call = mock_call.call_args_list[-1]
        assert "/repos/owner/repo/invitations/7" in delete_call[0][1]

    @patch("app.call_github")
    def test_user_not_found_returns_invite_deleted_false(self, mock_call):
        mock_call.side_effect = [
            make_response(200, json_body=[]),  # no collaborators
            make_response(200, json_body=[]),  # no invitations
        ]
        result = self._run()
        assert not result.invite_deleted


# ---------------------------------------------------------------------------
# add_collaborator
# ---------------------------------------------------------------------------


class TestAddCollaborator(unittest.TestCase):
    def _run(
        self,
        owner="owner",
        repo="repo",
        user="octocat",
        role="Push",
        override=None,
        asset=None,
    ):
        asset = asset or _pat_asset()
        from app import AddCollaboratorParams, add_collaborator

        params = AddCollaboratorParams(
            repo_owner=owner, repo_name=repo, user=user, role=role, override=override
        )
        return add_collaborator.__wrapped__(params, asset)

    @patch("app.call_github")
    def test_adds_new_collaborator_with_put(self, mock_call):
        # No direct collaborators, no pending invitations → PUT
        mock_call.side_effect = [
            make_response(200, json_body=[]),  # collaborators
            make_response(200, json_body=[]),  # invitations
            make_response(
                204, json_body={}, content=False
            ),  # PUT (204 = directly added)
        ]
        result = self._run()
        put_call = mock_call.call_args_list[-1]
        assert put_call[0][0] == "PUT"
        assert "/repos/owner/repo/collaborators/octocat" in put_call[0][1]
        assert result.collaborator_added

    @patch("app.call_github")
    def test_invitation_sent_on_201(self, mock_call):
        invite_body = {
            "id": 1,
            "invite_sent": True,
            "collaborator_added": False,
            "html_url": "https://github.com/owner/repo/invitations",
            "created_at": "2024-01-01T00:00:00Z",
            "permissions": "write",
        }
        mock_call.side_effect = [
            make_response(200, json_body=[]),  # collaborators
            make_response(200, json_body=[]),  # invitations
            make_response(201, json_body=invite_body),  # PUT → 201 invitation
        ]
        result = self._run()
        assert result.invite_sent

    @patch("app.call_github")
    def test_same_role_collaborator_returns_no_op(self, mock_call):
        collab = {
            **_MINIMAL_COLLABORATOR,
            "login": "octocat",
            "permissions": {"pull": True, "push": False, "admin": False},
        }
        mock_call.return_value = make_response(200, json_body=[collab])
        # role=Pull means pull=True, push=False, admin=False → same
        result = self._run(role="Pull")
        assert not result.invite_sent
        assert not result.collaborator_added

    @patch("app.call_github")
    def test_different_role_without_override_raises(self, mock_call):
        collab = {
            **_MINIMAL_COLLABORATOR,
            "login": "octocat",
            "permissions": {"pull": True, "push": False, "admin": False},
        }
        mock_call.return_value = make_response(200, json_body=[collab])
        with pytest.raises(ActionFailure):
            self._run(role="Push", override=False)

    @patch("app.call_github")
    def test_role_sent_in_put_payload(self, mock_call):
        mock_call.side_effect = [
            make_response(200, json_body=[]),
            make_response(200, json_body=[]),
            make_response(204, json_body={}, content=False),
        ]
        self._run(role="Push")
        put_call = mock_call.call_args_list[-1]
        assert put_call[1]["json"]["permission"] == "push"


# ---------------------------------------------------------------------------
# _paginate_all  (shared helper)
# ---------------------------------------------------------------------------


class TestPaginateAll(unittest.TestCase):
    @patch("app.call_github")
    def test_returns_all_pages(self, mock_call):
        from app import _paginate_all

        asset = _pat_asset()
        full = [{"id": i} for i in range(100)]
        partial = [{"id": 200}]
        mock_call.side_effect = [
            make_response(200, json_body=full),
            make_response(200, json_body=partial),
        ]
        result = _paginate_all("/some/endpoint", asset)
        assert len(result) == 101
        assert mock_call.call_count == 2

    @patch("app.call_github")
    def test_limit_stops_early(self, mock_call):
        from app import _paginate_all

        mock_call.return_value = make_response(
            200, json_body=[{"id": i} for i in range(100)]
        )
        result = _paginate_all("/ep", _pat_asset(), limit=5)
        assert len(result) == 5

    @patch("app.call_github")
    def test_dict_response_wrapped_in_list(self, mock_call):
        from app import _paginate_all

        mock_call.return_value = make_response(200, json_body={"id": 1})
        result = _paginate_all("/ep", _pat_asset())
        assert len(result) == 1

    @patch("app.call_github")
    def test_api_error_raises(self, mock_call):
        from app import _paginate_all

        mock_call.return_value = make_response(500)
        with pytest.raises(ActionFailure):
            _paginate_all("/ep", _pat_asset())


if __name__ == "__main__":
    unittest.main()
