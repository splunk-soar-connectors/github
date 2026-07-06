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
from soar_sdk.app import App

from .add_collaborator import add_collaborator
from .add_labels import add_labels
from .add_member import add_member
from .create_comment import create_comment
from .create_issue import create_issue
from .get_issue import get_issue
from .list_comments import list_comments
from .list_events import list_events
from .list_issues import list_issues
from .list_organizations import list_organizations
from .list_repos import list_repos
from .list_teams import list_teams
from .list_users import list_users
from .make_req import make_request
from .remove_collaborator import remove_collaborator
from .remove_member import remove_member
from .update_issue import update_issue


def register_actions(app: App) -> App:
    """Register all defined actions on to the provided app.

    Args:
        app (App): The app object to register actions on.

    Returns:
        App: The app object with actions registered.
    """
    app.make_request()(make_request)

    app.register_action(
        action=add_collaborator,
        description="Add user as a collaborator to repo",
        action_type="generic",
        read_only=False,
        verbose="For repo whose owner is an organization, if the user is not a member of the organization, GitHub will send an email invite to the user to join as a collaborator. Otherwise, he will be directly added as a collaborator. For repo whose owner is a user, GitHub will always send an email invite to the user to join as a collaborator. If an invite is already sent to the user, re-invite will not be sent. If the user is already a collaborator, his role will be updated.",
        render_as="table",
    )
    app.register_action(
        action=add_labels,
        description="Add label(s) to an issue on the GitHub repository",
        action_type="generic",
        read_only=False,
        verbose="Only users with push access can set labels for the issues.",
    )
    app.register_action(
        action=add_member,
        description="Add user in a team",
        action_type="generic",
        read_only=False,
        verbose="Parameter 'organization name' is mandatory if the team name is provided instead of team ID.",
        render_as="table",
    )
    app.register_action(
        action=create_comment,
        description="Create a comment for an issue on the GitHub repository",
        action_type="generic",
        read_only=False,
    )
    app.register_action(
        action=create_issue,
        description="Create an issue for the GitHub repository",
        action_type="generic",
        read_only=False,
        verbose="Only users with push access can set assignees/labels for the issues. \nAssignees/labels are silently dropped otherwise.",
        render_as="table",
    )
    app.register_action(
        action=get_issue,
        description="Retrieve an issue for the GitHub repository",
        action_type="investigate",
    )
    app.register_action(
        action=list_comments,
        description="List comments for an issue on the GitHub repository",
        action_type="investigate",
    )
    app.register_action(
        action=list_events,
        description="List events performed by a user",
        action_type="investigate",
        verbose="Action will list a maximum of 300 events. Only events from the past 90 days will be listed.",
        render_as="table",
    )
    app.register_action(
        action=list_issues,
        description="Get a list of issues for the GitHub repository",
        action_type="investigate",
        render_as="table",
    )
    app.register_action(
        action=list_organizations,
        description="List all organizations",
        action_type="investigate",
        render_as="table",
    )
    app.register_action(
        action=list_repos,
        description="List all repos of an organization",
        action_type="investigate",
        render_as="table",
    )
    app.register_action(
        action=list_teams,
        description="List all teams of an organization",
        action_type="investigate",
        render_as="table",
    )
    app.register_action(
        action=list_users,
        description="List users of an organization",
        action_type="investigate",
    )
    app.register_action(
        action=remove_collaborator,
        description="Remove user as a collaborator from the repo",
        action_type="generic",
        read_only=False,
        verbose="If the user is not a direct collaborator to the repo, any pending invitations to the user will also be deleted.",
        render_as="table",
    )
    app.register_action(
        action=remove_member,
        description="Remove user from the team",
        action_type="generic",
        read_only=False,
        verbose="Parameter 'organization name' is mandatory if the team name is provided instead of team ID.",
        render_as="table",
    )
    app.register_action(
        action=update_issue,
        description="Update an issue for the GitHub repository",
        action_type="generic",
        read_only=False,
        verbose="Only users with push access can set assignees/labels for new issues. \nAssignees/labels are silently dropped otherwise. The existing labels and assignees of the issue will be replaced with the labels and assignees provided in the respective input parameters by the user. If the to_empty parameter is checked, then, it will empty the field values of the issue (except for the title and the state of the issue) for which the parameter values are not provided or kept empty. If the to_empty parameter is not checked, then, it will simply ignore the empty parameter values from being updated on the issue.",
        render_as="table",
    )

    return app
