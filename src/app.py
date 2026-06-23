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
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .client import call_github
from .consts import (
    GITHUB_CONFIG_PARAMS_REQUIRED_CONNECTIVITY,
    GITHUB_CURRENT_USER_ENDPOINT,
    GITHUB_TEST_CONNECTIVITY_FAILED_MSG,
)

logger = getLogger()


class Asset(BaseAsset):
    personal_access_token: str | None = AssetField(
        description="Personal Access Token (PAT)", sensitive=True
    )
    client_id: str | None = AssetField(description="OAuth App Client ID")
    client_secret: str | None = AssetField(
        description="OAuth App Client Secret", sensitive=True
    )


app = App(
    name="GitHub",
    app_type="information",
    logo="logo_github.svg",
    logo_dark="logo_github_dark.svg",
    product_vendor="Microsoft",
    product_name="GitHub",
    publisher="Splunk",
    appid="5553a13b-ca44-4d03-ac48-293fce874001",
    fips_compliant=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Validate the asset configuration for connectivity using supplied configuration."""

    if not asset.personal_access_token:
        raise ActionFailure(GITHUB_CONFIG_PARAMS_REQUIRED_CONNECTIVITY)

    # GET /user is the canonical connectivity probe.
    endpoint = GITHUB_CURRENT_USER_ENDPOINT

    response = call_github("GET", endpoint, asset)
    if response.status_code == 401:
        raise ActionFailure(
            f"{GITHUB_TEST_CONNECTIVITY_FAILED_MSG}: "
            "HTTP 401 — check your Personal Access Token."
        )
    # _check_response is re-exported at module level below; safe to call after full load
    from .actions._helpers import _check_response  # noqa: PLC0415
    _check_response(response)


# Import action modules — registers all @app.action() handlers as a side-effect
from .actions import (  # noqa: F401, E402
    _helpers,
    add_collaborator,
    add_labels,
    add_member,
    create_comment,
    create_issue,
    get_issue,
    list_comments,
    list_events,
    list_issues,
    list_organizations,
    list_repos,
    list_teams,
    list_users,
    make_req,
    remove_collaborator,
    remove_member,
    update_issue,
)

from .actions._helpers import (  # noqa: F401
    _check_response,
    _if_role_same,
    _paginate_all,
    _resolve_team_id,
)
from .actions.add_collaborator import AddCollaboratorParams, add_collaborator  # noqa: F401
from .actions.add_labels import AddLabelsParams, add_labels  # noqa: F401
from .actions.add_member import AddMemberParams, add_member  # noqa: F401
from .actions.create_comment import CreateCommentParams, create_comment  # noqa: F401
from .actions.create_issue import CreateIssueParams, create_issue  # noqa: F401
from .actions.get_issue import GetIssueParams, get_issue  # noqa: F401
from .actions.list_comments import ListCommentsParams, list_comments  # noqa: F401
from .actions.list_events import ListEventsParams, list_events  # noqa: F401
from .actions.list_issues import ListIssuesParams, list_issues  # noqa: F401
from .actions.list_organizations import ListOrganizationsParams, list_organizations  # noqa: F401
from .actions.list_repos import ListReposParams, list_repos  # noqa: F401
from .actions.list_teams import ListTeamsParams, list_teams  # noqa: F401
from .actions.list_users import ListUsersParams, list_users  # noqa: F401
from .actions.remove_collaborator import RemoveCollaboratorParams, remove_collaborator  # noqa: F401
from .actions.remove_member import RemoveMemberParams, remove_member  # noqa: F401
from .actions.update_issue import UpdateIssueParams, update_issue  # noqa: F401

if __name__ == "__main__":
    app.cli()
