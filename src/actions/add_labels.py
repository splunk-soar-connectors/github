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
    GITHUB_ENDPOINT_LABELS,
    GITHUB_LABEL_ADDED_MSG,
    GITHUB_REQUEST_POST,
)
from ._helpers import _check_response

logger = getLogger()

class AddLabelsParams(Params):
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
    labels: str = Param(
        description="Comma-separated list of labels to add to the issue"
    )


class AddLabelsOutput(ActionOutput):
    color: str = OutputField(example_values=["ededed"])
    default: bool
    id: float = OutputField(example_values=[1454479580])
    name: str = OutputField(example_values=["app-testing"])
    node_id: str = OutputField(
        example_values=["MDU6TGFiZWwxNDU0NDc5NTgw"]  # pragma: allowlist secret
    )
    url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.github.com/repos/repoowner/TestingAPI/labels/app-testing"
        ],
    )


@app.action(
    description="Add label(s) to an issue on the GitHub repository",
    action_type="generic",
    read_only=False,
    verbose="Only users with push access can set labels for the issues.",
)
def add_labels(
    params: AddLabelsParams, soar: SOARClient, asset: Asset
) -> list[AddLabelsOutput]:
    labels = [label.strip() for label in params.labels.split(",") if label.strip()]

    endpoint = GITHUB_ENDPOINT_LABELS.format(
        repo_owner=params.repo_owner,
        repo_name=params.repo_name,
        issue_number=int(params.issue_number),
    )
    response = call_github(
        GITHUB_REQUEST_POST.upper(), endpoint, asset, json={"labels": labels}
    )
    _check_response(response)
    soar.set_message(
        GITHUB_LABEL_ADDED_MSG.format(
            labels=",".join(labels), issue_number=int(params.issue_number)
        )
    )
    return [AddLabelsOutput(**label) for label in response.json()]

