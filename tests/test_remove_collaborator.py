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

import importlib
from unittest.mock import Mock

import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions.remove_collaborator import RemoveCollaboratorParams

remove_module = importlib.import_module("src.actions.remove_collaborator")


def _response(*, status_code=200, data=None):
    response = Mock(status_code=status_code, is_success=status_code < 300, text="")
    response.json.return_value = data or {}
    return response


def test_remove_collaborator_fails_when_access_remains_after_delete(monkeypatch):
    monkeypatch.setattr(
        remove_module,
        "_paginate_all",
        Mock(return_value=[{"login": "octocat"}]),
    )
    call_github = Mock(
        side_effect=[
            _response(status_code=204),
            _response(data={"permission": "read"}),
        ]
    )
    monkeypatch.setattr(remove_module, "call_github", call_github)

    with pytest.raises(ActionFailure, match="through team or organization"):
        remove_module.remove_collaborator(
            RemoveCollaboratorParams(
                repo_owner="splunk", repo_name="connector", user="octocat"
            ),
            Mock(),
            Mock(),
        )


def test_remove_collaborator_fails_for_non_direct_effective_access(monkeypatch):
    monkeypatch.setattr(
        remove_module,
        "_paginate_all",
        Mock(side_effect=[[], []]),
    )
    monkeypatch.setattr(
        remove_module,
        "call_github",
        Mock(return_value=_response(data={"permission": "write"})),
    )

    with pytest.raises(ActionFailure, match='still has "write" access'):
        remove_module.remove_collaborator(
            RemoveCollaboratorParams(
                repo_owner="splunk", repo_name="connector", user="octocat"
            ),
            Mock(),
            Mock(),
        )
