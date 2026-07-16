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

from unittest.mock import Mock

import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions import _helpers
from src.actions._helpers import _format_endpoint


def test_format_endpoint_encodes_path_delimiters():
    endpoint = _format_endpoint(
        "/repos/{owner}/{repo}/issues", owner="splunk", repo="target/contents/x?#"
    )

    assert endpoint == "/repos/splunk/target%2Fcontents%2Fx%3F%23/issues"


def test_paginate_all_stops_at_page_safety_limit(monkeypatch):
    response = Mock(is_success=True)
    response.json.return_value = [{}] * 100
    call_github = Mock(return_value=response)
    monkeypatch.setattr(_helpers, "call_github", call_github)
    monkeypatch.setattr(_helpers, "GITHUB_PAGINATION_MAX_PAGES", 2)

    with pytest.raises(ActionFailure, match="2-page safety limit"):
        _helpers._paginate_all("/items", Mock())

    assert call_github.call_count == 2
