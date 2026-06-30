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
"""Shared fixtures for GitHub SOAR app tests."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Ensure src/ is on the path so tests can import app, client, consts directly.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def make_asset(
    *,
    personal_access_token=None,
    client_id=None,
    client_secret=None,
):
    """Return a mock Asset with the given credential fields set."""
    asset = MagicMock()
    asset.personal_access_token = personal_access_token
    asset.client_id = client_id
    asset.client_secret = client_secret
    return asset


def make_response(status_code=200, json_body=None, content=True):
    """Return a mock httpx.Response-like object."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.is_success = 200 <= status_code < 300
    resp.json.return_value = json_body if json_body is not None else {}
    resp.text = str(json_body)
    # Simulate truthy content only when content=True
    resp.content = b"body" if content else b""
    return resp


@pytest.fixture
def pat_asset():
    """Asset configured with a Personal Access Token."""
    return make_asset(personal_access_token="ghp_testtoken")


@pytest.fixture
def soar():
    """Stub SOARClient (not used by any implemented action, but required by test_connectivity)."""
    return MagicMock()
