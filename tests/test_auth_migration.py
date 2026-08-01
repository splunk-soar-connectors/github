# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
from pathlib import Path
from types import SimpleNamespace

from src.auth import _migrate_legacy_oauth_state


class Backend:
    def __init__(self, state, app_dir):
        self.state = state
        self.app_dir = app_dir

    def load_state(self):
        return json.loads(json.dumps(self.state))

    def save_state(self, state):
        self.state = json.loads(json.dumps(state))

    def get_app_dir(self):
        return str(self.app_dir)

    def load_state_from_file(self, asset_id):
        return json.loads((self.app_dir / f"{asset_id}_state.json").read_text())


class AuthState:
    asset_id = "42"

    def __init__(self, backend):
        self.backend = backend

    def get_all(self):
        return json.loads(json.dumps(self.backend.state.get("auth", {})))

    def put_all(self, state):
        self.backend.state["auth"] = json.loads(json.dumps(state))


def test_migrate_legacy_oauth_state_moves_token_and_removes_raw_copies(tmp_path):
    legacy = {
        "token": {"access_token": "legacy-token", "scope": "repo", "token_type": "bearer"},
        "code": "legacy-code",
        "redirect_uri": "https://soar.example/result",
        "authorization_url": "https://github.com/login/oauth/authorize?state=42",
        "unrelated": {"keep": True},
    }
    backend = Backend(json.loads(json.dumps(legacy)), tmp_path)
    legacy_file = Path(tmp_path) / "42_state.json"
    legacy_file.write_text(json.dumps(legacy))
    asset = SimpleNamespace(
        client_id="client-id",
        auth_state=AuthState(backend),
    )

    _migrate_legacy_oauth_state(asset)

    assert backend.state["unrelated"] == {"keep": True}
    assert not set(legacy).intersection(backend.state) - {"unrelated"}
    oauth = backend.state["auth"]["oauth"]
    assert oauth["client_id"] == "client-id"
    assert oauth["token"]["access_token"] == "legacy-token"
    assert not legacy_file.exists()


def test_migrate_legacy_oauth_state_discards_invalid_token(tmp_path):
    backend = Backend({"token": {"scope": "repo"}, "code": "legacy-code"}, tmp_path)
    asset = SimpleNamespace(client_id="client-id", auth_state=AuthState(backend))

    _migrate_legacy_oauth_state(asset)

    assert "token" not in backend.state
    assert "code" not in backend.state
    assert "auth" not in backend.state


def test_migration_does_not_overwrite_existing_sdk_auth_state(tmp_path):
    current_oauth = {"client_id": "client-id", "token": {"access_token": "current-token"}}
    backend = Backend(
        {
            "auth": {"oauth": current_oauth},
            "token": {"access_token": "legacy-token"},
        },
        tmp_path,
    )
    asset = SimpleNamespace(client_id="client-id", auth_state=AuthState(backend))

    _migrate_legacy_oauth_state(asset)

    assert backend.state["auth"]["oauth"] == current_oauth
    assert "token" not in backend.state
