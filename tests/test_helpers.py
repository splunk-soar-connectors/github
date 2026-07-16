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

from src.actions._helpers import _format_endpoint


def test_format_endpoint_encodes_path_delimiters():
    endpoint = _format_endpoint(
        "/repos/{owner}/{repo}/issues", owner="splunk", repo="target/contents/x?#"
    )

    assert endpoint == "/repos/splunk/target%2Fcontents%2Fx%3F%23/issues"
