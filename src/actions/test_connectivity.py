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
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from ..asset import Asset
from ..client import call_github
from ..consts import (
    GITHUB_CONFIG_PARAMS_REQUIRED_CONNECTIVITY,
    GITHUB_CURRENT_USER_ENDPOINT,
    GITHUB_MAKING_CONNECTION_MSG,
    GITHUB_TEST_CONNECTIVITY_FAILED_MSG,
    GITHUB_TEST_CONNECTIVITY_PASSED_MSG,
)
from ._helpers import _check_response

logger = getLogger()


def run_test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Validate the asset configuration for connectivity using supplied configuration."""

    logger.progress("Starting connectivity test")

    if not asset.personal_access_token:
        logger.error("No Personal Access Token configured on the asset")
        raise ActionFailure(GITHUB_CONFIG_PARAMS_REQUIRED_CONNECTIVITY)

    # GET /user is the canonical connectivity probe.
    endpoint = GITHUB_CURRENT_USER_ENDPOINT

    logger.progress(GITHUB_MAKING_CONNECTION_MSG)
    logger.debug("Sending GET request to %s", endpoint)
    response = call_github("GET", endpoint, asset)
    logger.debug("Received HTTP %s from %s", response.status_code, endpoint)

    if response.status_code == 401:
        logger.error("Authentication failed (HTTP 401) during connectivity test")
        raise ActionFailure(
            f"{GITHUB_TEST_CONNECTIVITY_FAILED_MSG}: "
            "HTTP 401 — check your Personal Access Token."
        )
    _check_response(response)

    logger.progress(GITHUB_TEST_CONNECTIVITY_PASSED_MSG)
