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
from soar_sdk.logging import getLogger

from .actions import register_actions
from .actions.test_connectivity import run_test_connectivity
from .asset import Asset
from .webhooks import register_oauth_webhook

logger = getLogger()


def create_github_app() -> App:
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

    register_oauth_webhook(app)

    @app.test_connectivity()
    def test_connectivity(soar: SOARClient, asset: Asset) -> None:
        run_test_connectivity(soar, asset, app=app)

    return register_actions(app)


app: App = create_github_app()


if __name__ == "__main__":
    app.cli()
