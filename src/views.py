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
from typing import Any

from soar_sdk.views.template_renderer import get_template_renderer, get_templates_dir


def _get_ctx_result(result: Any, provides: str) -> dict | None:
    """Build a template context dict from a single ActionResult."""
    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx: dict = {
        "check_param": len(list(param.keys())) > 1,
        "param": param,
        "action_name": provides,
        "status": "success" if result.get_status() else "failed",
    }
    if summary:
        ctx["summary"] = summary

    ctx["data"] = data if data else {}
    return ctx


_TEMPLATE_MAP: dict[str, str] = {
    "list events": "github_list_events.html",
    "list issues": "github_list_issues.html",
    "create issue": "github_update_issue.html",
    "update issue": "github_update_issue.html",
    "add collaborator": "github_add_collaborator.html",
    "remove collaborator": "github_remove_collaborator.html",
    "add member": "github_add_member.html",
    "remove member": "github_remove_member.html",
    "list teams": "github_list_teams.html",
    "list repos": "github_list_repos.html",
    "list organizations": "github_list_organizations.html",
}


def display_view(provides: str, all_app_runs: list, context: dict) -> str:
    """Entry point called by Splunk SOAR for custom action views.

    Mirrors the legacy github_view.display_view but renders via Jinja2
    instead of Django.  Returns a fully-rendered HTML string; SOAR treats
    any string return as prerendered HTML when context["prerender"] is True.
    """
    results: list[dict] = []
    for _summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if ctx_result:
                results.append(ctx_result)

    context["results"] = results

    template_name = _TEMPLATE_MAP.get(provides)
    if not template_name:
        return ""

    templates_dir = get_templates_dir(globals())
    renderer = get_template_renderer("jinja", templates_dir)
    html = renderer.render_template(template_name, context)
    context["prerender"] = True
    return html
