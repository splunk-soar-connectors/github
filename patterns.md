# Splunk SOAR SDK Migration Patterns

Generic patterns extracted from the GitHub app SDK-native migration. Apply these to any Splunk SOAR app being migrated from the legacy connector model to `splunk-soar-sdk` 3.22+.

______________________________________________________________________

## Pattern 1: SDK-Native Asset

**What changed:** Replace the legacy `BaseConnector` credential attributes and `get_config()` calls with a typed `BaseAsset` subclass.

```python
# src/asset.py
from soar_sdk.asset import AssetField, BaseAsset

class Asset(BaseAsset):
    personal_access_token: str | None = AssetField(
        description="Personal Access Token (PAT)", sensitive=True
    )
    client_id: str | None = AssetField(description="OAuth App Client ID")
    client_secret: str | None = AssetField(
        description="OAuth App Client Secret", sensitive=True
    )
```

**Rules:**

- One `Asset` class per app, in a dedicated `src/asset.py`.
- `AssetField(sensitive=True)` for any token/secret — the SDK masks it in logs.
- All fields `Optional` (` | None`) with `None` default — presence is validated at auth resolution time, not at asset definition time.
- The `Asset` instance is injected by the SDK into every action handler as the third parameter.

______________________________________________________________________

## Pattern 2: SDK-Native Auth Module

**What changed:** Replace manual `Authorization` header construction with SDK auth primitives. Auth resolution belongs in its own `src/auth.py`, not scattered across actions.

```python
# src/auth.py
from soar_sdk.auth import (
    AuthorizationCodeFlow, OAuthBearerAuth, OAuthConfig,
    SOARAssetOAuthClient, StaticTokenAuth,
)
from soar_sdk.exceptions import ActionFailure

def resolve_<app>_auth(asset: Asset) -> httpx.Auth:
    """Priority: PAT first, OAuth second, fail with ActionFailure if neither."""
    if asset.personal_access_token:
        return StaticTokenAuth(asset.personal_access_token)
    if asset.client_id and asset.client_secret:
        oauth_cfg = OAuthConfig(
            client_id=asset.client_id,
            client_secret=asset.client_secret,
            authorization_endpoint=AUTHORIZE_ENDPOINT,
            token_endpoint=TOKEN_ENDPOINT,
            scope=SCOPE,
        )
        client = SOARAssetOAuthClient(oauth_cfg, asset.auth_state)
        return OAuthBearerAuth(client, auto_refresh=True)
    raise ActionFailure(CONFIG_PARAMS_REQUIRED_MSG)
```

**Rules:**

- `StaticTokenAuth(token)` → emits `Authorization: Bearer <token>`.
- `OAuthBearerAuth(..., auto_refresh=True)` → reads token from `asset.auth_state`, transparently refreshes on 401.
- `AuthorizationCodeFlow` is only needed for the OAuth kick-off action (e.g. `test_connectivity` triggering user authorization). It is NOT used on every request.
- `resolve_<app>_auth()` raises `ActionFailure` (not a bare exception) so SOAR displays a clean error rather than a traceback.
- The return type is `httpx.Auth` — pass it directly to `httpx.Client(auth=...)`.

______________________________________________________________________

## Pattern 3: Single HTTP Client Function

**What changed:** Replace `_make_rest_call` / `requests` with a single `call_<app>` function using `httpx`.

```python
# src/client.py
import httpx
from soar_sdk.exceptions import ActionFailure
from .auth import resolve_<app>_auth
from .consts import API_BASE_URL

DEFAULT_HEADERS: dict[str, str] = {
    "Accept": "application/vnd.github+json",       # adjust per API
    "X-GitHub-Api-Version": "2022-11-28",          # adjust per API
}

def call_<app>(
    method: str,
    endpoint: str,
    asset,
    *,
    params: dict | None = None,
    json: dict | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 30.0,
    verify: bool = True,
) -> httpx.Response:
    url = f"{API_BASE_URL}{endpoint}"
    headers = {**DEFAULT_HEADERS, **(extra_headers or {})}
    auth = resolve_<app>_auth(asset)   # raises ActionFailure if unconfigured
    try:
        with httpx.Client(timeout=timeout, verify=verify) as client:
            return client.request(method=method, url=url, auth=auth,
                                  headers=headers, params=params, json=json)
    except httpx.RequestError as exc:
        raise ActionFailure(f"Error connecting to API: {exc}") from exc
    except Exception as exc:
        raise ActionFailure(f"Unexpected error: {exc}") from exc
```

**Rules:**

- Single function, all actions call it. Never construct `httpx.Client` inside action handlers.
- Always wrap network errors as `ActionFailure` — the SDK catches this and marks the action failed with a clean message.
- `verify=True` by default; expose it as a param if your asset has a "verify SSL" checkbox.
- `timeout` default 30s; increase for bulk/slow endpoints.

______________________________________________________________________

## Pattern 4: Action Registration — One File Per Action

**What changed:** Replace monolithic `handle_action` / `if action == "..."` dispatch with `@app.action()` decorated functions, one per file.

```
src/
  app.py                  ← thin shell: defines Asset, App, calls register_actions()
  auth.py                 ← auth resolution
  client.py               ← HTTP layer
  consts.py               ← all string constants
  asset.py                ← Asset class
  actions/
    __init__.py            ← imports all action modules (side-effects), exposes register_actions()
    list_things.py         ← Params + Output + handler for one action
    create_thing.py
    _helpers.py            ← shared: _paginate_all, _check_response, etc.
```

**`src/actions/__init__.py` pattern:**

```python
from soar_sdk.app import App
from .list_things import list_things
from .create_thing import create_thing
# ... all action imports

def register_actions(app: App) -> App:
    app.register_action(
        action=list_things,
        description="List all things",
        action_type="investigate",
        render_as="table",
    )
    app.register_action(
        action=create_thing,
        description="Create a thing",
        action_type="generic",
        read_only=False,
        verbose="Optional long-form notes for the SOAR UI.",
        render_as="table",
    )
    return app
```

**Key `register_action` parameters:**
| Parameter | Values | Notes |
|---|---|---|
| `action_type` | `"investigate"` / `"generic"` | investigate = read-only; generic = mutation |
| `read_only` | `True` / `False` | Set `False` on all mutations |
| `render_as` | `"table"` / `"json"` / `"custom"` | See Pattern 5 |
| `verbose` | str | Extended description shown in SOAR action UI |
| `view_handler` | callable | **Avoid** — use `render_as` instead (see Pattern 5) |

______________________________________________________________________

## Pattern 5: SDK-Native Table Rendering (no custom HTML)

**What changed:** Remove `view_handler=display_view` + Jinja templates entirely. Use `render_as="table"` driven by `OutputField(column_name=...)` metadata.

### Why custom view_handler fails

`register_action(..., view_handler=fn)` force-wraps `fn` with the SDK's `ViewFunctionParser`, which requires an `ActionOutput`-annotated parameter. The legacy `display_view(provides, all_app_runs, context)` signature has none, causing:

```
Error in component function 'display_view':
Could not auto-detect ActionOutput class from function signature of display_view
```

Even with a correctly-typed handler, custom prerender HTML renders as a **blank widget** on some SOAR instance versions. `render_as="table"` bypasses the custom render path entirely and uses SOAR's built-in generic table widget.

### How it works

SOAR reads your manifest's `render: {type: table}` block (generated from `render_as="table"`) + the `column_name` / `column_order` / `cef_types` metadata on each `OutputField`. Its own front-end draws the table — no HTML from your app is involved.

### Output class structure for table actions

```python
from soar_sdk.action_results import ActionOutput, OutputField
from pydantic import model_validator

class ListThingsOutput(ActionOutput):
    # ── Column fields first (order = display order in the table) ──
    id: float = OutputField(
        cef_types=["thing id"], example_values=[42], column_name="Thing ID"
    )
    name: str = OutputField(
        example_values=["my-thing"], column_name="Thing Name"
    )
    status: str = OutputField(
        example_values=["active"], column_name="Status"
    )
    owner_login: str | None = OutputField(          # flat field promoted from nested API obj
        cef_types=["username"], example_values=["alice"], column_name="Owner"
    )
    # ── Non-column fields after ──
    owner: OwnerOutput | None                        # original nested object, not a column
    created_at: str = OutputField(example_values=["2024-01-01T00:00:00Z"])
    url: str = OutputField(cef_types=["url"], example_values=["https://..."])

    @model_validator(mode="before")
    @classmethod
    def _flatten_owner(cls, values):
        """Promote nested owner.login → top-level owner_login column."""
        if isinstance(values, dict) and isinstance(values.get("owner"), dict):
            values.setdefault("owner_login", values["owner"].get("login"))
        return values
```

**Rules:**

1. **Column fields FIRST** in class body. The SDK assigns `column_order` by declaration order via `itertools.count()`. Declaration order = table column order. There is no `column_order` parameter on `OutputField`.
1. **`column_name=`** on every field that should appear as a column. Fields without it are stored in the data payload but not shown as table columns.
1. **`cef_types=`** drives SOAR's right-click context menu (click-to-pivot). Always set on fields like URLs, usernames, IDs, and any field a playbook might wire as input.
1. **Nested API objects** (e.g. `owner.login`, `assignee.login`, `repo.name`) become columns via a `@model_validator(mode="before")` flatten. Use `setdefault` so an explicitly-set value is never overwritten.
1. **`example_values=`** is required for any field surfaced in the manifest — the SDK uses it to generate the app's output spec.

### Registration

```python
app.register_action(
    action=list_things,
    description="List all things",
    action_type="investigate",
    render_as="table",            # ← this is all you need
)
```

No `view_handler`, no `view_template`, no `templates/` directory needed.

### Mutation actions with table rendering

Mutation actions (add/remove/create/update) work the same way. Their `column_name`-annotated `Param` fields also surface as leading columns (the SDK merges params before outputs in `column_order`), so the table echoes the inputs + result fields in one row.

```python
class AddThingOutput(ActionOutput):
    success: bool = OutputField(column_name="Success")
    message: str | None = OutputField(column_name="Message")

app.register_action(
    action=add_thing,
    action_type="generic",
    read_only=False,
    render_as="table",
)
```

The `set_message()` confirmation still appears above the table. The single-row table shows the result state.

______________________________________________________________________

## Pattern 6: Shared Action Helpers

Place these in `src/actions/_helpers.py`. All actions import from here.

```python
# _helpers.py
from soar_sdk.exceptions import ActionFailure
import httpx

def _check_response(response: httpx.Response) -> None:
    """Raise ActionFailure on any non-2xx response."""
    if not response.is_success:
        try:
            msg = response.json().get("message", response.text)
        except Exception:
            msg = response.text
        raise ActionFailure(f"GitHub API error {response.status_code}: {msg}")


def _paginate_all(
    endpoint: str,
    asset,
    *,
    extra_params: dict | None = None,
    limit: int | None = None,
) -> list[dict]:
    """Exhaust a GitHub list endpoint page-by-page (per_page=100)."""
    from .client import call_<app>   # avoid circular at module level
    results: list[dict] = []
    page = 1
    while True:
        params = {"per_page": 100, "page": page, **(extra_params or {})}
        response = call_<app>("GET", endpoint, asset, params=params)
        _check_response(response)
        batch = response.json()
        if not batch:
            break
        results.extend(batch)
        if limit and len(results) >= limit:
            return results[:limit]
        if len(batch) < 100:
            break
        page += 1
    return results
```

______________________________________________________________________

## Pattern 7: Summary vs. Message

| SDK call | When to use |
|---|---|
| `soar.set_summary(SummaryOutput(...))` | Structured key/value shown in the action result header. Use for totals, IDs, URLs. |
| `soar.set_message(str)` | Free-text status line. Use for mutation confirmations ("User X added to team Y"). |

Both can be called together. `set_summary` takes a typed `ActionOutput` subclass; `set_message` takes a plain string.

```python
class ListThingsSummary(ActionOutput):
    total_things: int = OutputField(example_values=[10])

def list_things(params, soar, asset) -> list[ListThingsOutput]:
    results = [...]
    soar.set_summary(ListThingsSummary(total_things=len(results)))
    return results

def add_thing(params, soar, asset) -> AddThingOutput:
    # ... do the add ...
    soar.set_message(f"Added {params.user} to {params.team}")
    return AddThingOutput(success=True)
```

______________________________________________________________________

## Pattern 8: Test Connectivity

```python
# src/app.py
@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    response = call_<app>("GET", "/user", asset)  # or whatever the "ping" endpoint is
    _check_response(response)
    soar.set_message("Successfully connected to <App> API")
```

**Rules:**

- Returns `None` — success is implicit (no exception = pass).
- Raises `ActionFailure` on failure — the SDK catches it and marks connectivity failed.
- Call the simplest authenticated read endpoint (e.g. `/user`, `/ping`, `/me`).

______________________________________________________________________

## Pattern 9: Removing Legacy Artifacts

When all actions are migrated, these legacy items can be deleted:

| Legacy item | SDK replacement | Delete when |
|---|---|---|
| `templates/*.html` | `render_as="table"` | All `view_handler` refs removed |
| `src/views.py` (`display_view`, `_TEMPLATE_MAP`) | N/A | All `view_handler` refs removed |
| `from ..views import display_view` | N/A | Same |
| `BaseConnector` subclass | `BaseAsset` | Full migration done |
| `handle_action()` / `if action == ...` | `@app.action()` per file | Full migration done |
| `_make_rest_call()` / `requests` | `call_<app>()` / `httpx` | Full migration done |
| `get_config()` calls in actions | `asset.<field>` | Full migration done |

**Verification checklist after cleanup:**

```bash
uv run ruff check src/            # no unused imports, no F401
uv run python -c "import src.app; print('OK')"   # clean import
uv run soarapps manifests create /tmp/manifest.json .  # inspect render/columns
uv run pytest                     # all tests green
```

To inspect render config in the manifest:

```python
import json
m = json.load(open("/tmp/manifest.json"))
for a in m["actions"]:
    print(a["action"], "->", a.get("render", {}).get("type"), 
          [(d["data_path"].split(".")[-1], d.get("column_name"), d.get("column_order"))
           for d in a.get("output", []) if d.get("column_name")])
```

______________________________________________________________________

## Quick Reference: Field Metadata

| `OutputField` kwarg | Purpose | Example |
|---|---|---|
| `column_name="..."` | Makes field a visible table column; value is the header label | `column_name="Issue Number"` |
| `cef_types=[...]` | CEF type(s) for click-to-pivot context menus in SOAR | `cef_types=["url"]`, `cef_types=["github username"]` |
| `example_values=[...]` | Required for manifest generation; the SDK uses these as the output spec | `example_values=["open"]` |
| `alias="from"` | Use when a Python-reserved word is a JSON key | `alias="from"` |

| `Param` kwarg | Purpose |
|---|---|
| `primary=True` | Shows field prominently in the SOAR action UI |
| `column_name="..."` | Surfaces the input as a leading table column (column_order precedes outputs) |
| `cef_types=[...]` | Allows SOAR to wire this param from upstream action output |
| `value_list=[...]` | Renders as a dropdown in the SOAR UI |
| `default=...` | Default value pre-filled in the UI |
