**Unreleased**
* - Fixed `closed_by` and `milestone` output fields to use correct nested object types instead of `str` 
* - Fixed `PayloadOutput` and `CommentOutput` fields to be optional to handle partial GitHub event payloads
* - The `list events`, `list issues`, `get issue`, `create issue`, and `update issue` actions now pass through every field returned by the GitHub API, including fields the app does not explicitly model (for example `reactions`, `pull_request`, and `state_reason`), so playbooks always have access to the complete response instead of a trimmed subset
* - Replaced wildcard consts import with explicit imports
* - GitHub has decommissioned username/password authentication; this app now requires either a Personal Access Token or OAuth Flow credentials (Client ID and Client Secret) to authenticate. When configuring the asset to use OAuth credentials, the "Enable webhooks for this asset" checkbox must be selected in the SOAR asset settings to complete the login flow.
* - Replaced `raise ValueError` with `raise ActionFailure` for limit validation
* - App name updated to `github`


