**Unreleased**
* - GitHub has decommissioned username/password authentication; this app now requires either a Personal Access Token or OAuth Flow credentials (Client ID and Client Secret) to authenticate. When configuring the asset to use OAuth credentials, the "Enable webhooks for this asset" checkbox must be selected in the SOAR asset settings to complete the login flow.
* - The `list events`, `list issues`, `get issue`, `create issue`, `update issue`, `list repos`, `list comments`, `create comment`, and `add collaborator` actions now pass through every field returned by the GitHub API, including fields the app does not explicitly model, so playbooks always have access to the complete response instead of a trimmed subset

