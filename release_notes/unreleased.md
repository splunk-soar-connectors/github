**Unreleased**
* Migrated the app to the SOAR SDK and added a new `make request` action for issuing arbitrary calls to the GitHub API
* - **Breaking:** GitHub has decommissioned username/password authentication; this app now requires either a Personal Access Token or OAuth Flow credentials (Client ID and Client Secret) to authenticate
* - **Breaking:** Assets configured with OAuth credentials must have the "Enable webhooks for this asset" checkbox selected in the SOAR asset settings to complete the login flow
* - **Breaking:** The `closed_by` and `milestone` output fields on `get issue`, `create issue`, `update issue`, and `list issues` are now nested objects instead of a plain string; playbooks referencing the old flat datapath must be updated to use the new sub-fields (e.g. `closed_by.login`)
 