**Unreleased**
* Migrated the app to the SOAR SDK and added a new `make request` action for issuing arbitrary calls to the GitHub API
* GitHub has decommissioned username/password authentication; this app now requires either a Personal Access Token or OAuth Flow credentials (Client ID and Client Secret) to authenticate
* Assets configured with OAuth credentials must have the "Enable webhooks for this asset" checkbox selected in the SOAR asset settings to complete the login flow
