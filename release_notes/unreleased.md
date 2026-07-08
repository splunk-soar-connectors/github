**Unreleased**
* - Fixed `closed_by` and `milestone` output fields to use correct nested object types instead of `str` 
* - Fixed `PayloadOutput` and `CommentOutput` fields to be optional to handle partial GitHub event payloads
* - Replaced wildcard consts import with explicit imports
* - Deprecated username/password authentication; authentication now requires either a Personal Access Token or OAuth Flow credentials. Make sure to mark the checkbox for enable webhooks for the asset when authenticating via OAuth Credentials.
* - Replaced `raise ValueError` with `raise ActionFailure` for limit validation
* - App name updated to `github`
