**Unreleased**

* - Fixed `closed_by` and `milestone` output fields to use correct nested object types instead of `str`
* - Fixed `PayloadOutput` and `CommentOutput` fields to be optional to handle partial GitHub event payloads
* - Replaced wildcard consts import with explicit imports
* - Updated asset fields: removed deprecated `oauth_token`/`access_token`, use `personal_access_token`; marked sensitive fields
* - Replaced `raise ValueError` with `raise ActionFailure` for limit validation
* - App name updated to `github`
