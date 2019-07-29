# File: githubissues_consts.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

GITHUB_BASE_URL = "https://api.github.com"
GITHUB_ENDPOINT_USER = "/user"
GITHUB_ENDPOINT_ISSUES = "/repos/{repo_owner}/{repo_name}/issues"
GITHUB_ENDPOINT_GET_ISSUE = "/repos/{repo_owner}/{repo_name}/issues/{issue_number}"
GITHUB_ENDPOINT_COMMENTS = "/repos/{repo_owner}/{repo_name}/issues/{issue_number}/comments"
GITHUB_ENDPOINT_LABELS = "/repos/{repo_owner}/{repo_name}/issues/{issue_number}/labels"
GITHUB_INVALID_INTEGER = "Please provide non-zero positive integer in {parameter}"

GITHUB_CONFIG_TOKEN = "personal_access_token"

GITHUB_JSON_REPO_OWNER = "repo_owner"
GITHUB_JSON_REPO_NAME = "repo_name"
GITHUB_JSON_ISSUE_NUMBER = "issue_number"
GITHUB_JSON_ISSUE_TITLE = "issue_title"
GITHUB_JSON_ISSUE_BODY = "issue_body"
GITHUB_JSON_COMMENT_BODY = "comment_body"
GITHUB_JSON_ASSIGNEES = "assignees"
GITHUB_JSON_LABELS = "labels"
GITHUB_JSON_STATE = "state"
