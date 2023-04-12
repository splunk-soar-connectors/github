# File: github_consts.py
#
# Copyright (c) 2019-2023 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
GITHUB_CONFIG_USERNAME = 'username'
GITHUB_CONFIG_PASSWORD = 'password'  # pragma: allowlist secret
GITHUB_CONFIG_CLIENT_ID = 'client_id'
GITHUB_CONFIG_CLIENT_SECRET = 'client_secret'  # pragma: allowlist secret
GITHUB_CONFIG_AUTH_TOKEN = 'personal_access_token'
GITHUB_ACCESS_TOKEN = 'access_token'
GITHUB_JSON_REPO_OWNER = 'repo_owner'
GITHUB_JSON_REPO_NAME = 'repo_name'
GITHUB_JSON_ISSUE_NUMBER = 'issue_number'
GITHUB_JSON_ISSUE_TITLE = 'issue_title'
GITHUB_JSON_ISSUE_BODY = 'issue_body'
GITHUB_JSON_ASSIGNEES = 'assignees'
GITHUB_JSON_LABELS = 'labels'
GITHUB_JSON_COMMENT_BODY = 'comment_body'
GITHUB_JSON_TO_EMPTY = 'to_empty'
GITHUB_ENDPOINT_ISSUES = '/repos/{repo_owner}/{repo_name}/issues'
GITHUB_ENDPOINT_COMMENTS = '/repos/{repo_owner}/{repo_name}/issues/{issue_number}/comments'
GITHUB_ENDPOINT_GET_ISSUE = '/repos/{repo_owner}/{repo_name}/issues/{issue_number}'
GITHUB_ENDPOINT_LABELS = '/repos/{repo_owner}/{repo_name}/issues/{issue_number}/labels'
GITHUB_INVALID_INTEGER = 'Please provide non-zero positive integer in "{parameter}"'
GITHUB_MAKING_CONNECTION_MSG = 'Connecting to an endpoint'
GITHUB_TEST_CONNECTIVITY_FAILED_MSG = 'Test connectivity failed'
GITHUB_TEST_CONNECTIVITY_PASSED_MSG = 'Test connectivity passed'
GITHUB_ORGANIZATION_REQUIRED_MSG = "Parameter 'organization_name' is required " \
                                   "if team name is provided in parameter 'team'"
GITHUB_USER_NOT_TEAM_MEMBER_MSG = 'Member with username "{user_name}" is not a member of Team "{team}" ' \
                                  'and all pending invitations have been deleted'
GITHUB_INVALID_TEAM_ID = 'Team "{team}" not found'
GITHUB_ALREADY_TEAM_MEMBER_MSG = 'Member with username "{user_name}" already a member of Team "{team}" with role of "{role}"'
GITHUB_ADD_MEMBER_MSG = 'Member with username "{user_name}" successfully added in Team "{team}" and assigned role of "{role}"'
GITHUB_ADD_MEMBER_PENDING_MSG = 'Member with username "{user_name}" has been successfully sent an invitation to join ' \
                                'Team "{team}" with role of "{role}"'
GITHUB_MEMBER_REMOVAL_MSG = 'Member with username "{user_name}" successfully removed from Team "{team}"'
GITHUB_CONFIG_PARAMS_REQUIRED_CONNECTIVITY = "Either 'username' and 'password' or 'client_id' and 'client_secret' or " \
                                "'oauth_access_token' are required for test connectivity"
GITHUB_CONFIG_PARAMS_REQUIRED = "Please provide 'username' and 'password' or 'oauth_access_token' or " \
                                "run test connectivity with 'client_id' and 'client_secret'"
GITHUB_BASE_URL_NOT_FOUND_MSG = 'Phantom Base URL not found in System Settings. Please specify the value ' \
                                'in System Settings'
GITHUB_OAUTH_URL_MSG = 'Using OAuth URL:'
GITHUB_AUTHORIZE_USER_MSG = 'Please authorize user in a separate tab using URL'
GITHUB_CODE_RECEIVED_MSG = 'Code Received'
GITHUB_GENERATING_ACCESS_TOKEN_MSG = 'Generating access token'
GITHUB_ALREADY_COLLABORATOR_MSG = 'User "{user_name}" already a collaborator to repo "{repo_full_name}" ' \
                                  'with role: "{repo_role}"'
GITHUB_COLLABORATOR_ADDED_MSG = 'User "{user_name}" added successfully as a collaborator to repo "{repo_full_name}" ' \
                                'with role "{repo_role}"'
GITHUB_COLLABORATOR_ROLE_UPDATED_MSG = 'Updated role of user "{user_name}" as a collaborator to repo "{repo_full_name}" ' \
                                       'with new role: "{repo_role}"'
GITHUB_COLLABORATOR_INVITATION_SENT_MSG = 'User "{user_name}" sent an invitation to join as a collaborator ' \
                                          'to repo "{repo_full_name}" with role: "{repo_role}"'
GITHUB_COLLABORATOR_INVITATION_ALREADY_SENT_MSG = 'Invitation to user "{user_name}" already sent to join as a ' \
                                                  'collaborator to repo "{repo_full_name}" with role: "{repo_role}"'
GITHUB_COLLABORATOR_INVITATION_UPDATED_MSG = 'Invitation to user "{user_name}" to join as a collaborator to repo ' \
                                             '"{repo_full_name}" is updated with role: "{repo_role}"'
GITHUB_COLLABORATOR_INVITATION_NOT_UPDATED_MSG = "Invitation already exists. Please set parameter 'override' to " \
                                                 "update an existing invitation"
GITHUB_COLLABORATOR_ROLE_NOT_UPDATED_MSG = "User is already a collaborator. Please set " \
                                           "parameter 'override' to update the role of user"
GITHUB_USER_NOT_COLLABORATOR_MSG = 'User "{user_name}" is not a direct collaborator to repo "{repo_full_name}" and ' \
                                   'no pending invitations exist'
GITHUB_COLLABORATOR_INVITATION_DELETED_MSG = 'User "{user_name}" is not a direct collaborator to repo "{repo_full_name}",' \
                                             ' all pending invitations deleted'
GITHUB_COLLABORATOR_REMOVED_MSG = 'User "{user_name}" successfully removed as a collaborator from repo "{repo_full_name}"'
GITHUB_LABEL_ADDED_MSG = 'Label(s) "{labels}" successfully added to the issue_number: "{issue_number}"'
GITHUB_PHANTOM_BASE_URL = '{phantom_base_url}rest'
GITHUB_API_BASE_URL = 'https://api.github.com'
GITHUB_PARAM_PAGE = 'page'
GITHUB_PARAM_PER_PAGE = 'per_page'
GITHUB_PARAM_AFFILIATION = 'affiliation'
GITHUB_PARAM_AFFILIATION_DIRECT = 'direct'
GITHUB_PHANTOM_SYS_INFO_URL = '/system_info'
GITHUB_PHANTOM_ASSET_INFO_URL = '/asset/{asset_id}'
GITHUB_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize?client_id={client_id}&scope={scope}&state={state}'
GITHUB_ACCESS_TOKEN_URL = 'https://github.com/login/oauth/access_token'
GITHUB_CURRENT_USER_ENDPOINT = '/user'
GITHUB_EVENTS_ENDPOINT = '/users/{username}/events'
GITHUB_LIST_ORGANIZATIONS_ENDPOINT = '/user/orgs'
GITHUB_LIST_REPOS_ENDPOINT = '/orgs/{org_name}/repos'
GITHUB_LIST_TEAMS_ENDPOINT = '/orgs/{org_name}/teams'
GITHUB_GET_MEMBERS_ENDPOINT = '/teams/{team_id}/members'
GITHUB_LIST_MEMBERS_PENDING_INVITATIONS_ENDPOINT = '/teams/{team_id}/invitations'
GITHUB_LIST_USERS_ENDPOINT = '/orgs/{organization_name}/members'
GITHUB_LIST_COLLABORATOR_PENDING_INVITATIONS_ENDPOINT = '/repos/{repo_full_name}/invitations'
GITHUB_ADD_REMOVE_MEMBER_ENDPOINT = '/teams/{team_id}/memberships/{user_name}'
GITHUB_ADD_REMOVE_COLLABORATOR_ENDPOINT = '/repos/{repo_full_name}/collaborators/{user_name}'
GITHUB_LIST_COLLABORATOR_ENDPOINT = '/repos/{repo_full_name}/collaborators'
GITHUB_UPDATE_DELETE_COLLABORATOR_INVITATION_ENDPOINT = '/repos/{repo_full_name}/invitations/{invitation_id}'
GITHUB_JSON_ORGANIZATION = 'organization_name'
GITHUB_JSON_ID = 'id'
GITHUB_JSON_NAME = 'name'
GITHUB_JSON_TEAM = 'team'
GITHUB_JSON_USER = 'user'
GITHUB_JSON_LOGIN = 'login'
GITHUB_JSON_ROLE = 'role'
GITHUB_JSON_REPO_ROLE = 'permission'
GITHUB_JSON_OVERRIDE = 'override'
GITHUB_JSON_INVITE_SENT = 'invite_sent'
GITHUB_JSON_INVITE_DELETED = 'invite_deleted'
GITHUB_JSON_COLLABORATOR_ADDED = 'collaborator_added'
GITHUB_JSON_INVITEE = "invitee"
GITHUB_MEMBERSHIP_ACTIVE = 'active'
GITHUB_JSON_STATE = 'state'
GITHUB_ROLE_MEMBER = 'member'
GITHUB_REPO_ROLE_PULL = 'pull'
GITHUB_REPO_ROLE_PUSH = 'push'
GITHUB_REPO_ROLE_ADMIN = 'admin'
GITHUB_REPO_ROLE_READ = 'read'
GITHUB_REPO_ROLE_WRITE = 'write'
GITHUB_JSON_PERMISSIONS = 'permissions'
GITHUB_REQUEST_DELETE = 'delete'
GITHUB_REQUEST_PUT = 'put'
GITHUB_REQUEST_POST = 'post'
GITHUB_REQUEST_PATCH = 'patch'
GITHUB_TC_FILE = 'oauth_task.out'
GITHUB_SCOPE = 'admin:org, user'
GITHUB_PAGINATION_MAX_SIZE = 100
GITHUB_TC_STATUS_SLEEP = 3
GITHUB_AUTHORIZE_WAIT_TIME = 15
DEFAULT_TIMEOUT = 30  # seconds
