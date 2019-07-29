# File: githubissues_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from githubissues_consts import *
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class GithubIssuesConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(GithubIssuesConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')

        if len(message) > 500:
            message = 'Error while connecting to the server. Please check the asset credentials.'

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result, raw_response):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            if raw_response:
                return RetVal(phantom.APP_SUCCESS, {'raw_response': r, 'processed_response': resp_json})
            else:
                return RetVal(phantom.APP_SUCCESS, resp_json)

        if resp_json.get('message') or resp_json.get('documentation_url'):
            message = "Error from server. Status Code: {0}. Error message: {1}. Documentation URL: {2}".format(
                        r.status_code, resp_json.get('message'), resp_json.get('documentation_url'))
        else:
            message = "Error from server. Status Code: {0} Data from server: {1}".format(
                    r.status_code, r.text.replace(u'{', '{{').replace(u'}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result, raw_response=False):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result, raw_response)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, method="get", raw_response=False, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        resp_json = None

        if not headers:
            headers = {}

        headers.update({"Authorization": "token %s" % self._token})

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            headers=headers,
                            **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        if raw_response:
            return self._process_response(r, action_result, raw_response)
        else:
            return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to https://api.github.com/user")

        ret_val, response = self._make_rest_call(GITHUB_ENDPOINT_USER, action_result)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _paginator(self, item_name, endpoint, limit, action_result):

        list_items = list()

        while endpoint:
            ret_val, result = self._make_rest_call(endpoint, action_result, raw_response=True)

            if phantom.is_fail(ret_val):
                return None

            if result:
                response_json = result.get('processed_response')
                raw_response = result.get('raw_response')
            else:
                action_result.set_status(phantom.APP_ERROR, 'Unknown error occurred while fetching the list of {0} using pagination'.format(item_name))
                return None

            # Handling the situation of GitHub returning a dictionary instead of list
            # in case of a single item returned in response of the API
            if response_json:
                if isinstance(response_json, list):
                    list_items.extend(response_json)
                elif isinstance(response_json, dict):
                    list_items.append(response_json)

            if limit and len(list_items) >= limit:
                return list_items[:limit]

            try:
                endpoint = raw_response.links['next']['url']
                endpoint = endpoint.replace('https://api.github.com', '')
            except KeyError:
                endpoint = None

        return list_items

    def _handle_list_issues(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        repo_owner = param[GITHUB_JSON_REPO_OWNER]
        repo_name = param[GITHUB_JSON_REPO_NAME]
        limit = param.get('limit')

        if (limit and not str(limit).isdigit()) or limit == 0:
            return action_result.set_status(phantom.APP_ERROR, GITHUB_INVALID_INTEGER.format(parameter='limit'))

        endpoint = GITHUB_ENDPOINT_ISSUES.format(
            repo_owner=repo_owner,
            repo_name=repo_name
        )

        issues = self._paginator('issues', endpoint, limit, action_result)

        if issues is None:
            return action_result.get_status()

        for issue in issues:
            action_result.add_data(issue)

        summary = action_result.update_summary({})
        summary['total_issues'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_comments(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        repo_owner = param[GITHUB_JSON_REPO_OWNER]
        repo_name = param[GITHUB_JSON_REPO_NAME]
        issue_number = param[GITHUB_JSON_ISSUE_NUMBER]
        limit = param.get('limit')

        if (limit and not str(limit).isdigit()) or limit == 0:
            return action_result.set_status(phantom.APP_ERROR, GITHUB_INVALID_INTEGER.format(parameter='limit'))

        endpoint = GITHUB_ENDPOINT_COMMENTS.format(
            repo_owner=repo_owner,
            repo_name=repo_name,
            issue_number=issue_number
        )

        comments = self._paginator('comments', endpoint, limit, action_result)

        if comments is None:
            return action_result.get_status()

        for comment in comments:
            action_result.add_data(comment)

        summary = action_result.update_summary({})
        summary['total_comments'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_issue(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        repo_owner = param[GITHUB_JSON_REPO_OWNER]
        repo_name = param[GITHUB_JSON_REPO_NAME]
        issue_number = param[GITHUB_JSON_ISSUE_NUMBER]

        endpoint = GITHUB_ENDPOINT_GET_ISSUE.format(
            repo_owner=repo_owner,
            repo_name=repo_name,
            issue_number=issue_number
        )

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['issue_number'] = response.get('number')
        summary['issue_url'] = response.get('html_url')

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_issue(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        repo_owner = param[GITHUB_JSON_REPO_OWNER]
        repo_name = param[GITHUB_JSON_REPO_NAME]
        issue_title = param[GITHUB_JSON_ISSUE_TITLE]

        issue_body = param.get(GITHUB_JSON_ISSUE_BODY, '')

        # assignees should be comma-separated
        assignees = param.get(GITHUB_JSON_ASSIGNEES, '')
        assignees = [assignee.strip() for assignee in assignees.split(',') if len(assignee.strip())]

        # labels should be comma-separated
        labels = param.get(GITHUB_JSON_LABELS, '')
        labels = [label.strip() for label in labels.split(',') if len(label.strip())]

        issue_json = {
            "title": issue_title,
            "body": issue_body,
            "assignees": assignees,
            "labels": labels
        }

        endpoint = GITHUB_ENDPOINT_ISSUES.format(
            repo_owner=repo_owner,
            repo_name=repo_name
        )

        ret_val, response = self._make_rest_call(endpoint, action_result, method="post", json=issue_json)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['issue_number'] = response.get('number')
        summary['issue_url'] = response.get('html_url')

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_issue(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        repo_owner = param[GITHUB_JSON_REPO_OWNER]
        repo_name = param[GITHUB_JSON_REPO_NAME]
        issue_number = param[GITHUB_JSON_ISSUE_NUMBER]
        issue_title = param.get(GITHUB_JSON_ISSUE_TITLE)
        issue_state = param.get(GITHUB_JSON_STATE)

        issue_body = param.get(GITHUB_JSON_ISSUE_BODY, '')

        # assignees should be comma-separated
        assignees = param.get(GITHUB_JSON_ASSIGNEES, '')
        assignees = [assignee.strip() for assignee in assignees.split(',') if len(assignee.strip())]

        # labels should be comma-separated
        labels = param.get(GITHUB_JSON_LABELS, '')
        labels = [label.strip() for label in labels.split(',') if len(label.strip())]

        issue_json = {
            "title": issue_title,
            "body": issue_body,
            "assignees": assignees,
            "labels": labels,
            "state": issue_state
        }

        endpoint = GITHUB_ENDPOINT_GET_ISSUE.format(
            repo_owner=repo_owner,
            repo_name=repo_name,
            issue_number=issue_number
        )

        ret_val, response = self._make_rest_call(endpoint, action_result, method="patch", json=issue_json)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['issue_number'] = response.get('number')
        summary['issue_url'] = response.get('html_url')

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_comment(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        repo_owner = param[GITHUB_JSON_REPO_OWNER]
        repo_name = param[GITHUB_JSON_REPO_NAME]
        issue_number = param[GITHUB_JSON_ISSUE_NUMBER]
        comment_body = param[GITHUB_JSON_COMMENT_BODY]

        comment_json = {
            "body": comment_body
        }

        endpoint = GITHUB_ENDPOINT_COMMENTS.format(
            repo_owner=repo_owner,
            repo_name=repo_name,
            issue_number=issue_number
        )

        ret_val, response = self._make_rest_call(endpoint, action_result, method="post", json=comment_json)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['comment_id'] = response.get('id')
        summary['comment_url'] = response.get('html_url')

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_labels(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        repo_owner = param[GITHUB_JSON_REPO_OWNER]
        repo_name = param[GITHUB_JSON_REPO_NAME]
        issue_number = param[GITHUB_JSON_ISSUE_NUMBER]

        # labels should be a comma-separated list
        labels = param[GITHUB_JSON_LABELS]
        labels = [label.strip() for label in labels.split(',') if len(label.strip())]

        labels_json = {
            "labels": labels
        }

        endpoint = GITHUB_ENDPOINT_LABELS.format(
            repo_owner=repo_owner,
            repo_name=repo_name,
            issue_number=issue_number
        )

        ret_val, response = self._make_rest_call(endpoint, action_result, method="post", json=labels_json)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.update_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_issues':
            ret_val = self._handle_list_issues(param)

        elif action_id == 'list_comments':
            ret_val = self._handle_list_comments(param)

        elif action_id == 'get_issue':
            ret_val = self._handle_get_issue(param)

        elif action_id == 'create_issue':
            ret_val = self._handle_create_issue(param)

        elif action_id == 'update_issue':
            ret_val = self._handle_update_issue(param)

        elif action_id == 'create_comment':
            ret_val = self._handle_create_comment(param)

        elif action_id == 'add_labels':
            ret_val = self._handle_add_labels(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = GITHUB_BASE_URL
        self._token = config.get(GITHUB_CONFIG_TOKEN)

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            login_url = GithubIssuesConnector._get_phantom_base_url() + '/login'

            print ("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print ("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = GithubIssuesConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
