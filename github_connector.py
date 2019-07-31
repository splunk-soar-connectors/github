# File: github_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

import json
import os
import time
import pwd
import grp
import requests
from django.http import HttpResponse
from bs4 import BeautifulSoup
from github_consts import *

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult


def _handle_login_redirect(request, key):
    """ This function is used to redirect login request to GitHub login page.

    :param request: Data given to REST endpoint
    :param key: Key to search in state file
    :return: response authorization_url/admin_consent_url
    """

    asset_id = request.GET.get('asset_id')
    if not asset_id:
        return HttpResponse('ERROR: Asset ID not found in URL')
    state = _load_app_state(asset_id)
    url = state.get(key)
    if not url:
        return HttpResponse('App state is invalid, {key} not found.'.format(key=key))
    response = HttpResponse(status=302)
    response['Location'] = url
    return response


def _load_app_state(asset_id, app_connector=None):
    """ This function is used to load the current state file.

    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: state: Current state file as a dictionary
    """

    dirpath = os.path.split(__file__)[0]
    state_file = '{0}/{1}_state.json'.format(dirpath, asset_id)
    state = {}
    try:
        with open(state_file, 'r') as state_file_obj:
            state_file_data = state_file_obj.read()
            state = json.loads(state_file_data)
    except Exception as e:
        if app_connector:
            app_connector.debug_print('In _load_app_state: Exception: {0}'.format(str(e)))

    if app_connector:
        app_connector.debug_print('Loaded state: ', state)
    return state


def _save_app_state(state, asset_id, app_connector):
    """ This functions is used to save current state in file.

    :param state: Dictionary which contains data to write in state file
    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: status: phantom.APP_SUCCESS
    """

    dirpath = os.path.split(__file__)[0]
    state_file = '{0}/{1}_state.json'.format(dirpath, asset_id)

    if app_connector:
        app_connector.debug_print('Saving state: ', state)

    try:
        with open(state_file, 'w+') as state_file_obj:
            state_file_obj.write(json.dumps(state))
    except Exception as e:
        print 'Unable to save state file: {0}'.format(str(e))

    return phantom.APP_SUCCESS


def _handle_login_response(request):
    """ This function is used to get the login response of authorization request from GitHub login page.

    :param request: Data given to REST endpoint
    :return: HttpResponse. The response displayed on authorization URL page
    """

    asset_id = request.GET.get('state')
    if not asset_id:
        return HttpResponse('ERROR: Asset ID not found in URL\n{}'.format(json.dumps(request.GET)))

    # Check for error in URL
    error = request.GET.get('error')
    error_description = request.GET.get('error_description')

    # If there is an error in response
    if error:
        message = 'Error: {0}'.format(error)
        if error_description:
            message = '{0} Details: {1}'.format(message, error_description)
        return HttpResponse('Server returned {0}'.format(message))

    code = request.GET.get('code')

    # If code is not available
    if not code:
        return HttpResponse('Error while authenticating\n{0}'.format(json.dumps(request.GET)))

    state = _load_app_state(asset_id)
    state['code'] = code
    _save_app_state(state, asset_id, None)

    return HttpResponse('Code received. Please close this window, the action will continue to get new token.')


def _handle_rest_request(request, path_parts):
    """ Handle requests for authorization.

    :param request: Data given to REST endpoint
    :param path_parts: Parts of the URL passed
    :return: Dictionary containing response parameters
    """

    if len(path_parts) < 2:
        return HttpResponse('error: True, message: Invalid REST endpoint request')

    call_type = path_parts[1]

    # To handle authorize request in test connectivity action
    if call_type == 'start_oauth':
        return _handle_login_redirect(request, 'authorization_url')

    # To handle response from GitHub login page
    if call_type == 'result':
        return_val = _handle_login_response(request)
        asset_id = request.GET.get('state')
        if asset_id:
            # Create file and provide permissions
            app_dir = os.path.dirname(os.path.abspath(__file__))
            auth_status_file_path = '{0}/{1}_{2}'.format(app_dir, asset_id, GITHUB_TC_FILE)
            open(auth_status_file_path, 'w').close()
            try:
                uid = pwd.getpwnam('apache').pw_uid
                gid = grp.getgrnam('phantom').gr_gid
                os.chown(auth_status_file_path, uid, gid)
                os.chmod(auth_status_file_path, '0664')
            except:
                pass

        return return_val
    return HttpResponse('error: Invalid endpoint')


def _get_dir_name_from_app_name(app_name):
    """ Get name of the directory for the app.

    :param app_name: Name of the application for which directory name is required
    :return: app_name: Name of the directory for the application
    """

    app_name = ''.join([x for x in app_name if x.isalnum()])
    app_name = app_name.lower()
    if not app_name:
        app_name = 'app_for_phantom'
    return app_name


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class GithubConnector(BaseConnector):

    def __init__(self):

        super(GithubConnector, self).__init__()

        self._state = None
        self._username = None
        self._password = None
        self._client_id = None
        self._client_secret = None
        self._oauth_token = None
        self._access_token = None

    @staticmethod
    def _process_empty_response(response, action_result):
        """ This function is used to process empty response.

        :param response: Response data
        :param action_result: Object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # 204 is for action like 'remove member'
        if response.status_code in [200, 204]:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
                      None)

    @staticmethod
    def _process_html_response(response, action_result):
        """ This function is used to process html response.

        :param response: Response data
        :param action_result: Object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text.encode('utf-8')
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        if len(message) > 500:
            message = 'Error while connecting to the server. Please check the asset credentials.'

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    @staticmethod
    def _process_json_response(response, action_result):
        """ This function is used to process json response.

        :param response: Response data
        :param action_result: Object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}"
                                                   .format(str(e))), None)

        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = None

        if resp_json.get('message'):
            message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code,
                                                                                         resp_json['message'])

        if not message:
            message = "Error from server. Status Code: {0} Data from server: {1}"\
                .format(response.status_code, response.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: Response data
        :param action_result: Object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': response.status_code})
            action_result.add_debug_data({'r_text': response.text})
            action_result.add_debug_data({'r_headers': response.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        if 'text/javascript' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        # Process an HTML response, Do this no matter what the API talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)

        # if no content-type is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_response(response, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".\
            format(response.status_code, response.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, url, action_result, headers=None, params=None, data=None, method="get", auth=None,
                        verify=True):
        """ This function is used to make the REST call.

        :param url: REST URL that needs to be called
        :param action_result: Object of ActionResult class
        :param headers: Request headers
        :param params: Request parameters
        :param data: Request body
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param auth: Authentication of the API
        :param verify: Verify server certificate (Default True)
        :return: Status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        try:
            request_response = request_func(url, auth=auth, data=data, headers=headers, verify=verify, params=params)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".
                                                   format(str(e))), resp_json)

        return self._process_response(request_response, action_result)

    def _handle_update_request(self, url, action_result, headers=None, data=None, params=None, verify=True,
                               method='get'):
        """ This method is used to call maker_rest_call using different authentication methods.

        :param url: REST URL that needs to be called
        :param action_result: Object of ActionResult class
        :param headers: Request headers
        :param data: Request data
        :param params: Request params
        :param verify: Verify server certificate(Default: True)
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: Status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        # If username and password are provided, call using basic auth
        if self._username and self._password:
            ret_val, response = self._make_rest_call(url=url, action_result=action_result, headers=headers, data=data,
                                                     params=params, verify=verify, method=method,
                                                     auth=(self._username, self._password))

            if phantom.is_fail(ret_val):
                # If error is not 401 or other config parameters are not provided, return error
                if '401' not in action_result.get_message() or not (self._oauth_token or self._access_token):
                    return action_result.get_status(), None
            else:
                return phantom.APP_SUCCESS, response

        # If personal access token is provided
        if self._oauth_token:

            # Personal access token is passed as a password and username is not required
            ret_val, response = self._make_rest_call(url=url, action_result=action_result, headers=headers, data=data,
                                                     params=params, verify=verify, method=method,
                                                     auth=(None, self._oauth_token))

            if phantom.is_fail(ret_val):
                # If error is not 401 or other config parameters are not provided, return error
                if '401' not in action_result.get_message() or not self._access_token:
                    return action_result.get_status(), None
            else:
                return phantom.APP_SUCCESS, response

        if self._access_token:
            if not headers:
                headers = {}
            # Pass access token in headers
            headers.update({'Authorization': 'Bearer {0}'.format(self._access_token)})

            ret_val, response = self._make_rest_call(url=url, action_result=action_result, headers=headers, data=data,
                                                     params=params, verify=verify, method=method)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            return phantom.APP_SUCCESS, response

        return action_result.set_status(phantom.APP_ERROR, status_message='Authentication failed'), None

    def _handle_test_connectivity(self, param):
        """ This function is used to handle the test connectivity action.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        self._state = {}
        # If none of the config parameters are present, return error
        if not(self._username and self._password)\
           and not(self._client_id and self._client_secret)\
           and not self._oauth_token:
            self.save_progress(GITHUB_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.set_status(phantom.APP_ERROR,
                                            status_message=GITHUB_CONFIG_PARAMS_REQUIRED_CONNECTIVITY)

        self.save_progress(GITHUB_MAKING_CONNECTION_MSG)

        url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_CURRENT_USER_ENDPOINT)

        if self._username and self._password:
            # make rest call
            ret_val, _ = self._make_rest_call(url=url, action_result=action_result,
                                              auth=(self._username, self._password))

            if phantom.is_fail(ret_val):
                # If error is not 401 or other config parameters are not provided, return error
                if '401' not in action_result.get_message() or \
                        not (self._oauth_token or (self._client_id and self._client_secret)):
                    self.save_progress(GITHUB_TEST_CONNECTIVITY_FAILED_MSG)
                    return action_result.get_status()
            else:
                self.save_progress(GITHUB_TEST_CONNECTIVITY_PASSED_MSG)
                return action_result.set_status(phantom.APP_SUCCESS)

        if self._oauth_token:
            ret_val, _ = self._make_rest_call(url=url, action_result=action_result, auth=(None, self._oauth_token))

            if phantom.is_fail(ret_val):
                # If error is not 401 or other config parameters are not provided, return error
                if '401' not in action_result.get_message() or not (self._client_id and self._client_secret):
                    self.save_progress(GITHUB_TEST_CONNECTIVITY_FAILED_MSG)
                    return action_result.get_status()
            else:
                self.save_progress(GITHUB_TEST_CONNECTIVITY_PASSED_MSG)
                return action_result.set_status(phantom.APP_SUCCESS)

        if self._client_id and self._client_secret:
            # If client_id and client_secret is provided, go for interactive login
            ret_val = self._handle_interactive_login(action_result=action_result)

            if phantom.is_fail(ret_val):
                self.save_progress(GITHUB_TEST_CONNECTIVITY_FAILED_MSG)
                return action_result.get_status()

            # Call using access_token
            request_headers = {
                'Authorization': 'Bearer {}'.format(self._access_token)
            }
            ret_val, _ = self._make_rest_call(url=url, action_result=action_result, headers=request_headers)

            if phantom.is_fail(ret_val):
                self.save_progress(GITHUB_TEST_CONNECTIVITY_FAILED_MSG)
                return action_result.get_status()

            self.save_progress(GITHUB_TEST_CONNECTIVITY_PASSED_MSG)
            return action_result.set_status(phantom.APP_SUCCESS)

        return action_result.set_status(phantom.APP_ERROR, status_message='Authentication failed')

    def _handle_interactive_login(self, action_result):
        """ This function is used to handle the interactive login during test connectivity
        while client_id and client_secret is provided.

        :param action_result: Object of ActionResult class
        :return: status(success/failure)
        """

        ret_val, app_rest_url = self._get_app_rest_url(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Append /result to create redirect_uri
        redirect_uri = '{0}/result'.format(app_rest_url)
        self._state['redirect_uri'] = redirect_uri

        self.save_progress(GITHUB_OAUTH_URL_MSG)
        self.save_progress(redirect_uri)

        asset_id = self.get_asset_id()

        # Authorization URL used to make request for getting code which is used to generate access token
        authorization_url = GITHUB_AUTHORIZE_URL.format(client_id=self._client_id, scope=GITHUB_SCOPE, state=asset_id)

        self._state['authorization_url'] = authorization_url

        # URL which would be shown to the user
        url_for_authorize_request = '{0}/start_oauth?asset_id={1}&'.format(app_rest_url, asset_id)
        _save_app_state(self._state, asset_id, self)

        self.save_progress(GITHUB_AUTHORIZE_USER_MSG)
        self.save_progress(url_for_authorize_request)

        # Wait for 15 seconds for authorization
        time.sleep(GITHUB_AUTHORIZE_WAIT_TIME)

        # Wait for 105 seconds while user login to GitHub
        status = self._wait(action_result=action_result)

        # Empty message to override last message of waiting
        self.send_progress('')
        if phantom.is_fail(status):
            return action_result.get_status()

        self.save_progress(GITHUB_CODE_RECEIVED_MSG)
        self._state = _load_app_state(asset_id, self)

        # if code is not available in the state file
        if not self._state or not self._state.get('code'):
            return action_result.set_status(phantom.APP_ERROR, status_message=GITHUB_TEST_CONNECTIVITY_FAILED_MSG)

        current_code = self._state['code']
        self.save_state(self._state)

        self.save_progress(GITHUB_GENERATING_ACCESS_TOKEN_MSG)

        # Generate access_token using code
        request_data = {
            'client_id': self._client_id,
            'client_secret': self._client_secret,
            'code': current_code
        }

        request_headers = {'Accept': 'application/json'}

        ret_val, response = self._make_rest_call(url=GITHUB_ACCESS_TOKEN_URL, action_result=action_result,
                                                 method='post', data=request_data, headers=request_headers)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # If there is any error while generating access_token, API returns 200 with error and error_description fields
        if not response.get(GITHUB_ACCESS_TOKEN):
            if response.get('error_description'):
                return action_result.set_status(phantom.APP_ERROR, status_message=response['error_description'])

            return action_result.set_status(phantom.APP_ERROR, status_message='Error while generating access_token')

        self._state = response
        self._access_token = response[GITHUB_ACCESS_TOKEN]
        _save_app_state(self._state, asset_id, self)

        return phantom.APP_SUCCESS

    def _get_app_rest_url(self, action_result):
        """ Get URL for making rest calls.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        URL to make rest calls
        """

        ret_val, phantom_base_url = self._get_phantom_base_url_github(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        ret_val, asset_name = self._get_asset_name(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        self.save_progress('Using Phantom base URL as: {0}'.format(phantom_base_url))
        app_json = self.get_app_json()
        app_name = app_json['name']

        app_dir_name = _get_dir_name_from_app_name(app_name)
        url_to_app_rest = '{0}/rest/handler/{1}_{2}/{3}'.format(phantom_base_url, app_dir_name, app_json['appid'],
                                                                asset_name)
        return phantom.APP_SUCCESS, url_to_app_rest

    def _get_phantom_base_url_github(self, action_result):
        """ Get base url of phantom.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        base url of phantom
        """

        url = '{}{}'.format(GITHUB_PHANTOM_BASE_URL.format(phantom_base_url=self._get_phantom_base_url()), GITHUB_PHANTOM_SYS_INFO_URL)
        ret_val, resp_json = self._make_rest_call(action_result=action_result, url=url, verify=False)
        if phantom.is_fail(ret_val):
            return ret_val, None

        phantom_base_url = resp_json.get('base_url')
        if not phantom_base_url:
            return action_result.set_status(phantom.APP_ERROR, status_message=GITHUB_BASE_URL_NOT_FOUND_MSG), None
        return phantom.APP_SUCCESS, phantom_base_url

    def _get_asset_name(self, action_result):
        """ Get name of the asset using Phantom URL.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), asset name
        """

        asset_id = self.get_asset_id()
        rest_endpoint = GITHUB_PHANTOM_ASSET_INFO_URL.format(asset_id=asset_id)
        url = '{}{}'.format(GITHUB_PHANTOM_BASE_URL.format(phantom_base_url=self._get_phantom_base_url()), rest_endpoint)
        ret_val, resp_json = self._make_rest_call(action_result=action_result, url=url, verify=False)

        if phantom.is_fail(ret_val):
            return ret_val, None

        asset_name = resp_json.get('name')
        if not asset_name:
            return action_result.set_status(phantom.APP_ERROR, status_message='Asset Name for id: {0} not found.'
                                            .format(asset_id)), None
        return phantom.APP_SUCCESS, asset_name

    def _wait(self, action_result):
        """ This function is used to hold the action till user login for 105 seconds.

        :param action_result: Object of ActionResult class
        :return: status (success/failed)
        """

        app_dir = os.path.dirname(os.path.abspath(__file__))
        # file to check whether the request has been granted or not
        auth_status_file_path = '{0}/{1}_{2}'.format(app_dir, self.get_asset_id(), GITHUB_TC_FILE)

        # wait-time while request is being granted for 105 seconds
        for _ in range(0, 35):
            self.send_progress('Waiting...')
            self._state = _load_app_state(self.get_asset_id(), self)
            # If file is generated
            if os.path.isfile(auth_status_file_path):
                os.unlink(auth_status_file_path)
                break
            time.sleep(GITHUB_TC_STATUS_SLEEP)
        else:
            self.send_progress('')
            return action_result.set_status(phantom.APP_ERROR, status_message='Timeout. Please try again later.')
        self.send_progress('Authenticated')
        return phantom.APP_SUCCESS

    def _handle_list_events(self, param):
        """ This function is used to handle list events action.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not(self._username and self._password) and not self._oauth_token and not self._access_token:
            return action_result.set_status(phantom.APP_ERROR, status_message=GITHUB_CONFIG_PARAMS_REQUIRED)

        username = param[GITHUB_CONFIG_USERNAME]

        url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_EVENTS_ENDPOINT.format(username=username))
        per_page = GITHUB_PAGINATION_MAX_SIZE
        page = 1

        while True:
            request_params = {
                'per_page': per_page,
                'page': page
            }
            ret_val, response = self._handle_update_request(url=url, action_result=action_result, params=request_params)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            for item in response:
                action_result.add_data(item)

            # If response size is less than we asked for,
            # it is a last page of the response
            if len(response) < GITHUB_PAGINATION_MAX_SIZE:
                break
            page += 1

            # API returns only past 300 events
            # So 100 events per page, page = 3 should be our last iteration
            if page > 3:
                break

        summary = action_result.update_summary({})
        summary['total_events'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_users(self, param):
        """ This function is used to handle list users action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not (self._username and self._password) and not self._oauth_token and not self._access_token:
            return action_result.set_status(phantom.APP_ERROR, status_message=GITHUB_CONFIG_PARAMS_REQUIRED)

        organization_name = param[GITHUB_JSON_ORGANIZATION]
        limit = param.get('limit')

        if (limit and not str(limit).isdigit()) or limit == 0:
            return action_result.set_status(phantom.APP_ERROR, GITHUB_INVALID_INTEGER.format(parameter='limit'))

        url = '{0}{1}'.format(GITHUB_API_BASE_URL,
                              GITHUB_LIST_USERS_ENDPOINT.format(organization_name=organization_name))

        user_list = self._get_list_response(url=url, action_result=action_result, limit=limit)

        # If None is returned, action is failed.
        # For empty list action is successful
        if user_list is None:
            return action_result.get_status()

        for user in user_list:
            action_result.add_data(user)

        summary = action_result.update_summary({})
        summary['total_users'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_collaborator(self, param):
        """ This function is used to handle the remove collaborator action.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not (self._username and self._password) and not self._oauth_token and not self._access_token:
            return action_result.set_status(phantom.APP_ERROR, status_message=GITHUB_CONFIG_PARAMS_REQUIRED)

        repo_owner = param[GITHUB_JSON_REPO_OWNER]
        repo_name = param[GITHUB_JSON_REPO_NAME]
        repo = '{0}/{1}'.format(repo_owner, repo_name)
        user = param[GITHUB_JSON_USER]

        # 2. Check if the user not a collaborator to the repo
        url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_LIST_COLLABORATOR_ENDPOINT.format(repo_full_name=repo))
        params = {GITHUB_PARAM_AFFILIATION: GITHUB_PARAM_AFFILIATION_DIRECT}
        list_collaborators_direct = self._get_list_response(url, action_result, params)

        # If None is returned, action is failed.
        # For empty list action is successful
        if list_collaborators_direct is None:
            return action_result.get_status()

        for collaborator in list_collaborators_direct:
            if user.lower() == collaborator.get(GITHUB_JSON_LOGIN).lower():
                break
        else:
            # Check if user is not a direct collaborator, if any pending invitations exist,
            # delete the pending invitations
            url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_LIST_COLLABORATOR_PENDING_INVITATIONS_ENDPOINT.
                                  format(repo_full_name=repo))
            list_collaborators_pending_invitations = self._get_list_response(url, action_result)

            # If None is returned, action is failed.
            # For empty list action is successful
            if list_collaborators_pending_invitations is None:
                return action_result.get_status()

            invite_deleted = False
            for invitation in list_collaborators_pending_invitations:
                # Delete all pending invitations to the user being removed as a collaborator
                if user.lower() == invitation.get(GITHUB_JSON_INVITEE).get(GITHUB_JSON_LOGIN).lower():
                    url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_UPDATE_DELETE_COLLABORATOR_INVITATION_ENDPOINT.
                                          format(repo_full_name=repo, invitation_id=invitation.get(GITHUB_JSON_ID)))

                    ret_val, _ = self._handle_update_request(url=url, action_result=action_result,
                                                             method=GITHUB_REQUEST_DELETE)

                    if phantom.is_fail(ret_val):
                        return None

                    invite_deleted = True

            action_result.add_data({GITHUB_JSON_INVITE_DELETED: invite_deleted})
            if invite_deleted:
                return action_result.set_status(phantom.APP_SUCCESS, GITHUB_COLLABORATOR_INVITATION_DELETED_MSG.
                                                format(user_name=user, repo_full_name=repo))

            return action_result.set_status(phantom.APP_SUCCESS, GITHUB_USER_NOT_COLLABORATOR_MSG.
                                            format(user_name=user, repo_full_name=repo))

        # 3. Endpoint for remove user as a collaborator to the provided repo
        url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_ADD_REMOVE_COLLABORATOR_ENDPOINT.
                              format(repo_full_name=repo, user_name=user))

        # make rest call
        ret_val, response_json = self._handle_update_request(url=url, action_result=action_result,
                                                             method=GITHUB_REQUEST_DELETE)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data({GITHUB_JSON_INVITE_DELETED: False})
        return action_result.set_status(phantom.APP_SUCCESS, GITHUB_COLLABORATOR_REMOVED_MSG.
                                        format(repo_full_name=repo, user_name=user))

    def _handle_add_collaborator(self, param):
        """ This function is used to handle the add collaborator action.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not(self._username and self._password) and not self._oauth_token and not self._access_token:
            return action_result.set_status(phantom.APP_ERROR, status_message=GITHUB_CONFIG_PARAMS_REQUIRED)

        override = param.get(GITHUB_JSON_OVERRIDE, False)
        repo_owner = param[GITHUB_JSON_REPO_OWNER]
        repo_name = param[GITHUB_JSON_REPO_NAME]
        repo = '{0}/{1}'.format(repo_owner, repo_name)
        user = param[GITHUB_JSON_USER]

        # Default role is 'push' if repo role is not provided or incorrect repo role is provided by the user
        role = param.get(GITHUB_JSON_ROLE, GITHUB_REPO_ROLE_PUSH).lower()

        role_mapping_dict = dict()
        role_mapping_dict[GITHUB_REPO_ROLE_PULL] = GITHUB_REPO_ROLE_READ
        role_mapping_dict[GITHUB_REPO_ROLE_PUSH] = GITHUB_REPO_ROLE_WRITE
        role_mapping_dict[GITHUB_REPO_ROLE_ADMIN] = GITHUB_REPO_ROLE_ADMIN

        # 2. Check if the user already a direct collaborator to the repo
        url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_LIST_COLLABORATOR_ENDPOINT.format(repo_full_name=repo))
        params = {GITHUB_PARAM_AFFILIATION: GITHUB_PARAM_AFFILIATION_DIRECT}
        list_collaborators_direct = self._get_list_response(url, action_result, params)

        # If None is returned, action is failed.
        # For empty list action is successful
        if list_collaborators_direct is None:
            return action_result.get_status()

        collaborator_exist_diff_role = False

        for collaborator in list_collaborators_direct:
            # Check if user is already a collaborator
            if user.lower() == collaborator.get(GITHUB_JSON_LOGIN).lower():
                # If user is a collaborator with same rights, return success
                if self._if_role_same(collaborator, role):
                    action_result.add_data({GITHUB_JSON_INVITE_SENT: False, GITHUB_JSON_COLLABORATOR_ADDED: False})
                    return action_result.set_status(phantom.APP_SUCCESS, GITHUB_ALREADY_COLLABORATOR_MSG.
                                                    format(user_name=user, repo_full_name=repo, repo_role=role))
                # User is collaborator with different role
                else:
                    collaborator_exist_diff_role = True
                    break
        # User is not a collaborator
        # Check pending invitations
        else:
            # Check if the invite is already sent to the member to join repo as a collaborator with same role
            url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_LIST_COLLABORATOR_PENDING_INVITATIONS_ENDPOINT.
                                  format(repo_full_name=repo))
            list_collaborators_pending_invitations = self._get_list_response(url, action_result)

            # If None is returned, action is failed.
            # For empty list action is successful
            if list_collaborators_pending_invitations is None:
                return action_result.get_status()

            # In case of multiple invitations to the user if we find any single invitation,
            # we will not further send an invite
            for invitation in list_collaborators_pending_invitations:
                # No need to check if repo of invite is same or not as the API call is done
                # for pending invitations of the same repo
                if user.lower() == invitation.get(GITHUB_JSON_INVITEE).get(GITHUB_JSON_LOGIN).lower():

                    if role_mapping_dict[role].lower() == invitation.get(GITHUB_JSON_PERMISSIONS).lower():
                        # Do nothing as invitation for same role already exist
                        action_result.add_data({GITHUB_JSON_INVITE_SENT: False, GITHUB_JSON_COLLABORATOR_ADDED: False})
                        return action_result.set_status(phantom.APP_SUCCESS,
                                                        GITHUB_COLLABORATOR_INVITATION_ALREADY_SENT_MSG.
                                                        format(user_name=user, repo_full_name=repo, repo_role=role))

                    # Update the invitation if role is different and parameter override is True
                    if override:
                        url = '{0}{1}'.format(GITHUB_API_BASE_URL,
                                              GITHUB_UPDATE_DELETE_COLLABORATOR_INVITATION_ENDPOINT.
                                              format(repo_full_name=repo, invitation_id=invitation.get(GITHUB_JSON_ID)))

                        request_data = dict()
                        request_data[GITHUB_JSON_PERMISSIONS] = role_mapping_dict[role]

                        ret_val, _ = self._handle_update_request(url=url, action_result=action_result,
                                                                 data=json.dumps(request_data),
                                                                 method=GITHUB_REQUEST_PATCH)

                        if phantom.is_fail(ret_val):
                            return action_result.get_status()

                        action_result.add_data({GITHUB_JSON_INVITE_SENT: True,
                                                GITHUB_JSON_COLLABORATOR_ADDED: False})
                        return action_result.set_status(phantom.APP_SUCCESS,
                                                        GITHUB_COLLABORATOR_INVITATION_UPDATED_MSG.
                                                        format(user_name=user, repo_full_name=repo, repo_role=role))

                    # If override is False, return error
                    action_result.add_data({GITHUB_JSON_INVITE_SENT: False, GITHUB_JSON_COLLABORATOR_ADDED: False})
                    return action_result.set_status(phantom.APP_ERROR,
                                                    status_message=GITHUB_COLLABORATOR_INVITATION_NOT_UPDATED_MSG.
                                                    format(user_name=user, repo_full_name=repo, repo_role=role))

        # If user is collaborator with different role
        if collaborator_exist_diff_role:
            # If override is True
            if override:
                success_message = GITHUB_COLLABORATOR_ROLE_UPDATED_MSG.format(user_name=user, repo_full_name=repo,
                                                                              repo_role=role)
                return self._add_collaborator(repo, user, role, success_message, action_result)

            # If override is False, return error
            action_result.add_data({GITHUB_JSON_INVITE_SENT: False, GITHUB_JSON_COLLABORATOR_ADDED: False})
            return action_result.set_status(phantom.APP_ERROR, status_message=GITHUB_COLLABORATOR_ROLE_NOT_UPDATED_MSG.
                                            format(user_name=user, repo_full_name=repo, repo_role=role))

        # User is not a direct collaborator and no pending invitations exists
        success_message = GITHUB_COLLABORATOR_ADDED_MSG.format(user_name=user, repo_full_name=repo, repo_role=role)
        return self._add_collaborator(repo, user, role, success_message, action_result)

    def _add_collaborator(self, repo, user, role, success_message, action_result):
        """ This function is used to add user as a collaborator to the repo or update role of existing collaborator.

        :param repo: Repo full name
        :param user: User to be added as a collaborator
        :param role: New role of collaborator
        :param success_message: Message to be displayed on successful action
        :parm action_result: Object of ActionResult class
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_ADD_REMOVE_COLLABORATOR_ENDPOINT.
                              format(repo_full_name=repo, user_name=user))

        request_data = dict()
        request_data[GITHUB_JSON_REPO_ROLE] = role

        # make rest call
        ret_val, response_json = self._handle_update_request(url=url, action_result=action_result,
                                                             data=json.dumps(request_data), method=GITHUB_REQUEST_PUT)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if response_json and isinstance(response_json, dict):
            response_json[GITHUB_JSON_INVITE_SENT] = True
            response_json[GITHUB_JSON_COLLABORATOR_ADDED] = False
            action_result.add_data(response_json)

            return action_result.set_status(phantom.APP_SUCCESS, GITHUB_COLLABORATOR_INVITATION_SENT_MSG.
                                            format(user_name=user, repo_full_name=repo, repo_role=role))

        if response_json:
            response_json = {}

        response_json[GITHUB_JSON_INVITE_SENT] = False
        response_json[GITHUB_JSON_COLLABORATOR_ADDED] = True
        action_result.add_data(response_json)
        return action_result.set_status(phantom.APP_SUCCESS, success_message)

    @staticmethod
    def _if_role_same(collaborator, role):
        """ This function is used to check if existing collaborator role is same as provided new collaborator role.

        :param collaborator: Existing direct collaborator object
        :param role: New role of collaborator
        :return: True if role of collaborator is same as provided role, False otherwise
        """
        collaborator_pull_permission = collaborator[GITHUB_JSON_PERMISSIONS][GITHUB_REPO_ROLE_PULL]
        collaborator_push_permission = collaborator[GITHUB_JSON_PERMISSIONS][GITHUB_REPO_ROLE_PUSH]
        collaborator_admin_permission = collaborator[GITHUB_JSON_PERMISSIONS][GITHUB_REPO_ROLE_ADMIN]

        if role == GITHUB_REPO_ROLE_PULL:
            return collaborator_pull_permission and not collaborator_push_permission and \
                   not collaborator_admin_permission
        elif role == GITHUB_REPO_ROLE_PUSH:
            return collaborator_pull_permission and collaborator_push_permission and not collaborator_admin_permission
        elif role == GITHUB_REPO_ROLE_ADMIN:
            return collaborator_pull_permission and collaborator_push_permission and collaborator_admin_permission

        return False

    def _handle_remove_member(self, param):
        """ This function is used to handle the remove member action.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not(self._username and self._password) and not self._oauth_token and not self._access_token:
            return action_result.set_status(phantom.APP_ERROR, status_message=GITHUB_CONFIG_PARAMS_REQUIRED)

        team = param[GITHUB_JSON_TEAM]
        user = param[GITHUB_JSON_USER]
        organization_name = param.get(GITHUB_JSON_ORGANIZATION)

        # 1. For input team check whether it is Team name or Team ID and if Team Name fetch Team ID from it
        ret_val, team_id = self._verify_and_get_team_id(team=team, action_result=action_result,
                                                        org_name=organization_name)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # 2. If valid team_id not found, fail the action
        if not team_id:
            return action_result.set_status(phantom.APP_ERROR, status_message=GITHUB_INVALID_TEAM_ID.format(team=team))

        # 3. Verify if user already removed from given team
        url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_GET_MEMBERS_ENDPOINT.format(team_id=team_id))

        list_teams_members = self._get_list_response(url, action_result)

        # If team_members_list is None, FAIL the action else if team_members_list is empty, do not fail
        # because this implies that the input user is already not a member of the team with given team id
        if list_teams_members is None:
            return action_result.get_status()

        for member in list_teams_members:
            if member.get(GITHUB_JSON_LOGIN).lower() == user.lower():
                break
        else:
            # Check if user is not a direct member, remove all pending invitations to user for joining the team
            url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_LIST_MEMBERS_PENDING_INVITATIONS_ENDPOINT.
                                  format(team_id=team_id))
            list_members_pending_invitations = self._get_list_response(url, action_result)

            # If None is returned, action is failed.
            # For empty list action is successful
            if list_members_pending_invitations is None:
                return action_result.get_status()

            for invitation in list_members_pending_invitations:
                if user.lower() == invitation.get(GITHUB_JSON_LOGIN).lower():
                    invite_deleted = self._remove_member_or_pending_invitation(team_id, user, action_result)

                    if phantom.is_fail(invite_deleted):
                        return action_result.get_status()

            return action_result.set_status(phantom.APP_SUCCESS, GITHUB_USER_NOT_TEAM_MEMBER_MSG.format(team=team,
                                                                                                        user_name=user))

        # 4. At this point, it is verified that given user is a member of given team
        # and hence, removing the user from team
        member_deleted = self._remove_member_or_pending_invitation(team_id, user, action_result)

        if phantom.is_fail(member_deleted):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, GITHUB_MEMBER_REMOVAL_MSG.format(user_name=user,
                                                                                              team=team))

    def _remove_member_or_pending_invitation(self, team_id, user, action_result):
        """ This function is used to remove member from team or remove pending invitation to join the team.

        :param team_id: Team ID
        :param user: User to be removed from team
        :param action_result: Object of ActionResult class
        :return: True if member or pending invitation is successfully removed
        """

        url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_ADD_REMOVE_MEMBER_ENDPOINT.format(team_id=team_id,
                                                                                            user_name=user))

        # make rest call
        ret_val, _ = self._handle_update_request(url=url, action_result=action_result, method=GITHUB_REQUEST_DELETE)

        if phantom.is_fail(ret_val):
            return False

        return True

    def _verify_and_get_team_id(self, team, action_result, org_name=None):
        """ This function is used to get the team_id if team_name is provided.

        :param team: Team ID or Team name
        :param action_result: Object of ActionResult class
        :param org_name: Organization name
        :return: phantom.APP_SUCCESS/phantom.APP_ERROR, team_id/None
        """

        team_id = None
        try:
            if not team.isdigit():
                raise ValueError
            team_id = int(team)
        except ValueError:
            # Exception while converting to valid integer implies that provided input is Team name and not Team ID
            # Further verifying that if Team name mentioned, Organization name is required
            if not org_name:
                return action_result.set_status(phantom.APP_ERROR, status_message=GITHUB_ORGANIZATION_REQUIRED_MSG), \
                       None

            url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_LIST_TEAMS_ENDPOINT.format(org_name=org_name))

            list_teams = self._get_list_response(url, action_result)

            # If team_list is None, FAIL the action else if team_list is empty, do not fail
            # because number of teams in an organization can be zero
            if list_teams is None:
                return action_result.get_status(), None

            # Fetch Team ID from Team name
            for each_team in list_teams:
                if team.lower() == each_team.get(GITHUB_JSON_NAME).lower():
                    team_id = each_team.get(GITHUB_JSON_ID)
                    break

        return phantom.APP_SUCCESS, team_id

    def _handle_add_member(self, param):
        """ This function is used to handle the add member action.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not(self._username and self._password) and not self._oauth_token and not self._access_token:
            return action_result.set_status(phantom.APP_ERROR, status_message=GITHUB_CONFIG_PARAMS_REQUIRED)

        team = param[GITHUB_JSON_TEAM]
        user = param[GITHUB_JSON_USER]
        organization_name = param.get(GITHUB_JSON_ORGANIZATION)
        # Default role is 'member' if role is not provided or incorrect role is provided by the user
        role = param.get(GITHUB_JSON_ROLE, GITHUB_ROLE_MEMBER)

        # 1. For input team check whether it is Team name or Team ID and if Team Name fetch Team ID from it
        ret_val, team_id = self._verify_and_get_team_id(team=team, action_result=action_result, org_name=organization_name)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # 2. If valid integer team_id not found, fail the action
        if not team_id:
            return action_result.set_status(phantom.APP_ERROR, status_message=GITHUB_INVALID_TEAM_ID.format(team=team))

        # 3. Verify if user already a member of team with same role
        url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_GET_MEMBERS_ENDPOINT.format(team_id=team_id))
        params = {GITHUB_JSON_ROLE: role.lower()}
        list_teams_members = self._get_list_response(url, action_result, params)

        # If team_members_list is None, FAIL the action else if team_members_list is empty, do not fail
        # because this implies that the input user is already not a member of the team with given team id
        if list_teams_members is None:
            return action_result.get_status()

        for member in list_teams_members:
            if member.get(GITHUB_JSON_LOGIN).lower() == user.lower():
                return action_result.set_status(phantom.APP_SUCCESS, GITHUB_ALREADY_TEAM_MEMBER_MSG.
                                                format(user_name=user, team=team, role=role))

        # 4. If given user is not a member of given team, it will be created with mentioned rights
        # or if user already present with different rights, rights will be updated for the same user
        # and rights will be kept unchanged if found same
        url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_ADD_REMOVE_MEMBER_ENDPOINT.
                              format(team_id=team_id, user_name=user))

        request_data = dict()
        request_data[GITHUB_JSON_ROLE] = role.lower()

        # make rest call
        ret_val, response_json = self._handle_update_request(url=url, action_result=action_result,
                                                             data=json.dumps(request_data), method=GITHUB_REQUEST_PUT)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response_json)
        if GITHUB_MEMBERSHIP_ACTIVE == response_json.get(GITHUB_JSON_STATE):
            return action_result.set_status(phantom.APP_SUCCESS, GITHUB_ADD_MEMBER_MSG.format(user_name=user, team=team,
                                                                                              role=role))

        return action_result.set_status(phantom.APP_SUCCESS, GITHUB_ADD_MEMBER_PENDING_MSG.format(user_name=user,
                                                                                                  team=team, role=role))

    def _handle_list_teams(self, param):
        """ This function is used to handle the list teams action.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not(self._username and self._password) and not self._oauth_token and not self._access_token:
            return action_result.set_status(phantom.APP_ERROR, status_message=GITHUB_CONFIG_PARAMS_REQUIRED)

        limit = param.get('limit')

        if (limit and not str(limit).isdigit()) or limit == 0:
            return action_result.set_status(phantom.APP_ERROR, GITHUB_INVALID_INTEGER.format(parameter='limit'))

        url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_LIST_TEAMS_ENDPOINT.
                              format(org_name=param[GITHUB_JSON_ORGANIZATION]))

        list_teams = self._get_list_response(url, action_result, limit=limit)

        # If team_list is None, FAIL the action else if team_list is empty, do not fail
        # because number of teams in an organization can be zero
        if list_teams is None:
            return action_result.get_status()

        for team in list_teams:
            action_result.add_data(team)

        summary = action_result.update_summary({})
        summary['total_teams'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_list_response(self, url, action_result, additional_params=None, limit=None):
        """ This function is used to fetch list response based on API URL to be fetched and pagination.

        :rtype: list
        :param url: endpoint URL
        :param action_result: action_result
        :param additional_params: additional parameters for API request
        :return: List of teams
        """

        page_number = 1
        response_items_list = []
        params = dict()

        while True:
            # Define page and per_page as params for the api request
            if additional_params:
                params.update(additional_params)
            params[GITHUB_PARAM_PAGE] = page_number
            params[GITHUB_PARAM_PER_PAGE] = GITHUB_PAGINATION_MAX_SIZE

            # make rest call
            ret_val, response_json = self._handle_update_request(url=url, action_result=action_result, params=params)

            if phantom.is_fail(ret_val):
                return None

            # Handling the situation of GitHub returning a dictionary instead of list
            # in case of a single item returned in response of the API
            if response_json:
                if isinstance(response_json, list):
                    response_items_list.extend(response_json)
                elif isinstance(response_json, dict):
                    response_items_list.append(response_json)

            if limit and len(response_items_list) >= limit:
                return response_items_list[:limit]

            if len(response_json) < GITHUB_PAGINATION_MAX_SIZE:
                return response_items_list

            # Increment page_number for fetching next page in upcoming cycle
            page_number += 1

        return response_items_list

    def _handle_list_repos(self, param):
        """ This function is used to handle the list repos action.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not(self._username and self._password) and not self._oauth_token and not self._access_token:
            return action_result.set_status(phantom.APP_ERROR, status_message=GITHUB_CONFIG_PARAMS_REQUIRED)

        limit = param.get('limit')

        if (limit and not str(limit).isdigit()) or limit == 0:
            return action_result.set_status(phantom.APP_ERROR, GITHUB_INVALID_INTEGER.format(parameter='limit'))

        url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_LIST_REPOS_ENDPOINT
                              .format(org_name=param[GITHUB_JSON_ORGANIZATION]))

        repo_list = self._get_list_response(url, action_result, limit=limit)

        # If repo_list is None, FAIL the action
        # If repo_list is empty, action is successful
        if repo_list is None:
            return action_result.get_status()

        for repo in repo_list:
            action_result.add_data(repo)

        summary = action_result.update_summary({})
        summary['total_repos'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_organizations(self, param):
        """ This function is used to handle the list organizations action.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not(self._username and self._password) and not self._oauth_token and not self._access_token:
            return action_result.set_status(phantom.APP_ERROR, status_message=GITHUB_CONFIG_PARAMS_REQUIRED)

        limit = param.get('limit')

        if (limit and not str(limit).isdigit()) or limit == 0:
            return action_result.set_status(phantom.APP_ERROR, GITHUB_INVALID_INTEGER.format(parameter='limit'))

        url = '{0}{1}'.format(GITHUB_API_BASE_URL, GITHUB_LIST_ORGANIZATIONS_ENDPOINT)

        org_list = self._get_list_response(url, action_result, limit=limit)

        # If org_list is None, FAIL the action
        # If org_list is empty, action is successful
        if org_list is None:
            return action_result.get_status()

        for org in org_list:
            action_result.add_data(org)

        summary = action_result.update_summary({})
        summary['total_organizations'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

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

        url = '{0}{1}'.format(GITHUB_API_BASE_URL, endpoint)

        issues_list = self._get_list_response(url, action_result, limit=limit)

        if issues_list is None:
            return action_result.get_status()

        for issue in issues_list:
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

        url = '{0}{1}'.format(GITHUB_API_BASE_URL, endpoint)

        comments_list = self._get_list_response(url, action_result, limit=limit)

        if comments_list is None:
            return action_result.get_status()

        for comment in comments_list:
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

        url = '{0}{1}'.format(GITHUB_API_BASE_URL, endpoint)

        # make rest call
        ret_val, response_json = self._handle_update_request(url=url, action_result=action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response_json)

        summary = action_result.update_summary({})
        summary['issue_number'] = response_json.get('number')
        summary['issue_url'] = response_json.get('html_url')

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_issue(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        repo_owner = param[GITHUB_JSON_REPO_OWNER]
        repo_name = param[GITHUB_JSON_REPO_NAME]
        issue_title = param[GITHUB_JSON_ISSUE_TITLE]

        issue_body = param.get(GITHUB_JSON_ISSUE_BODY, '')

        # assignees should be comma-separated
        assignees = [x.strip() for x in param.get(GITHUB_JSON_ASSIGNEES, '').split(',')]
        assignees = list(filter(None, assignees))

        # labels should be comma-separated
        labels = [x.strip() for x in param.get(GITHUB_JSON_LABELS, '').split(',')]
        labels = list(filter(None, labels))

        request_data = {
            "title": issue_title,
            "body": issue_body,
            "assignees": assignees,
            "labels": labels
        }

        endpoint = GITHUB_ENDPOINT_ISSUES.format(
            repo_owner=repo_owner,
            repo_name=repo_name
        )

        url = '{0}{1}'.format(GITHUB_API_BASE_URL, endpoint)

        # make rest call
        ret_val, response_json = self._handle_update_request(url=url, action_result=action_result, method=GITHUB_REQUEST_POST, data=json.dumps(request_data))

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response_json)

        summary = action_result.update_summary({})
        summary['issue_number'] = response_json.get('number')
        summary['issue_url'] = response_json.get('html_url')

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_issue(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        repo_owner = param[GITHUB_JSON_REPO_OWNER]
        repo_name = param[GITHUB_JSON_REPO_NAME]
        issue_number = param[GITHUB_JSON_ISSUE_NUMBER]
        issue_title = param.get(GITHUB_JSON_ISSUE_TITLE)
        issue_state = param.get(GITHUB_JSON_STATE)
        issue_body = param.get(GITHUB_JSON_ISSUE_BODY)

        # assignees should be comma-separated
        assignees = [x.strip() for x in param.get(GITHUB_JSON_ASSIGNEES, '').split(',')]
        assignees = list(filter(None, assignees))

        # labels should be comma-separated
        labels = [x.strip() for x in param.get(GITHUB_JSON_LABELS, '').split(',')]
        labels = list(filter(None, labels))

        to_empty = param.get(GITHUB_JSON_TO_EMPTY, False)

        request_data = dict()

        if not to_empty:
            if issue_body:
                request_data["body"] = issue_body

            if assignees:
                request_data["assignees"] = assignees

            if labels:
                request_data["labels"] = labels
        else:
            request_data = {
                "body": issue_body,
                "assignees": assignees,
                "labels": labels
            }

        if issue_title:
            request_data["title"] = issue_title

        if issue_state:
            request_data["state"] = issue_state

        endpoint = GITHUB_ENDPOINT_GET_ISSUE.format(
            repo_owner=repo_owner,
            repo_name=repo_name,
            issue_number=issue_number
        )

        url = '{0}{1}'.format(GITHUB_API_BASE_URL, endpoint)

        # make rest call
        ret_val, response_json = self._handle_update_request(url=url, action_result=action_result, method=GITHUB_REQUEST_PATCH, data=json.dumps(request_data))

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response_json)

        summary = action_result.update_summary({})
        summary['issue_number'] = response_json.get('number')
        summary['issue_url'] = response_json.get('html_url')

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_comment(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        repo_owner = param[GITHUB_JSON_REPO_OWNER]
        repo_name = param[GITHUB_JSON_REPO_NAME]
        issue_number = param[GITHUB_JSON_ISSUE_NUMBER]
        comment_body = param[GITHUB_JSON_COMMENT_BODY]

        request_data = {
            "body": comment_body
        }

        endpoint = GITHUB_ENDPOINT_COMMENTS.format(
            repo_owner=repo_owner,
            repo_name=repo_name,
            issue_number=issue_number
        )

        url = '{0}{1}'.format(GITHUB_API_BASE_URL, endpoint)

        # make rest call
        ret_val, response_json = self._handle_update_request(url=url, action_result=action_result, method=GITHUB_REQUEST_POST, data=json.dumps(request_data))

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response_json)

        summary = action_result.update_summary({})
        summary['comment_id'] = response_json.get('id')
        summary['comment_url'] = response_json.get('html_url')

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_labels(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        repo_owner = param[GITHUB_JSON_REPO_OWNER]
        repo_name = param[GITHUB_JSON_REPO_NAME]
        issue_number = param[GITHUB_JSON_ISSUE_NUMBER]

        # labels should be comma-separated list
        labels = [x.strip() for x in param[GITHUB_JSON_LABELS].split(',')]
        labels = list(filter(None, labels))

        request_data = {
            "labels": labels
        }

        endpoint = GITHUB_ENDPOINT_LABELS.format(
            repo_owner=repo_owner,
            repo_name=repo_name,
            issue_number=issue_number
        )

        url = '{0}{1}'.format(GITHUB_API_BASE_URL, endpoint)

        # make rest call
        ret_val, response_json = self._handle_update_request(url=url, action_result=action_result, method=GITHUB_REQUEST_POST, data=json.dumps(request_data))

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.update_data(response_json)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status(success/failure)
        """
        self.debug_print("action_id", self.get_action_identifier())

        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'remove_collaborator': self._handle_remove_collaborator,
            'add_collaborator': self._handle_add_collaborator,
            'remove_member': self._handle_remove_member,
            'add_member': self._handle_add_member,
            'list_events': self._handle_list_events,
            'list_users': self._handle_list_users,
            'list_teams': self._handle_list_teams,
            'list_repos': self._handle_list_repos,
            'list_organizations': self._handle_list_organizations,
            'list_issues': self._handle_list_issues,
            'list_comments': self._handle_list_comments,
            'get_issue': self._handle_get_issue,
            'create_issue': self._handle_create_issue,
            'update_issue': self._handle_update_issue,
            'create_comment': self._handle_create_comment,
            'add_labels': self._handle_add_labels
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        self._state = self.load_state()

        config = self.get_config()

        self._username = config.get(GITHUB_CONFIG_USERNAME)
        self._password = config.get(GITHUB_CONFIG_PASSWORD)
        self._client_id = config.get(GITHUB_CONFIG_CLIENT_ID)
        self._client_secret = config.get(GITHUB_CONFIG_CLIENT_SECRET)
        self._oauth_token = config.get(GITHUB_CONFIG_AUTH_TOKEN)

        self._access_token = self._state.get(GITHUB_ACCESS_TOKEN)
        return phantom.APP_SUCCESS

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.

        :return: status (success/failure)
        """

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

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print "Accessing the Login page"
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={0}'.format(csrftoken)
            headers['Referer'] = login_url

            print "Logging into Platform to get the session id"
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print "Unable to get session id from the platform. Error: {0}".format(str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = GithubConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(ret_val), indent=4)

    exit(0)
