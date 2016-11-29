# -*- coding: utf-8 -*-

# Copyright (c) 2015 - 2016 EMC Corporation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
 HTTP helper script for communicating with RESTful services
"""

from __future__ import print_function

import datetime
import functools
import json
import logging
import os.path
import time

import enum
import requests

from siolib import exceptions
from siolib import utilities

try:
    logging.getLogger('requests').setLevel(logging.WARNING)
    # only valid if using request v2.7 or greater
    requests.packages.urllib3.disable_warnings()  # disable warnings
except:
    pass

LOG = logging.getLogger(__name__)

API_LOGIN_PATH = 'api/login'

GW_REQ_TIMEOUT = 30.0
GW_REQ_RETRIES = 4
TOKEN_INACTIVITY_LIFETIME = 60 * 8  # 8 min


def basicauth(func):
    """
    Decorator that will acquire an HTTP token that will be used for
    authentication between the client and the ScaleIO gateway.
    :param func: Function decorated
    :return: None
    """

    @functools.wraps(func)
    def auth(*args, **kwargs):
        """
        Check if Token is valid, if not create a new Token
        """

        # get current Token or create a new Token
        token = kwargs.get('token') or Token()
        # get the ip/port address pair of gw
        addr = kwargs.get('host', ())
        # get current credentials
        httpauth = kwargs.get('auth', ())

        if not token.valid():  # token has expired get a new one
            # function name is uri endpoint
            r_uri = API_LOGIN_PATH
            http_resp = request(op=HttpAction.GET, addr=addr,
                                uri=r_uri, auth=httpauth)
            if http_resp.status_code != 200:
                raise exceptions.Unauthorized(
                    'Could not authenticate on ScaleIO with: [%s] %s'
                    % (http_resp.status_code, http_resp.json().get('message')))
            token.token = http_resp.text
            LOG.debug('Token %x acquired', id(token.token))

        kwargs['token'] = token
        # call function/method this decorator wraps
        ret = func(*args, **kwargs)
        return ret

    return auth


@basicauth
def api_request(**kwargs):
    """
    Perform a HTTP RESTful request call. If Token is passed in, it will be
    updated correctly because Python passes values by reference.
    :param op: HttpAction GET, PUT, POST, DELETE
    :param uri: HTTP resource endpoint
    :param host: RESTful gateway host ip
    :param data: HTTP Payload (optional)
    :param auth: HTTP basic authentication credentials (optional)
    :param token: HTTP token (optional)
    :return: HTTP request object
    """

    # attempt to use gw 1 token
    server_authtoken = kwargs.get('token')
    username, _ = kwargs.get('auth')
    auth = (username, server_authtoken.token)

    req = request(op=kwargs.get('op'), addr=kwargs.get('host'),
                  uri=kwargs.get('uri'), auth=auth,
                  data=kwargs.get('data', {}))

    if req.status_code == 401:
        LOG.info('Auth error [%s] %s occured with request of %s on %s with '
                 'token %s. Trying to re-new the token and re-run the request',
                 req.status_code, req.json().get('message'),
                 kwargs.get('uri'), kwargs.get('host'), id(server_authtoken))
        server_authtoken.expire()
        api_request(**kwargs)
        req = request(op=kwargs.get('op'), addr=kwargs.get('host'),
                      uri=kwargs.get('uri'), auth=auth,
                      data=kwargs.get('data', {}))

    return req


def request(op, addr, uri, data=None, headers=None, auth=None):
    """
    Perform HTTP request
    :param op: HTTPACTION verb GET, PUT, POST, DELETE
    :param addr: ip:port address of http endpoint
    :param uri: Request url
    :param data: Request payload
    :param headers: Request headers
    :param auth: Request authentication tuple
    :return: HTTP response Object
    """

    u_prefix = 'https://'  # default to secure https
    headers = headers or {'Content-Type': 'application/json'}

    # enum34 handles things differently than enum0.4.4
    op_value = utilities.eval_compat(op)

    # always remove slashes at beginning of uri
    uri = uri.strip('/')
    user, password = auth  # split up auth tuple
    # create HTTP basic auth object
    http_auth = requests.auth.HTTPBasicAuth(user, password)
    session = requests.Session()  # Get session
    # Mount to adapter session.headers.update({'Authorization': password})
    session.mount(u_prefix,
                  requests.adapters.HTTPAdapter(max_retries=GW_REQ_RETRIES))
    session.headers.update(headers)  # update headers
    r_url = os.path.join(u_prefix, '%s:%s' % addr, uri)  # create request url

    http_func = getattr(session, op_value)  # get request method

    if op_value in ('put', 'post', 'patch'):
        data_str = json.dumps(data)
        LOG.debug('REQ: %s %s %s', op_value, r_url, data_str)
        http_resp = http_func(
            r_url, auth=http_auth, data=data_str, verify=False,
            timeout=GW_REQ_TIMEOUT)
    else:
        LOG.debug('REQ: %s %s', op_value, r_url)
        http_resp = http_func(r_url, auth=http_auth, verify=False,
                              timeout=GW_REQ_TIMEOUT)

    resp_text = http_resp.text
    if uri == API_LOGIN_PATH and http_resp.status_code == 200:
        resp_text = '<new token>'
    LOG.debug('RESP: [%s] (elapsed %s) %s',
              http_resp.status_code, http_resp.elapsed, resp_text)

    return http_resp


class Singleton(type):
    """
    A singleton factory. A defined class behavior expected to be used
    as a metaclass
    """

    _klasses = {}

    def __call__(self, *args, **kwargs):
        """
        Callable used to check if the class is already instanced
        :param self:
        :param args: Class args
        :param kwargs: Class keyword args
        :return: Instance of class or a new instance of the class
        """

        # standard design pattern for a singleton class if instance exists
        # return
        if self not in self._klasses:
            self._klasses[self] = super(Singleton, self).__call__(*args,
                                                                  **kwargs)
        return self._klasses[self]


class Token(object):
    """
    Class represents an HTTP Token object that is used for HTTP basic
    authentication
    """

    def __init__(self, http_token=None):
        """
        Create a Token instance that will be used to perform basic
        authentication against an HTTP web/rest service.
        :param http_token: Token string if you want to create a
                           new Token with an existing hashed value
        :return: HTTP auth Token object
        """

        self._start_time = 0  # record when we created the token
        self._token = http_token
        if self._token:
            self._start_time = time.time()
        self._expired = not self._token
        LOG.debug('Initialize new %x token', id(self))

    def valid(self):
        if self._expired:
            return False

        if time.time() - self._start_time > TOKEN_INACTIVITY_LIFETIME:
            self._expired = True
            if self._start_time:
                LOG.debug('Token %x is expired at %s',
                          id(self), datetime.datetime.utcnow())

        return not self._expired

    def expire(self):
        self._expired = True
        LOG.debug('Token %s is forcedly expired', id(self))

    @property
    def token(self):
        """
        Token property getter
        """
        return self._token

    @token.setter
    def token(self, value):
        """
        Token property setter
        """

        if value:
            self._token = value.strip('"')  # strip extra double quotes
        else:
            self._token = value
        self._start_time = time.time()
        self._expired = False  # new token set expiry to false
        current_datetime = datetime.datetime.now().utcnow()
        expire_datetime = (datetime.datetime.utcnow() +
                           datetime.timedelta(minutes=8))
        LOG.debug('Token %s is set at %s, expires at %s',
                  id(self), current_datetime, expire_datetime)


class TokenFactory(object):

    __metaclass__ = Singleton  # this class behaves like a singleton

    def __init__(self):
        self._tokens = {}

    def get_token(self, addr, auth):
        addr_str = '%s:%s' % addr
        auth_str = '%s:%s' % auth
        token_key = '%s@%s' % (auth_str, addr_str)
        if token_key not in self._tokens:
            LOG.debug('Creating new token for %s@%s:%s',
                      auth[0], addr[0], addr[1])
            self._tokens[token_key] = Token()
        token = self._tokens[token_key]
        LOG.debug('Use %x token for %s@%s:%s',
                  id(token), auth[0], addr[0], addr[1])
        return token


class HttpAction(enum.Enum):

    """
    Enumeration object to aid in setting op functions for HTTP requests
    """

    GET = 'get'
    PUT = 'put'
    POST = 'post'
    PATCH = 'patch'
    DELETE = 'delete'
