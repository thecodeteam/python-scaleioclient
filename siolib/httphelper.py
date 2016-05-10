# -*- coding: utf-8 -*-

"""
 HTTP helper script for communicating with RESTful services
"""

#
# Copyright (c) 2015 EMC Corporation
# All Rights Reserved
#
# This software contains the intellectual property of EMC Corporation
# or is licensed to EMC Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of EMC.
#

from __future__ import print_function
from enum import Enum
from json import dumps
from os.path import join as path_join
from functools import wraps
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from time import time
from datetime import datetime, timedelta
from siolib.utilities import eval_compat
import requests

try:
    import logging
    logging.getLogger("requests").setLevel(logging.WARNING)
    # only valid if using request v2.7 or greater
    requests.packages.urllib3.disable_warnings()  # disable warnings
except:
    pass

# script scaleio (as of v1.30) constants
API_LOGIN = 'api/login'
API_GW_LOGIN = 'api/gatewayLogin'
REQ_TYPE = {'gw_request': API_GW_LOGIN, 'api_request': API_LOGIN}

GW_REQ_TIMEOUT = 30.0
GW_REQ_RETRIES = 4

def basicauth(func):
    """
    Decorator that will acquire an HTTP token that will be used for authentication
    between the client and the ScaleIO gateway.
    :param func: Function decorated
    :return: None
    """

    @wraps(func)
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
            r_uri = REQ_TYPE[func.__name__]
            http_resp = request(op=HttpAction.GET, addr=addr,
                                uri=r_uri, auth=httpauth)
            token.token = http_resp.text
            logging.warn("SIOLIB: (basicauth) New ScaleIO gateway token={0}".format(http_resp.text))

        kwargs['token'] = token
        # call function/method this decorator wraps
        ret = func(*args, **kwargs)
        return ret

    return auth

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

    status_code = 0  # default status code
    reason = None  # default reason
    u_prefix = 'https://'  # default to secure https
    headers = headers or {'Content-Type': 'application/json'}

    # enum34 handles things differently than enum0.4.4
    op_value = eval_compat(op)

    # always remove slashes at beginning of uri
    uri = uri.strip('/')
    user, password = auth  # split up auth tuple
    http_auth = HTTPBasicAuth(user, password)  # create HTTP basic auth object
    session = requests.Session()  # Get session
    session.mount(u_prefix, Adapter(max_retries=GW_REQ_RETRIES))  # Mount to adapter
    #session.headers.update({'Authorization': password})
    session.headers.update(headers)  # update headers
    r_url = path_join(u_prefix, '%s:%s' % addr, uri)  # create url of request

    http_func = getattr(session, op_value)  # get request method

    try:
        if op_value in ('put', 'post', 'patch'):
            http_resp = http_func(
                r_url, auth=http_auth, data=dumps(data), verify=False, timeout=GW_REQ_TIMEOUT)
        else:
            http_resp = http_func(r_url, auth=http_auth, verify=False, timeout=GW_REQ_TIMEOUT)
        status_code = http_resp.status_code
        reason = http_resp.reason
    except requests.Timeout as err:
        logging.error(
            'Error: HTTP - {0} request to {1} failed'.format(repr(err), r_url))
        raise RuntimeError(
            'httpStatusCode = {0}, reason = {1}, request timed out!'.format(status_code, reason))
    except requests.ConnectionError as err:
        logging.error(
            'Error: HTTP - {0} request to {1} failed'.format(repr(err), r_url))
        raise RuntimeError(
            'httpStatusCode = {0}, reason = {1}, check connection!'.format(status_code, reason))
    except requests.HTTPError as err:
        logging.error(
            'Error: HTTP - {0} request to {1} failed'.format(repr(err), r_url))
        raise RuntimeError(
            'httpStatusCode = {0}, reason = {1}, check rest gateway!'.format(status_code, reason))
    except requests.RequestException as err:
        logging.error(
            'Error: HTTP - {0} request to {1} failed'.format(repr(err), r_url))
        raise RuntimeError('httpStatusCode = {0}, reason = {1}, check '
                           'request payload!'.format(status_code, reason))

    if http_resp is not None and http_resp.status_code == 401:
        logging.error('Error: HTTP - Unauthorized request to {0}, '
              'please check basic credentials {1}'.format(r_url, auth))


    return http_resp

class Singleton(type):
    """
    A singleton factory. A defined class behavior expected to be used
    as a metaclass
    """


    _klasses = {}
    def __call__(cls, *args, **kwargs):
        """
        Callable used to check if the class is already instanced
        :param cls:
        :param args: Class args
        :param kwargs: Class keyword args
        :return: Instance of class or a new instance of the class
        """

        # standard design pattern for a singleton class if instance exists return
        if cls not in cls._klasses:
            cls._klasses[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._klasses[cls]


class Token(object):
    """
    Class represents an HTTP Token object that is used for HTTP basic authentication
    """

    __metaclass__ = Singleton # this class behaves like a singleton

    def __init__(self, http_token=None):
        """
        Create a Token instance that will be used to perform basic
        authentication against an HTTP web/rest service.
        :param http_token: Token string if you want to create a
                           new Token with an existing hashed value
        :return: HTTP auth Token object
        """

        self._start_time = 0  # record when we created the token
        self._expired = False
        if not http_token:  # if not seeded assume expired
            self._expired = True
        self._token = http_token

    def valid(self, force_expire=False):
        """
        Token property getter
        """

        _current_time = time()

        if _current_time - self._start_time > 60*8 or force_expire:  # 8 min
            self._expired = True
            self._start_time = time()  # reset

        if self._expired:
            logging.warn("SIOLIB: (token) token expired at={0}".format(datetime.utcnow()))
            return False # token invalid
        else:
            return True # token valid

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
        current_datetime = datetime.now().utcnow()
        expire_datetime = datetime.utcnow() + timedelta(minutes=8)
        logging.warn("SIOLIB: (token) token created at at={0} expires in={1}".format(current_datetime, expire_datetime))
        self._expired = False  # new token set expiry to false

class Adapter(HTTPAdapter):

    """
    The built-in HTTP Adapter for urllib3. Provides a general-case interface
    for Requests sessions to contact HTTP and HTTPS urls by implementing the
    Transport Adapter interface.
    """

    def init_poolmanager(self, connections, maxsize, block=False):
        """
        Initializes a urllib3 PoolManager.
        :param connections: The number of urllib3 connection pools to cache.
        :param maxsize: The maximum number of connections to save in the pool.
        :param block: Block when no free connections are available.
        :return:
        """

        # only exposed for use when subclassing the HTTPAdapter.

        from ssl import PROTOCOL_TLSv1

        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=PROTOCOL_TLSv1)


class HttpAction(Enum):

    """
    Enumeration object to aid in setting op functions for HTTP requests
    """

    GET = 'get'
    PUT = 'put'
    POST = 'post'
    PATCH = 'patch'
    DELETE = 'delete'

