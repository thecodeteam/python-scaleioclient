# -*- coding: utf-8 -*-

"""
 Utility functions for ScaleIO API library
"""

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

from base64 import b16decode, b64encode, urlsafe_b64encode
from collections import OrderedDict
from time import time
import enum
import uuid
import math
import re

class ProvisionType(enum.Enum):

    """
    Enumeration object to aid in setting op functions for HTTP requests
    """

    THICK = 'ThickProvisioned'
    THIN = 'ThinProvisioned'

class UnitSize(enum.Enum):

    BYTE = 1099511627776
    KBYTE = 1073741824
    MBYTE = 1048576
    GBYTE = 1024
    TBYTE = 1

def encode_base64(value):
    """
    Binary to text encoding of a string into a base 64
    using a radix-numerical system. Function is idempotent.
    :param value: String value to encode into base64
    :return: Base64 encoded ASCII string
    """

    from string import maketrans
    # UUID regex
    uuid_regx = re.compile("^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z", re.IGNORECASE)
    # GUID regex
    guid_regex = re.compile("[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}", re.IGNORECASE)
    # Base64 regex
    b64_regx = re.compile("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$")
    # store value it may already be encoded
    encoded_name = value

    # check if value is a UUID if True convert to hex
    uuid_match = uuid_regx.match(value)
    if uuid_match:
        value = uuid.UUID(uuid_match.group(0)).hex
    # check if value is a GUID (GUID is just a MS impelentation of UUID)
    guid_match = guid_regex.match((value))
    if guid_match:
        value = uuid.UUID(guid_match.group(0)).hex
    # Use translation table to remove hyphens - and
    # underscores _ these are invalid b64 characters
    trans_tbl = maketrans("-_", "+/")
    value = str(value).translate(trans_tbl)

    try:
        # if string is hex decode first
        name = b16decode(value.upper())
        # encode now in base 64
        encoded_name = b64encode(name)
    except TypeError: # b16 decode failure
        # check if passed in string is already base64
        b64_match = b64_regx.match(value)
        if not b64_match:
            # if string is not hex and not b64 create a new b64 string
            encoded_name = urlsafe_b64encode(uuid.uuid4().bytes) # generate a valid b64 value

    return  encoded_name

def encode_string(value, double=False):
    """
    Url encode a string to ASCII in order to escape any characters not
     allowed :, /, ?, #, &, =. If parameter 'double=True' perform two passes
     of encoding which may be required for some REST api endpoints. This is
     usually done to remove any additional special characters produce by the
     single encoding pass.
    :param value: Value to encode
    :param double: Double encode string
    :return:
    """

    from urllib import quote
    # Replace special characters in string using the %xx escape
    encoded_str = quote(value, '')
    if double: # double encode
        encoded_str = quote(encoded_str, '')

    return encoded_str

def in_container():
    """
    Check if we are running inside a container.  Check cgroups to determine if
    we are running inside a container.

    :return: Boolean True, running in a container False, not running in a container
    """

    containerized = False
    cn_match =  re.compile('.*?' + '(docker)|(lxc)', re.IGNORECASE|re.DOTALL)
    try:
        with open("/proc/1/cgroup") as cgroup_out:
            match = cn_match.search(cgroup_out.read()) # stop at first match
            if match:
                print("ScaleIO OpenStack Nova LibVirt driver is running inside of a {0} container.".format(match.group(1)))
                containerized = True
    except IOError:
        pass # do nothing if we are not running in a container

    return containerized

def eval_compat(enumarg):
    if hasattr(enumarg, 'value'):
        return enumarg.value
    else:
        return enumarg

def check_size(size, unit_from, unit_to):

    # enum34 handles things differently than enum0.4.4
    unit_from = eval_compat(unit_from)
    unit_to = eval_compat(unit_to)

    if int(unit_from) == int(unit_to):
        new_size = int(size)
        if int(unit_to) == eval_compat(UnitSize.BYTE):
            block_size = 8589934592
        if int(unit_to) == eval_compat(UnitSize.KBYTE):
            block_size = 8388608
        if int(unit_to) == eval_compat(UnitSize.MBYTE):
            block_size = 8192
        if int(unit_to) == eval_compat(UnitSize.GBYTE):
            block_size = 8
        if int(unit_to) == eval_compat(UnitSize.TBYTE):
            block_size = 0.0078125
    elif int(unit_from) > int(unit_to): # division
        if int(unit_to) == eval_compat(UnitSize.BYTE):
            new_size = size
            block_size = 8589934592
        if int(unit_to) == eval_compat(UnitSize.KBYTE):
            new_size = size / 1024
            block_size = 8388608
        if int(unit_to) == eval_compat(UnitSize.MBYTE):
            new_size = size / math.pow(1024, 2)
            block_size = 8192
        if int(unit_to) == eval_compat(UnitSize.GBYTE):
            new_size = size / math.pow(1024, 3)
            block_size = 8
        if int(unit_to) == eval_compat(UnitSize.TBYTE):
            new_size = size / math.pow(1024, 4)
            block_size = 0.0078125
    else: #multiplication
        if int(unit_from) == eval_compat(UnitSize.KBYTE):
            new_size = size
            block_size = 8388608
        if int(unit_from) == eval_compat(UnitSize.MBYTE):
            new_size = size * 1024
            block_size = 8192
        if int(unit_from) == eval_compat(UnitSize.GBYTE):
            new_size = size * math.pow(1024, 2)
            block_size = 8
        if int(unit_from) == eval_compat(UnitSize.TBYTE):
            new_size = size * math.pow(1024, 3)
            block_size = 0.0078125

    return int(new_size), int(block_size)

class LRUCache(object):

    def __init__(self, cache_size, expiry_sec=60*10):
        """
        Create a simple LRU cache with expiration
        :param cache_size: Size of the LRU cache to create
        :param expiry_sec: Time in which item in cache expires
        :return: LRUCache object
        """

        # All items will expire at some point regardless of access
        # this will prevent stale data in the cache.
        # We use an ordered dictionary because it keeps track
        # of when an item is added to the cache.  If we add an
        # item and the capacity is > max, we will purge the oldest
        # last item added to the cache.

        self.size = cache_size
        self.expiry = expiry_sec
        # ordered dict containing cache items
        self.lru = OrderedDict()
        # ordered dict containing the time cached entry was inserted
        self.lru_access_time = OrderedDict()

    def set(self, key, value):
        """
        Add item to the LRUCache. If item being added exceeds cache capacity
        remove the last (oldest) item added in the cache.
        :param key: Unique key of item to set in cache
        :param value: Item to add to cache
        :return: Nothing
        """

        try:
            self.lru.pop(key=key)
        except KeyError:
            if len(self.lru) >= self.size:
                self.lru.popitem(last=False)
                self.lru_access_time.pop(key=key)

        self.lru_access_time[key] = time()
        self.lru[key] = value

    def get(self, key):
        """
        Return cached item in LRUCache. Will return False if item has been
        evicted or the cache is stale.
        :param key: Unique key of item to retrieve from cache
        :return: Item in cache
        """

        try:
            # get current time stamp
            now = time()
            # check accesstime of entry if expiry, evsict and return False
            expiry = self.lru_access_time[key]
            if now - expiry > self.expiry:
                # Pop item from cache
                self.lru_access_time.pop(key=key)
                self.lru.pop(key=key)
                return False
            else:
                value = self.lru[key]# get item from cache
                self.lru_access_time[key] = time()

            return value
        except KeyError:
            # item is not found in cache return False
            return False

def parse_value(value):

    if is_openstack_id(value):
        print "OPENSTACK ID FOUND"
        # base 64 encode and return
        value = encode_base64(value)

    return value

def is_openstack_id(value):

    valid_identifier = False
    # UUID regex
    uuid_regx = re.compile("^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z", re.IGNORECASE)
    # GUID regex
    guid_regex = re.compile("[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}", re.IGNORECASE)

    # check if value is a UUID if True convert to hex
    uuid_match = uuid_regx.match(value)
    if uuid_match:
        valid_identifier = True

    guid_match = guid_regex.match(value)
    if guid_match:
        valid_identifier = True

    return valid_identifier

def is_sio_native(value):

    valid_identifier = False
    # Base64 regex
    b64_regx = re.compile("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$")

    #
    b64_match = b64_regx.match(value)
    if b64_match:
        valid_identifier = True

    return valid_identifier

def is_id(value):

    try:
        int(value, 16)
        return True
    except ValueError:
        return False
