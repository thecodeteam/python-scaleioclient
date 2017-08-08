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
 Utility functions for ScaleIO API library
"""

import enum
import math
import re
from six.moves.urllib.parse import quote


class UnitSize(enum.Enum):

    BYTE = 1099511627776
    KBYTE = 1073741824
    MBYTE = 1048576
    GBYTE = 1024
    TBYTE = 1


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

    # Replace special characters in string using the %xx escape
    encoded_str = quote(value, '')
    if double:  # double encode
        encoded_str = quote(encoded_str, '')

    return encoded_str


def in_container():
    """
    Check if we are running inside a container.  Check cgroups to determine if
    we are running inside a container.

    :return: Boolean True, running in a container False, not running in
             a container
    """

    containerized = False
    cn_match = re.compile('.*?' + '(docker)|(lxc)', re.IGNORECASE | re.DOTALL)
    try:
        with open('/proc/1/cgroup') as cgroup_out:
            match = cn_match.search(cgroup_out.read())  # stop at first match
            if match:
                print('ScaleIO OpenStack Nova LibVirt driver is running '
                      'inside of a {0} container.'.format(match.group(1)))
                containerized = True
    except IOError:
        pass  # do nothing if we are not running in a container

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
    elif int(unit_from) > int(unit_to):  # division
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
    else:  # multiplication
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


def is_id(value):

    try:
        int(value, 16)
        return True
    except ValueError:
        return False
