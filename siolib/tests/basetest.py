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
ScaleIO API library tests
"""

import os
import random
import string
from unittest import TestCase

import siolib

class BaseTest(TestCase):

    scaleio = None
    initial_vol_size = 8
    extend_vol_size = 16
    volume_base_name = "test-siolib-"
    random_string_len = 10
    gateway = None
    port = None
    username = None
    password = None
    domain = None
    pool = None
    default_sdc = None

    def setUp(self):
        self.gateway = os.getenv('SIO_GATEWAY')
        self.assertIsNotNone(self.gateway, "SIO_GATEWAY is not set")
        self.port = os.getenv('SIO_GATEWAY_PORT')
        self.assertIsNotNone(self.port, "SIO_GATEWAY_PORT is not set")
        self.username = os.getenv('SIO_USERNAME')
        self.assertIsNotNone(self.username, "SIO_USERNAME is not set")
        self.password = os.getenv('SIO_PASSWORD')
        self.assertIsNotNone(self.password, "SIO_PASSWORD is not set")

        self.domain = os.getenv('SIO_DOMAIN')
        self.assertIsNotNone(self.domain, "SIO_DOMAIN is not set")
        self.pool = os.getenv('SIO_POOL')
        self.assertIsNotNone(self.pool, "SIO_POOL is not set")

        self.default_sdc = os.getenv('SIO_SDCGUID')
        #self.assertIsNotNone(self.default_sdc, "SIO_SDCGUID is not set")

        self.scaleio = siolib.ScaleIO(rest_server_ip=self.gateway,
                                      rest_server_port=self.port,
                                      rest_server_username=self.username,
                                      rest_server_password=self.password,
                                      verify_server_certificate=False,
                                      server_certificate_path=''
                                      )

    def _random_name(self):
        # randomized volume name
        unique = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(self.random_string_len))
        return self.volume_base_name + unique



