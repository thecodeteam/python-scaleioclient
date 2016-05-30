# -*- coding: utf-8 -*-

""" ScaleIO API base library

This package provides a module for wrapping the ScaleIO HTTP
RESTful API.

This module is a stand alone module and may be used by any tool
to manage ScaleIO volumes.
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

__version__ = "1.6.0.dev1"
__license__ = "Apache Software License, Version 2.0"
__author__ = "Cloudscaling (EMC)"
__author_email__ = "openstack@cloudscaling.com"
__company__ = "EMC Corporation"
_copyright_year_begin = "2015"
__date__ = "2016-05-30"
_copyright_year_latest = __date__.split('-')[0]
_copyright_year_range = _copyright_year_begin
if _copyright_year_latest > _copyright_year_begin:
    _copyright_year_range += "–%(_copyright_year_latest)s" % vars()
__copyright__ = (
    "Copyright © %(_copyright_year_range)s"
    " %(__company__)s") % vars()

# ScaleIO volume provision type constant
VOL_TYPE = {"thickprovisioned": "ThickProvisioned", "thinprovisioned": "ThinProvisioned",
            "thick": "ThickProvisioned", "thin": "ThinProvisioned"}
