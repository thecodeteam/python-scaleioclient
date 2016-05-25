# -*- coding: utf-8 -*-

""" ScaleIO API base library

This package provides a module for wrapping the ScaleIO HTTP
RESTful API.

This module is a stand alone module and may be used by any tool
to manage ScaleIO volumes.
"""

#
# Copyright (c) 2015 EMC Corporation
# All Rights Reserved

# This software contains the intellectual property of EMC Corporation
# or is licensed to EMC Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of EMC.
#

__version__ = "1.3.5"
__license__ = "emc"
__author__ = "Ryan Hobbs"
__author_email__ = "ryan.hobbs@emc.com"
__company__ = "emc"
_copyright_year_begin = "2015"
__date__ = "2015-06-04"
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
