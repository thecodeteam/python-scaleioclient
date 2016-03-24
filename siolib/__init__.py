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

from oslo.config import cfg

# ScaleIO volume provision type constant
VOL_TYPE = {"thickprovisioned": "ThickProvisioned", "thinprovisioned": "ThinProvisioned"}

SIOGROUP = cfg.OptGroup(name='scaleio',
                        title='ScaleIO Configuration Values')

SIOOPTS = [
    cfg.IntOpt('rest_server_port',
               default=443,
               help='The ScaleIO host gateway port address'),
    cfg.StrOpt('rest_server_ip',
                help='The ScaleIO host gateway ip addresses'),
    cfg.StrOpt('rest_server_username',
               default='admin',
               help='The ScaleIO current gateway username for install'),
    cfg.StrOpt('rest_server_password',
               default='123456',
               help='The ScaleIO current gateway password for install'),
    cfg.StrOpt('protection_domain_name',
               help='The ScaleIO default protection domain'),
    cfg.StrOpt('storage_pool_name',
               help='The ScaleIO default storage pool'),
    cfg.ListOpt('storage_pools',
                default=[],
               help='The ScaleIO default available storage pools'),
    cfg.BoolOpt('round_volume_capacity',
                default=True,
                help='Provides ability to control behavior of creating or '
                     'extending a volume to a size which is a nonmultiple '
                     'of 8GB'),
    cfg.BoolOpt('force_delete',
                default=False,
                help='Allows force deletions of volumes that do not exist'
                     'in ScaleIO due to an error in creation'),
    cfg.BoolOpt('unmap_volume_before_deletion',
                default=False,
                help='Ensure that the volume is not mapped to any SDC'
                     'before deletion, since in OpenStack, a volume can'
                     'be deleted automatically when terminating instances.'),
    cfg.BoolOpt('verify_server_certificate',
                default=False,
                help='The OpenStack ScaleIO Cinder driver communicates with '
                     'the ScaleIO Gateway through https (in other words, over SSL). '
                     'By default, the driver ignores the gateway SSL certificate '
                     'verification. However, the ScaleIO Cinder driver can be '
                     'configured to verify the certificate'),
    cfg.StrOpt('server_certificate_path',
               help='Path to the certificate to use if verify_certificate is set True'),
    cfg.StrOpt('provisioning_type',
               default="ThickProvisioned",
               help='Define volumes as thick, where the entire capacity '
                    'is provisioned for storage, or thin, where only the '
                    'capacity currently needed is provisioned.'),
    cfg.StrOpt('default_sdcguid',
               default=None,
               help='The ScaleIO default SDC guid to use (test use only)'),
]

class ConfigOpts(cfg.ConfigOpts):

    def __init__(self):

        super(ConfigOpts, self).__init__()


