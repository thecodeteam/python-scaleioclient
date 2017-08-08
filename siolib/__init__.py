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

""" ScaleIO API base library

This package provides a module for wrapping the ScaleIO HTTP
RESTful API.

This module is a stand alone module and may be used by any tool
to manage ScaleIO volumes.
"""

from .scaleio import ScaleIO
from .exceptions import (Error,
                         Unauthorized,
                         VolumeNotFound,
                         VolumeExists,
                         VolumeAlreadyMapped,
                         VolumeNotMapped,
                         SizeTooSmall,
                         )

__all__ = ['ScaleIO',
           'Error',
           'Unauthorized',
           'VolumeNotFound',
           'VolumeExists',
           'VolumeAlreadyMapped',
           'VolumeNotMapped',
           'SizeTooSmall',
           ]
