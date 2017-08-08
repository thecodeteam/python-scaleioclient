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

from basetest import BaseTest
import siolib

class Test_AttachDetach(BaseTest):

    def test_attach(self):
        self.assertIsNotNone(self.default_sdc, "SIO_SDCGUID not set, failing attach tests")

        volume_name = self._random_name()
        self.scaleio.create_volume(volume_name,
                                   self.domain,
                                   self.pool,
                                   provisioning_type='thin')
        self.scaleio.attach_volume(volume_name, self.default_sdc)
        # make sure it is attached
        self.assertTrue(self.scaleio.is_volume_attached(volume_name, self.default_sdc))
        # detach it
        self.scaleio.detach_volume(volume_name, self.default_sdc)
        # make sure it is detached
        self.assertFalse(self.scaleio.is_volume_attached(volume_name, self.default_sdc))
        # delete the volume
        self.scaleio.delete_volume(volume_name)

    def test_delete_while_attached(self):
        self.assertIsNotNone(self.default_sdc, "SIO_SDCGUID not set, failing attach tests")

        volume_name = self._random_name()
        self.scaleio.create_volume(volume_name,
                                   self.domain,
                                   self.pool,
                                   provisioning_type='thin')
        self.scaleio.attach_volume(volume_name, self.default_sdc)
        # make sure it is attached
        self.assertTrue(self.scaleio.is_volume_attached(volume_name, self.default_sdc))
        # delete it, without unmapping first
        self.assertRaises(siolib.Error, self.scaleio.delete_volume, volume_name, unmap_on_delete=False)
        # make sure volume is still available and not unmapped
        self.assertTrue(self.scaleio.is_volume_attached(volume_name, self.default_sdc))
        # delete it and unmap
        self.scaleio.delete_volume(volume_name, unmap_on_delete=True)
        # make sure the volume is deleted
        self.assertRaises(siolib.VolumeNotFound,
                          self.scaleio.get_volumename,
                          volume_name)



