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

class Test_Volume(BaseTest):

    def test_create_and_delete_volume(self):
        volume_name = self._random_name()
        self.scaleio.create_volume(volume_name,
                                   self.domain,
                                   self.pool,
                                   provisioning_type='thin')
        volume_id = self.scaleio.get_volumeid(volume_name)
        self.assertEqual(volume_name, self.scaleio.get_volumename(volume_id))
        self.scaleio.delete_volume(volume_name, True)
        self.assertRaises(siolib.VolumeNotFound,
                          self.scaleio.get_volumename, volume_name)

    def test_resize_volume(self):
        volume_name = self._random_name()
        # create a volume, and check the size
        self.scaleio.create_volume(volume_name,
                                   self.domain,
                                   self.pool,
                                   provisioning_type='thin',
                                   volume_size_gb=self.initial_vol_size)
        initial_size = self.scaleio.get_volumesize(volume_name)
        self.assertEqual(initial_size, self.initial_vol_size*1024*1024)
        # resize it
        self.scaleio.extend_volume(volume_name, self.extend_vol_size)
        new_size = self.scaleio.get_volumesize(volume_name)
        self.assertEqual(new_size, self.extend_vol_size*1024*1024)
        # delete it
        self.scaleio.delete_volume(volume_name, True)

    def test_rename_volume(self):
        volume_name_1 = self._random_name()
        volume_name_2 = self._random_name()
        # create a volume
        self.scaleio.create_volume(volume_name_1,
                                   self.domain,
                                   self.pool,
                                   provisioning_type='thin',
                                   volume_size_gb=self.initial_vol_size)
        # get the volume id
        volume_id = self.scaleio.get_volumeid(volume_name_1)
        # rename it
        self.scaleio.rename_volume(volume_name_1, volume_name_2)
        # make sure it got renamed
        self.assertEqual(volume_name_2, self.scaleio.get_volumename(volume_id))
        # make sure old volume name is no longer valid
        self.assertRaises(siolib.VolumeNotFound,
                          self.scaleio.get_volumename,
                          volume_name_1)
        # delete the volume
        self.scaleio.delete_volume(volume_id, True)

    def test_snapshot(self):
        volume_name = self._random_name()
        snapshot_name = volume_name + "snap"
        # create a volume
        self.scaleio.create_volume(volume_name,
                                   self.domain,
                                   self.pool,
                                   provisioning_type='thin')
        # snap it
        self.scaleio.snapshot_volume(volume_name, snapshot_name)
        snapshot_id = self.scaleio.get_volumeid(snapshot_name)
        self.assertEqual(snapshot_name, self.scaleio.get_volumename(snapshot_id))
        # delete the volume
        self.scaleio.delete_volume(volume_name)
        self.assertRaises(siolib.VolumeNotFound,
                          self.scaleio.get_volumename,
                          volume_name)
        # delete the snapshot
        self.scaleio.delete_volume(snapshot_name)
        self.assertRaises(siolib.VolumeNotFound,
                          self.scaleio.get_volumename,
                          snapshot_name)

    def test_delete_multiple_modes(self):
        volume_name = self._random_name()
        snapshot_name = self._random_name()
        # create the volume
        self.scaleio.create_volume(volume_name,
                                   self.domain,
                                   self.pool,
                                   provisioning_type='thin',
                                   volume_size_gb=self.initial_vol_size)
        # snap the volume
        self.scaleio.snapshot_volume(volume_name, snapshot_name)
        # try deleting with two remove modes, invalid request
        self.assertRaises(ValueError,
                          self.scaleio.delete_volume,
                          volume_name,
                          include_descendents=True,
                          only_descendents=True)
        # delete the whole vtree
        self.scaleio.delete_volume(volume_name, vtree=True)
        # make sure no volumes or snaps exist
        self.assertRaises(siolib.VolumeNotFound,
                          self.scaleio.get_volumename,
                          volume_name)
        self.assertRaises(siolib.VolumeNotFound,
                          self.scaleio.get_volumename,
                          snapshot_name)

    def test_delete_only_descendants(self):
        volume_name = self._random_name()
        snapshot_name = self._random_name()
        # create the volume
        self.scaleio.create_volume(volume_name,
                                   self.domain,
                                   self.pool,
                                   provisioning_type='thin',
                                   volume_size_gb=self.initial_vol_size)
        # snap the volume
        self.scaleio.snapshot_volume(volume_name, snapshot_name)
        # delete just the descendants
        self.scaleio.delete_volume(volume_name,
                                   only_descendents=True)
        # the snapshot should be gone
        self.assertRaises(siolib.VolumeNotFound,
                          self.scaleio.get_volumename,
                          snapshot_name)
        # the volume should still exist
        self.scaleio.get_volumeid(volume_name)
        # delete the volume
        self.scaleio.delete_volume(volume_name, vtree=True)
        # make sure no volumes exist
        self.assertRaises(siolib.VolumeNotFound,
                          self.scaleio.get_volumename,
                          volume_name)

    def test_delete_include_descendants(self):
        volume_name = self._random_name()
        snapshot_name = self._random_name()
        # create the volume
        self.scaleio.create_volume(volume_name,
                                   self.domain,
                                   self.pool,
                                   provisioning_type='thin',
                                   volume_size_gb=self.initial_vol_size)
        # snap the volume
        self.scaleio.snapshot_volume(volume_name, snapshot_name)
        # delete just the descendants
        self.scaleio.delete_volume(volume_name,
                                   include_descendents=True)
        # make sure no volumes or snaps exist
        self.assertRaises(siolib.VolumeNotFound,
                          self.scaleio.get_volumename,
                          volume_name)
        self.assertRaises(siolib.VolumeNotFound,
                          self.scaleio.get_volumename,
                          snapshot_name)

    def test_delete_vtree(self):
        volume_name = self._random_name()
        snapshot_name = self._random_name()
        # create the volume
        self.scaleio.create_volume(volume_name,
                                   self.domain,
                                   self.pool,
                                   provisioning_type='thin',
                                   volume_size_gb=self.initial_vol_size)
        # snap the volume
        self.scaleio.snapshot_volume(volume_name, snapshot_name)
        # delete the snapshot but specify the whole vtree (will also delete parents)
        self.scaleio.delete_volume(snapshot_name,
                                   vtree=True)
        # make sure no volumes or snaps exist
        self.assertRaises(siolib.VolumeNotFound,
                          self.scaleio.get_volumename,
                          volume_name)
        self.assertRaises(siolib.VolumeNotFound,
                          self.scaleio.get_volumename,
                          snapshot_name)

    def test_delete_only_me(self):
        volume_name = self._random_name()
        snapshot_name = self._random_name()
        # create the volume
        self.scaleio.create_volume(volume_name,
                                   self.domain,
                                   self.pool,
                                   provisioning_type='thin',
                                   volume_size_gb=self.initial_vol_size)
        # snap the volume
        self.scaleio.snapshot_volume(volume_name, snapshot_name)
        # delete just the volume
        self.scaleio.delete_volume(volume_name)
        # make sure the volumes does not exist
        self.assertRaises(siolib.VolumeNotFound,
                          self.scaleio.get_volumename,
                          volume_name)
        # but the snapshot will
        self.scaleio.get_volumeid(snapshot_name)
        self.scaleio.delete_volume(snapshot_name)
        self.assertRaises(siolib.VolumeNotFound,
                          self.scaleio.get_volumename,
                          snapshot_name)
