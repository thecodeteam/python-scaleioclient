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

class Test_System(BaseTest):

    def test_domains(self):
        # get the list of all domains
        domains = self.scaleio.list_protection_domain_infos()
        # make sure each domain id matches what we get when requesting the id
        for d in domains:
            self.assertEquals(d['id'],
                              self.scaleio.get_domain_id(d['name']))

    def test_pools(self):
        # get the list of all domains
        domains = self.scaleio.list_protection_domain_infos()
        # get the storage pools for each domain
        for d in domains:
            pools = self.scaleio.list_storage_pool_infos(d['name'])
            for p in pools:
                # for each pool, validate the pool id returned
                self.assertEquals(p['id'],
                                  self.scaleio.get_pool_id(d['name'], p['name']))
                # validate that we can get the size information
                used, total, free = self.scaleio.storagepool_size(d['name'], p['name'])
                self.assertEqual(used + free, total)

    def test_systempool(self):
        used , total, free = self.scaleio.systempool_size()
        self.assertEqual(used+free, total)

    def test_protection_domain_props(self):
        props = self.scaleio.get_protection_domain_properties(self.domain)
        self.assertEqual(props['id'], self.scaleio.get_domain_id(self.domain))

    def test_storage_pool_props(self):
        props = self.scaleio.get_storage_pool_properties(self.domain, self.pool)
        self.assertEqual(props['id'], self.scaleio.get_pool_id(self.domain, self.pool))

    def test_version(self):
        version = self.scaleio.get_scaleio_api_version()
        self.assertRegexpMatches(version, "^\d+(\.\d+)*$")

    def test_storage_pool_statistics(self):
        requested_stats = [
            "capacityAvailableForVolumeAllocationInKb",
            "capacityLimitInKb", "spareCapacityInKb",
            "thickCapacityInUseInKb"]
        stats = self.scaleio.get_storage_pool_statistics(self.domain, self.pool, requested_stats)
        self.assertEqual(len(stats), len(requested_stats))

