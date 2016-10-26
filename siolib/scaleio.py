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
ScaleIO API library
"""

from os import listdir
from os.path import exists
from time import sleep
from siolib.utilities import check_size, UnitSize, encode_string, in_container
from siolib.utilities import is_id
from siolib.httphelper import HttpAction, api_request, Token

import logging
LOG = logging.getLogger(__name__)

# ScaleIO error constants
RESOURCE_NOT_FOUND_ERROR = 3
SDS_COMMUNICATION_ERROR = 69
VOLUME_NOT_FOUND_ERROR = 79
VOLUME_ALREADY_MAPPED_ERROR = 81
VOLUME_NOT_MAPPED_ERROR = 84
SDS_PORT_INUSE = 93
VOLUME_ALREADY_EXISTS = 99
SDS_REMOVAL_INPROGRESS = 103
VOLUME_MAPPED = 104
DEVICE_NOT_FOUND = 126
VOLUME_CANNOT_EXTEND = 133
DEVICE_REMOVAL_INPROGRESS = 135
DEVICE_ALREADY_EXISTS = 206

MAX_HOST_DEVICE_RENEWAL_CHECKS = 5
HOST_DEVICE_RENEWAL_CHECK_INTERVAL = 3


class Error(Exception):
    pass


class VolumeNotFound(Error):
    pass


class VolumeExists(Error):
    pass


class VolumeAlreadyMapped(Error):
    pass


class VolumeNotMapped(Error):
    pass


class SizeTooSmall(Error):
    pass


# ScaleIO volume provision type constant
VOL_TYPE = {'thickprovisioned': 'ThickProvisioned',
            'thinprovisioned': 'ThinProvisioned',
            'thick': 'ThickProvisioned',
            'thin': 'ThinProvisioned'}

DEVICES_PATH_ON_HOST = '/dev/disk/by-id'
DEVICES_PATH_IN_CONTAINER = '/var/scaleio/dev/disk/by-id'

if in_container():
    LOCAL_DEVICES_PATH = DEVICES_PATH_IN_CONTAINER
else:
    LOCAL_DEVICES_PATH = DEVICES_PATH_ON_HOST


class _ScaleIOVolume(object):

    """
    Private class representing a ScaleIO Volume object
    """

    def __init__(self, vol_json):
        """
        Create a ScaleIO Volume object
        :param vol_json: ScaleIO Volume obect
        :return: Nothing
        """

        self.full_device_path = None
        # populate Volume object based on JSON properties
        for k, v in vol_json.iteritems():
            self.__setattr__(k, v)  # set class attribs based on json

    def volume_partitions(self):
        """
        Return a list of
        :return:
        """

        disk_devices = []

        # get a list of devices
        devices = listdir(LOCAL_DEVICES_PATH)
        for device in devices:
            if (device.startswith('emc-vol') and self.id in device and
                    'part' in device):
                full_device_path = LOCAL_DEVICES_PATH + '/' + device
                disk_devices.append(full_device_path)

        LOG.info(
            'SIOLIB --> ScaleIO volume partitions {0}'.format(disk_devices))
        return disk_devices

    def _find_volume_device(self, by_id_path):
        if exists(by_id_path):
            devices = listdir(by_id_path)
            for dev in devices:
                if (dev.startswith('emc-vol') and dev.endswith(self.id)):
                    return dev
        return None

    def volume_path(self, with_no_wait=False):
        """
        Return the device path pf a volume which is the actual
        location of the device such as /dev/scinia, or
        dev/scinix.
        :param with_no_wait: Whether wait for the volume occures in host
                             device list
        :return: Device path of volume
        """
        if self.full_device_path and exists(self.full_device_path):
            return self.full_device_path

        tries = 1
        disk_device = ''

        if with_no_wait:
            return (LOCAL_DEVICES_PATH + '/' +
                    self._find_volume_device(LOCAL_DEVICES_PATH))

        while not disk_device and tries <= MAX_HOST_DEVICE_RENEWAL_CHECKS:
            disk_device = self._find_volume_device(LOCAL_DEVICES_PATH)
            if not disk_device:
                tries += 1
                sleep(HOST_DEVICE_RENEWAL_CHECK_INTERVAL)

        if not disk_device:
            LOG.warn(
                'SIOLIB --> ScaleIO device path not found {0}'
                .format(disk_device))
            raise VolumeNotMapped(
                "Device path is not found for volume '%s'" % self.id)

        LOG.info(
            'SIOLIB --> ScaleIO device path found {0}'.format(disk_device))
        self.full_device_path = LOCAL_DEVICES_PATH + '/' + disk_device
        return self.full_device_path


class ScaleIO(object):

    """
    ScaleIO API class
    """

    def __init__(self, rest_server_ip='', rest_server_port=443,
                 rest_server_username='', rest_server_password='',
                 verify_server_certificate=False, server_certificate_path=''):
        """
        Create a ScaleIO API object
        :param conf_filepath: Path to configuration file for ScaleIO
        :return: Nothing
        """

        self.host_addr = (rest_server_ip, str(rest_server_port))
        self.auth = (rest_server_username, rest_server_password)
        self.server_authtoken = Token()

        # set the volume type thick or thin provisioned
        # Check if we will be using a certificate
        if verify_server_certificate:
            self._set_certificate(server_certificate_path)

    def _get_provisiontype(self, provisioning_type):
        """
        Convert the volume provisioning type 'Thick' or 'Thin' provisioned from
        siolib representation to SIO one. You can define volumes as thick,
        where the entire capacity is provisioned for storage, or thin, where
        only the capacity currently needed is provisioned.
        :param provisioning_type: Provisioning type value supported by siolib
        :return: Provisioning type value supported by ScaleIO
        """

        try:
            provisioning_type = provisioning_type.lower()
            # sio requires string value to be ThickProvisioned or
            # ThinProvisioned
            return VOL_TYPE[provisioning_type]
        except KeyError:
            raise ValueError(
                'Provisioning type is not valid. Correct values are '
                'thick or thin')

    def _set_certificate(self, server_certificate_path):
        """
        Set certificate to use for ScaleIO REST gateway calls
        :return: Nothing
        """

        from os.path import isabs
        if isabs(server_certificate_path):
            self.verify_cert = True
            self.cert_path = server_certificate_path

    def _validate_volume_id(self, volume_id_or_name):
        """
        Validate and convert volume ID. If specified volume ID is not ScaleIO
        volume ID, the function interprets it as a name and requests ScaleIO
        to get ID by the name.
        :param volume_id_or_name: ScaleIO volume ID or volume name
        :return: ScaleIO volume ID
        """
        if not volume_id_or_name:
            raise ValueError(
                'Invalid volume_id parameter, volume_id=%s'
                % volume_id_or_name)

        if is_id(volume_id_or_name):
            return volume_id_or_name

        volume_id = self.get_volumeid(volume_id_or_name)
        LOG.info('SIOLIB -> Parameter %s is not a valid ID retrieving ID. '
                 'Found %s'
                 % (volume_id_or_name, volume_id))
        return volume_id

    def _validate_size(self, size, from_unit, to_unit):
        """
        Validate and convert volume size.  Volume size is limited to multiples
        of 8GB.  This method ensures that the size requirement is
        adhered to. Should be called prior to creating any volume,
        extending a volume.
        :param size: Size value may be in bytes, KB, MB, GB, etc
        :param from_unit: Unit size converting from (SI)
        :param to_unit: Unit size converting to (SI)
        :return:
        """

        new_size, block_size = check_size(size, from_unit, to_unit)

        # check and ensure size is a multiple of 8GB modulo op
        if new_size % block_size != 0:
            raise ValueError(
                'Cannot create volume with size %sGB (not a multiple of 8GB)'
                % size)

        return new_size

    def _get(self, r_uri):
        return api_request(op=HttpAction.GET, host=self.host_addr,
                           uri=r_uri, data=None, auth=self.auth,
                           token=self.server_authtoken)

    def _post(self, r_uri, params=None):
        return api_request(op=HttpAction.POST, host=self.host_addr,
                           uri=r_uri, data=params, auth=self.auth,
                           token=self.server_authtoken)

    def _get_pdid(self, protection_domain):
        """
        Private method retrieves the ScaleIO protection domain ID. ScaleIO
        objects are assigned a unique ID that can be used to identify the
        object.
        :param protection_domain: Unique 32 character string name of Protection
                                  Domain
        :return: Protection domain ID
        """

        if not protection_domain:
            raise ValueError(
                'Invalid protection_domain parameter, protection_domain=%s'
                % protection_domain)

        # request uri to retrieve pd id
        r_uri = '/api/types/Domain/instances/getByName::' + \
            encode_string(protection_domain, double=True)
        req = self._get(r_uri)
        if req.status_code != 200:
            raise Error('Error retrieving ScaleIO protection domain ID '
                        'for %s: %s'
                        % (protection_domain, req.content))

        return req.json()

    def _get_spid(self, storage_pool, pd_id):
        """
        Private method retrieves the ScaleIO storage pool ID. ScaleIO objects
        are assigned a unique ID that can be used to identify the object.
        :param storage_pool: Unique 32 character string name of Storage Pool
        :param pd_id: Protection domain id associated with storage pool
        :return: Storage pool id
        """

        if not storage_pool:
            raise ValueError(
                'Invalid storage_pool parameter, storage_pool=%s'
                % storage_pool)

        # request uri to retrieve sp id
        r_uri = '/api/types/Pool/instances/getByName::' + \
            pd_id + ',' + encode_string(storage_pool, double=True)
        req = self._get(r_uri)
        if req.status_code != 200:
            raise Error('Error retrieving ScaleIO storage pool ID for %s: %s'
                        % (storage_pool, req.content))

        return req.json()

    def _unmap_volume(self, volume_id, sdc_guid=None, unmap_all=False):
        """
        Private method unmaps a volume from one or all SDCs.
        :param volume_id: ScaleIO volume ID
        :param sdc_guid: Unique SDC identifier
        :param unmap_all: True, unmap from all SDCs, False only unmap from
                          local SDC
        :return: Nothing
        """

        if not unmap_all:
            if not sdc_guid:
                LOG.warn('SIOLIB -> Invalid _unmap_volume invoke')
                raise TypeError(
                    'sdc_guid must be specified or unmap_all must be True')
            else:
                LOG.info(
                    'SIOLIB -> Using ScaleIO SDC client GUID %s for '
                    'map operation.' % sdc_guid)

        if unmap_all:  # unmap from all sdcs
            params = {'allSdcs': ''}
        else:  # only unmap from local sdc
            params = {'guid': sdc_guid}

        LOG.debug('SIOLIB -> unmap volume params=%r' % params)
        r_uri = '/api/instances/Volume::' + \
            volume_id + '/action/removeMappedSdc'
        req = self._post(r_uri, params=params)
        if req.status_code == 200:  # success
            LOG.info('SIOLIB -> Unmapped volume %s successfully' % volume_id)
        elif req.json().get('errorCode') == VOLUME_NOT_MAPPED_ERROR:
            LOG.warn('SIOLIB -> Volume cannot be unmapped: %s' %
                     (req.json().get('message')))
            raise VolumeNotMapped("Volume '%s' is not mapped" % volume_id)
        else:
            LOG.error('SIOLIB -> Error unmapping volume: %s' %
                      (req.json().get('message')))
            raise Error("Error unmapping volume '%s': %s"
                        % (volume_id, req.json().get('message')))

    def _map_volume(self, volume_id, sdc_guid=None, map_all=True):
        """
        Private method maps a volume to a SDC
        :param volume_id: ScaleIO volume ID
        :param sdc_guid: Unique SDC identifier supplied by drv_cfg utility
        :param map_all: True, map volume to all configured SDCs. False only
                        map to local SDC.
        :return: Nothing
        """

        # Check if sdc configured if not do not perform map
        if not sdc_guid and not map_all:
            LOG.warn('SIOLIB -> Invalid _map_volume invoke')
            raise TypeError(
                'sdc_guid must be specified or map_all must be True')
        else:
            LOG.info(
                'SIOLIB -> Using ScaleIO SDC client GUID %s for map operation.'
                % sdc_guid)

        multi_map = str(map_all).lower()
        params = {'guid': sdc_guid, 'allowMultipleMappings': multi_map}

        LOG.debug('SIOLIB -> map volume params=%r' % params)
        r_uri = '/api/instances/Volume::' + volume_id + '/action/addMappedSdc'
        req = self._post(r_uri, params=params)
        if req.status_code == 200:  # success
            LOG.info('SIOLIB -> Mapped volume %s successfully' % volume_id)
        elif req.json().get('errorCode') == VOLUME_ALREADY_MAPPED_ERROR:
            LOG.warn('SIOLIB -> Volume already mapped: %s' %
                     (req.json().get('message')))
            raise VolumeAlreadyMapped("Volume '%s' is already mapped: %s"
                                      % (volume_id, req.json().get('message')))
        else:
            LOG.error('SIOLIB -> Error mapping volume: %s' %
                      (req.json().get('message')))
            raise Error("Error mapping volume '%s': %s"
                        % (volume_id, req.json().get('message')))

    def _volume(self, volume_id_or_name):
        """
        Return a ScaleIOVolume object
        :param volume_id_or_name: ScaleIO volume ID or volume name
        :return: ScaleIOVolume object or None if no valid volume found
        """

        volume_id = self._validate_volume_id(volume_id_or_name)

        volume_obj = None

        r_uri = '/api/instances/Volume::' + volume_id
        req = self._get(r_uri)
        if req.status_code == 200:  # success
            LOG.info(
                'SIOLIB --> Retrieved volume object %s successfully'
                % volume_id)
            volume_obj = _ScaleIOVolume(req.json())
        elif req.json().get('errorCode') == VOLUME_NOT_FOUND_ERROR:
            raise VolumeNotFound('Volume %s is not found' % volume_id)
        else:
            LOG.error('SIOLIB -> Error retrieving volume object: %s' %
                      (req.json().get('message')))
            raise Error("Error retrieving volume '%s': %s"
                        % (volume_id, req.json().get('message')))

        return volume_obj

    def get_volumeid(self, volume_name):
        """
        Return ScaleIO volume ID given a unique string volume name
        :param volume_name: Unique 32 character string name of the volume
        :return: ScaleIO ID of volume
        """

        volume_id = None

        if not volume_name:
            raise ValueError(
                'Invalid volume_name parameter, volume_name=%s' % volume_name)

        r_uri = '/api/types/Volume/instances/getByName::' + \
            encode_string(volume_name, double=True)
        req = self._get(r_uri)
        if req.status_code == 200:
            volume_id = req.json()
            LOG.info('SIOLIB -> Retrieved volume id %s successfully' %
                     volume_id)
            return volume_id
        elif req.json().get('errorCode') == RESOURCE_NOT_FOUND_ERROR:
            raise VolumeNotFound("Volume name '%s' is not found" % volume_name)
        else:
            LOG.error('SIOLIB -> Error retreiving volume id: %s' %
                      (req.json().get('message')))
            raise Error("Error resolving volume name '%s' to id: %s"
                        % (volume_name, req.json().get('message')))

    def get_volumepath(self, volume_id_or_name, with_no_wait=False):
        """
        Return the volume path
        :param volume_id_or_name: ScaleIO volume ID or volume name
        :param with_no_wait: Whether wait for the volume occures in host
                             device list
        :return: Path of volume mapped on local host
        """

        volume_object = self._volume(volume_id_or_name)
        return volume_object.volume_path(with_no_wait)

    def get_volumeparts(self, volume_id_or_name):
        """
        Return all partitions associated with volume
        :param volume_id_or_name: ScaleIO volume ID or volume name
        :return:
        """

        volume_object = self._volume(volume_id_or_name)
        return volume_object.volume_partitions()

    def get_volumesize(self, volume_id_or_name):
        """
        Return the volume size in kb
        :param volume_id_or_name: ScaleIO volume ID or volume name
        :return: Integer containing voluem size in kilobytes
        """

        volume_object = self._volume(volume_id_or_name)
        return int(volume_object.sizeInKb)

    def get_volumename(self, volume_id_or_name):
        """
        Return the ScaleIO volume name
        :param volume_id_or_name: ScaleIO volume ID or volume name
        :return: String name of ScaleIO volume
        """

        volume_object = self._volume(volume_id_or_name)
        return volume_object.name

    def create_volume(self, volume_name, protection_domain, storage_pool,
                      provisioning_type='thick', volume_size_gb=8):
        """
        Add a volume. You can create a volume when the requested capacity is
        available. To start allocating volumes, the system requires that
        there be at least three SDS nodes.

        User-defined names are optional. You can define object names,
        according to the following rules:
          * Contain less than 32 characters
          * Contain only alphanumeric and punctuation characters
          * Be unique within the object type
        :param volume_name: Name of the volume you want to create
        :param protection_domain: Protection domain name
        :param storage_pool: Storage pool name
        :param provisioning_type: thick/ThickProvisioned or
                                  thin/ThinProvisioned
        :param volume_size_gb: The size of the volume in GB
                                (must be multiple of 8GB)
        :return: Tuple containing the volume id and volume name created
        """

        if not volume_name:
            raise ValueError(
                'Invalid volume_name parameter, volume_name=%s' % volume_name)

        # get protection domain id for request store this for the duration of
        # the object
        pd_id = self._get_pdid(protection_domain)
        sp_id = self._get_spid(storage_pool, pd_id)
        # create requires size in KB, so we will convert and check size is
        # multiple of 8GB
        volume_size_kb = self._validate_size(
            volume_size_gb, UnitSize.GBYTE, UnitSize.KBYTE)

        # request payload containing volume create params
        params = {'protectionDomainId': pd_id,
                  'volumeSizeInKb': str(volume_size_kb),
                  'name': volume_name,
                  'volumeType': self._get_provisiontype(provisioning_type),
                  'storagePoolId': sp_id}

        LOG.debug('SIOLIB -> creating volume params=%r' % params)

        r_uri = '/api/types/Volume/instances'
        req = self._post(r_uri, params=params)
        LOG.debug('SIOLIB -> request to create volume returned %s' % req)
        if req.status_code == 200:
            volume_id = req.json().get('id')
            LOG.info('SIOLIB -> Created volume %s successfully' % volume_id)
        elif req.json().get('errorCode') == VOLUME_ALREADY_EXISTS:
            raise VolumeExists("Volume name '%s' already exists" % volume_name)
        else:
            raise Error("Error creating volume '%s': %s "
                        % (volume_name, req.json().get('message')))

        return volume_id, volume_name

    def delete_volume(self, volume_id_or_name, include_descendents=False,
                      only_descendents=False, vtree=False,
                      unmap_on_delete=False, force_delete=True):
        """
        Delete a volume. This command removes a ScaleIO volume. Before
        removing a volume, you must ensure that it is not mapped to any SDCs.

        When removing a volume, you can remove the VTree as well
        (all related snapshots), the volume and its snapshots, or
        just the snapshots. Before removing a VTree, you must unmap
        all volumes in the VTree before removing them.

        Note: Removal of a volume erases all the data on the corresponding
        volume.

        :param volume_id_or_name: ScaleIO volume ID or volume name
        :param include_descendents: Remove volume along with any descendents
        :param only_descendents: Remove only the descendents of the volume
        :param vtree: Remove the entire VTREE
        :param unmap_on_delete: Unmap volume from all SDCs before deleting
        :param force_delete: Ignore if volume is already deleted
        :return: Nothing
        """

        volume_id = self._validate_volume_id(volume_id_or_name)

        # if no other option set True assume only me
        if not any((include_descendents, only_descendents, vtree)):
            remove_mode = 'ONLY_ME'
        else:
            # TODO: Add bit masking and testing to see what option selected
            remove_mode = 'ONLY_ME'

        params = {'removeMode': remove_mode}

        LOG.debug('SIOLIB -> removing volume params=%r' % params)

        if unmap_on_delete:
            LOG.info('SIOLIB -> Unmap before delete flag True, attempting '
                     'to unmap volume from all sdcs before deletion')
            try:
                self._unmap_volume(volume_id, unmap_all=True)
            except VolumeNotMapped:
                pass

        r_uri = '/api/instances/Volume::' + volume_id + '/action/removeVolume'
        req = self._post(r_uri, params=params)
        if req.status_code == 200:
            LOG.info('SIOLIB -> Removed volume %s successfully' % volume_id)
        elif req.json().get('errorCode') == VOLUME_NOT_FOUND_ERROR:
            if not force_delete:
                LOG.info('SIOLIB -> Error removing volume: %s' %
                         (req.json().get('message')))
                raise VolumeNotFound("Volume '%s' is not found" % volume_id)
        else:
            raise Error("Error removing volume '%s': %s"
                        % (volume_id, req.json().get('message')))

    def extend_volume(self, volume_id_or_name, volume_size_gb):
        """
        Extend the volume size.  Extend a volume in multiples of 8GB.
        Increases the capacity of a volume. You can increase
        (but not decrease) a volume capacity at any time,
        as long as there is enough capacity for the volume size to grow.
        :param volume_id_or_name: ScaleIO volume ID or volume name
        :param volume_size_gb: New volume size in GB
        :return: Nothing
        """

        volume_id = self._validate_volume_id(volume_id_or_name)

        # extend requires size in GB, so we will convert and check size is
        # multiple of 8GB
        volume_size_gb = self._validate_size(
            volume_size_gb, UnitSize.GBYTE, UnitSize.GBYTE)
        params = {'sizeInGB': str(volume_size_gb)}

        LOG.debug('SIOLIB -> extend volume params=%r' % params)
        r_uri = '/api/instances/Volume::' + volume_id + '/action/setVolumeSize'
        req = self._post(r_uri, params=params)
        if req.status_code == 200:
            LOG.info('SIOLIB -> Extended volume size %s successfully new size '
                     'is %s GB' % (volume_id, volume_size_gb))
        elif req.json().get('errorCode') == VOLUME_CANNOT_EXTEND:
            LOG.error('SIOLIB -> Volume extend error: %s' %
                      (req.json().get('message')))
            raise SizeTooSmall(
                "Required size %s GB for volume '%s' is too small: %s"
                % (volume_size_gb, volume_id, req.json().get('message')))
        else:
            raise Error("Error extending volume '%s': %s"
                        % (volume_id, req.json().get('message')))

    def snapshot_volume(self, volume_id_or_name, snapshot_name):
        """
        Snapshot an existing volume. The ScaleIO storage system
        enables you to take snapshots of existing volumes,
        up to 31 per volume. The snapshots are thinly provisioned
        and are extremely quick. Once a snapshot is generated,
        it becomes a new, unmapped volume in the system.
        :param volume_id_or_name: ScaleIO volume ID or volume name
        :param snapshot_name: Name of the snapshot
        :return: Tuple containing the volume id of snapshot and volume list
        """

        volume_id = self._validate_volume_id(volume_id_or_name)
        if not snapshot_name:
            raise ValueError(
                'Invalid snapshot snapshot_name parameter, snapshot_name=%s'
                % snapshot_name)

        snapshot_gid = volume_list = None
        params = {
            'snapshotDefs': [{'volumeId': volume_id,
                              'snapshotName': snapshot_name}]}

        LOG.debug('SIOLIB -> snapshot volume params=%r' % params)
        r_uri = '/api/instances/System/action/snapshotVolumes'
        req = self._post(r_uri, params=params)
        if req.status_code == 200:
            snapshot_gid = req.json().get('snapshotGroupId')
            volume_list = req.json().get('volumeIdList')
        elif req.json().get('errorCode') == VOLUME_ALREADY_EXISTS:
            raise VolumeExists(
                "Volume name '%s' already exists, cannot make snapshot '%s'"
                % (snapshot_name, volume_id))
        else:
            raise Error(
                "Error making snapshot '%s' of volume '%s': %s"
                % (snapshot_name, volume_id, req.json().get('message')))

        return snapshot_gid, volume_list

    def detach_volume(self, volume_id_or_name, sdc_guid=None, unmap_all=False):
        """
        Detach volume from SDC
        :param volume_id_or_name: ScaleIO volume ID or volume name
        :param unmap_all: True unmap from all SDC's, False only unmap from
                          local SDC
        :return: Nothing
        """

        volume_id = self._validate_volume_id(volume_id_or_name)
        self._unmap_volume(volume_id, sdc_guid=sdc_guid, unmap_all=unmap_all)

    def attach_volume(self, volume_id_or_name, sdc_guid):
        """
        Attach a volume to a SDC
        :param volume_id_or_name: ScaleIO volume ID or volume name
        :return: Nothing
        """

        volume_id = self._validate_volume_id(volume_id_or_name)
        self._map_volume(volume_id, sdc_guid=sdc_guid)

    def rename_volume(self, volume_id_or_name, new_volume_name):
        """
        Rename an existing volume
        :param volume_id_or_name: ScaleIO volume ID or volume name
        :param new_volume_name: New volume name
        :return: Nothing
        """
        volume_id = self._validate_volume_id(volume_id_or_name)
        if not new_volume_name:
            raise ValueError(
                'Invalid new_volume_name parameter, volume_name=%s'
                % new_volume_name)

        params = {'newName': new_volume_name}

        LOG.debug('SIOLIB -> rename volume params=%r' % params)
        r_uri = '/api/instances/Volume::' + volume_id + '/action/setVolumeName'
        req = self._post(r_uri, params=params)
        if req.status_code == 200:  # success
            LOG.info('SIOLIB -> Renamed volume %s successfully' % volume_id)
        elif req.json().get('errorCode') == VOLUME_ALREADY_EXISTS:
            raise VolumeExists(
                "Volume name '%s' already exists, cannot rename '%s'"
                % (new_volume_name, volume_id))
        else:
            LOG.error('SIOLIB -> Error renaming volume: %s' %
                      (req.json().get('message')))
            raise Error(
                "Error renaming volume '%s' to '%s': %s"
                % (volume_id, new_volume_name, req.json().get('message')))

    def storagepool_size(self, protection_domain, storage_pool):
        """
        For a given single storage pool, return the used, total and free space
        in bytes that can be allocated for Volumes. Note this is not the total
        capacity of the system.
        :param protection_domain: Protection domain name
        :param storage_pool: Storage pool name
        :return: Tuple used_bytes, total_bytes, free_bytes
        """

        if not protection_domain:
            raise ValueError(
                'Invalid protection_domain parameter, protection_domain=%s'
                % protection_domain)
        if not storage_pool:
            raise ValueError(
                'Invalid storage_pool parameter, storage_pool=%s'
                % storage_pool)

        used_bytes = 0
        total_bytes = 0
        free_bytes = 0

        # FIXME: Redo all of this must be a better and more efficient way
        # get protection domain id for request store this for the duration of
        # the object
        pd_id = self._get_pdid(protection_domain)
        sp_id = self._get_spid(storage_pool, pd_id)

        # FIXME: Redo all of this must be a better and more efficient way
        r_uri = ('/api/types/StoragePool/instances/action/'
                 'querySelectedStatistics')
        r_uri2 = ('/api/types/ProtectionDomain/instances/action/'
                  'querySelectedStatistics')
        params = {'ids': [sp_id],
                  'properties': ['capacityInUseInKb', 'capacityLimitInKb']}
        params2 = {'ids': [pd_id], 'properties': ['numOfSds']}
        req = self._post(r_uri, params=params)
        req2 = self._post(r_uri2, params=params2)

        # FIXME: Redo all of this must be a better and more efficient way
        if req.status_code == 200 and req2.status_code == 200:
            sds_count = req2.json().get(pd_id).get('numOfSds')
            # Total capacity for volumes in a given pool
            total_kb = req.json().get(sp_id).get(
                'capacityLimitInKb') / sds_count
            # Used capacity divide by 2
            used_kb = req.json().get(sp_id).get('capacityInUseInKb')
            # Calculate the free capacity for the storage pool
            free_kb = int(total_kb) - int(used_kb)
            # convert to bytes
            used_bytes = used_kb * 1024
            total_bytes = total_kb * 1024
            free_bytes = free_kb * 1024
        else:
            msg = (req.json().get('message')
                   if req.status_code != 200
                   else req2.json().get('message'))
            raise Error('Error retrieving storage pool statistics: %s' % msg)

        return (used_bytes, total_bytes, free_bytes)

    def systempool_size(self):
        """
        Return ScaleIO cluster storage statistics in kilobytes.
        This is the raw total system capacity.
        :return: Tuple (used, total, free) in kilobytes
        """

        used_kb = 0
        total_kb = 0
        free_kb = 0

        r_uri = '/api/types/System/instances/action/querySelectedStatistics'
        params = {'ids': [],
                  'properties': ['capacityInUseInKb', 'capacityLimitInKb']}
        req = self._post(r_uri, params=params)
        if req.status_code == 200:
            used_kb = req.json().get('capacityInUseInKb')
            total_kb = req.json().get('capacityLimitInKb')
            free_kb = (int(total_kb) - int(used_kb))
            LOG.debug('Total=%sKB, Used=%sKB, Free=%sKB' %
                      (total_kb, used_kb, free_kb))
        else:
            raise Error('Error retrieving cluster statistics: %s'
                        % req.json().get('message'))

        return (used_kb, total_kb, free_kb)

    def get_pool_id(self, protection_domain, storage_pool):

        if not protection_domain:
            raise ValueError(
                'Invalid protection_domain parameter, protection_domain=%s'
                % protection_domain)
        if not storage_pool:
            raise ValueError(
                'Invalid storage_pool parameter, storage_pool=%s'
                % storage_pool)

        r_uri = '/api/types/StoragePool/instances/action/queryIdByKey'
        params = {
            'name': storage_pool, 'protectionDomainName': protection_domain}
        req = self._post(r_uri, params=params)
        if req.status_code == 200:
            pool_id = req.json()
        else:
            LOG.error('SIOLIB -> Pool %s not found: %s' %
                      (storage_pool, req.json().get('message')))
            raise LookupError(
                'SIOLIB -> Error retrieving Pool ID: %s'
                % (req.json().get('message')))

        return pool_id

    def list_volume_names(self):

        volume_names = []
        r_uri = '/api/types/Volume/instances'
        req = self._get(r_uri)
        if req.status_code != 200:
            LOG.error('SIOLIB -> Error listing volumes: %s' %
                      (req.json().get('message')))
            raise Error('Error listing volumes: %s' %
                        (req.json().get('message')))

        volume_objects = req.json()
        for volume in volume_objects:
            volume_names.append(volume['name'])

        return volume_names
