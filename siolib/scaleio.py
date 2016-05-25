# -*- coding: utf-8 -*-

"""
ScaleIO API library
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

from os import listdir
from os.path import exists
from functools import wraps
from time import sleep
from siolib import ConfigOpts, SIOGROUP, SIOOPTS, VOL_TYPE
from siolib.utilities import check_size, UnitSize, encode_string, in_container, parse_value, is_id
from siolib.httphelper import HttpAction, request, basicauth, Token
from time import time
import oslo_config

import logging
LOG = logging.getLogger(__name__)

# Oslo conf object
CONF = ConfigOpts()
CONF.register_group(SIOGROUP)
CONF.register_opts(SIOOPTS, SIOGROUP)

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


def urlencode_volume(func):
    """
    Decorator used to properly encode a volume name so that it may be used
    in RESTful HTTP request calls.  Since ScaleIO volume names are base 64
    encoded, we must make the url safe too.
    :param func: Function to decorate
    :return: URL encoded volume name
    """

    @wraps(func)
    def encode(*args, **kwargs):
        """
        Encode string to safe URL format
        :param args: Function arguments
        :param kwargs: Function keyword arguments
        :return: URL safe encoded string
        """

        use_args = False
        xargs = list(args)

        # if args present expecting the
        # first argument to be the volume_name string
        if len(args) > 1:
            use_args = True
            volume_name = xargs.pop(1)
        else:
            volume_name = kwargs.get('volume_name')

        volume_name = parse_value(volume_name)
        encoded_volume_name = encode_string(volume_name, double=True)
        if use_args:  # url encode base64 string and re-insert args
            xargs.insert(1, encoded_volume_name)
        else:
            kwargs['volume_name'] = encoded_volume_name
        # call decorated function
        ret = func(*xargs, **kwargs)
        # return decorated function result
        return ret
    # return outer wrapper
    return encode

def b64encode_volume(func):
    """
    Decorator used to properly encode a string value into base64 value.  All ScaleIO
    volumes are stored in base64 format
    :param func: Function to decorate
    :return: Base 64 encoded string
    """

    @wraps(func)
    def encode(*args, **kwargs):
        """
        Encode string to base 64 format
        :param args: Function arguments
        :param kwargs: Function keyword arguments
        :return: Base 64 encoded string
        """

        use_args = False
        xargs = list(args)

        # if args present expecting the
        # first argument to be the volume_name string
        if len(args) > 1:
            use_args = True
            volume_name = xargs.pop(1)
        else:
            volume_name = kwargs.get('volume_name')

        volume_name = parse_value(volume_name)
        # string is already base 16 re-insert args
        if use_args:
            xargs.insert(1, volume_name)
        else:
            kwargs['volume_name'] = volume_name
        # call decorated function
        ret = func(*xargs, **kwargs)
        # return decorated function result
        return ret
    # return outer wrapper
    return encode


@basicauth
def api_request(**kwargs):
    """
    Perform a HTTP RESTful request call. If Token is passed in, it will be updated
    correctly because Python passes values by reference.
    :param op: HttpAction GET, PUT, POST, DELETE
    :param uri: HTTP resource endpoint
    :param host: RESTful gateway host ip
    :param data: HTTP Payload (optional)
    :param auth: HTTP basic authentication credentials (optional)
    :param token: HTTP token (optional)
    :return: HTTP request object
    """

    # attempt to use gw 1 token
    server_authtoken = kwargs.get('token')
    username, _ = kwargs.get('auth')
    auth = (username, server_authtoken.token)
    start_time = time()

    req = request(op=kwargs.get('op'), addr=kwargs.get('host'),
                  uri=kwargs.get('uri'), auth=auth,
                  data=kwargs.get('data', {}))

    if req.status_code == 401:
        server_authtoken.valid(force_expire=True)
        api_request(**kwargs)
        req = request(op=kwargs.get('op'), addr=kwargs.get('host'),
                  uri=kwargs.get('uri'), auth=auth,
                  data=kwargs.get('data', {}))

    elapsed = time() - start_time
    # FIXME: set to debug after deployed and tested in a dev environment
    LOG.debug("SIOLIB: (api_request) Response Code == {0}, elapsed=={1}".format(req.status_code, elapsed))

    return req


class _ScaleIOSDC(object):

    """
     Private class that represents a ScaleIO SDC client object.
    """
    _guid = None

    def __init__(self, host_addr, auth, sdc_uuid=None):
        """
        Create a ScaleIO SDC object.
        :param sdc_uuid: Force SDC object to use an already defined SDC uuid (optional)
        :return: HTTP request object
        """

        # locate the local SDC binary and query the local guid
        if not sdc_uuid:
            raise RuntimeError("Cannot locate SDC")

        self.guid = sdc_uuid.strip()
        self._set_properties(host_addr=host_addr, auth=auth)

    def _set_properties(self, host_addr, auth):
        """
        Private method that will create class attributes based on SDC object returned
        by ScaleIO
        :param host_addr: IP:port tuple pair of ScaleIO rest gateway
        :param auth: Username:Password tuple for talking to ScaleIO rest gateway
        :return: Nothing
        """

        def list_sdcs():
            """
            Nested function that will call the ScaleIO gateway and return a list of SDC's
            for a given system installation.
            """

            # TODO: It would be far more efficient if there was a REST API call
            # that could retrieve a SDC object from ScaleIO based on the GUID
            r_uri = "/api/types/Sdc/instances"
            req = api_request(op=HttpAction.GET, host=host_addr,
                              uri=r_uri, data=None, auth=auth)
            sdc_list = req.json()
            return sdc_list

        # retrieve a list of SDCs
        sdc_instances = list_sdcs()
        # iterare over returned SDC's select one whose GUID matches
        sdc_instance = [
            x for x in sdc_instances if x.get('sdcGuid') == self.guid.strip()]
        if sdc_instance and len(sdc_instance) == 1:
            # set class attributes
            for k, v in sdc_instance[0].iteritems():
                self.__setattr__(k, v)
        else:
            raise Exception("Error setting SDC object properties. Ensure that the local SDC has MDM's configured."
                            "use drv_cfg --query_mdms for more information!")

    @property
    def guid(self):
        """
        Get SDC guid identifier
        :return:
        """

        return self._guid

    @guid.setter
    def guid(self, value):
        """
        Set the SDC guid identifier
        :param value:
        :return:
        """
        self._guid = value


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
        # True if we are running inside a container
        self.container = in_container()
        # populate Volume object based on JSON properties
        for k, v in vol_json.iteritems():
            self.__setattr__(k, v)  # set class attribs based on json

    def volume_partitions(self):
        """
        Return a list of
        :return:
        """

        disk_devices = []
        # FIXME maybe try and use filters instead of hard coded path
        if self.container:
            by_id_path = "/var/scaleio/dev/disk/by-id"
        else:
            by_id_path = "/dev/disk/by-id"

        # get a list of devices
        devices = listdir(by_id_path)
        for device in devices:
            if (device.startswith("emc-vol") and self.id in device and 'part' in device):
                full_device_path = by_id_path + "/" + device
                disk_devices.append(full_device_path)

        LOG.info("SIOLIB --> ScaleIO volume partitions {0}".format(disk_devices))
        return disk_devices

    def volume_path(self):
        """
        Return the device path pf a volume which is the actual
        location of the device such as /dev/scinia, or
        dev/scinix.
        :return: Device path of volume
        """

        tries = 1
        disk_device = ""

        # FIXME maybe try and use filters instead of hard coded path
        if self.container:
            by_id_path = "/var/scaleio/dev/disk/by-id"
        else:
            by_id_path = "/dev/disk/by-id"

        while not disk_device and tries <= 5:
            if self.full_device_path and exists(self.full_device_path):
                break  # exit loop control
            if exists(by_id_path):
                devices = listdir(by_id_path)
                for dev in devices:
                    if (dev.startswith("emc-vol") and dev.endswith(self.id)):
                        disk_device = dev
            if not disk_device:
                tries = tries + 1
                sleep(3)

        if disk_device:
            LOG.info("SIOLIB --> ScaleIO device path found {0}".format(disk_device))
            self.full_device_path = by_id_path + "/" + disk_device
        else:
            LOG.warn("SIOLIB --> ScaleIO device path not found {0}".format(disk_device))
            raise VolumeNotMapped("Device path is not found for volume '%s'" % self.id)

        return self.full_device_path


class ScaleIO(object):

    """
    ScaleIO API class
    """

    pd_id = None  # store protection domain id
    sp_id = None  # store storage pool id
    sdc = None # ScaleIO data client object

    def __init__(self, conf_filepath=None, conf=None, pd_name=None, sp_name=None, skip_sdc=False):
        """
        Create a ScaleIO API object
        :param conf_filepath: Path to configuration file for ScaleIO
        :param pd_name: Protection domain name (optional)
        :param sp_name: Storage pool name (optional)
        :return: Nothing
        """

        # FIXME: The config object needs to be refactored in.
        if conf: # force conf
            self.sio_conf = conf
        elif conf_filepath and isinstance(conf_filepath, oslo_config.cfg.ConfigOpts):
            # use what we have (storage manager, other c3 modules)
            default_path = conf_filepath.default_config_files
            CONF(default_config_files=default_path)
            self.sio_conf = CONF
        else: # file path passed in use that
            CONF(default_config_files=[conf_filepath])
            self.sio_conf = CONF

        self.host_addr = (
            self.sio_conf.scaleio.rest_server_ip, str(self.sio_conf.scaleio.rest_server_port))
        self.auth = (
            self.sio_conf.scaleio.rest_server_username, self.sio_conf.scaleio.rest_server_password)
        self.protection_domain = pd_name or self.sio_conf.scaleio.protection_domain_name
        self.storage_pool = sp_name or self.sio_conf.scaleio.storage_pool_name
        self.storage_pools = self.sio_conf.scaleio.storage_pools
        self.round_volume = self.sio_conf.scaleio.round_volume_capacity
        self.force_delete = self.sio_conf.scaleio.force_delete
        self.unmap_on_delete = self.sio_conf.scaleio.unmap_volume_before_deletion
        self.server_authtoken = Token()

        # set the volume type thick or thin provisioned
        self._set_provisiontype()
        # Check if we will be using a certificate
        if self.sio_conf.scaleio.verify_server_certificate:
            self._set_certificate()
        # if testing allow ps without sdc
        if not skip_sdc:
            # get SDC object
            self.sdc = _ScaleIOSDC(
                host_addr=self.host_addr, auth=self.auth, sdc_uuid=self.sio_conf.scaleio.default_sdcguid)

    def _set_provisiontype(self):
        """
        Set the volume provisioning type "Thick" or "Thin" provisioned. You can
        define volumes as thick, where the entire capacity is provisioned
        for storage, or thin, where only the capacity currently needed is
        provisioned.
        :return: Nothing
        """

        try:
            # retrieve value from config file
            provisioning_type = self.sio_conf.scaleio.provisioning_type.lower()
            # sio requires string value to be ThickProvisioned or
            # ThinProvisioned
            self.provisioning_type = VOL_TYPE[provisioning_type]
        except KeyError:
            raise ValueError(
                "Provisioning type is not valid. Correct values are ThickProvisioned or ThinProvisioned")

    def _set_certificate(self):
        """
        Set certificate to use for ScaleIO REST gateway calls
        :return: Nothing
        """

        from os.path import isabs
        if isabs(self.sio_conf.scaleio.server_certificate_path):
            self.verify_cert = True
            self.cert_path = self.sio_conf.scaleio.server_certificate_path

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
        if new_size % block_size != 0 and not self.round_volume:
            raise ValueError(
                "Cannot create volume with size %sGB (not a multiple of 8GB)" % size)

        return new_size

    def _get_pdid(self, pd_name):
        """
        Private method retrieves the ScaleIO protection domain ID. ScaleIO objects
        are assigned a unique ID that can be used to identify the object.
        :param pd_name: Unique 32 character string name of Protection Domain
        :return: Protection domain id
        """

        # request uri to retrieve pd id
        r_uri = "/api/types/Domain/instances/getByName::" + pd_name
        # make HTTP RESTful API request to ScaleIO gw
        req = api_request(op=HttpAction.GET, host=self.host_addr,
                          uri=r_uri, data=None, auth=self.auth,
                          token=self.server_authtoken)
        if req.status_code <> 200:
            raise Error("Error retrieving ScaleIO protection domain ID for %s: %s" % (pd_name, req.content))

        return req.json()

    def _get_spid(self, sp_name, pd_id):
        """
        Private method retrieves the ScaleIO storage pool ID. ScaleIO objects
        are assigned a unique ID that can be used to identify the object.
        :param sp_name: Unique 32 character string name of Storage Pool
        :param pd_id: Protection domain id associated with storage pool
        :return: Storage pool id
        """

        # request uri to retrieve sp id
        r_uri = "/api/types/Pool/instances/getByName::" + pd_id + "," + sp_name
        # make HTTP RESTful API request to ScaleIO gw
        req = api_request(op=HttpAction.GET, host=self.host_addr,
                          uri=r_uri, data=None, auth=self.auth,
                          token=self.server_authtoken)
        if req.status_code <> 200:
            raise Error("Error retrieving ScaleIO storage pool ID for %s: %s" % (sp_name, req.content))

        return req.json()

    def _unmap_volume(self, volume_id, sdc_id=None, unmap_all=False):
        """
        Private method unmaps a volume from one or all SDCs.
        :param volume_id: Volume id
        :param sdcid: Unique SDC identifier
        :param unmap_all: True, unmap from all SDCs, False only unmap from local SDC
        :return: Nothing
        """

        if not is_id(volume_id):
            volume_id = self.get_volumeid(volume_name=volume_id)
            LOG.warn("SIOLIB -> Parameter is not a valid ID retrieving ID for _unmap_volume. Found %s" % volume_id)

        if not unmap_all:
            # Check if sdc configured if not do not perform map
            if not self.sdc and not unmap_all:
                LOG.warn("SIOLIB -> SDC is not configured, unable to unmap volumes")
                return
            else:
                sdc_id = sdc_id or self.sdc.id
                LOG.info("SIOLIB -> Using ScaleIO SDC client ID %s for map operation." % self.sdc.id)

        if unmap_all:  # unmap from all sdcs
            params = {'allSdcs': ''}
        else:  # only unmap from local sdc
            params = {'sdcId': sdc_id}

        LOG.debug("SIOLIB -> unmap volume params=%r" % params)
        r_uri = "/api/instances/Volume::" + \
            volume_id + "/action/removeMappedSdc"
        # make HTTP RESTful API request to ScaleIO gw
        req = api_request(op=HttpAction.POST, host=self.host_addr,
                          uri=r_uri, data=params, auth=self.auth,
                          token=self.server_authtoken)
        if req.status_code == 200:  # success
            LOG.info("SIOLIB -> Unmapped volume %s successfully" % volume_id)
        elif req.status_code == VOLUME_NOT_MAPPED_ERROR:
            LOG.warn("SIOLIB -> Volume cannot be unmapped: %s" %
                  (req.json().get('message')))
            raise VolumeNotMapped("Volume '%s' is not mapped" % volume_id)
        else:
            LOG.error("SIOLIB -> Error unmapping volume: %s" % (req.json().get('message')))
            raise Error("Error unmapping volume '%s': %s"
                        % (volume_id, req.json().get('message')))

    def _map_volume(self, volume_id, guid=None, map_all=True):
        """
        Private method maps a volume to a SDC
        :param volume_id: Volume id
        :param guid: Unique SDC identifier supplied by drv_cfg utility
        :param map_all: True, map volume to all configured SDCs. False only map to local SDC.
        :return: Nothing
        """

        if not is_id(volume_id):
            volume_id = self.get_volumeid(volume_name=volume_id)
            LOG.warn("SIOLIB -> Parameter is not a valid ID retrieving ID for _map_volume. Found %s" % volume_id)

        # Check if sdc configured if not do not perform map
        if not self.sdc:
            LOG.warn("SIOLIB -> SDC is not configured, unable to map volumes")
            return
        else:
            LOG.info("SIOLIB -> Using ScaleIO SDC client ID %s for map operation." % self.sdc.id)

        sdc_guid = guid or self.sdc.guid
        multi_map = str(map_all).lower()
        params = {'guid': sdc_guid, 'allowMultipleMappings': multi_map}

        LOG.debug("SIOLIB -> map volume params=%r" % params)
        r_uri = "/api/instances/Volume::" + volume_id + "/action/addMappedSdc"
        # make HTTP RESTful API request to ScaleIO gw
        req = api_request(op=HttpAction.POST, host=self.host_addr,
                          uri=r_uri, data=params, auth=self.auth,
                          token=self.server_authtoken)
        if req.status_code == 200:  # success
            LOG.info("SIOLIB -> Mapped volume %s successfully" % volume_id)
        elif req.status_code == VOLUME_ALREADY_MAPPED_ERROR:
            LOG.warn("SIOLIB -> Volume already mapped: %s" % (req.json().get('message')))
            raise VolumeAlreadyMapped("Volume '%s' is already mapped: %s"
                                      % (volume_id, req.json().get('message')))
        else:
            LOG.error("SIOLIB -> Error mapping volume: %s" % (req.json().get('message')))
            raise Error("Error mapping volume '%s': %s"
                        % (volume_id, req.json().get('message')))

    @urlencode_volume
    def get_volumeid(self, volume_name):
        """
        Return volume id given a unique string volume name
        :param volume_name: Unique 32 character string name of Volume
        :return: Id of volume
        """

        volume_id = None

        if not volume_name:
            raise ValueError(
                "Invalid volume_name parameter, volume_name=%s" % volume_name)

        try:
            int(volume_name, 16) # already hex id passed in do nothing
            volume_id = volume_name
        except ValueError: # string name get the id
            r_uri = "/api/types/Volume/instances/getByName::" + volume_name
            # make HTTP RESTful API request to ScaleIO gw
            req = api_request(op=HttpAction.GET, host=self.host_addr,
                              uri=r_uri, data=None, auth=self.auth,
                              token=self.server_authtoken)
            if req.status_code == 200:
                volume_id = req.json()
                LOG.info("SIOLIB -> Retrieved volume id %s successfully" % volume_id)
            elif req.json().get('errorCode') == RESOURCE_NOT_FOUND_ERROR:
                raise VolumeNotFound("Volume name '%s' is not found" % volume_name)
            else:
                LOG.error("SIOLIB -> Error retreiving volume id: %s" % (req.json().get('message')))
                raise Error("Error resolving volume name '%s' to id: %s"
                            % (volume_name, req.json().get('message')))

        return volume_id

    def get_volumepath(self, volume_id):
        """
        Return the volume path
        :param volume_id: ScaleIO volume id
        :return: Path of volume mapped on local host
        """

        if not is_id(volume_id):
            volume_id = self.get_volumeid(volume_name=volume_id)
            LOG.warn("SIOLIB -> Parameter is not a valid ID retrieving ID for get_volumepath. Found %s" % volume_id)

        volume_object = self.volume(volume_id)
        return volume_object.volume_path()

    def get_volumeparts(self, volume_id):
        """
        Return all partitions associated with volume
        :param volume_id:
        :return:
        """

        if not is_id(volume_id):
            LOG.warn("SIOLIB -> Parameter is not a valid ID retrieving ID for get_volumeparts. Found %s" % volume_id)
            volume_id = self.get_volumeid(volume_name=volume_id)

        volume_object = self.volume(volume_id)
        return volume_object.volume_partitions()

    def get_volumesize(self, volume_id):
        """
        Return the volume size in kb
        :param volume_id: ScaleIO volume id
        :return: Integer containing voluem size in kilobytes
        """

        if not is_id(volume_id):
            volume_id = self.get_volumeid(volume_name=volume_id)
            LOG.warn("SIOLIB -> Parameter is not a valid ID retrieving ID for get_volumesize. Found %s" % volume_id)

        volume_object = self.volume(volume_id)
        return int(volume_object.sizeInKb)

    def get_volumename(self, volume_id):
        """
        Return the ScaleIO volume name
        :param volume_id: ScaleIO volume id
        :return: String name of ScaleIO volume
        """

        if not is_id(volume_id):
            volume_id = self.get_volumeid(volume_name=volume_id)
            LOG.warn("SIOLIB -> Parameter is not a valid ID retrieving ID for get_volumename. Found %s" % volume_id)

        volume_object = self.volume(volume_id)
        return volume_object.name

    @b64encode_volume
    def create_volume(self, volume_name, volume_size_gb=8, provisioning_type=None):
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
        :param volume_size_gb: The size of the volume in GB (must be multiple of 8GB)
        :param provisioning_type: ThickProvisioning or ThinProvisioning
        :return: Tuple containing the volume id and volume name created
        """

        if not volume_name:
            raise ValueError(
                "Invalid volume_name parameter, volume_name=%s" % volume_name)

        # get protection domain id for request store this for the duration of
        # the object
        if not self.pd_id:
            self.pd_id = self._get_pdid(self.protection_domain)
        if not self.sp_id:
            self.sp_id = self._get_spid(self.storage_pool, self.pd_id)
        # create requires size in KB, so we will convert and check size is
        # multiple of 8GB
        volume_size_kb = self._validate_size(
            volume_size_gb, UnitSize.GBYTE, UnitSize.KBYTE)

        # request payload containing volume create params
        params = {'protectionDomainId': self.pd_id,
                  'volumeSizeInKb': str(volume_size_kb),
                  'name': volume_name,
                  'volumeType': provisioning_type or self.provisioning_type,
                  'storagePoolId': self.sp_id}

        LOG.debug("SIOLIB -> creating volume params=%r" % params)

        r_uri = "/api/types/Volume/instances"
        # make HTTP RESTful API request to ScaleIO gw
        req = api_request(op=HttpAction.POST, host=self.host_addr,
                          uri=r_uri, data=params, auth=self.auth,
                          token=self.server_authtoken)
        LOG.debug("SIOLIB -> request to create volume returned %s" % req)
        if req.status_code == 200:
            volume_id = req.json().get('id')
            LOG.info("SIOLIB -> Created volume %s successfully" % volume_id)
        elif req.json().get('errorCode') == VOLUME_ALREADY_EXISTS:
            raise VolumeExists("Volume name '%s' already exists" % volume_name)
        else:
            raise Error("Error creating volume '%s': %s "
                        % (volume_name, req.json().get('message')))

        return volume_id, volume_name

    @b64encode_volume
    def delete_volume(self, volume_name=None, include_descendents=False, only_descendents=False, vtree=False, unmap_on_delete=False):
        """
        Delete a volume. This command removes a ScaleIO volume. Before
        removing a volume, you must ensure that it is not mapped to any SDCs.

        When removing a volume, you can remove the VTree as well
        (all related snapshots), the volume and its snapshots, or
        just the snapshots. Before removing a VTree, you must unmap
        all volumes in the VTree before removing them.

        Note: Removal of a volume erases all the data on the corresponding volume.

        :param volume_name: Name of the volume you want to delete
        :param include_descendents: Remove volume along with any descendents
        :param only_descendents: Remove only the descendents of the volume
        :param vtree: Remove the entire VTREE
        :return: Nothing
        """

        if not volume_name:
            raise ValueError(
                "Invalid volume_name parameter, volume_name=%s" % volume_name)

        if not is_id(volume_name):
            volume_id = self.get_volumeid(volume_name=volume_name)
            LOG.warn("SIOLIB -> Parameter is not a valid ID retrieving ID for delete_volume. Found %s" % volume_id)
        else:
            volume_id = self.get_volumeid(volume_name=volume_name)

        # if no other option set True assume only me
        if not any((include_descendents, only_descendents, vtree)):
            remove_mode = "ONLY_ME"
        else:
            # TODO: Add bit masking and testing to see what option selected
            remove_mode = "ONLY_ME"

        params = {'removeMode': remove_mode}

        LOG.debug("SIOLIB -> removing volume params=%r" % params)

        if self.unmap_on_delete or unmap_on_delete:
            LOG.info("SIOLIB -> Unmap before delete flag True, "
                     "attempting to unmap volume from all sdcs before deletion")
            try:
                self._unmap_volume(volume_id=volume_id, unmap_all=True)
            except VolumeNotMapped:
                pass

        r_uri = "/api/instances/Volume::" + volume_id + "/action/removeVolume"
        # make HTTP RESTful API request to ScaleIO gw
        req = api_request(op=HttpAction.POST, host=self.host_addr,
                          uri=r_uri, data=params, auth=self.auth,
                          token=self.server_authtoken)
        if req.status_code == 200:
            LOG.info("SIOLIB -> Removed volume %s successfully" % volume_id)
        elif req.json().get('errorCode') == VOLUME_NOT_FOUND_ERROR:
            if not self.force_delete:
                LOG.info("SIOLIB -> Error removing volume: %s" %
                      (req.json().get('message')))
                raise VolumeNotFound("Volume '%s' is not found" % volume_id)
        else:
            raise Error("Error removing volume '%s': %s"
                        % (volume_id, req.json().get('message')))

    def extend_volume(self, volume_id, volume_size_gb):
        """
        Extend the volume size.  Extend a volume in multiples of 8GB.
        Increases the capacity of a volume. You can increase
        (but not decrease) a volume capacity at any time,
        as long as there is enough capacity for the volume size to grow.
        :param volume_id: Id of volume to extend
        :param volume_size_gb: New volume size in GB
        :return: Nothing
        """

        if not is_id(volume_id):
            volume_id = self.get_volumeid(volume_name=volume_id)
            LOG.warn("SIOLIB -> Parameter is not a valid ID retrieving ID for extend_volume. Found %s" % volume_id)

        # extend requires size in GB, so we will convert and check size is
        # multiple of 8GB
        volume_size_gb = self._validate_size(
            volume_size_gb, UnitSize.GBYTE, UnitSize.GBYTE)
        params = {'sizeInGB': str(volume_size_gb)}

        LOG.debug("SIOLIB -> extend volume params=%r" % params)
        r_uri = "/api/instances/Volume::" + volume_id + "/action/setVolumeSize"
        # make HTTP RESTful API request to ScaleIO gw
        req = api_request(op=HttpAction.POST, host=self.host_addr,
                          uri=r_uri, data=params, auth=self.auth,
                          token=self.server_authtoken)
        if req.status_code == 200:
            LOG.info("SIOLIB -> Extended volume size %s successfully new size is %s GB" %
                  (volume_id, volume_size_gb))
        elif req.json().get('errorCode') == VOLUME_CANNOT_EXTEND:
            LOG.error("SIOLIB -> Volume extend error: %s" % (req.json().get('message')))
            raise SizeTooSmall("Required size %s GB for volume '%s' is too small: %s"
                               % (volume_size_gb, volume_id, req.json().get('message')))
        else:
            raise Error("Error extending volume '%s': %s"
                        % (volume_id, req.json().get('message')))

    @b64encode_volume
    def snapshot_volume(self, volume_name, origin_volume_id):
        """
        Snapshot an existing volume. The ScaleIO storage system
        enables you to take snapshots of existing volumes,
        up to 31 per volume. The snapshots are thinly provisioned
        and are extremely quick. Once a snapshot is generated,
        it becomes a new, unmapped volume in the system.
        :param volume_name: Name of of snapshot
        :param origin_volume_id: Id of volume to snapshot
        :return: Tuple containing the volume id of snapshot and volume list
        """

        snapshot_gid = volume_list = None
        if not origin_volume_id:
            raise ValueError(
                "Invalid volume_id parameter, volume_id=%s" % origin_volume_id)
        if not volume_name:
            raise ValueError(
                "Invalid snapshot volume_name parameter, volume_name=%s" % volume_name)

        params = {
            'snapshotDefs': [{"volumeId": origin_volume_id, "snapshotName": volume_name}]}

        LOG.debug("SIOLIB -> snapshot volume params=%r" % params)
        r_uri = "/api/instances/System/action/snapshotVolumes"
        req = api_request(op=HttpAction.POST, host=self.host_addr,
                          uri=r_uri, data=params, auth=self.auth,
                          token=self.server_authtoken)
        if req.status_code == 200:
            snapshot_gid = req.json().get('snapshotGroupId')
            volume_list = req.json().get('volumeIdList')
        elif req.json().get('errorCode') == VOLUME_ALREADY_EXISTS:
            raise VolumeExists("Volume name '%s' already exists, cannot make snapshot '%s'"
                               % (volume_name, origin_volume_id))
        else:
            raise Error("Error making snapshot '%s' of volume '%s': %s"
                        % (volume_name, origin_volume_id, req.json().get('message')))

        return snapshot_gid, volume_list

    def detach_volume(self, volume_id, unmap_all=False):
        """
        Detach volume from SDC
        :param volume_id: Id of volume to detach
        :param unmap_all: True unmap from all SDC's, False only unmap from local SDC
        :return: Nothing
        """

        if not is_id(volume_id):
            volume_id = self.get_volumeid(volume_name=volume_id)
            LOG.warn("SIOLIB -> Parameter is not a valid ID retrieving ID for detach_volume. Found %s" % volume_id)

        # unmap
        self._unmap_volume(volume_id=volume_id, unmap_all=unmap_all)

    def attach_volume(self, volume_id):
        """
        Attach a volume to a SDC
        :param volume_id: If of volume to attach
        :return: Nothing
        """

        if not is_id(volume_id):
            volume_id = self.get_volumeid(volume_name=volume_id)
            LOG.warn("SIOLIB -> Parameter is not a valid ID retrieving ID for attach_volume. Found %s" % volume_id)
        # map
        self._map_volume(volume_id)

    def rename_volume(self, volume_id, new_volume_name):
        """
        Rename an existing volume
        :param volume_id: If of volume to remove
        :param new_volume_name: New volume name
        :return: Nothing
        """
        if not is_id(volume_id):
            volume_id = self.get_volumeid(volume_name=volume_id)
            LOG.warn("SIOLIB -> Parameter is not a valid ID retrieving ID for rename_volume. Found %s" % volume_id)

        params = {'newName': new_volume_name}

        LOG.debug("SIOLIB -> rename volume params=%r" % params)
        r_uri = "/api/instances/Volume::" + volume_id + "/action/setVolumeName"
        # make HTTP RESTful API request to ScaleIO gw
        req = api_request(op=HttpAction.POST, host=self.host_addr,
                          uri=r_uri, data=params, auth=self.auth,
                          token=self.server_authtoken)
        if req.status_code == 200:  # success
            LOG.info("SIOLIB -> Renamed volume %s successfully" % volume_id)
        elif req.json().get('errorCode') == VOLUME_ALREADY_EXISTS:
            raise VolumeExists("Volume name '%s' already exists, cannot rename '%s'"
                               % (new_volume_name, volume_id))
        else:
            LOG.error("SIOLIB -> Error renaming volume: %s" % (req.json().get('message')))
            raise Error("Error renaming volume '%s' to '%s': %s"
                        % (volume_id, new_volume_name, req.json().get('message')))

    def volume(self, volume_id):
        """
        Return a ScaleIOVolume object
        :param volume_id: Id of volume to generate volume object from
        :return: ScaleIOVolume object or None if no valid volume found
        """

        if not is_id(volume_id):
            volume_id = self.get_volumeid(volume_name=volume_id)
            LOG.warn("SIOLIB -> Parameter is not a valid ID retrieving ID for volume. Found %s" % volume_id)

        volume_obj = None

        r_uri = "/api/instances/Volume::" + volume_id
        # make HTTP RESTful API request to ScaleIO gw
        req = api_request(op=HttpAction.GET, host=self.host_addr,
                      uri=r_uri, data=None, auth=self.auth,
                      token=self.server_authtoken)
        if req.status_code == 200:  # success
            LOG.info("SIOLIB --> Retrieved volume object %s successfully" % volume_id)
            volume_obj = _ScaleIOVolume(req.json())
        elif req.json().get('errorCode') == VOLUME_NOT_FOUND_ERROR:
            raise VolumeNotFound("Volume %s is not found" % volume_id)
        else:
            LOG.error("SIOLIB -> Error retrieving volume object: %s" % (req.json().get('message')))
            raise Error("Error retrieving volume '%s': %s"
                        % (volume_id, req.json().get('message')))

        return volume_obj

    def storagepool_size(self, sp_id=None, by_sds=False):
        """
        For a given single storage pool, return the used, total and free space
        in bytes that can be allocated for Volumes. Note this is not the total
        capacity of the system.
        :param sp_id:  ScaleIO storage pool id to query against
        :param by_sds: True, divide results by SDS count used primarily for
                       reporting capacity results in OpenStack Nova.
        :return: Tuple used_bytes, total_bytes, free_bytes
        """

        used_bytes = 0
        total_bytes = 0
        free_bytes = 0

        # FIXME: Redo all of this must be a better and more efficient way
        # get protection domain id for request store this for the duration of
        # the object
        if not self.pd_id:
            self.pd_id = self._get_pdid(self.protection_domain)
        if not self.sp_id and not sp_id:
            self.sp_id = self._get_spid(self.storage_pool, self.pd_id)

        # set based on if param passed in
        sp_id = self.sp_id or sp_id

        # FIXME: Redo all of this must be a better and more efficient way
        r_uri = "/api/types/StoragePool/instances/action/querySelectedStatistics"
        r_uri2 = "/api/types/ProtectionDomain/instances/action/querySelectedStatistics"
        params = {"ids": [sp_id], "properties": ["capacityInUseInKb", "capacityLimitInKb"]}
        params2 = {"ids": [self.pd_id ], "properties": ["numOfSds"]}
        req = api_request(op=HttpAction.POST, host=self.host_addr,
                          uri=r_uri, data=params, auth=self.auth,
                          token=self.server_authtoken)
        req2 = api_request(op=HttpAction.POST, host=self.host_addr,
                          uri=r_uri2, data=params2, auth=self.auth,
                          token=self.server_authtoken)

        # FIXME: Redo all of this must be a better and more efficient way
        if req.status_code == 200 and req2.status_code == 200:
            sds_count = req2.json().get(self.pd_id).get('numOfSds')
            # Total capacity for volumes in a given pool
            total_kb = req.json().get(sp_id).get('capacityLimitInKb') / sds_count
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
            raise Error("Error retrieving storage pool statistics: %s" % msg)

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

        r_uri = "/api/types/System/instances/action/querySelectedStatistics"
        params = {"ids": [],
                  "properties": ["capacityInUseInKb", "capacityLimitInKb"]}
        req = api_request(op=HttpAction.POST, host=self.host_addr,
                          uri=r_uri, data=params, auth=self.auth,
                          token=self.server_authtoken)
        if req.status_code == 200:
            used_kb = req.json().get('capacityInUseInKb')
            total_kb = req.json().get('capacityLimitInKb')
            free_kb = (int(total_kb) - int(used_kb))
            LOG.debug("Storage pool id %s, Total=%sKB, Used=%sKB, "
                      "Free=%sKB" % (self.pd_id, total_kb, used_kb, free_kb))
        else:
            raise Error("Error retrieving cluster statistics: %s"
                        % req.json().get('message'))

        return (used_kb, total_kb, free_kb)

    def get_pool_id(self, pool_name, domain_name):

        r_uri = "/api/types/StoragePool/instances/action/queryIdByKey"
        params = {'name':pool_name, 'protectionDomainName':domain_name}
        req = api_request(op=HttpAction.POST, host=self.host_addr,
                          uri=r_uri, data=params, auth=self.auth,
                          token=self.server_authtoken)

        if req.status_code == 200:
            pool_id = req.json()
        else:
            LOG.error("SIOLIB -> Pool %s not found: %s" % (pool_name, req.json().get('message')))
            raise LookupError("SIOLIB -> Error retrieving Pool ID: %s" % (req.json().get('message')))

        return pool_id

    def list_volume_names(self):

        volume_names = []
        r_uri = "/api/types/Volume/instances"
        req = api_request(op=HttpAction.GET, host=self.host_addr,
                          uri=r_uri, auth=self.auth,
                          token=self.server_authtoken)

        if req.status_code != 200:
            LOG.error("SIOLIB -> Error listing volumes: %s" % (req.json().get('message')))
            raise Error("Error listing volumes: %s" % (req.json().get('message')))

        volume_objects = req.json()
        for volume in volume_objects:
            volume_names.append(volume['name'])

        return volume_names

    @property
    def dataclient(self):
        """
        SDC property, returns SDC object associated with this local connection
        :return: SDC object
        """

        # Check if sdc configured if not do not perform map
        if not self.sdc:
            return
        return self.sdc

    @property
    def server_authtoken(self):
        """
        HTTP Token object property getter
        :return: Token object
        """

        return self._server_authtoken

    @server_authtoken.setter
    def server_authtoken(self, token):
        """
        HTTP Token object property setter
        :param token: Token object
        :return: Nothing
        """

        self._server_authtoken = token

    @property
    def sdc_guid(self):
        """
        Return GUID of current local SDC
        :return: GUID identifier of local SDC
        """

        # Check if sdc configured if not do not perform map
        if not self.sdc:
            return
        return self.sdc.guid