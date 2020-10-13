#  coding: utf-8
#  VMware Carbon Black EDR Taxii Connector © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################

import datetime
import logging
import os
import sys
import tempfile
import time
from typing import Any, AnyStr, Dict, List, Optional, Tuple, Union

import dateutil
import dateutil.tz
from cabby import Client10, Client11, create_client
from cabby.constants import (CB_CAP_11, CB_SMIME, CB_STIX_XML_10, CB_STIX_XML_101, CB_STIX_XML_11, CB_STIX_XML_111,
                             CB_XENC_122002)
from cabby.entities import Collection as CabbyCollection
from cbapi.errors import ServerError
from cbapi.example_helpers import get_object_by_name_or_id
from cbapi.response import CbResponseAPI, Feed
from lxml import etree
from stix.core import STIXPackage

from .cb_feed_util import build_feed_data, FeedHelper
from .config_util import parse_config
from .cybox_parse import cybox_parse_observable
from .singleton import SingleInstance, SingleInstanceException
from .util import cleanup_string

CB_STIX_XML_12 = 'urn:stix.mitre.org:xml:1.2'

BINDING_CHOICES = [CB_STIX_XML_111, CB_CAP_11, CB_SMIME, CB_STIX_XML_12,
                   CB_STIX_XML_10, CB_STIX_XML_101, CB_STIX_XML_11,
                   CB_XENC_122002]

_logger = logging.getLogger(__name__)


def total_seconds(td: datetime) -> int:
    """
    Simple method to return integer time in seconds from a supplied datetime.

    :param td: datetime object to be converted
    :return: epoch time in seconds
    """
    try:
        return int(time.mktime(td.timetuple()))
    except Exception as err:
        _logger.debug(f"Supplied `td` could not be converted: {err}")
        return 0


class CbTaxiiFeedConverter(object):
    """
    Class to convert TAXII feeds into EDR feeds.
    """

    def __init__(self, config_file_path: str, debug_mode: bool = False, import_dir: str = '',
                 export_dir: Optional[str] = None):
        """
        Parse config file and save off the information we need.

        :param config_file_path: configuration file location
        :param debug_mode: If True, operate in debug mode
        :param import_dir: feed import directory
        :param export_dir: export directory (optional)
        """
        config_dict = parse_config(config_file_path)
        if debug_mode:
            _logger.debug(f"Config: {config_dict}")

        self.server_url = config_dict.get('server_url', 'https://127.0.0.1')
        self.api_token = config_dict.get('api_token', '')
        self.sites = config_dict.get('sites', [])
        self.debug = config_dict.get('debug', False)
        self.export_dir = export_dir
        self.import_dir = import_dir
        self.integration_name = 'Cb Taxii Connector 1.6.5'

        self.http_proxy_url = config_dict.get('http_proxy_url', None)
        self.https_proxy_url = config_dict.get('https_proxy_url', None)

        # if exporting, make sure the directory exists
        if self.export_dir and not os.path.exists(self.export_dir):
            os.mkdir(self.export_dir)

        # Test Cb Response connectivity
        try:
            self.cb = CbResponseAPI(url=self.server_url, token=self.api_token,
                                    ssl_verify=False, integration_name=self.integration_name)
            self.cb.info()
        except Exception as err:
            _logger.error(f"Failed to make connection: {err}", exc_info=True)
            sys.exit(-1)

    @staticmethod
    def write_to_temp_file(message: AnyStr) -> Tuple[tempfile.NamedTemporaryFile, str]:
        """
        Write text to a temp file for later use.

        :param message: text to be saved
        :return: Tuple of (NamedTemporaryFile, tempfile name)
        """
        temp_file = tempfile.NamedTemporaryFile()
        temp_file.write(message)
        temp_file.flush()
        return temp_file, temp_file.name

    # NOTE: currently unused; retained for future need
    # noinspection PyUnusedFunction
    def read_from_xml(self) -> List[str]:
        """
        Walk the import dir and return all filenames.  We are assuming all xml files.

        :return: List of filenames
        """
        the_list = []
        for (dirpath, dirnames, filenames) in os.walk(self.import_dir):
            the_list.extend(filenames)
            break
        return the_list

    def export_xml(self, feed_name: str, start_time: str, end_time: str, block_num: int, message: AnyStr) -> None:
        """
        :param feed_name: name of the feed, for the holding directory name
        :param start_time: start time
        :param end_time: end time
        :param block_num: write block number (for uniqueness)
        :param message: feed text
        """
        # create a directory to store all content blocks
        dir_name = f"{feed_name}".replace(' ', '_')
        full_dir_name = os.path.join(self.export_dir, dir_name)

        # Make sure the directory exists
        if not os.path.exists(os.path.join(self.export_dir, dir_name)):
            os.mkdir(full_dir_name)

        # Actually write the file
        file_name = f"{start_time}-{end_time}-{block_num}".replace(' ', "_")
        full_file_name = os.path.join(full_dir_name, file_name)

        with open(full_file_name, 'wb') as file_handle:
            file_handle.write(message)

    def _import_collection(self, client: Union[Client10, Client11], site: dict, collection: CabbyCollection,
                           data_set: bool = False) -> int:
        """
        Import a taxii client collectio into a feed.

        :param client: Taxii spec client v1.0 or v1.1
        :param site: site definition
        :param collection: cabby collection
        :param data_set: True if DATA_SET, False otherwise
        :return: the EDR feed id, or -1 if not available
        """
        global BINDING_CHOICES

        collection_name = collection.name
        sanitized_feed_name = cleanup_string(f"{site.get('site')}{collection_name}%s")
        feed_summary = f"{site.get('site')} {collection_name}"
        available = collection.available
        collection_type = collection.type
        default_score = site.get('default_score')
        _logger.info(f"{site.get('site')},{collection_name},{sanitized_feed_name},{available},{collection_type}")

        # if not available, nothing else to do
        if not available:
            return -1

        # Sanity check on start date; provide a bare minimum
        start_date_str = site.get('start_date')
        if not start_date_str or len(start_date_str) == 0:
            start_date_str = "2019-01-01 00:00:00"

        # Create a feed helper object
        feed_helper = FeedHelper(site.get('output_path'), sanitized_feed_name, site.get('minutes_to_advance'),
                                 start_date_str, reset_start_date=site.get('reset_start_date', False))

        if not data_set:
            _logger.info("Feed start time %s" % feed_helper.start_date)
        _logger.info(f"polling Collection: {collection}...")

        #
        # Build up the URI for polling
        #

        if not site.get('poll_path', ''):
            uri: Optional[str] = None
        else:
            uri: str = ''
            if site.get('use_https'):
                uri += 'https://'
            else:
                uri += 'http://'

            uri += site.get('site')
            uri += site.get('poll_path')
            _logger.info(f'Poll path: {uri}')

        # build up all the reports for the feed
        reports: List[Dict[str, Any]] = []
        while True:
            num_times_empty_content_blocks = 0
            try:
                try:
                    _logger.info(f"Polling Collection: {collection}")
                    content_blocks = client.poll(collection_name=collection.name, begin_date=feed_helper.start_date,
                                                 end_date=feed_helper.end_date, content_bindings=BINDING_CHOICES,
                                                 uri=uri)
                except Exception as e:
                    _logger.info(f"{e}")
                    content_blocks = []

                #
                # Iterate through all content_blocks
                #
                num_blocks = 0

                if not data_set:
                    _logger.info(f"polling start_date: {feed_helper.start_date}, end_date: {feed_helper.end_date}")
                for block in content_blocks:
                    _logger.debug(block.content)

                    #
                    # if in export mode then save off this content block
                    #
                    if self.export_dir:
                        self.export_xml(collection_name,
                                        feed_helper.start_date,
                                        feed_helper.end_date,
                                        num_blocks,
                                        block.content)

                    #
                    # This code accounts for a case found with ThreatCentral.io where the content is url encoded.
                    # etree.fromstring can parse this data.
                    #
                    try:
                        root = etree.fromstring(block.content)
                        content = root.find('.//{http://taxii.mitre.org/messages/taxii_xml_binding-1.1}Content')
                        if content is not None and len(content) == 0 and len(list(content)) == 0:
                            #
                            # Content has no children.  So lets make sure we parse the xml text for content and re-add
                            # it as valid XML so we can parse
                            #
                            new_stix_package = etree.fromstring(root.find(
                                "{http://taxii.mitre.org/messages/taxii_xml_binding-1.1}"
                                "Content_Block/{http://taxii.mitre.org/messages/taxii_xml_binding-1.1}Content").text)
                            content.append(new_stix_package)

                        #
                        # Since we modified the xml, we need create a new xml message string to parse
                        #
                        message = etree.tostring(root)

                        #
                        # Write the content block to disk so we can parse with python stix
                        #
                        file_handle, file_path = self.write_to_temp_file(message)

                        #
                        # Parse STIX data
                        #
                        stix_package = STIXPackage.from_xml(file_path)

                        #
                        # if it is a DATA_SET make feed_summary from the stix_header description
                        # NOTE: this is for RecordedFuture, also note that we only do this for data_sets.
                        #       to date I have only seen RecordedFuture use data_sets
                        #
                        if data_set and stix_package.stix_header and stix_package.stix_header.descriptions:
                            for desc in stix_package.stix_header.descriptions:
                                feed_summary = f"{desc.value}: {collection_name}"
                                break

                        #
                        # Get the timestamp of the STIX Package so we can use this in our feed
                        #
                        timestamp = total_seconds(stix_package.timestamp)

                        # check for empty content in this block; we break out after 10 empty blocks
                        if not stix_package.indicators and not stix_package.observables:
                            num_times_empty_content_blocks += 1
                            if num_times_empty_content_blocks > 10:
                                break

                        # Go through all STIX indicators
                        if stix_package.indicators:
                            for indicator in stix_package.indicators:

                                if not indicator or not indicator.observable:
                                    continue

                                if indicator.confidence:
                                    if str(indicator.confidence.value).isdigit():
                                        #
                                        # Get the confidence score and use it for our score
                                        #
                                        score = int(indicator.confidence.to_dict().get("value", default_score))
                                    else:
                                        if str(indicator.confidence.value).lower() == "high":
                                            score = 75
                                        elif str(indicator.confidence.value).lower() == "medium":
                                            score = 50
                                        elif str(indicator.confidence.value).lower() == "low":
                                            score = 25
                                        else:
                                            score = default_score
                                else:
                                    score = default_score

                                if not indicator.timestamp:
                                    timestamp = 0
                                else:
                                    timestamp = int((indicator.timestamp -
                                                     datetime.datetime(1970, 1, 1).replace(
                                                         tzinfo=dateutil.tz.tzutc())).total_seconds())

                                # Cybox observable returns a list
                                reports.extend(cybox_parse_observable(indicator.observable, indicator, timestamp,
                                                                      score))

                        #
                        # Now lets find some data.  Iterate through all observables and parse
                        #
                        if stix_package.observables:
                            for observable in stix_package.observables:
                                if not observable:
                                    continue

                                # Cybox observable returns a list
                                reports.extend(cybox_parse_observable(observable, None, timestamp, default_score))

                        #
                        # Delete our temporary file
                        #
                        file_handle.close()

                        # increase block count
                        num_blocks += 1
                    except Exception as e:
                        _logger.info(f"{e}")
                        continue

                _logger.info(f"content blocks read: {num_blocks}")
                _logger.info(f"current number of reports: {len(reports)}")

                if len(reports) > site.get('reports_limit'):
                    _logger.info(f"We have reached the reports limit of {site.get('reports_limit')}")
                    break
            except Exception as e:
                _logger.info(f"{e}")

            # If it is just a data_set, the data is unordered, so we can just break out of the while loop
            if data_set:
                break

            if feed_helper.advance():
                continue
            else:
                break

        _logger.info(f"Found {len(reports)} new reports.")

        if not data_set:
            # We only want to concatenate if we are NOT a data set, otherwise we want to refresh all the reports
            _logger.info("Adding existing reports...")
            reports = feed_helper.load_existing_feed_data() + reports

        _logger.info(f"Total number of reports: {len(reports)}")

        if site.get('reports_limit') < len(reports):
            _logger.info("Truncating reports to length {0}".format(site.get('reports_limit')))
            reports = reports[:site.get('reports_limit')]

        data = build_feed_data(sanitized_feed_name,
                               "%s %s" % (site.get('site'), collection_name),
                               feed_summary,
                               site.get('site'),
                               site.get('icon_link'),
                               reports)

        if feed_helper.write_feed(data):
            feed_helper.save_details()

        #
        # Create Cb Response Feed if necessary
        #

        feed_id = None

        try:
            feeds = get_object_by_name_or_id(self.cb, Feed, name=sanitized_feed_name)

            if not feeds:
                _logger.info("Feed {} was not found, so we are going to create it".format(sanitized_feed_name))

            elif len(feeds) > 1:
                _logger.warning("Multiple feeds found, selecting Feed id {}".format(feeds[0].id))
                feed_id = feeds[0].id

            elif feeds:
                feed_id = feeds[0].id
                _logger.info("Feed {} was found as Feed ID {}".format(sanitized_feed_name, feed_id))

        except Exception as e:
            _logger.info(f"{e}")

        if not feed_id:
            _logger.info("Creating {} feed for the first time".format(sanitized_feed_name))

            f = self.cb.create(Feed)
            f.feed_url = "file://" + feed_helper.path
            f.enabled = site.get('feeds_enable')
            f.use_proxy = False
            f.validate_server_cert = False
            try:
                f.save()
            except ServerError as se:
                if se.error_code == 500:
                    _logger.info("Could not add feed:")
                    _logger.info("   Received error code 500 from server. This is usually because "
                                 "the server cannot retrieve the feed.")
                    _logger.info("   Check to ensure the Cb server has network connectivity "
                                 "and the credentials are correct.")
                else:
                    _logger.info("Could not add feed: {0:s}".format(str(se)))
            except Exception as e:
                _logger.info("Could not add feed: {0:s}".format(str(e)))
            else:
                _logger.info("Feed data: {0:s}".format(str(f)))
                _logger.info("Added feed. New feed ID is {0}".format(f.id))
                feed_id = f.id

        return feed_id

    def perform(self) -> None:
        """
        Perform the taxii hailing service.
        """
        for site in self.sites:
            client: Union[Client10, Client11] = create_client(site.get('site'),
                                                              use_https=site.get('use_https'),
                                                              discovery_path=site.get('discovery_path'))

            #
            # Set verify_ssl and ca_cert inside the client
            #
            client.set_auth(verify_ssl=site.get('ssl_verify'), ca_cert=site.get('ca_cert'))

            #
            # Proxy Settings
            #
            proxy_dict = dict()

            if self.http_proxy_url:
                _logger.info(f"Found HTTP Proxy: {self.http_proxy_url}")
                proxy_dict['http'] = self.http_proxy_url

            if self.https_proxy_url:
                _logger.info(f"Found HTTPS Proxy: {self.https_proxy_url}")
                proxy_dict['https'] = self.https_proxy_url

            if proxy_dict:
                client.set_proxies(proxy_dict)

            # If a username is supplied use basic authentication
            if site.get('username') or site.get('cert_file'):
                _logger.info("Found Username in config, using basic auth...")
                client.set_auth(username=site.get('username'),
                                password=site.get('password'),
                                verify_ssl=site.get('ssl_verify'),
                                ca_cert=site.get('ca_cert'),
                                cert_file=site.get('cert_file'),
                                key_file=site.get('key_file'))

            if not site.get('collection_management_path', ''):
                collections = client.get_collections()
            else:
                uri = ''
                if site.get('use_https'):
                    uri += 'https://'
                else:
                    uri += 'http://'

                uri += site.get('site')
                uri += site.get('collection_management_path')
                _logger.info('Collection Management Path: {}'.format(uri))

                collections: List[CabbyCollection] = client.get_collections(uri=uri)

            for collection in collections:
                _logger.info(f'Collection Name: {collection.name}, Collection Type: {collection.type}')

            if len(collections) == 0:
                _logger.info('Unable to find any collections.  Exiting...')
                sys.exit(0)

            desired_collections = [x.strip() for x in site.get('collections').lower().split(',')]

            want_all = False
            if '*' in desired_collections:
                want_all = True

            for collection in collections:
                if collection.type != 'DATA_FEED' and collection.type != 'DATA_SET':
                    continue

                if collection.type == 'DATA_SET':
                    data_set = True
                else:
                    data_set = False

                if want_all or collection.name.lower() in desired_collections:
                    self._import_collection(client, site, collection, data_set)


def runner(configpath: str, debug_mode: bool, import_dir: str, export_dir: str):
    try:
        #
        # Setting nice inside script so we don't get killed by OOM
        #
        os.nice(1)

        #
        # run only one instance of this script
        #
        # noinspection PyUnusedLocal
        me = SingleInstance()
        cbt = CbTaxiiFeedConverter(configpath, debug_mode, import_dir, export_dir)
        cbt.perform()
    except SingleInstanceException as e:
        _logger.error(f"Cannot run multiple copies of this script: {e}")
        return False
    except Exception as e:
        _logger.error(f"{e}")
        return False
    return True
