from util import *
import traceback
import os
import sys
import time
import tempfile
from lxml import etree
from contextlib import contextmanager
from cb_feed_util import FeedHelper, build_feed_data

from cbapi.response import CbResponseAPI, Feed
from cbapi.example_helpers import get_object_by_name_or_id
from cbapi.errors import ServerError

from cabby import create_client
from cybox_parse import cybox_parse_observable
from stix.core import STIXPackage
from config_util import parse_config
import logging
import datetime
import dateutil
import dateutil.tz
from tendo import singleton

from cabby.constants import (
    CB_STIX_XML_111, CB_CAP_11, CB_SMIME,
    CB_STIX_XML_10, CB_STIX_XML_101, CB_STIX_XML_11, CB_XENC_122002)

CB_STIX_XML_12 = 'urn:stix.mitre.org:xml:1.2'

BINDING_CHOICES = [CB_STIX_XML_111, CB_CAP_11, CB_SMIME, CB_STIX_XML_12,
                   CB_STIX_XML_10, CB_STIX_XML_101, CB_STIX_XML_11,
                   CB_XENC_122002]

logger = logging.getLogger(__name__)


def total_seconds(td):
    try:
        return int(time.mktime(td.timetuple()))
    except:
        return 0


class CbTaxiiFeedConverter(object):
    def __init__(self, config_file_path, debug_mode=False, import_dir='', export_dir=''):

        #
        # parse config file and save off the information we need
        #
        config_dict = parse_config(config_file_path)

        self.server_url = config_dict.get('server_url', 'https://127.0.0.1')
        self.api_token = config_dict.get('api_token', '')
        self.sites = config_dict.get('sites', [])
        self.debug = config_dict.get('debug', False)
        self.export_dir = export_dir
        self.import_dir = import_dir
        self.integration_name = 'Cb Taxii Connector 1.6.4'

        self.http_proxy_url = config_dict.get('http_proxy_url', None)
        self.https_proxy_url = config_dict.get('https_proxy_url', None)

        if self.export_dir and not os.path.exists(self.export_dir):
            os.mkdir(self.export_dir)

        #
        # Test Cb Response connectivity
        #
        try:
            self.cb = CbResponseAPI(url=self.server_url,
                                    token=self.api_token,
                                    ssl_verify=False,
                                    integration_name=self.integration_name)
            self.cb.info()
        except:
            logger.error(traceback.format_exc())
            sys.exit(-1)

    def write_to_temp_file(self, message):
        temp_file = tempfile.NamedTemporaryFile()
        temp_file.write(message)
        temp_file.flush()
        return temp_file, temp_file.name

    def read_from_xml(self):
        """
        Walk the import dir and return all filenames.  We are assuming all xml files
        :return:
        """
        f = []
        for (dirpath, dirnames, filenames) in os.walk(self.import_dir):
            f.extend(filenames)
            break
        return f

    def export_xml(self, feed_name, start_time, end_time, block_num, message):
        """
        :param feed_name:
        :param start_time:
        :param end_time:
        :param block_num:
        :param message:
        :return:
        """
        #
        # create a directory to store all content blocks
        #
        dir_name = "{}".format(feed_name).replace(' ', '_')
        full_dir_name = os.path.join(self.export_dir, dir_name)

        #
        # Make sure the directory exists
        #
        if not os.path.exists(os.path.join(self.export_dir, dir_name)):
            os.mkdir(full_dir_name)

        #
        # Actually write the file
        #
        file_name = "{}-{}-{}".format(start_time, end_time, block_num).replace(' ', "_")
        full_file_name = os.path.join(full_dir_name, file_name)

        with open(full_file_name, 'wb') as file_handle:
            file_handle.write(message)

    def _import_collection(self, client, site, collection, data_set=False):

        collection_name = collection.name
        sanitized_feed_name = cleanup_string("%s%s" % (site.get('site'), collection_name))
        feed_summary = "%s %s" % (site.get('site'), collection_name)
        available = collection.available
        collection_type = collection.type
        default_score = site.get('default_score')
        logger.info("%s,%s,%s,%s,%s" % (site.get('site'),
                                        collection_name,
                                        sanitized_feed_name,
                                        available,
                                        collection_type))

        if not available:
            return False

        #
        # Sanity check on start date
        #
        start_date_str = site.get('start_date')
        if not start_date_str or len(start_date_str) == 0:
            start_date_str = "2017-01-01 00:00:00"

        #
        # Create a feed helper object
        #
        feed_helper = FeedHelper(
            site.get('output_path'),
            sanitized_feed_name,
            site.get('minutes_to_advance'),
            start_date_str)

        if not data_set:
            logger.info("Feed start time %s" % feed_helper.start_date)
        logger.info("polling Collection: {}...".format(collection.name))

        #
        # Build up the URI for polling
        #

        if not site.get('poll_path', ''):
            uri = None
        else:
            uri = ''
            if site.get('use_https'):
                uri += 'https://'
            else:
                uri += 'http://'

            uri += site.get('site')
            uri += site.get('poll_path')
            logger.info('Poll path: {}'.format(uri))

        reports = []
        while True:

            try:
                try:
                    content_blocks = client.poll(uri=uri,
                                                 collection_name=collection.name,
                                                 begin_date=feed_helper.start_date,
                                                 end_date=feed_helper.end_date,
                                                 content_bindings=BINDING_CHOICES)

                except Exception as e:
                    logger.info(e.message)
                    content_blocks = []

                #
                # Iterate through all content_blocks
                #
                num_blocks = 0

                if not data_set:
                    logger.info(
                        "polling start_date: {}, end_date: {}".format(feed_helper.start_date, feed_helper.end_date))
                for block in content_blocks:
                    logger.debug(block.content)

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
                                "{http://taxii.mitre.org/messages/taxii_xml_binding-1.1}Content_Block/{http://taxii.mitre.org/messages/taxii_xml_binding-1.1}Content").text)
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
                                feed_summary = "{}: {}".format(desc.value, collection_name)
                                break

                        #
                        # Get the timestamp of the STIX Package so we can use this in our feed
                        #
                        timestamp = total_seconds(stix_package.timestamp)

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

                                reports.extend(
                                    cybox_parse_observable(indicator.observable, indicator, timestamp, score))

                        #
                        # Now lets find some data.  Iterate through all observables and parse
                        #
                        if stix_package.observables:
                            for observable in stix_package.observables:
                                if not observable:
                                    continue
                                #
                                # Cybox observable returns a list
                                #
                                reports.extend(cybox_parse_observable(observable, None, timestamp, default_score))

                        #
                        # Delete our temporary file
                        #
                        file_handle.close()

                        num_blocks += 1

                        #
                        # end for loop through content blocks
                        #

                    except Exception as e:
                        # logger.info(traceback.format_exc())
                        logger.info(e.message)
                        continue

                logger.info("content blocks read: {}".format(num_blocks))
                logger.info("current number of reports: {}".format(len(reports)))

                if len(reports) > site.get('reports_limit'):
                    logger.info("We have reached the reports limit of {0}".format(site.get('reports_limit')))
                    break
                #
                # DEBUG CODE
                #
                # if len(reports) > 10:
                #    break

                #
                # Attempt to advance the start time and end time
                #

            except Exception as e:
                logger.info(traceback.format_exc())

            #
            # If it is just a data_set, the data is unordered, so we can just break out of the while loop
            #
            if data_set:
                break

            if feed_helper.advance():
                continue
            else:
                break
            #
            # end While True
            #

        logger.info("Found {} new reports.".format(len(reports)))

        if not data_set:
            #
            # We only want to concatenate if we are NOT a data set, otherwise we want to refresh all the reports
            #
            logger.info("Adding existing reports...")
            reports = feed_helper.load_existing_feed_data() + reports

        logger.info("Total number of reports: {}".format(len(reports)))

        if site.get('reports_limit') < len(reports):
            logger.info("Truncating reports to length {0}".format(site.get('reports_limit')))
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
                logger.info("Feed {} was not found, so we are going to create it".format(sanitized_feed_name))

            elif len(feeds) > 1:
                logger.warning("Multiple feeds found, selecting Feed id {}".format(feeds[0].id))
                feed_id = feeds[0].id

            elif feeds:
                feed_id = feeds[0].id
                logger.info("Feed {} was found as Feed ID {}".format(sanitized_feed_name, feed_id))

        except Exception as e:
            logger.info(e.message)

        if not feed_id:
            logger.info("Creating {} feed for the first time".format(sanitized_feed_name))

            f = self.cb.create(Feed)
            f.feed_url = "file://" + feed_helper.path
            f.enabled = site.get('feeds_enable')
            f.use_proxy = False
            f.validate_server_cert = False
            try:
                f.save()
            except ServerError as se:
                if se.error_code == 500:
                    logger.info("Could not add feed:")
                    logger.info(
                        " Received error code 500 from server. This is usually because the server cannot retrieve the feed.")
                    logger.info(
                        " Check to ensure the Cb server has network connectivity and the credentials are correct.")
                else:
                    logger.info("Could not add feed: {0:s}".format(str(se)))
            except Exception as e:
                logger.info("Could not add feed: {0:s}".format(str(e)))
            else:
                logger.info("Feed data: {0:s}".format(str(f)))
                logger.info("Added feed. New feed ID is {0:d}".format(f.id))
                feed_id = f.id

        return feed_id

    def perform(self):
        """
        :param self:
        :param enumerate_collections_only:
        :return:
        """
        for site in self.sites:

            client = create_client(site.get('site'),
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
                logger.info("Found HTTP Proxy: {}".format(self.http_proxy_url))
                proxy_dict['http'] = self.http_proxy_url

            if self.https_proxy_url:
                logger.info("Found HTTPS Proxy: {}".format(self.https_proxy_url))
                proxy_dict['https'] = self.https_proxy_url

            if proxy_dict:
                client.set_proxies(proxy_dict)

            if site.get('username') or site.get('cert_file'):
                #
                # If a username is supplied use basic authentication
                #
                logger.info("Found Username in config, using basic auth...")
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
                logger.info('Collection Management Path: {}'.format(uri))

                collections = client.get_collections(uri=uri)

            for collection in collections:
                logger.info('Collection Name: {}, Collection Type: {}'.format(collection.name, collection.type))

            if len(collections) == 0:
                logger.info('Unable to find any collections.  Exiting...')
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


def runner(configpath, debug_mode, import_dir, export_dir):
    try:
        #
        # Setting nice inside script so we don't get killed by OOM
        #
        os.nice(1)

        #
        # run only one instance of this script
        #
        me = singleton.SingleInstance()
        cbt = CbTaxiiFeedConverter(configpath, debug_mode, import_dir, export_dir)
        cbt.perform()
    except singleton.SingleInstanceException as e:
        logger.error("Cannot run multiple copies of this script")
        return False
    except Exception as e:
        logger.error(traceback.format_exc())
        return False
    return True
