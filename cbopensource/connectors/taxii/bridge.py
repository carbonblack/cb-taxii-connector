from util import *
import traceback
import os
import sys
import time
import tempfile
from lxml import etree
from contextlib import contextmanager
from cb_feed_util import FeedHelper, build_feed_data
from cbapi import CbApi
from cabby import create_client
from cybox_parse import cybox_parse_observable
from stix.core import STIXPackage
from config_util import parse_config
import logging

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

        if self.export_dir and not os.path.exists(self.export_dir):
            os.mkdir(self.export_dir)

        #
        # Test Cb Response connectivity
        #
        try:
            self.cb = CbApi(server=self.server_url, token=self.api_token, ssl_verify=False)
            self.cb.feed_enum()
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


    def _import_collection(self, client, site, collection):

        collection_name = collection.name
        sanitized_feed_name = cleanup_string("%s%s" % (site.get('site'), collection_name))
        available = collection.available
        collection_type = collection.type
        logger.info("%s,%s,%s,%s,%s" % (site.get('site'),
                                         collection_name,
                                         sanitized_feed_name,
                                         available,
                                         collection_type))

        #
        # We only care about DATA_FEED type
        #
        if not available or collection_type != "DATA_FEED":
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
                    traceback.print_exc()
                    content_blocks = []


                #
                # Iterate through all content_blocks
                #
                num_blocks = 0

                logger.info("polling start_date: {}, end_date: {}".format(feed_helper.start_date,feed_helper.end_date))
                for block in content_blocks:

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
                        # Get the timestamp of the STIX Package so we can use this in our feed
                        #
                        timestamp = total_seconds(stix_package.timestamp)

                        #
                        # Now lets find some data.  Iterate through all observables and parse
                        #
                        if stix_package.observables:
                            for observable in stix_package.observables:
                                #
                                # Cybox observable returns a list
                                #
                                reports.extend(cybox_parse_observable(observable, timestamp))

                        #
                        # Delete our temporary file
                        #
                        file_handle.close()



                        num_blocks += 1

                        #
                        # end for loop through content blocks
                        #

                    except Exception as e:
                        print block.content
                        traceback.print_exc()
                        continue

                logger.info("content blocks read: {}".format(num_blocks))
                logger.info("current number of reports: {}".format(len(reports)))

                #
                # DEBUG CODE
                #
                #if len(reports) > 10:
                #    break

                #
                # Attempt to advance the start time and end time
                #

            except Exception as e:
                traceback.print_exc()

            if feed_helper.advance():
                continue
            else:
                break
            #
            # end While True
            #


        logger.info("Found {} new reports.".format(len(reports)))

        reports = feed_helper.load_existing_feed_data() + reports

        logger.info("Total number of reports: {}".format(len(reports)))

        data = build_feed_data(sanitized_feed_name,
                               "%s %s" % (site.get('site'), collection_name),
                               site.get('site'),
                               site.get('icon_link'),
                               reports)

        if feed_helper.write_feed(data):
            feed_helper.save_details()

        #
        # Create Cb Response Feed if necessary
        #
        feed_id = self.cb.feed_get_id_by_name(sanitized_feed_name)
        if not feed_id:
            data = self.cb.feed_add_from_url("file://" + feed_helper.path,
                                             site.get('feeds_enable'),
                                             False,
                                             False)


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

            if site.get('username'):
                #
                # If a username is supplied use basic authentication
                #
                logger.info("Found Username in config, using basic auth...")
                client.set_auth(username=site.get('username'),
                                password=site.get('password'),
                                verify_ssl=site.get('ssl_verify'),
                                ca_cert=site.get('ca_cert'))
            elif site.get('cert_file'):
                #
                # if a cert file is specified use SSL authentication
                #
                client.set_auth(cert_file=site.get('cert_file'),
                                key_file=site.get('key_file'),
                                verify_ssl=site.get('ssl_verify'),
                                ca_cert=site.get('ca_cert'))

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

            desired_collections = site.get('collections').lower().split(',')

            want_all = False
            if '*' in desired_collections:
                want_all = True

            for collection in collections:
                if collection.type != 'DATA_FEED':
                    continue

                if want_all or collection.name.lower() in desired_collections:
                    self._import_collection(client, site, collection)


@contextmanager
def file_lock(lock_file):
    if os.path.exists(lock_file):
        pid = file(lock_file).read()
        print 'Only one instance can run at once. ' \
              'Script is locked with %s (pid: %s)' % (lock_file, pid)
        sys.exit(-1)
    else:
        open(lock_file, 'w').write("%d" % os.getpid())
        try:
            yield
        finally:
            os.remove(lock_file)


def runner(configpath, debug_mode, import_dir, export_dir):
    with file_lock('/var/run/cb/cbtaxii.py.pid'):
        try:
            cbt = CbTaxiiFeedConverter(configpath, debug_mode, import_dir, export_dir)
            cbt.perform()
        except:
            logger.error(traceback.format_exc())
            return False
    return True

