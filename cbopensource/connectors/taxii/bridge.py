#!/usr/bin/env python
#
#The MIT License (MIT)
#
# Copyright (c) 2015 Bit9 + Carbon Black
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

from util import *
from version import __version__
import ConfigParser
import traceback
import os
import sys
import time
import tempfile
import requests
import simplejson as json
from lxml import etree
from contextlib import contextmanager

from taxii_client import TaxiiClient, stix_element_to_reports, fast_xml_iter, UnauthorizedException
from cb_feed_util import FeedHelper, build_feed_data
from cbapi import CbApi




#################################################################################
# TODO -- do we want to enable email alerting?

_logger = None

class CbTaxiiFeedConverter(object):
    def __init__(self, configpath, export_mode=False):

        self.export_mode = export_mode

        self.sites = []
        if self.export_mode:
            _logger.warn("CB Taxii %s running (EXPORT MODE)" % __version__)
        else:
            _logger.warn("CB Taxii %s running" % __version__)

        config = ConfigParser.ConfigParser()
        if not os.path.exists(configpath):
            _logger.error("Config File %s does not exist!" % configpath)
            print("Config File %s does not exist!" % configpath)
            sys.exit(-1)

        config.read(configpath)

        # SEE IF THERE's A DIFFERENT SERVER_PORT
        self.server_port = 443
        if config.has_section("cbconfig"):
            if config.has_option("cbconfig", "server_port"):
                self.server_port = config.getint("cbconfig", "server_port")
        self.server_url = "https://127.0.0.1:%d" % self.server_port

        self.api_token = None
        if config.has_option("cbconfig", "auth_token"):
            self.api_token = config.get("cbconfig", "auth_token")

        for section in config.sections():
            # don't do cbconfig
            if section.lower() == 'cbconfig':
                continue

            # get site and strip off preceeding http(s):// if necessary
            site = config.get(section, "site").lower()

            if site.startswith("https://"):
                site = site[8:]

            if site.startswith("http://"):
                site = site[7:]

            if site.endswith("/"):
                site = site.strip("/")

            output_path = config.get(section, "output_path")
            icon_link = config.get(section, "icon_link")
            username = config.get(section, "username")
            password = config.get(section, "password")
            feeds_enable = config.getboolean(section, "feeds_enable")
            feeds_alerting = config.get(section, "feeds_alerting")
            collections = config.get(section, "collections") if config.has_option(section, "collections") else "*"


            ### OPTIONAL ARGUMENTS #######################################################
            if config.has_option(section, "start_date"):
                start_date = config.get(section, "start_date")
            else:
                start_date = "2015-01-01 00:00:00"

            if config.has_option(section, "use_https"):
                use_https=config.getboolean(section, "use_https")
            else:
                use_https = False

            cert_file = None
            key_file = None

            if config.has_option(section, "cert_file") and config.has_option(section, "key_file"):
                cert_file = config.get(section, "cert_file").strip()
                if cert_file == "":
                    cert_file = None
                elif not os.path.exists(cert_file):
                    _logger.error("Cert file supplied but doesn't exist: %s" % (cert_file))

                key_file = config.get(section, "key_file").strip()
                if key_file == "":
                    cert_file = None
                elif not os.path.exists(key_file):
                    _logger.error("Key file supplied but doesn't exist: %s" % (key_file))

            if config.has_option(section, "minutes_to_advance"):
                minutes_to_advance = int(config.get(section, "minutes_to_advance"))
            else:
                minutes_to_advance = 15


            if config.has_option(section, "enable_ip_ranges"):
                enable_ip_ranges = config.getboolean(section, "enable_ip_ranges")
            else:
                enable_ip_ranges = True

            ssl_verify = True
            if config.has_option(section, "sslverify"):
                ssl_verify = config.getboolean(section, "sslverify")

            discovery_request_uri = "/taxii-discovery-service"
            if config.has_option(section, "discovery_request_uri"):
                discovery_request_uri = config.get(section, "discovery_request_uri")

            poll_request_uri = "/taxii-data"
            if config.has_option(section, "poll_request_uri"):
                poll_request_uri = config.get(section, "poll_request_uri")

            _logger.info("Configured Site: %s Path: %s" % (site, output_path))

            self.sites.append({"site": site,
                               "output_path": output_path,
                               "username": username,
                               "password": password,
                               "collections": collections,
                               "icon_link": icon_link,
                               "feeds_enable": feeds_enable,
                               "feeds_alerting": feeds_alerting,
                               "enable_ip_ranges": enable_ip_ranges,
                               "start_date": start_date,
                               "use_https": use_https,
                               "key_file": key_file,
                               "cert_file": cert_file,
                               "minutes_to_advance": minutes_to_advance,
                               "ssl_verify": ssl_verify,
                               "discovery_request_uri": discovery_request_uri,
                               "poll_request_uri": poll_request_uri})
            self.cb = None

    def __enable_cb_api_if_necessary(self):
        if self.cb:
            return

        if len(self.api_token) == 0:
            _logger.error("***** auth_token setting in config file cannot be empty! *****")
            sys.exit(-1)

        _logger.info("Using Server URL: %s" % self.server_url)
        self.cb = CbApi(self.server_url, token=self.api_token, ssl_verify=False)
        try:
            # TEST CB CONNECTIVITY
            self.cb.feed_enum()
        except:
            e = traceback.format_exc()
            _logger.error("Unable to connect to CB using url: %s Error: %s" % (self.server_url, e))
            print("Unable to connect to CB using url: %s Error: %s" % (self.server_url, e))
            sys.exit(-1)

    @staticmethod
    def _message_to_reports(filepath, site, site_url, collection, enable_ip_ranges):
        context = etree.iterparse(filepath, tag='{http://stix.mitre.org/stix-1}STIX_Package')
        global _logger
        reports = fast_xml_iter(context, stix_element_to_reports, site, site_url, collection, enable_ip_ranges, _logger)
        return reports

    def _write_message_to_disk(self, message):
        fd,path = tempfile.mkstemp()
        #        os.write(fd, message)
        os.close(fd)
        f = file(path, 'wb')
        f.write(message)
        f.close()
        return path

    def _export_message_to_disk(self, feed_name, start_time, end_time, message):
        log_dir = "/var/run/cb/cbtaxii-export"
        if not os.path.exists(log_dir):
            os.mkdir(log_dir)
        path = "%s/%s-%s-%s.xml" % (log_dir, feed_name, start_time, end_time)
        path = path.replace(' ', '_')
        f = file(path, 'wb')
        f.write(message)
        f.close()
        return path


    def _import_collection(self, client, site, collection):
        if not self.export_mode:
            self.__enable_cb_api_if_necessary()

        collection_name = collection.get('collection_name', '')
        sanitized_feed_name = cleanup_string("%s%s" % (site.get('site'), collection_name))
        available = collection.get('available', False)
        collection_type = collection.get('collection_type', '').upper()
        _logger.info("%s,%s,%s,%s,%s" % (site.get('site'),
                                              collection_name,
                                              sanitized_feed_name,
                                              available,
                                              collection_type))

        if not available or collection_type != "DATA_FEED":
            return

        start_date_str = site.get('start_date')
        if not start_date_str or len(start_date_str) == 0:
            start_date_str = "2015-04-01 00:00:00"

        feed_helper = FeedHelper(site.get('output_path'), sanitized_feed_name, site.get('minutes_to_advance'), start_date_str, self.export_mode)

        _logger.info("Feed start time %s" % feed_helper.start_date)

        reports = []
        try:
            # CATCHUP -- TODO, move to a function??
            while True:
                break_requested = False
                these_reports = []
                tries = 0
                while tries < 5:
                    try:
                        if feed_helper.start_date > feed_helper.end_date:
                            break

                        t1 = time.time()
                        message = client.retrieve_collection(collection_name, feed_helper.start_date, feed_helper.end_date)
                        t2 = time.time()

                        message_len = len(message)

                        if self.export_mode:
                            path = self._export_message_to_disk(sanitized_feed_name, feed_helper.start_date, feed_helper.end_date, message)
                            _logger.info("%s - %s - %s - %d (%f)- %s" % (feed_helper.start_date, feed_helper.end_date, collection_name, message_len, (t2-t1), path))
                            message = None
                        else:
                            filepath = self._write_message_to_disk(message)
                            message = None
                            site_url = "%s://%s" % ("https" if site.get('use_https') else "http", site.get('site'))
                            these_reports = self._message_to_reports(filepath, site.get('site'), site_url, collection_name, site.get('enable_ip_ranges'))
                            t3 = time.time()
                            os.remove(filepath)
                            count = len(these_reports)
                            _logger.info("%s - %s - %s - %d (%d)(%.2f)(%.2f)" % (feed_helper.start_date, feed_helper.end_date, collection_name, count, message_len, (t2-t1), (t3-t2)))
                        break
                    except KeyboardInterrupt:
                        break_requested = True
                    except:
                        _logger.error("%s" % traceback.format_exc())
                        time.sleep(5)
                        tries += 1

                if tries == 5:
                    _logger.error("Giving up for site %s, collection %s" % (site.get('site'), collection))
                    return

                if break_requested:
                    break

                if not self.export_mode:
                    reports.extend(these_reports)

                if not feed_helper.advance():
                    break

        except KeyboardInterrupt:
            pass

        ########## end while (for iterating across time)

        _logger.info("COMPLETED %s,%s,%s,%s,%s (%d)" % (site.get('site'),
                                              collection_name,
                                              sanitized_feed_name,
                                              available,
                                              collection_type,
                                              len(reports)))

        if not self.export_mode:

            # TODO -- clean this up
            if len(reports) > 0:
                # load existing data and convert new data
                reports = feed_helper.load_existing_feed_data() + reports

                # convert feed info and reports to json
                data = build_feed_data(sanitized_feed_name,
                                       "%s %s" % (site.get('site'), collection_name),
                                       site.get('site'),
                                       site.get('icon_link'),
                                       reports)

                # SAVE THE DATA: write out the feed file and save the details for when we last queried it
                if feed_helper.write_feed(data):
                    feed_helper.save_details()

                # Actually add CB feed if necessary
                feed_id = self.cb.feed_get_id_by_name(sanitized_feed_name)
                if not feed_id:
                    data = self.cb.feed_add_from_url("file://" + feed_helper.path,
                                              site.get('feeds_enable'),
                                              False,
                                              False)

                    # FEED ALERTING!!
                    feed_id = data.get('id')
                    url = "%s/api/v1/feed/%d/action" % (self.server_url, feed_id)
                    alert_types = site.get('feeds_alerting', '').split(',')
                    headers = {'X-Auth-Token' : self.api_token, "Accept" : "application/json"}
                    for alert in alert_types:
                        if alert.lower() == "syslog":
                            action_data = {"action_data": """{"email_recipients":[1]}""", "action_type": 1, "group_id": feed_id, "watchlist_id": ""}
                            resp = requests.post(url, headers=headers, data=json.dumps(action_data), verify=False)
                            if resp.status_code != 200:
                                _logger.warn("Error for syslog action (%d): %s" % (feed_id, resp.content))
                        elif alert.lower() == "cb":
                            action_data = {"action_data": """{"email_recipients":[1]}""", "action_type": 3, "group_id": feed_id, "watchlist_id": ""}
                            resp = requests.post(url, headers=headers, data=json.dumps(action_data), verify=False)
                            if resp.status_code != 200:
                                _logger.warn("Error for cb action (%d): %s" % (feed_id, resp.content))
            else: # no reports
                feed_helper.save_details()

    @staticmethod
    def perform_from_files(directory):
        global _logger
        _logger = create_stdout_log("cb-taxii", logging.DEBUG)
        files = os.listdir(directory)
        for filepath in files:
            if not filepath.endswith(".xml"):
                continue
            pieces = filepath.split('-')
            site = pieces[0]
            filepath = os.path.join(directory, filepath)
            these_reports = CbTaxiiFeedConverter._message_to_reports(filepath, site, site, site, True)
            for report in these_reports:
                iocs = report.get('iocs')
                if "dns" in iocs:
                    print "%s - %s" % (site, iocs['dns'])

                if "ipv4" in iocs:
                    print "%s - %s" % (site, iocs['ipv4'])

                if "query" in iocs:
                    print "%s - %s" % (site, iocs['query'])

                if "md5" in iocs:
                    print "%s - %s" % (site, iocs['md5'])

    def perform(self, enumerate_collections_only=False):
        """
        Loops through the sites supplied and adds each one if necessary.

        Then downloads new data and appends to existing feed file.
        """

        for site in self.sites:
            client = TaxiiClient(site.get('site'),
                                 site.get('username'),
                                 site.get('password'),
                                 site.get('use_https'),
                                 site.get('key_file'),
                                 site.get('cert_file'),
                                 site.get('ssl_verify'))

            desired_collections = site.get('collections').lower().split(',')

            if '*' in desired_collections:
                want_all = True
            else:
                want_all = False

            try:
                collections = client.enumerate_collections(_logger)
                if len(collections) == 0:
                    _logger.warn("No collections returned!")
            except UnauthorizedException, e:
                _logger.error("Site: %s, Exception: %s" % (site.get('site'), e))
                continue

            for collection in collections:
                if collection.get('collection_type').upper() != 'DATA_FEED':
                    continue

                if want_all or collection.get('collection_name').lower() in desired_collections:
                    if not enumerate_collections_only:
                        self._import_collection(client, site, collection)
                    else:
                        print "Site %s - Collection MATCHED   Name: %s - Available: %s - Description: %s" % (site.get('site'), collection.get('collection_name'), collection.get('available'), collection.get('collection_description', ''))
                else: # only print
                    if enumerate_collections_only:
                        print "Site %s - Collection (skipped) Name: %s - Available: %s - Description: %s" % (site.get('site'), collection.get('collection_name'), collection.get('available'), collection.get('collection_description', ''))

@contextmanager
def file_lock(lock_file):
    if os.path.exists(lock_file):
        pid = file(lock_file).read()
        print 'Only one instance can run at once. '\
              'Script is locked with %s (pid: %s)' % (lock_file, pid)
        sys.exit(-1)
    else:
        open(lock_file, 'w').write("%d" % os.getpid())
        try:
            yield
        finally:
            os.remove(lock_file)

def runner(configpath, export_mode, enumerate_only=False, loglevel=logging.DEBUG):
    with file_lock('/var/run/cb/cbtaxii.py.pid'):
        global _logger
        if export_mode:
            _logger = create_stdout_log("cb-taxii", loglevel)
        else:
            _logger = create_rotating_log("cb-taxii",
                                       "/var/log/cb/integrations/cbtaxii/cbtaxii.log",
                                       loglevel,
                                       1048576,
                                       10)

        try:
            if not export_mode:
                print "CbTaxii %s Running (could take a while).  Check status: /var/log/cb/integrations/cbtaxii/cbtaxii.log" % __version__
            cbt = CbTaxiiFeedConverter(configpath, export_mode)
            return cbt.perform(enumerate_only)
        except:
            _logger.error("%s" % traceback.format_exc())
            return -1

def runner_import(importdir):
    CbTaxiiFeedConverter.perform_from_files(importdir)
