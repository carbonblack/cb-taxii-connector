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

from taxii_client import TaxiiClient, stix_element_to_reports, fast_xml_iter, UnauthorizedException
from cb_feed_util import FeedHelper, build_feed_data, lookup_admin_api_token
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
        server_port = 443
        if config.has_section("cbconfig"):
            if config.has_option("cbconfig", "server_port"):
                server_port = config.getint("cbconfig", "server_port")

        for section in config.sections():
            # don't do cbconfig
            if section.lower() == 'cbconfig':
                continue

            site = config.get(section, "site")
            output_path = config.get(section, "output_path")
            icon_link = config.get(section, "icon_link")
            username = config.get(section, "username")
            password = config.get(section, "password")
            feeds_enable = config.getboolean(section, "feeds_enable")
            feeds_alerting = config.get(section, "feeds_alerting")

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

            _logger.info("Configured Site: %s Path: %s" % (site, output_path))

            self.sites.append({"site": site,
                               "output_path": output_path,
                               "username": username,
                               "password": password,
                               "icon_link": icon_link,
                               "feeds_enable": feeds_enable,
                               "feeds_alerting": feeds_alerting,
                               "enable_ip_ranges": enable_ip_ranges,
                               "start_date": start_date,
                               "use_https": use_https,
                               "key_file": key_file,
                               "cert_file": cert_file,
                               "minutes_to_advance": minutes_to_advance})

        self.api_token = lookup_admin_api_token()
        server_url = "https://127.0.0.1:%d/" % server_port
        _logger.info("Using Server URL: %s" % server_url)
        self.cb = CbApi(server_url, token=self.api_token, ssl_verify=False)
        try:
            # TEST CB CONNECTIVITY
            self.cb.feed_enum()
        except:
            e = traceback.format_exc()
            _logger.error("Unable to connect to CB using url: %s Error: %s" % (server_url, e))
            print("Unable to connect to CB using url: %s Error: %s" % (server_url, e))
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
        # CATCHUP -- TODO, move to a function??
        while True:
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
                except:
                    _logger.error("%s" % traceback.format_exc())
                    time.sleep(5)
                    tries += 1

            if tries == 5:
                _logger.error("Giving up for site %s, collection %s" % (site.get('site'), collection))
                return

            if not self.export_mode:
                reports.extend(these_reports)

            if not feed_helper.advance():
                break
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
                    url = "https://127.0.0.1/api/v1/feed/%d/action" % feed_id
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

                if "hash" in iocs:
                    print "%s - %s" % (site, iocs['hash'])

    def perform(self):
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
                                 site.get('cert_file'))
            try:
                collections = client.enumerate_collections(_logger)
                if len(collections) == 0:
                    _logger.warn("No collections returned!")
            except UnauthorizedException, e:
                _logger.error("Site: %s, Exception: %s" % (site.get('site'), e))
                continue

            for collection in collections:
                self._import_collection(client, site, collection)
