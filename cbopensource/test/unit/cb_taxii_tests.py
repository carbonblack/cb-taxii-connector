#  coding: utf-8
#  VMware Carbon Black EDR Taxii Connector © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################

import datetime
import os
import unittest
from mock import patch, MagicMock

import collections
import dateutil
from stix.core import STIXPackage

from cbopensource.connectors.taxii.cybox_parse import cybox_parse_observable
from cbopensource.connectors.taxii.bridge import CbTaxiiFeedConverter

RESOURCE_PATH_PREFIX = 'cbopensource/test/resources'

Collection = collections.namedtuple('Collection', 'name available type')

ContentBlock = collections.namedtuple('Block', 'content')


def get_collection_block_data():
    with open(os.path.join(RESOURCE_PATH_PREFIX, 'cybox_hash_watchlist.xml'), "r") as myfile:
        return ContentBlock(content=myfile.read())


def convert_indicator_timestamp(timestamp):
    return int((timestamp - datetime.datetime(1970, 1, 1).replace(tzinfo=dateutil.tz.tzutc())).total_seconds())


def run_xml_to_reports(xml_file_name):
    reports = []
    stix_package = STIXPackage.from_xml(
        os.path.join(RESOURCE_PATH_PREFIX, xml_file_name))
    if stix_package.indicators:
        for indicator in stix_package.indicators:
            reports.extend(cybox_parse_observable(
                indicator.observable, indicator, convert_indicator_timestamp(indicator.timestamp), 25))

    if stix_package.observables:
        for observable in stix_package.observables:
            reports.extend(cybox_parse_observable(observable, None, convert_indicator_timestamp(stix_package.timestamp), 25))
    return reports



def get_site():
    site = {"site": "site",
            "output_path": ".",
            "username": "username",
            "password": "password",
            "collections": "*",
            "icon_link": "icon_link",
            "feeds_enable": True,
            "start_date": "2016-12-01 00:00:00",
            "use_https": True,
            "key_file": None,
            "cert_file": None,
            "minutes_to_advance": 60,
            "ssl_verify": True,
            "ca_cert": None,
            "discovery_path": '/services/discovery',
            "collection_management_path": '',
            "poll_path": '',
            "default_score": 25,
            "reports_limit": 10}
    return site


class TestStringMethods(unittest.TestCase):

    def test_simple_ip_indicator(self):
        reports = run_xml_to_reports('simple_ip_watchlist.xml')
        assert len(reports[0]['iocs']['ipv4']) == 3

    def test_simple_ipv6_indicator(self):
        reports = run_xml_to_reports('simple_ipv6_watchlist.xml')
        assert len(reports[0]['iocs']['ipv6']) == 3
        assert len(reports[1]['iocs']['ipv6']) == 1

    def test_hash_watchlist_indicator(self):
        reports = run_xml_to_reports('cybox_hash_watchlist.xml')
        assert len(reports) == 5

    def test_dns_watchlist_indicator(self):
        reports = run_xml_to_reports('simple_dns_watchlist.xml')
        assert len(reports) == 2
        assert len(reports[0]['iocs']['dns']) == 3
        assert len(reports[1]['iocs']['dns']) == 1

    def test_hat_dns_example(self):
        reports = run_xml_to_reports('hat_dns_example.xml')
        assert len(reports) == 1
        assert len(reports[0]['iocs']['dns']) == 1

    def test_simple_ipv4_indicator(self):
        reports = run_xml_to_reports('simple_ipv4.xml')
        assert len(reports) == 1
        assert len(reports[0]['iocs']['ipv4']) == 1

    @patch("cbopensource.connectors.taxii.bridge.parse_config")
    @patch("cbopensource.connectors.taxii.bridge.CbResponseAPI")
    @patch("cbopensource.connectors.taxii.bridge.create_client")
    @patch("cbopensource.connectors.taxii.bridge.logger.debug")
    def test_connector_simple(self, debug_logger_mock, cabby_client_mock, cbr_api_mock, parse_config_mock):
        debug_logger_mock = MagicMock()
        cbapi_object_mock = MagicMock()
        cbapi_object_mock.info.return_value = True
        cbr_api_mock.return_value = cbapi_object_mock

        parse_config_mock.return_value = {'server_url': "cbresponseserver",
                                          'api_token': "apitoken",
                                          'sites': [get_site()],
                                          'http_proxy_url': None,
                                          'https_proxy_url': None}
        cabby_client_mock.return_value.get_collections.return_value = [
            Collection(name='somecollection', available=True, type='DATA_FEED')]
        cabby_client_mock.return_value.poll.side_effect = [[
            get_collection_block_data()], []]
        cbt = CbTaxiiFeedConverter("taxii.conf", True, ".", None)
        cbt.perform()


if __name__ == '__main__':
    unittest.main()
