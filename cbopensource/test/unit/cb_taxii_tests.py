#  coding: utf-8
#  VMware Carbon Black EDR Taxii Connector © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################

import collections
import configparser
import datetime
import logging
import os
import unittest

import dateutil
import simplejson as json
from mock import MagicMock, patch
from stix.core import STIXPackage

from cbopensource.connectors.taxii.bridge import CbTaxiiFeedConverter, dt_to_seconds
from cbopensource.connectors.taxii.config_util import parse_config, TaxiiConfigurationException
from cbopensource.connectors.taxii.cybox_parse import cybox_parse_observable, validate_domain_name, \
    validate_ip_address, validate_md5sum, validate_sha256

HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RESOURCE_PATH_PREFIX = os.path.join(HOME, 'cbopensource/test/resources')

Collection = collections.namedtuple('Collection', 'name available type')

ContentBlock = collections.namedtuple('Block', 'content')


def get_collection_block_data():
    with open(os.path.join(RESOURCE_PATH_PREFIX, 'cybox_hash_watchlist.xml'), "r") as myfile:
        return ContentBlock(content=myfile.read())


def convert_indicator_timestamp(timestamp: datetime) -> int:
    """
    Convert supplied datetime to epoch seconds based on UTC time.

    :param timestamp: supplied datetime
    :return: epoch seconds (UTC)
    """
    # noinspection PyUnresolvedReferences
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
            reports.extend(
                cybox_parse_observable(observable, None, convert_indicator_timestamp(stix_package.timestamp), 25))
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
            "reports_limit": 10
            }
    return site


class TestStringMethods(unittest.TestCase):

    # ----- Internal Functionality Tests ----------------------------------------- #

    def test_01a_validate_domain_name(self):
        """
        Verify that an valid domain name is accepted.
        """
        test = "foo.bar.com"
        assert validate_domain_name(test)

    def test_01b_validate_domain_name_international_punycode(self):
        """
        Verify that international domains mapped with punycode are accepted.  In this case, københavn.eu is mapped to
        xn--kbenhavn-54a.eu.
        """
        test = "xn--kbenhavn-54a.eu"
        assert validate_domain_name(test), "punycode domain name denied"

    def test_01c_validate_domain_name_octet_at_63_char(self):
        """
        Verify that domain names containing an octet at the limit of 64 characters are accepted.
        """
        test = "test.empty.aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffffxxx.com"
        assert validate_domain_name(test), "Domain name with octet over 63 characters denied"

    def test_01d_validate_domain_name_253_char(self):
        """
        Verify that domain names at the RFC 1035 limit of 253 are accepted.
        """
        test = "xxxxxxxxx." * 25 + "com"
        assert len(test) == 253
        assert validate_domain_name(test), "Domain name at 253 characters denied"

    def test_02a_invalid_domain_name_one_octet(self):
        """
        Verify that domain names of a single octet words are not accepted.
        """
        test = "foobar"
        assert not validate_domain_name(test), "Simple word accepted as domain"

    def test_02b_invalid_domain_name_too_long(self):
        """
        Verify that domain names over the RFC 1035 limit of 253 are not accepted.
        """
        test = "testing." * 32 + "com"
        assert not validate_domain_name(test), "Domain name over 253 characters accepted"

    def test_02c_invalid_domain_name_empty_octet(self):
        """
        Verify that domain names containing an empty octet are not accepted.
        """
        test = "test.empty..com"
        assert not validate_domain_name(test), "Domain name with empty octet accepted"

    def test_02d_invalid_domain_name_octet_over_63_char(self):
        """
        Verify that domain names containing an octet over 63 characters are not accepted.
        """
        test = "test.empty.aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffffxxxx.com"
        assert not validate_domain_name(test), "Domain name with octet over 63 characters accepted"

    def test_03a_validate_md5_upper(self):
        """
        Verify that an valid md5 is accepted with upper case A-F.
        """
        test = "00112233445566778899AABBCCDDEEFF"
        assert validate_md5sum(test)

    def test_03b_validate_md5_lower(self):
        """
        Verify that an valid md5 is accepted with lower case a-f.
        """
        test = "00112233445566778899aabbccddeeff"
        assert validate_md5sum(test)

    def test_04a_invalid_md5_short(self):
        """
        Verify that an md5 that is too short is not accepted.
        """
        test = "00112233445566778899AABBCCDDEEF"  # short 1 char
        assert not validate_md5sum(test), "Short md5 accepted!"

    def test_04b_invalid_md5_long(self):
        """
        Verify that an md5 that is too long is not accepted.
        """
        test = "00112233445566778899AABBCCDDEEFF0"  # long 1 char
        assert not validate_md5sum(test), "Long md5 accepted!"

    def test_04c_invalid_md5_bad_characters(self):
        """
        Verify that an md5 that contains non-alphanumerics is not accepted.
        """
        check = ["-", ".", "+"]
        allowed = []
        for item in check:
            test = f"001122334455667{item}8899AABBCCDDEEFF"
            if validate_md5sum(test):
                allowed.append(item)
        assert len(allowed) == 0, f"Invalid md5 characters accepted: {allowed}"

    def test_04d_invalid_md5_invalid_alphabetic(self):
        """
        Verify that an md5 that contains other than 0-F is rejected.
        """
        test = "00112233445566778899AABBCCDDggXX"
        assert not validate_md5sum(test), "md5 with invalid alphabetics accepted!"

    def test_05a_validate_sha256_upper(self):
        """
        Verify that an valid sha256 is accepted with upper case A-F.
        """
        test = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
        assert validate_sha256(test)

    def test_05b_validate_sha256_lower(self):
        """
        Verify that an valid sha256 is accepted with lower case a-f.
        """
        test = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        assert validate_sha256(test)

    def test_06a_invalid_sha256_short(self):
        """
        Verify that an sha256 that is too short is not accepted.
        """
        test = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEF"  # short 1 char
        assert not validate_sha256(test), "Short sha256 accepted!"

    def test_06b_invalid_sha256_long(self):
        """
        Verify that an sha256 that is too long is not accepted.
        """
        test = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF0"  # long 1 char
        assert not validate_sha256(test), "Long sha256 accepted!"

    def test_06c_invalid_sha256_bad_characters(self):
        """
        Verify that an sha256 that contains non-alphanumerics is not accepted.
        """
        check = ["-", ".", "+"]
        allowed = []
        for item in check:
            test = f"001122334455667{item}8899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
            if validate_sha256(test):
                allowed.append(item)
        assert len(allowed) == 0, f"Invalid sha256 characters accepted: {allowed}"

    def test_06d_invalid_sha256_invalid_alphabetic(self):
        """
        Verify that an sha256 that contains other than 0-F is rejected.
        """
        test = "00112233445566778899AABBCCDDggXX00112233445566778899AABBCCDDEEFF"
        assert not validate_sha256(test), "sha256 with invalid alphabetics accepted!"

    def test_07a_validate_ipv4(self):
        """
        Verify that an valid ipv4 is accepted.
        """
        test = "11.22.33.44"
        assert validate_ip_address(test)

    def test_08a_invalid_ipv4_short(self):
        """
        Verify that an ipv4 that is short an entry is rejected.
        """
        test = "11.22.33"
        assert not validate_ip_address(test), "short ipv4 accepted"

    def test_08b_invalid_ipv4_long(self):
        """
        Verify that an ipv4 that is long an entry is rejected.
        """
        test = "11.22.33.44.55"
        assert not validate_ip_address(test), "long ipv4 accepted"

    def test_08c_invalid_ipv4_high_number(self):
        """
        Verify that an ipv4 that contains an entry over 255 is rejected.
        """
        test = "11.22.333.44"
        assert not validate_ip_address(test), "ipv4 with excessive entry accepted"

    def test_08d_invalid_ipv4_low_entry(self):
        """
        Verify that an ipv4 that contains a negative entry is rejected.
        """
        test = "11.22.-33.44"
        assert not validate_ip_address(test), "ipv4 with negative entry accepted"

    def test_08e_invalid_ipv4_empty_entry(self):
        """
        Verify that an ipv4 that contains an empty entry is rejected.
        """
        test = "11.22..44"
        assert not validate_ip_address(test), "ipv4 with empty entry accepted"

    def test_08f_invalid_ipv4_bogus(self):
        """
        Verify that an ipv4 that contains an empty entry is rejected.
        """
        test = "aa.bb.cc.dd"
        assert not validate_ip_address(test), "bogus ipv4 accepted"

    def test_09a_validate_ipv6(self):
        """
        Verify that an valid ipv6 is accepted.
        """
        test = "0000:1111:2222:3333:4444:5555:6666:7777"
        assert validate_ip_address(test)

    def test_09b_validate_ipv6_compressed(self):
        """
        Verify that an valid compressed ipv6 is accepted.
        """
        test = "0:1:22:333:444:55:6:7"  # same as 0000:0001:0022:0333:0444:0055:0006:0007
        assert validate_ip_address(test)

    def test_09c_validate_ipv6_very_compressed(self):
        """
        Verify that an ipv6 that is 0 compressed is rejected.
        """
        test = "1111::8888"  # same as 1111:0000:0000:0000:0000:0000:0000:8888
        assert validate_ip_address(test)

    def test_10a_invalid_ipv6_short(self):
        """
        Verify that an ipv6 that is short an entry is rejected.
        """
        test = "0000:1111:2222:3333:4444:5555:6666"
        assert not validate_ip_address(test), "short ipv6 accepted"

    def test_10b_invalid_ipv6_long(self):
        """
        Verify that an ipv6 that is long an entry is rejected.
        """
        test = "0000:1111:2222:3333:4444:5555:6666:7777:8888"
        assert not validate_ip_address(test), "long ipv6 accepted"

    def test_10c_invalid_ipv6_high_number(self):
        """
        Verify that an ipv6 that is long an entry is rejected.
        """
        test = "10000:1111:2222:3333:4444:5555:6666:7777"  # first entry over FFFF
        assert not validate_ip_address(test), "high entry ipv6 accepted"

    def test_10d_invalid_ipv6_bogus_entry(self):
        """
        Verify that an ipv6 that contains a non-hex entry is rejected.
        """
        test = "0000:1111:2222:3333:good:5555:6666:7777"
        assert not validate_ip_address(test), "bogus entry ipv6 accepted"

    def test_11a_datetime_convert(self):
        """
        Verify that bridge.py's time convert is correct.
        """
        test = datetime.datetime.strptime("1999-09-13 12:00:00", "%Y-%m-%d %H:%M:%S")
        conv = dt_to_seconds(test)
        assert conv == 937238400

    def test_11b_datetime_convert_none(self):
        """
        Verify that bridge.py's time convert returns 0 for non-datetime
        """
        # noinspection PyTypeChecker
        conv = dt_to_seconds(None)
        assert conv == 0

    # ----- Report Handling Tests ------------------------------------------------ #

    def test_20_simple_ip_indicator(self):
        """
        Verify that we can digest feeds that contain multiple ip entries.
        """
        reports = run_xml_to_reports('simple_ip_watchlist.xml')
        assert len(reports[0]['iocs']['ipv4']) == 3

    def test_21_simple_ipv4_indicator(self):
        """
        Verify that we can digest ipv4 feeds.
        """
        reports = run_xml_to_reports('simple_ipv4.xml')
        assert len(reports) == 1
        assert len(reports[0]['iocs']['ipv4']) == 1

    def test_22_simple_ipv6_indicator(self):
        """
        Verify that we can digest ipv6 feeds.
        """
        reports = run_xml_to_reports('simple_ipv6_watchlist.xml')
        assert len(reports[0]['iocs']['ipv6']) == 3
        assert len(reports[1]['iocs']['ipv6']) == 1

    def test_23_hash_watchlist_indicator(self):
        """
        Verify that we can digest md5 and sha256 feeds.
        """
        reports = run_xml_to_reports('cybox_hash_watchlist.xml')
        assert len(reports) == 5
        assert "md5" in reports[0]['iocs']
        assert "md5" in reports[1]['iocs']
        assert "md5" in reports[2]['iocs']
        assert "md5" in reports[3]['iocs']
        assert "sha256" in reports[4]['iocs']

    def test_24_dns_watchlist_indicator(self):
        """
        Verify that we can digest domain feeds.
        """
        reports = run_xml_to_reports('simple_dns_watchlist.xml')
        assert len(reports) == 2
        assert len(reports[0]['iocs']['dns']) == 3
        assert len(reports[1]['iocs']['dns']) == 1

    def test_24_hat_dns_example(self):
        """
        Verify that we can digest domain feeds in hail-a-taxii format
        """
        reports = run_xml_to_reports('hat_dns_example.xml')
        assert len(reports) == 1
        assert len(reports[0]['iocs']['dns']) == 1

    # ----- Configuration Tests -------------------------------------------------- #

    _config = "./my_config"

    def _config_cleanup(self):
        if os.path.exists(self._config):
            os.remove(self._config)

    def _make_config(self, **kwargs):
        """
        Create a config for use in testing

        :param kwargs: entries to add, remove for testing
        """
        cp = configparser.ConfigParser()

        # add header defaults
        data = {
            'server_url': "https://123.45.6.78",
            'auth_token': "deadbeef97dabe459da5772969a82b61f47d1913",
        }
        cp['cbconfig'] = data

        # add sites
        cbconfig = cp['cbconfig']

        # save config file
        with open(self._config, 'w') as fp:
            cp.write(fp)

    def test_30a_invalid_no_config(self):
        """
        Verify that missing config files are detected..
        """
        try:
            # noinspection PyTypeChecker
            parse_config(None)
            self.fail("Did not detect missing config file")
        except TaxiiConfigurationException as tce:
            assert 'Config File: must be specified' in tce.args[0]

    def test_30b_invalid_config_not_exist(self):
        """
        Verify that missing config files are detected..
        """
        try:
            # noinspection PyTypeChecker
            parse_config("./no-such-config-file")
            self.fail("Did not detect non-existant config file")
        except TaxiiConfigurationException as tce:
            assert 'Config File: ./no-such-config-file does not exis' in tce.args[0]

    # ----- Connectivity Tests --------------------------------------------------- #

    @staticmethod
    def _collection_cleanup():
        if os.path.exists("./sitesomecollections"):
            os.remove("./sitesomecollections")
        if os.path.exists("./sitesomecollections.details"):
            os.remove("./sitesomecollections.details")

    # noinspection PyUnusedLocal,DuplicatedCode
    @patch("cbopensource.connectors.taxii.bridge.parse_config")
    @patch("cbopensource.connectors.taxii.bridge.CbResponseAPI")
    @patch("cbopensource.connectors.taxii.bridge.create_client")
    @patch("cbopensource.connectors.taxii.bridge._logger.debug")
    def test_40_connector_simple(self, debug_logger_mock, cabby_client_mock, cbr_api_mock, parse_config_mock):
        """
        Make a mock connection attempt.
        """
        self._collection_cleanup()

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

        try:
            cbt.perform()

            # check for feeds
            assert os.path.exists("./sitesomecollections")
            with open("./sitesomecollections", 'r') as file_handle:
                data = json.loads(file_handle.read())

            assert data['feedinfo']['name'] == "sitesomecollections"
            assert len(data['reports']) == 5
            assert data['reports'][4]['iocs']['sha256'][
                       0] == 'ecebd25a39aaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        finally:
            self._collection_cleanup()

    # noinspection PyUnusedLocal,DuplicatedCode
    @patch("cbopensource.connectors.taxii.bridge.parse_config")
    @patch("cbopensource.connectors.taxii.bridge.CbResponseAPI")
    @patch("cbopensource.connectors.taxii.bridge.create_client")
    @patch("cbopensource.connectors.taxii.bridge._logger.debug")
    def test_41_invalid_connector_simple_no_input(self, debug_logger_mock, cabby_client_mock, cbr_api_mock,
                                                  parse_config_mock):
        """
        Attempt a connection attempt with no input directory; simulates invokation with no `-i` specified
        (should have no effect since at this time import is unused)
        """
        self._collection_cleanup()

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
        # noinspection PyTypeChecker
        cbt = CbTaxiiFeedConverter("taxii.conf", True, None, None)

        try:
            cbt.perform()

            # check for feeds
            assert os.path.exists("./sitesomecollections")
            with open("./sitesomecollections", 'r') as file_handle:
                data = json.loads(file_handle.read())

            assert data['feedinfo']['name'] == "sitesomecollections"
            assert len(data['reports']) == 5
            assert data['reports'][4]['iocs']['sha256'][
                       0] == 'ecebd25a39aaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        finally:
            self._collection_cleanup()


_logger = logging.getLogger(__name__)

if __name__ == '__main__':
    _logger.setLevel(logging.DEBUG)
    unittest.main()
