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

from cbopensource.connectors.taxii import CbTaxiiFeedConverter, dt_to_seconds
from cbopensource.connectors.taxii import parse_config, TaxiiConfigurationException
from cbopensource.connectors.taxii import cybox_parse_observable, validate_domain_name, \
    validate_ip_address, validate_md5sum, validate_sha256

HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RESOURCE_PATH_PREFIX = os.path.join(HOME, 'cbopensource', 'test', 'resources')
ICON = os.path.abspath(os.path.join(HOME, 'root', 'usr', 'share', 'cb', 'integrations', 'cbtaxii', 'taxii-logov2.png'))

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
            "icon_link": ICON,
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
    _output = "./output_path"
    _cert = "./fake_cert"
    _key = "./fake_key"

    def _config_cleanup(self):
        if os.path.exists(self._config):
            os.remove(self._config)
        if os.path.exists(self._output):
            os.rmdir(self._output)
        if os.path.exists(self._cert):
            os.remove(self._cert)
        if os.path.exists(self._key):
            os.remove(self._key)

    def _make_config(self, **kwargs):
        """
        Create a config for use in testing

        :param kwargs: entries to add, remove for testing
        """
        if os.path.exists(self._output):
            os.rmdir(self._output)

        cp = configparser.ConfigParser()

        # add header defaults
        data = {
            'server_url': "https://123.45.6.78",
            'auth_token': "deadbeef97dabe459da5772969a82b61f47d1913",
        }
        cp['cbconfig'] = data

        # set up test site, fill in default data, alter with data from kwargs
        site = {
            'site': "testsite.com",
            'output_path': self._output,
            'icon_link': ICON,
            'username': 'guest',
            'password': 'guest',
            'collections': "*",
            'default_score': 42,
            'feeds_enable': 'true',
            'start_date': '2016-11-01 00:00:00',
            'minutes_to_advance': '1440',
            'discovery_path': '/taxii-discovery-service'
        }
        os.mkdir(self._output)

        # mangle with kwargs
        for key, value in kwargs.items():
            if value is None and key in site:
                del site[key]
            elif value is not None:
                site[key] = value

        cp['testsite'] = site

        # save config file
        with open(self._config, 'w') as fp:
            cp.write(fp)

        # create fake cert files
        with open(self._cert, 'w') as fp:
            fp.write("Fake cert info (for testing)")
        with open(self._key, 'w') as fp:
            fp.write("Fake key info (for testing)")

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

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
        finally:
            self._config_cleanup()

    def test_30b_invalid_config_not_exist(self):
        """
        Verify that missing config files are detected..
        """
        try:
            parse_config("./no-such-config-file")
            self.fail("Did not detect non-existant config file")
        except TaxiiConfigurationException as tce:
            assert 'Config File: ./no-such-config-file does not exist' in tce.args[0]
        finally:
            self._config_cleanup()

    def test_31a_invalid_site_missing(self):
        """
        Verify that site section with missing site is detected.
        """
        self._make_config(site=None)

        try:
            parse_config(self._config)
            self.fail("Did not detect missing site")
        except TaxiiConfigurationException as tce:
            assert "Config File: section `testsite` has no `site` entry (required)" in tce.args[0]
        finally:
            self._config_cleanup()

    def test_31b_invalid_site_empty(self):
        """
        Verify that site section with empty site is detected.
        """
        self._make_config(site="")

        try:
            parse_config(self._config)
            self.fail("Did not detect emptry site")
        except TaxiiConfigurationException as tce:
            assert "Config File: `site` must be defined for section `testsite`" in tce.args[0]
        finally:
            self._config_cleanup()

    # NOTE: No way to test for "invalid sites"

    def test_31c_site_https_normalize(self):
        """
        Verify that site section with https:// is cleaned up.
        """
        self._make_config(site="https://testsite.com")

        check = parse_config(self._config)
        assert check['sites'][0]['site'] == "testsite.com"

    def test_31d_site_http_normalize(self):
        """
        Verify that site section with http:// is cleaned up.
        """
        self._make_config(site="http://testsite.com")

        check = parse_config(self._config)
        assert check['sites'][0]['site'] == "testsite.com"

    def test_31e_site_trailing_slash_normalize(self):
        """
        Verify that site section with trailing / is cleaned up.
        """
        self._make_config(site="http://testsite.com/")

        check = parse_config(self._config)
        assert check['sites'][0]['site'] == "testsite.com"

    def test_32a_invalid_output_path_missing(self):
        """
        Verify that site section with missing site is detected.
        """
        self._make_config(output_path=None)

        try:
            parse_config(self._config)
            self.fail("Did not detect missing output_path")
        except TaxiiConfigurationException as tce:
            assert "Config File: section `testsite` has no `output_path` entry (required)" in tce.args[0]
        finally:
            self._config_cleanup()

    def test_32b_invalid_output_path_empty(self):
        """
        Verify that site section with empty output_path is detected.
        """
        self._make_config(output_path="")

        try:
            parse_config(self._config)
            self.fail("Did not detect empty output_path")
        except TaxiiConfigurationException as tce:
            assert "Config File: `output_path` must be defined for section `testsite`" in tce.args[0]
        finally:
            self._config_cleanup()

    def test_32c_output_path_not_exists(self):
        """
        Verify that site section with output path defined but not present will have the path created
        """
        td = os.path.abspath("./nonesuch")
        if os.path.exists(td):
            os.rmdir(td)

        self._make_config(output_path=td)
        try:
            parse_config(self._config)
            assert os.path.exists(td)
        finally:
            self._config_cleanup()
            if os.path.exists(td):
                os.rmdir(td)

    def test_32d_invalid_output_path_not_exists_strict(self):
        """
        Verify that site section with output path defined but not present, in strict mode this will stop progress.
        """
        td = os.path.abspath("./nonesuch")
        if os.path.exists(td):
            os.rmdir(td)

        self._make_config(output_path=td)
        try:
            parse_config(self._config, strict_mode=True)
            self.fail("Did not detect non-existant output_file")
        except TaxiiConfigurationException as tce:
            assert "Config File: `output_path` for section `testsite` must already exist" in tce.args[0]
        finally:
            self._config_cleanup()
            if os.path.exists(td):
                os.rmdir(td)

    def test_33a_icon_link_missing(self):
        """
        Verify that missing icon link is safely allowed with a default value of ""
        """
        self._make_config(icon_link=None)

        check = parse_config(self._config)
        assert check['sites'][0]['icon_link'] == ""

    def test_33b_invalid_icon_link_no_such_path(self):
        """
        Verify that site section with icon_link defined but not present will be detected.
        """
        self._make_config(icon_link="./no_such_icon.png")
        try:
            parse_config(self._config)
            self.fail("Did not detect non-existant icon_link")
        except TaxiiConfigurationException as tce:
            assert "Config File: `icon_link` for section `testsite` must exist" in tce.args[0]
        finally:
            self._config_cleanup()

    # NOTE: no way to tell if the file content is valid icon data

    def test_34a_feed_enabled_missing(self):
        """
        Verify that site section with feed_enabled missing will be converted to False (a warning will also be produced).
        """
        self._make_config(feeds_enable=None)

        try:
            check = parse_config(self._config)
            assert not check['sites'][0]['feeds_enable']
        finally:
            self._config_cleanup()

    def test_34b_invalid_feed_enabled_bogus(self):
        """
        Verify that site section with feed_enabled not a boolean will be detected.
        """
        self._make_config(feeds_enable="booga")

        try:
            parse_config(self._config)
            self.fail("Did not detect bogus feeds_enable")
        except TaxiiConfigurationException as tce:
            assert "Config File: `feeds_enable` for section `testsite` must be true or false" in tce.args[0]
        finally:
            self._config_cleanup()

    def test_35_collections_missing(self):
        """
        Verify that site section with collections is missing will be converted to "*".
        """
        self._make_config(collections=None)

        try:
            check = parse_config(self._config)
            assert check['sites'][0]['collections'] == "*"
        finally:
            self._config_cleanup()

    def test_36a_default_score_missing(self):
        """
        Verify that site section with default score is missing will be converted to 50.
        """
        self._make_config(default_score=None)

        try:
            check = parse_config(self._config)
            assert check['sites'][0]['default_score'] == 50
        finally:
            self._config_cleanup()

    def test_36b_invalid_default_score_bogus(self):
        """
        Verify that site section with default score not an int is properly trapped.
        """
        self._make_config(default_score="foobar")

        try:
            parse_config(self._config)
            self.fail("Did not detect bogus default_score")
        except TaxiiConfigurationException as tce:
            assert "Config File: `default_score` for section `testsite` must be an integer" in tce.args[0]
        finally:
            self._config_cleanup()

    def test_36c_default_score_excessive(self):
        """
        Verify that site section with default score outside of 1-100 is allowed, if not strict mode.
        """
        self._make_config(default_score="150")

        try:
            check = parse_config(self._config)
            assert check['sites'][0]['default_score'] == 150
        finally:
            self._config_cleanup()

    def test_36d_invalid_default_score_too_low(self):
        """
        Verify that site section with default score must be at least 1, when strict enabled.
        """
        self._make_config(default_score="0")  # strict mode requires output path existance

        try:
            parse_config(self._config, strict_mode=True)
            self.fail("Did not detect bogus feeds_enable")
        except TaxiiConfigurationException as tce:
            assert "Config File: `default_score` for section `testsite` must be between 1 and 100 (inclusive)" in \
                   tce.args[0]
        finally:
            self._config_cleanup()

    def test_36e_invalid_default_score_too_high(self):
        """
        Verify that site section with default score must be at most 100, when strict enabled.
        """
        self._make_config(default_score="101")  # strict mode requires output path existance

        try:
            parse_config(self._config, strict_mode=True)
            self.fail("Did not detect bogus feeds_enable")
        except TaxiiConfigurationException as tce:
            assert "Config File: `default_score` for section `testsite` must be between 1 and 100 (inclusive)" in \
                   tce.args[0]
        finally:
            self._config_cleanup()

    def test_37a_reset_start_date_missing(self):
        """
        Verify that site section with reset_start_date missing will be converted to False
        (a warning will also be produced).
        """
        self._make_config(reset_start_date=None)

        try:
            check = parse_config(self._config)
            assert not check['sites'][0]['reset_start_date']
        finally:
            self._config_cleanup()

    def test_37b_invalid_reset_start_date_bogus(self):
        """
        Verify that site section with reset_start_date not a boolean will be detected.
        """
        self._make_config(reset_start_date="booga")

        try:
            parse_config(self._config)
            self.fail("Did not detect bogus reset_start_date")
        except TaxiiConfigurationException as tce:
            assert "Config File: `reset_start_date` for section `testsite` must be true or false" in tce.args[0]
        finally:
            self._config_cleanup()

    def test_38a_start_date_missing(self):
        """
        Verify that site section with start_date is missing will be converted to a
        baseline date ("2016-12-01 00:00:00").
        """
        self._make_config(start_date=None)

        try:
            check = parse_config(self._config)
            assert check['sites'][0]['start_date'] == "2016-12-01 00:00:00"
        finally:
            self._config_cleanup()

    def test_38b_invalid_start_date_bogus(self):
        """
        Verify that site section with start_date not in the proper format will be detected.
        """
        self._make_config(start_date="2016-12-01")

        try:
            parse_config(self._config)
            self.fail("Did not detect bogus reset_start_date")
        except TaxiiConfigurationException as tce:
            assert "Config File: `start_date` for section `testsite` must be in the format `%Y-%m-%d %H:%M:%S`" in \
                   tce.args[0]
        finally:
            self._config_cleanup()

    def test_39a_use_https_missing(self):
        """
        Verify that site section with use_https missing will be default to False.
        """
        self._make_config(use_https=None)

        try:
            check = parse_config(self._config)
            assert not check['sites'][0]['use_https']
        finally:
            self._config_cleanup()

    def test_39b_invalid_use_https_bogus(self):
        """
        Verify that site section with use_https not a boolean will be detected.
        """
        self._make_config(use_https="booga")

        try:
            parse_config(self._config)
            self.fail("Did not detect bogus use_https")
        except TaxiiConfigurationException as tce:
            assert "Config File: `use_https` for section `testsite` must be true or false" in tce.args[0]
        finally:
            self._config_cleanup()

    def test_40a_invalid_cert_and_no_key(self):
        """
        Verify that site section with cert_file specified but no key_file specified is detected.
        """
        self._make_config(cert_file=self._cert)

        try:
            parse_config(self._config)
            self.fail("Did not detect missing key_file")
        except TaxiiConfigurationException as tce:
            assert "Config File: both `cert_file` and `key_file` for section `testsite` must be specified" in tce.args[
                0]
        finally:
            self._config_cleanup()

    def test_40b_invalid_key_and_no_cert(self):
        """
        Verify that site section with key_file specified but no cert_file specified is detected.
        """
        self._make_config(key_file=self._key)

        try:
            parse_config(self._config)
            self.fail("Did not detect missing cert_file")
        except TaxiiConfigurationException as tce:
            assert "Config File: both `cert_file` and `key_file` for section `testsite` must be specified" in tce.args[
                0]
        finally:
            self._config_cleanup()

    def test_40c_cert_and_key_undefined(self):
        """
        Verify that site section with cert_file and key_file stated but undefined converts to None
        """
        self._make_config(cert_file="", key_file="")

        try:
            check = parse_config(self._config)
            assert check['sites'][0]['cert_file'] is None
            assert check['sites'][0]['key_file'] is None
        finally:
            self._config_cleanup()

    # NOTE: can't validate bad cert or key file data

    def test_41a_minutes_to_advance_missing(self):
        """
        Verify that site section with minutes_to_advance is missing will have a default of 60 minutes.
        """
        self._make_config(minutes_to_advance=None)

        try:
            check = parse_config(self._config)
            assert check['sites'][0]['minutes_to_advance'] == 60
        finally:
            self._config_cleanup()

    def test_41b_invalid_minutes_to_advance_bogus(self):
        """
        Verify that site section with minutes_to_advance not in the proper format will be detected.
        """
        self._make_config(minutes_to_advance="bogus")

        try:
            parse_config(self._config)
            self.fail("Did not detect bogus minutes_to_advance")
        except TaxiiConfigurationException as tce:
            assert "Config File: `minutes_to_advance` for section `testsite` must be an integer" in tce.args[0]
        finally:
            self._config_cleanup()

    def test_41c_invalid_minutes_to_advance_too_low(self):
        """
        Verify that site section with minutes_to_advance less than 1.
        """
        self._make_config(minutes_to_advance="0")

        try:
            parse_config(self._config)
            self.fail("Did not detect minutes_to_advance too low")
        except TaxiiConfigurationException as tce:
            assert "Config File: `minutes_to_advance` for section `testsite` must be at least 1" in tce.args[0]
        finally:
            self._config_cleanup()

    def test_42a_ssl_verify_missing(self):
        """
        Verify that site section with ssl_verify is missing will have a default of true.
        """
        self._make_config(ssl_verify=None)

        try:
            check = parse_config(self._config)
            assert check['sites'][0]['ssl_verify']
        finally:
            self._config_cleanup()

    def test_42b_invalid_ssl_verify_bogus(self):
        """
        Verify that site section with bogus ssl_verify  will be detected.
        """
        self._make_config(ssl_verify="bogus")

        try:
            parse_config(self._config)
            self.fail("Did not detect bogus ssl_verify")
        except TaxiiConfigurationException as tce:
            assert "Config File: `ssl_verify` for section `testsite` must be true or false" in tce.args[0]
        finally:
            self._config_cleanup()

    def test_43_discovery_path_missing(self):
        """
        Verify that site section with discovery_path is missing will have a proper default.
        """
        self._make_config(discovery_path=None)

        try:
            check = parse_config(self._config)
            assert check['sites'][0]['discovery_path'] == "/services/discovery"
        finally:
            self._config_cleanup()

    def test_44_collection_management_path_missing(self):
        """
        Verify that site section with collection_management_path is missing will have a proper default.
        """
        self._make_config(collection_management_path=None)

        try:
            check = parse_config(self._config)
            assert check['sites'][0]['collection_management_path'] == ""
        finally:
            self._config_cleanup()

    def test_45_poll_path_missing(self):
        """
        Verify that site section with poll_path is missing will have a proper default.
        """
        self._make_config(poll_path=None)

        try:
            check = parse_config(self._config)
            assert check['sites'][0]['poll_path'] == ""
        finally:
            self._config_cleanup()

    def test_46_ca_cert_missing(self):
        """
        Verify that site section with ca_cert is missing will have a proper default.
        """
        self._make_config(ca_cert=None)

        try:
            check = parse_config(self._config)
            assert check['sites'][0]['ca_cert'] is None
        finally:
            self._config_cleanup()

    def test_47a_reports_limit_missing(self):
        """
        Verify that site section with reports_limit is missing will have a default value.
        """
        self._make_config(reports_limit=None)

        try:
            check = parse_config(self._config)
            assert check['sites'][0]['reports_limit'] == 10000
        finally:
            self._config_cleanup()

    def test_47b_invalid_reports_limit_bogus(self):
        """
        Verify that site section with minutes_to_advance not in the proper format will be detected.
        """
        self._make_config(reports_limit="bogus")

        try:
            parse_config(self._config)
            self.fail("Did not detect bogus reports_limit")
        except TaxiiConfigurationException as tce:
            assert "Config File: `reports_limit` for section `testsite` must be an integer" in tce.args[0]
        finally:
            self._config_cleanup()

    def test_47c_invalid_reports_limit_too_low(self):
        """
        Verify that site section with reports_limit less than 1.
        """
        self._make_config(reports_limit="0")

        try:
            parse_config(self._config)
            self.fail("Did not detect reports_limit too low")
        except TaxiiConfigurationException as tce:
            assert "Config File: `reports_limit` for section `testsite` must be at least 1" in tce.args[0]
        finally:
            self._config_cleanup()

    # ----- Connectivity Tests --------------------------------------------------- #

    @staticmethod
    def _collection_cleanup():
        if os.path.exists("./sitesomecollection"):
            os.remove("./sitesomecollection")
        if os.path.exists("./sitesomecollection.details"):
            os.remove("./sitesomecollection.details")

    # noinspection PyUnusedLocal,DuplicatedCode
    @patch("cbopensource.connectors.taxii.bridge.parse_config")
    @patch("cbopensource.connectors.taxii.bridge.CbResponseAPI")
    @patch("cbopensource.connectors.taxii.bridge.create_client")
    @patch("cbopensource.connectors.taxii.bridge._logger.debug")
    def test_50_connector_simple(self, debug_logger_mock, cabby_client_mock, cbr_api_mock, parse_config_mock):
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
            assert os.path.exists("./sitesomecollection")
            with open("./sitesomecollection", 'r') as file_handle:
                data = json.loads(file_handle.read())

            assert data['feedinfo']['name'] == "sitesomecollection"
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
    def test_51_invalid_connector_simple_no_input(self, debug_logger_mock, cabby_client_mock, cbr_api_mock,
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
            assert os.path.exists("./sitesomecollection")
            with open("./sitesomecollection", 'r') as file_handle:
                data = json.loads(file_handle.read())

            assert data['feedinfo']['name'] == "sitesomecollection"
            assert len(data['reports']) == 5
            assert data['reports'][4]['iocs']['sha256'][
                       0] == 'ecebd25a39aaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        finally:
            self._collection_cleanup()


_logger = logging.getLogger(__name__)

if __name__ == '__main__':
    _logger.setLevel(logging.DEBUG)
    unittest.main()
