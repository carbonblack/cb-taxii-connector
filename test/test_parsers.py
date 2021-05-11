# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.
################################################################################

import unittest

import stix2patterns
from cbopensource.driver.taxii import STIXIndicator

from cbopensource.driver.taxii_parser import STIXPatternParser


# noinspection HttpUrlsUsage
class ParserTests(unittest.TestCase):
    def test_parser_basic(self):
        stix_object = {'created': '2014-05-08T09:00:00.000Z', 'id': 'indicator--cd981c25-8042-4166-8945-51178443bdac',
                       'indicator_types': ['file-hash-watchlist'], 'modified': '2014-05-08T09:00:00.000Z',
                       'name': 'File hash for Poison Ivy variant',
                       'pattern': "[file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c']",
                       'pattern_type': 'stix', 'spec_version': '2.1', 'type': 'indicator',
                       'valid_from': '2014-05-08T09:00:00.000000Z'}
        indicator = STIXIndicator(stix_object, "http://server:5000/taxii2/collections/collection-id-basic")
        report = indicator.report
        assert "timestamp" in report
        assert report["timestamp"] == int(STIXIndicator.strptime('2014-05-08T09:00:00.000Z').timestamp())
        assert "id" in report
        assert report["id"] == 'indicator--cd981c25-8042-4166-8945-51178443bdac'
        assert 'score' in report and report['score'] == 100
        assert 'title' in report and report['title'] == 'File hash for Poison Ivy variant'
        assert 'iocs' in report
        assert 'sha256' in report['iocs'] and 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c' in \
               report['iocs']['sha256']
        assert 'link' in report

    def test_parser_basic_error_in_pattern(self):
        stix_object = {'created': '2014-05-08T09:00:00.000Z', 'id': 'indicator--cd981c25-8042-4166-8945-51178443bdac',
                       'indicator_types': ['file-hash-watchlist'], 'modified': '2014-05-08T09:00:00.000Z',
                       'name': 'File hash for Poison Ivy variant',
                       'pattern': "afdsafdsfdafas",
                       'pattern_type': 'stix', 'spec_version': '2.1', 'type': 'indicator',
                       'valid_from': '2014-05-08T09:00:00.000000Z'}
        self.assertRaises(stix2patterns.exceptions.ParseException, STIXIndicator, stix_object,
                          "http://server:5000/taxii2/collections/collection-id-basic")

    def test_parser_basic_two_hashes(self):
        stix_object = {'created': '2014-05-08T09:00:00.000Z', 'id': 'indicator--cd981c25-8042-4166-8945-51178443bdac',
                       'indicator_types': ['file-hash-watchlist'], 'modified': '2014-05-08T09:00:00.000Z',
                       'name': 'File hash for Poison Ivy variant',
                       'pattern': "[file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c' OR file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6d']",
                       'pattern_type': 'stix', 'spec_version': '2.1', 'type': 'indicator',
                       'valid_from': '2014-05-08T09:00:00.000000Z'}
        indicator = STIXIndicator(stix_object, "http://server:5000/taxii2/collections/collection-id-basic")
        report = indicator.report
        assert "timestamp" in report
        assert report["timestamp"] == int(STIXIndicator.strptime('2014-05-08T09:00:00.000Z').timestamp())
        assert "id" in report
        assert report["id"] == 'indicator--cd981c25-8042-4166-8945-51178443bdac'
        assert 'score' in report and report['score'] == 100
        assert 'title' in report and report['title'] == 'File hash for Poison Ivy variant'
        assert 'iocs' in report
        assert 'sha256' in report['iocs']
        assert 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c' in report['iocs']['sha256']
        assert 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6d' in report['iocs']['sha256']
        assert 'link' in report

    def test_parser_basic_dns(self):
        stix_object = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
            "created": "2014-06-29T13:49:37.079Z",
            "modified": "2014-06-29T13:49:37.079Z",
            "name": "Malicious site hosting downloader",
            "description": "This organized threat actor group operates to create profit from all types of crime.",
            "indicator_types": [
                "malicious-activity"
            ],
            "pattern": "[url:value = 'http://x4z9arb.cn/4712/']",
            "pattern_type": "stix",
            "valid_from": "2014-06-29T13:49:37.079Z"
        }
        indicator = STIXIndicator(stix_object, "http://server:5000/taxii2/collections/collection-id-basic")
        report = indicator.report
        assert "timestamp" in report
        assert report["timestamp"] == int(STIXIndicator.strptime('2014-06-29T13:49:37.079Z').timestamp())
        assert "id" in report
        assert report["id"] == 'indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f'
        assert 'score' in report and report['score'] == 100
        assert 'title' in report and report['title'] == 'Malicious site hosting downloader'
        assert 'iocs' in report
        assert 'dns' in report['iocs'] and 'x4z9arb.cn' in report['iocs']['dns']
        assert 'link' in report

    def test_parser_basic_two_dns(self):
        stix_object = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
            "created": "2014-06-29T13:49:37.079Z",
            "modified": "2014-06-29T13:49:37.079Z",
            "name": "Malicious site hosting downloader",
            "description": "This organized threat actor group operates to create profit from all types of crime.",
            "indicator_types": [
                "malicious-activity"
            ],
            "pattern": "[url:value = 'http://x4z9arb.cn/4712/' OR url:value = 'http://x4z9arc.cn/4712/']",
            "pattern_type": "stix",
            "valid_from": "2014-06-29T13:49:37.079Z"
        }
        indicator = STIXIndicator(stix_object, "http://server:5000/taxii2/collections/collection-id-basic")
        report = indicator.report
        assert "timestamp" in report
        assert report["timestamp"] == int(STIXIndicator.strptime('2014-06-29T13:49:37.079Z').timestamp())
        assert "id" in report
        assert report["id"] == 'indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f'
        assert 'score' in report and report['score'] == 100
        assert 'title' in report and report['title'] == 'Malicious site hosting downloader'
        assert 'iocs' in report
        assert 'dns' in report['iocs']
        assert 'x4z9arb.cn' in report['iocs']['dns']
        assert 'x4z9arc.cn' in report['iocs']['dns']
        assert 'link' in report

    def test_parser_basic_ip(self):
        stix_object = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
            "created": "2014-06-29T13:49:37.079Z",
            "modified": "2014-06-29T13:49:37.079Z",
            "name": "Malicious site hosting downloader",
            "description": "This organized threat actor group operates to create profit from all types of crime.",
            "indicator_types": [
                "malicious-activity"
            ],
            "pattern": "[ipv4-addr:value = '198.51.100.1/32']",
            "pattern_type": "stix",
            "valid_from": "2014-06-29T13:49:37.079Z"
        }
        indicator = STIXIndicator(stix_object, "http://server:5000/taxii2/collections/collection-id-basic")
        report = indicator.report
        assert "timestamp" in report
        assert report["timestamp"] == int(STIXIndicator.strptime('2014-06-29T13:49:37.079Z').timestamp())
        assert "id" in report
        assert report["id"] == 'indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f'
        assert 'score' in report and report['score'] == 100
        assert 'title' in report and report['title'] == 'Malicious site hosting downloader'
        assert 'iocs' in report
        assert 'ipv4' in report['iocs']
        assert '198.51.100.1' in report['iocs']['ipv4']
        assert 'link' in report

    def test_parser_basic_ip_no_cidr(self):
        stix_object = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
            "created": "2014-06-29T13:49:37.079Z",
            "modified": "2014-06-29T13:49:37.079Z",
            "name": "Malicious site hosting downloader",
            "description": "This organized threat actor group operates to create profit from all types of crime.",
            "indicator_types": [
                "malicious-activity"
            ],
            "pattern": "[ipv4-addr:value = '198.51.100.1']",
            "pattern_type": "stix",
            "valid_from": "2014-06-29T13:49:37.079Z"
        }
        indicator = STIXIndicator(stix_object, "http://server:5000/taxii2/collections/collection-id-basic")
        report = indicator.report
        assert "timestamp" in report
        assert report["timestamp"] == int(STIXIndicator.strptime('2014-06-29T13:49:37.079Z').timestamp())
        assert "id" in report
        assert report["id"] == 'indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f'
        assert 'score' in report and report['score'] == 100
        assert 'title' in report and report['title'] == 'Malicious site hosting downloader'
        assert 'iocs' in report
        assert 'ipv4' in report['iocs']
        assert '198.51.100.1' in report['iocs']['ipv4']
        assert 'link' in report

    def test_parser_basic_ip_cidr_range(self):
        stix_object = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
            "created": "2014-06-29T13:49:37.079Z",
            "modified": "2014-06-29T13:49:37.079Z",
            "name": "Malicious site hosting downloader",
            "description": "This organized threat actor group operates to create profit from all types of crime.",
            "indicator_types": [
                "malicious-activity"
            ],
            "pattern": "[ipv4-addr:value = '198.51.100.1/31']",
            "pattern_type": "stix",
            "valid_from": "2014-06-29T13:49:37.079Z"
        }
        indicator = STIXIndicator(stix_object, "http://server:5000/taxii2/collections/collection-id-basic")
        report = indicator.report
        assert "timestamp" in report
        assert report["timestamp"] == int(STIXIndicator.strptime('2014-06-29T13:49:37.079Z').timestamp())
        assert "id" in report
        assert report["id"] == 'indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f'
        assert 'score' in report and report['score'] == 100
        assert 'title' in report and report['title'] == 'Malicious site hosting downloader'
        assert 'iocs' in report
        assert 'ipv4' in report['iocs']
        assert '198.51.100.1' in report['iocs']['ipv4']
        assert '198.51.100.0' in report['iocs']['ipv4']
        assert 'link' in report

    def test_parser_complex_ip(self):
        stix_object = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
            "created": "2014-06-29T13:49:37.079Z",
            "modified": "2014-06-29T13:49:37.079Z",
            "name": "Malicious site hosting downloader",
            "description": "This organized threat actor group operates to create profit from all types of crime.",
            "indicator_types": [
                "malicious-activity"
            ],
            "pattern": "[ipv4-addr:value = '198.51.100.1/32' OR ipv4-addr:value = '203.0.113.33/32' OR ipv6-addr:value = '2001:0db8:dead:beef:dead:beef:dead:0001/128']",
            "pattern_type": "stix",
            "valid_from": "2014-06-29T13:49:37.079Z"
        }
        indicator = STIXIndicator(stix_object, "http://server:5000/taxii2/collections/collection-id-basic")
        report = indicator.report
        assert "timestamp" in report
        assert report["timestamp"] == int(STIXIndicator.strptime('2014-06-29T13:49:37.079Z').timestamp())
        assert "id" in report
        assert report["id"] == 'indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f'
        assert 'score' in report and report['score'] == 100
        assert 'title' in report and report['title'] == 'Malicious site hosting downloader'
        assert 'iocs' in report
        assert 'ipv4' in report['iocs']
        assert '198.51.100.1' in report['iocs']['ipv4']
        assert '203.0.113.33' in report['iocs']['ipv4']
        assert 'ipv6' in report['iocs']
        assert '2001:0db8:dead:beef:dead:beef:dead:0001' in report['iocs']['ipv6']
        assert 'link' in report

    def test_parser_complex_ip_cidr_range(self):
        stix_object = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
            "created": "2014-06-29T13:49:37.079Z",
            "modified": "2014-06-29T13:49:37.079Z",
            "name": "Malicious site hosting downloader",
            "description": "This organized threat actor group operates to create profit from all types of crime.",
            "indicator_types": [
                "malicious-activity"
            ],
            "pattern": "[ipv4-addr:value = '198.51.100.1/32' OR ipv4-addr:value = '203.0.113.33/32' OR ipv6-addr:value = '2001:0db8:dead:beef:dead:beef:dead:0001/127']",
            "pattern_type": "stix",
            "valid_from": "2014-06-29T13:49:37.079Z"
        }
        indicator = STIXIndicator(stix_object, "http://server:5000/taxii2/collections/collection-id-basic")
        report = indicator.report
        assert "timestamp" in report
        assert report["timestamp"] == int(STIXIndicator.strptime('2014-06-29T13:49:37.079Z').timestamp())
        assert "id" in report
        assert report["id"] == 'indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f'
        assert 'score' in report and report['score'] == 100
        assert 'title' in report and report['title'] == 'Malicious site hosting downloader'
        assert 'iocs' in report
        assert 'ipv4' in report['iocs']
        assert '198.51.100.1' in report['iocs']['ipv4']
        assert '203.0.113.33' in report['iocs']['ipv4']
        assert 'ipv6' in report['iocs']
        assert '2001:db8:dead:beef:dead:beef:dead:1' in report['iocs']['ipv6']
        assert '2001:db8:dead:beef:dead:beef:dead:0' in report['iocs']['ipv6']
        assert 'link' in report

    def test_parser_complex_ip_with_domain(self):
        stix_object = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
            "created": "2014-06-29T13:49:37.079Z",
            "modified": "2014-06-29T13:49:37.079Z",
            "name": "Malicious site hosting downloader",
            "description": "This organized threat actor group operates to create profit from all types of crime.",
            "indicator_types": [
                "malicious-activity"
            ],
            "pattern": "[ipv4-addr:value = '198.51.100.1/32' OR ipv4-addr:value = '203.0.113.33/32' OR "
                       "ipv6-addr:value = '2001:0db8:dead:beef:dead:beef:dead:0001/128' OR domain-name:value = "
                       "'example.com']",
            "pattern_type": "stix",
            "valid_from": "2014-06-29T13:49:37.079Z"
        }
        indicator = STIXIndicator(stix_object, "http://server:5000/taxii2/collections/collection-id-basic")
        report = indicator.report
        assert "timestamp" in report
        assert report["timestamp"] == int(STIXIndicator.strptime('2014-06-29T13:49:37.079Z').timestamp())
        assert "id" in report
        assert report["id"] == 'indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f'
        assert 'score' in report and report['score'] == 100
        assert 'title' in report and report['title'] == 'Malicious site hosting downloader'
        assert 'iocs' in report
        assert 'ipv4' in report['iocs']
        assert '198.51.100.1' in report['iocs']['ipv4']
        assert '203.0.113.33' in report['iocs']['ipv4']
        assert 'ipv6' in report['iocs']
        assert '2001:0db8:dead:beef:dead:beef:dead:0001' in report['iocs']['ipv6']
        assert 'link' in report
        assert 'dns' in report['iocs'] and 'example.com' in report['iocs']['dns']

    def test_parser_complex_ip_with_domain_but_address_not_enabled(self):
        stix_object = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
            "created": "2014-06-29T13:49:37.079Z",
            "modified": "2014-06-29T13:49:37.079Z",
            "name": "Malicious site hosting downloader",
            "description": "This organized threat actor group operates to create profit from all types of crime.",
            "indicator_types": [
                "malicious-activity"
            ],
            "pattern": "[ipv4-addr:value = '198.51.100.1/32' OR ipv4-addr:value = '203.0.113.33/32' OR "
                       "ipv6-addr:value = '2001:0db8:dead:beef:dead:beef:dead:0001/128' OR domain-name:value = "
                       "'example.com']",
            "pattern_type": "stix",
            "valid_from": "2014-06-29T13:49:37.079Z"
        }
        indicator = STIXIndicator(stix_object, "http://server:5000/taxii2/collections/collection-id-basic",
                                  pattern_parser=STIXPatternParser(["domain"]))
        report = indicator.report
        assert "timestamp" in report
        assert report["timestamp"] == int(STIXIndicator.strptime('2014-06-29T13:49:37.079Z').timestamp())
        assert "id" in report
        assert report["id"] == 'indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f'
        assert 'score' in report and report['score'] == 100
        assert 'title' in report and report['title'] == 'Malicious site hosting downloader'
        assert 'iocs' in report
        assert 'ipv4' not in report['iocs']
        assert 'ipv6' not in report['iocs']
        assert 'link' in report
        assert 'dns' in report['iocs'] and 'example.com' in report['iocs']['dns']

    def test_parser_complex_ip_with_domain_but_nothing_enabled(self):
        stix_object = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
            "created": "2014-06-29T13:49:37.079Z",
            "modified": "2014-06-29T13:49:37.079Z",
            "name": "Malicious site hosting downloader",
            "description": "This organized threat actor group operates to create profit from all types of crime.",
            "indicator_types": [
                "malicious-activity"
            ],
            "pattern": "[ipv4-addr:value = '198.51.100.1/32' OR ipv4-addr:value = '203.0.113.33/32' OR "
                       "ipv6-addr:value = '2001:0db8:dead:beef:dead:beef:dead:0001/128' OR domain-name:value = "
                       "'example.com']",
            "pattern_type": "stix",
            "valid_from": "2014-06-29T13:49:37.079Z"
        }
        indicator = STIXIndicator(stix_object, "http://server:5000/taxii2/collections/collection-id-basic",
                                  pattern_parser=STIXPatternParser(["hash"]))
        report = indicator.report
        assert not report

    def test_indicator_not_intelligble_to_edr(self):
        stix_object = {"type": "indicator",
                       "spec_version": "2.1",
                       "id": "indicator--e26a5a10-09e4-423b-84d7-eb026c3ff482",
                       "created": "2021-02-14T07:10:49.000Z",
                       "modified": "2021-06-27T19:45:26.000Z",
                       "description": "Month majority nearly century manage.",
                       "indicator_types": [
                           "attribution"
                       ],
                       "pattern": "[process:defanged NOT = false]",
                       "pattern_type": "stix",
                       "pattern_version": "2.1",
                       "valid_from": "2020-06-26T01:48:15Z",
                       "valid_until": "2021-05-18T13:37:59Z",
                       "kill_chain_phases": [
                           {
                               "kill_chain_name": "lweDuklJOhJMBoQcY",
                               "phase_name": "ptQuXqPySK"
                           }
                       ],
                       "labels": [
                           "role",
                           "treat",
                           "fire",
                           "power",
                           "although"
                       ],
                       "confidence": 22,
                       "lang": "en"
                       }
        indicator = STIXIndicator(stix_object, "http://server:5000/taxii2/collections/collection-id-basic")
        assert not indicator.report


if __name__ == '__main__':
    unittest.main()
