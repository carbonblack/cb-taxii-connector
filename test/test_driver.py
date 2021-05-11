import os
import re
import unittest
from unittest import mock
from urllib.parse import urlparse

import requests_mock
from medallion import MEDIA_TYPE_TAXII_V21
from medallion.backends.memory_backend import MemoryBackend
import os
import re
from cbopensource.driver.taxii import TaxiiDriver
from cbopensource.driver.taxii_server_config import TaxiiServerConfiguration


class MockTaxiiServer(MemoryBackend):

    def __init__(self):
        super().__init__(filename=f"{os.path.dirname(os.path.abspath(__file__))}/utils/mock_taxii_data.json")

    @staticmethod
    def process_path_to_parts(request):
        path = urlparse(request.url).path
        split_path = path.strip("/").split("/")
        api_root = split_path[0].strip("/")
        if len(split_path) >= 3:
            collection_id = split_path[2].strip("/")
            return api_root, collection_id
        return api_root

    @staticmethod
    def set_content_type(context):
        context.headers['Content-Type'] = MEDIA_TYPE_TAXII_V21

    def handle_discovery(self, request, context):
        self.set_content_type(context)
        discovery_info = self._get("/discovery")
        print(f"DISCOVERY IS {discovery_info}")
        return discovery_info

    def handle_get_api_root(self, request, context):
        self.set_content_type(context)
        api_root = MockTaxiiServer.process_path_to_parts(request)
        return self.get_api_root_information(api_root)

    def handle_get_api_root_collections(self, request, context):
        self.set_content_type(context)
        api_root = MockTaxiiServer.process_path_to_parts(request)
        return self.get_collections(api_root)

    def handle_get_api_root_collection(self, request, context):
        self.set_content_type(context)
        api_root, collection_id = MockTaxiiServer.process_path_to_parts(request)
        return self.get_collection(api_root, collection_id=collection_id)

    def handle_get_api_root_collections_objects(self, request, context):
        self.set_content_type(context)
        api_root, collection_id = MockTaxiiServer.process_path_to_parts(request)
        limit = int(request.qs.get("limit", ['100'])[0])
        request_args_as_dict = {arg: request.qs[arg][0] for arg in request.qs if arg != 'limit'}
        objects, headers = self.get_objects(
            api_root, collection_id, request_args_as_dict, ("id", "type", "version", "spec_version"), limit
        )
        context.headers.update(headers)
        return objects


class _TestDriverMockedServer(unittest.TestCase):
    default_settings = [{"url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}]

    match_api_root = re.compile(r"^/\S+/$")
    match_api_root_collections = re.compile(r"/\S+/collections/$")
    match_api_root_collection_objects = re.compile(r"/\S+/collections/\S+/objects/")

    def make_driver(self, settings=None):
        if not settings:
            settings = _TestDriverMockedServer.default_settings
        parsed_settings = [TaxiiServerConfiguration.parse(server_settings).dict for server_settings in settings]
        return TaxiiDriver(servers=parsed_settings)

    def run(self, result=None):
        with requests_mock.Mocker() as mocker:
            mock_server = MockTaxiiServer()
            mocker.get("/taxii2/", json=mock_server.handle_discovery)
            mocker.get(self.match_api_root, json=mock_server.handle_get_api_root)
            mocker.get(self.match_api_root_collections, json=mock_server.handle_get_api_root_collections)
            mocker.get(self.match_api_root_collection_objects, json=mock_server.handle_get_api_root_collections_objects)
            super(_TestDriverMockedServer, self).run(result)

    def test_verify_connection(self):
        driver = self.make_driver()
        driver.test_connections()

    def test_get_collections(self):
        driver = self.make_driver()
        assert len(driver.collections) > 0

    def test_get_collections_constrained(self):
        settings = [{"collections": "91a7b528-80eb-42ed-a74d-c6fbd5a26116", "url": "http://localhost:5000/taxii2",
                     "username": "user", "password": "pass"}]
        driver = self.make_driver(settings)
        assert len(driver.collections) == 1

    def test_get_indicators(self):
        driver = self.make_driver()
        for collection in driver.collections:
            for indicator in collection.stream_indicators():
                assert indicator

    def test_get_reports(self):
        driver = self.make_driver()
        reports = list(driver.generate_reports())
        assert len(reports) > 0
        for report in reports:
            assert report is not None
            assert 'title' in report
            assert 'score' in report
            assert report['score'] == TaxiiServerConfiguration.DEFAULT_SCORE
            assert 'iocs' in report
            assert 'link' in report
            assert 'id' in report

    def test_get_reports_score_set(self):
        scored_settings = [
            {"url": "http://localhost:5000/taxii2", "username": "user", "password": "pass", "score": '100'}]
        driver = self.make_driver(scored_settings)
        reports = list(driver.generate_reports())
        assert len(reports) > 0
        for report in reports:
            assert report is not None
            assert 'title' in report
            assert 'score' in report
            assert report['score'] == 100
            assert 'iocs' in report
            assert 'link' in report
            assert 'id' in report

    def test_get_reports_constrained_iocs_hashes(self):
        settings = [
            {"ioc_types": "hash", "url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}]
        driver = self.make_driver(settings)
        reports = list(driver.generate_reports())
        assert len(reports) > 0
        for report in reports:
            assert report is not None
            assert 'title' in report
            assert 'score' in report
            assert 'iocs' in report
            assert 'md5' in report['iocs'] or 'sha256' in report['iocs']
            assert 'dns' not in report['iocs']
            assert 'ipv4' not in report['iocs']
            assert 'ipv6' not in report['iocs']
            assert 'link' in report
            assert 'id' in report

    def test_get_reports_constrained_iocs_addresses(self):
        settings = [
            {"ioc_types": "address", "url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}]
        driver = self.make_driver(settings)
        reports = list(driver.generate_reports())
        assert len(reports) > 0
        for report in reports:
            assert report is not None
            assert 'title' in report
            assert 'score' in report
            assert 'iocs' in report
            assert 'ipv4' in report['iocs'] or 'ipv6' in report['iocs']
            assert 'dns' not in report['iocs']
            assert 'md5' not in report['iocs']
            assert 'sha256' not in report['iocs']
            assert 'link' in report
            assert 'id' in report

    def test_get_reports_constrained_iocs_domain(self):
        settings = [
            {"ioc_types": "domain", "url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}]
        driver = self.make_driver(settings)
        reports = list(driver.generate_reports())
        assert len(reports) > 0
        for report in reports:
            assert report is not None
            assert 'title' in report
            assert 'score' in report
            assert 'iocs' in report
            assert 'ipv4' not in report['iocs']
            assert 'ipv6' not in report['iocs']
            assert 'dns' in report['iocs']
            assert 'md5' not in report['iocs']
            assert 'sha256' not in report['iocs']
            assert 'link' in report
            assert 'id' in report

    def test_get_reports_constrained_iocs_domain_and_address(self):
        settings = [
            {"ioc_types": "domain,address", "url": "http://localhost:5000/taxii2", "username": "user",
             "password": "pass"}]
        driver = self.make_driver(settings)
        reports = list(driver.generate_reports())
        assert len(reports) > 0
        for report in reports:
            assert report is not None
            assert 'title' in report
            assert 'score' in report
            assert 'iocs' in report
            assert 'ipv4' in report['iocs'] or 'ipv6' in report['iocs'] or 'dns' in report['iocs']
            assert 'md5' not in report['iocs']
            assert 'sha256' not in report['iocs']
            assert 'link' in report
            assert 'id' in report

    @mock.patch("cbopensource.driver.taxii.TaxiiServer.verify_connected")
    @mock.patch("taxii2client.common._HTTPConnection")
    @mock.patch("os.path.exists")
    def test_multiple_servers(self, path_exists_mock, http_connection_mock, verify_connected):
        path_exists_mock.return_value = True
        settings = [{"url": "http://localhost:5000/taxii2"}, {"url": "http://localhost:5000/taxii2"}]
        self.make_driver(settings)
        assert len(http_connection_mock.mock_calls) == 2

    """
    def test_anomali_server(self):
        settings = [{"url": "https://limo.anomali.com/api/v1/taxii2/taxii/", "version": "V20", "username":"guest", "password":"guest"}]
        driver = self.make_driver(settings)
        reports = driver.generate_reports()
        assert len(list(reports)) > 0"""

    @mock.patch("cbopensource.driver.taxii.TaxiiServer.verify_connected")
    @mock.patch("taxii2client.common._HTTPConnection")
    @mock.patch("os.path.exists")
    def test_certificate_support_pem(self, path_exists_mock, http_connection_mock, verify_connected):
        verify_connected.return_value = True
        path_exists_mock.return_value = True
        settings = [{"ioc_types": "domain", "url": "http://localhost:5000/taxii2",
                     "username": "user", "password": "pass", "cert": "/path/to/cert.pem"}]
        self.make_driver(settings)
        http_connection_mock.assert_called_with('user', 'pass', True, None, auth=None, cert='/path/to/cert.pem',
                                                version='2.1')

    @mock.patch("cbopensource.driver.taxii.TaxiiServer.verify_connected")
    @mock.patch("taxii2client.common._HTTPConnection")
    @mock.patch("os.path.exists")
    def test_certificate_support_cert_key_pair(self, path_exists_mock, http_connection_mock, verify_connected):
        verify_connected.return_value = True
        path_exists_mock.return_value = True
        settings = [{"ioc_types": "domain", "url": "http://localhost:5000/taxii2",
                     "username": "user", "password": "pass", "cert": "/path/to/cert,/path/to/key"}]
        self.make_driver(settings)
        http_connection_mock.assert_called_with('user', 'pass', True, None, auth=None,
                                                cert=('/path/to/cert', '/path/to/key'), version='2.1')


if __name__ == "__main__":
    unittest.main()
