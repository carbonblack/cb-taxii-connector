import threading
import time
import unittest
from cbopensource.driver import taxii
from test.utils.taxii_mock_server import start_mock_server


class _TestDriverMockedServer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        servers = [{"url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}]
        t = threading.Thread(target=start_mock_server)
        t.daemon = True
        t.start()
        time.sleep(3.0)
        cls.driver = taxii.TaxiiDriver(servers=servers)

    def test_verify_connection(self):
        self.driver.test_connections()

    def test_get_collections(self):
        for server in self.driver.servers:
            assert len(server.collections) > 0

    def test_get_indicators(self):
        for server in self.driver.servers:
            for collection in server.collections:
                for indicator in collection.stream_indicators(10):
                    print(indicator)

    def test_get_reports(self):
        for report in self.driver.generate_reports():
            print(report)
            assert report is not None


if __name__ == "__main__":
    unittest.main()
