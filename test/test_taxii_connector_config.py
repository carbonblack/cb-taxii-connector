# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.
################################################################################

from typing import Dict
from unittest import TestCase

from cbopensource.connectors.taxii.taxii_connector_config import TaxiiConnectorConfiguration
from cbopensource.utilities.common_config import CommonConfigException


class TestConnectorConfig(TestCase):

    @staticmethod
    def minimal() -> Dict:
        """
        Create and return a config structure with everything that does not have defaults.

        NOTE: All supplied values are strings, as if read from a file.
        :return:
        """
        kwargs = {
            "carbonblack_server_token": "DEADBEEF0000000000000000CAFEBABE",
            "feed_retrieval_minutes": "22",
            "listener_port": "4242",
        }
        return kwargs

    # ----- Begin Tests ------------------------------------------------------------

    def test_01a_config_minimal(self):
        """
        Ensure config defaults work with the minimally supplied init values.

        Config settings are:
            cache_path (str)
            debug (bool)
            feed_retrieval_minutes (int)
            host_address (str)
            https_proxy (str)
            listener_address (str)
            listen_port (int)
            log_file_size (int)
            log_level (str)
            multi_core (bool)
            pretty_print_json (bool)
            server_token (str)
            server_url (str)
            skip_cb_sync (bool)
            use_feed_stream (str)
        """
        cfg = TaxiiConnectorConfiguration.parse(self.minimal())

        self.assertEqual('/usr/share/cb/integrations/cb-taxii-connector/cache', cfg['cache_folder'])
        self.assertFalse(cfg['debug'])
        self.assertEqual(22, cfg['feed_retrieval_minutes'])
        self.assertEqual('127.0.0.1', cfg['host_address'])
        assert 'https_proxy' not in cfg
        self.assertEqual('0.0.0.0', cfg['listener_address'])
        self.assertEqual(4242, cfg['listener_port'])
        self.assertEqual(10485760, cfg['log_file_size'])
        self.assertEqual('INFO', cfg['log_level'])
        self.assertTrue(cfg['multi_core'])
        self.assertFalse(cfg['pretty_print_json'])
        self.assertEqual('DEADBEEF0000000000000000CAFEBABE', cfg['carbonblack_server_token'])
        self.assertEqual('https://127.0.0.1', cfg['carbonblack_server_url'])
        self.assertFalse(cfg['skip_cb_sync'])
        self.assertTrue(cfg['use_feed_stream'])

    def test_01b_config_empty(self):
        """
        If we supply nothing, ensure we get the expected number of errors.

        """
        try:
            TaxiiConnectorConfiguration.parse({})
            self.fail("Did not get expected exception!")
        except CommonConfigException as err:
            assert "Configuration key 'carbonblack_server_token' is required" in str(err)

    def test_02_cache_folder(self):
        """
        Ensure 'cache_folder' can be defined.
        """
        base = self.minimal()
        base['cache_folder'] = "/usr/bin/foobar"

        cfg = TaxiiConnectorConfiguration.parse(base)
        self.assertEqual("/usr/bin/foobar", cfg['cache_folder'])

    def test_03_debug(self):
        """
        Ensure 'debug' can be defined.
        """
        base = self.minimal()
        base['debug'] = "true"

        cfg = TaxiiConnectorConfiguration.parse(base)
        self.assertEqual(True, cfg['debug'])

    # NOTE: feed_retrieval_minutes part of all tests as required value

    def test_04a_feed_retrieval_minutes_below_1(self):
        """
        Ensure 'feed_retrieval_minutes' minimum is tracked.
        """
        base = self.minimal()
        base['feed_retrieval_minutes'] = "0"

        try:
            TaxiiConnectorConfiguration.parse(base)
            self.fail("Did not get expected exception!")
        except CommonConfigException as err:
            assert "feed_retrieval_minutes' must be between 1 and 43200 (got 0)" in str(err)

    def test_04b_feed_retrieval_minutes_above_max(self):
        """
        Ensure 'feed_retrieval_minutes' minimum is tracked.
        """
        base = self.minimal()
        base['feed_retrieval_minutes'] = "100000"

        try:
            TaxiiConnectorConfiguration.parse(base)
            self.fail("Did not get expected exception!")
        except CommonConfigException as err:
            assert "feed_retrieval_minutes' must be between 1 and 43200 (got 100000)" in str(err)

    def test_05_host_address(self):
        """
        Ensure 'host_address' can be defined.
        """
        base = self.minimal()
        base['host_address'] = "https://foo.com"

        cfg = TaxiiConnectorConfiguration.parse(base)
        self.assertEqual("https://foo.com", cfg['host_address'])

    def test_06_https_proxy(self):
        """
        Ensure 'https_proxy' can be defined.
        """
        base = self.minimal()
        base['https_proxy'] = "https://foo.com"

        cfg = TaxiiConnectorConfiguration.parse(base)
        self.assertEqual("https://foo.com", cfg['https_proxy'])

    def test_07_listener_address(self):
        """
        Ensure 'listener_address' can be defined.
        """
        base = self.minimal()
        base['listener_address'] = "https://foo.com"

        cfg = TaxiiConnectorConfiguration.parse(base)
        self.assertEqual("https://foo.com", cfg['listener_address'])

    # NOTE: listener_port part of all tests as required value

    def test_08a_listener_port_below_minimum(self):
        """
        Ensure 'listener_port' minimum is tracked.
        """
        base = self.minimal()
        base['listener_port'] = "-20"

        try:
            TaxiiConnectorConfiguration.parse(base)
            self.fail("Did not get expected exception!")
        except CommonConfigException as err:
            assert "'listener_port' must be between 1 and 65535 (got -20)" in str(err)

    def test_08b_listener_port_above_maximum(self):
        """
        Ensure 'listener_port' maximum is tracked.
        """
        base = self.minimal()
        base['listener_port'] = "70000"

        try:
            TaxiiConnectorConfiguration.parse(base)
            self.fail("Did not get expected exception!")
        except CommonConfigException as err:
            assert "'listener_port' must be between 1 and 65535 (got 70000)" in str(err)

    def test_09a_log_file_size(self):
        """
        Ensure 'log_file_size' can be defined.
        """
        base = self.minimal()
        base['log_file_size'] = "12345678"

        cfg = TaxiiConnectorConfiguration.parse(base)
        self.assertEqual(12345678, cfg['log_file_size'])

    def test_09b_log_file_size(self):
        """
        Ensure 'log_file_size' below 0 is tracked.
        """
        base = self.minimal()
        base['log_file_size'] = "-1"

        try:
            TaxiiConnectorConfiguration.parse(base)
            self.fail("Did not get expected exception!")
        except CommonConfigException as err:
            assert "log_file_size' must be between 1048576 and 1073741824 (got -1)" in str(err)

    def test_10a_log_level(self):
        """
        Ensure 'log_level' can be defined.
        """
        base = self.minimal()
        base['log_level'] = "warning"

        cfg = TaxiiConnectorConfiguration.parse(base)
        self.assertEqual("WARNING", cfg['log_level'])

    def test_10b_log_level_unmatched(self):
        """
        Ensure an invalid log level reverts to INFO.
        """
        base = self.minimal()
        base['log_level'] = "warn"

        try:
            TaxiiConnectorConfiguration.parse(base)
            self.fail("Did not get expected exception!")
        except CommonConfigException as err:
            assert ("Configuration key 'log_level' must be in allowed values "
                    "['DEBUG', 'INFO', 'WARNING', 'ERROR']") in str(err)

    def test_11_multi_core(self):
        """
        Ensure 'multi_core' can be defined.
        """
        base = self.minimal()
        base['multi_core'] = "False"

        cfg = TaxiiConnectorConfiguration.parse(base)
        self.assertEqual(False, cfg['multi_core'])

    def test_12_pretty_print_json(self):
        """
        Ensure 'multi_core' can be defined.
        """
        base = self.minimal()
        base['pretty_print_json'] = "true"

        cfg = TaxiiConnectorConfiguration.parse(base)
        self.assertEqual(True, cfg['pretty_print_json'])

    # NOTE: carbonblack_server_token part of all tests as required value

    def test_13_carbonblack_server_url(self):
        """
        Ensure 'carbonblack_server_url' can be defined.
        """
        base = self.minimal()
        base['carbonblack_server_url'] = "https://foo.com"

        cfg = TaxiiConnectorConfiguration.parse(base)
        self.assertEqual("https://foo.com", cfg['carbonblack_server_url'])

    def test_14a_skip_cb_sync(self):
        """
        Ensure 'skip_cb_sync' can be defined.
        """
        base = self.minimal()
        base['skip_cb_sync'] = "True"

        cfg = TaxiiConnectorConfiguration.parse(base)
        self.assertEqual(True, cfg['skip_cb_sync'])

    def test_15a_feed_save_mode(self):
        """
        Ensure 'feed_save_mode' can be defined.
        """
        base = self.minimal()
        base['feed_save_mode'] = "Stream"

        cfg = TaxiiConnectorConfiguration.parse(base)
        self.assertEqual("STREAM", cfg['feed_save_mode'])
        self.assertEqual(True, cfg['use_feed_stream'])

    def test_15b_save_mode_unmatched(self):
        """
        Ensure a feed_save_mode reverts to STREAM with a bad entry.
        """
        base = self.minimal()
        base['feed_save_mode'] = "Saved"

        try:
            TaxiiConnectorConfiguration.parse(base)
            self.fail("Did not get expected exception!")
        except CommonConfigException as err:
            assert "Configuration key 'feed_save_mode' must be in allowed values ['STREAM', 'BULK']" in str(err)
