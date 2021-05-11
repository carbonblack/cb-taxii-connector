from unittest import TestCase
from cbopensource.connectors.taxii.config import Config


class TestConfig(TestCase):

    @staticmethod
    def base_definitions():
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

    def test_01a_core_get_boolean(self):
        """
        Ensure that _get_boolean handles all allowed formats.
        """
        checks = [
            ("True", True), ("t", True), ("TRue", True), ("on", True), ("1", True), ("yes", True),
            ("false", False), ("F", False), ("OFF", False), ("0", False), ("Off", False),
            ("", False), ("BOGUS", False), ("42", False)
        ]
        for item in checks:
            base = self.base_definitions()
            base['check-me'] = item[0]
            cfg = Config(base)
            self._errors = []
            val = cfg._get_boolean("check-me")
            self.assertEqual(0, cfg.errored)
            self.assertEqual(item[1], val)

    def test_01b_core_get_boolean_required(self):
        """
        Ensure that specifying 'required=True' forces the definition of a parameter.
        """
        base = self.base_definitions()
        cfg = Config(base)
        self._errors = []
        val = cfg._get_boolean("check-me", required=True)
        self.assertEqual(1, cfg.errored)
        assert "The config option `check-me` is required" in cfg.errors[0]
        self.assertFalse(val)  # if error, return base default

    def test_01c_core_get_boolean_default(self):
        """
        Ensure that a specified default value is used if the parameter is not suppled.
        """
        base = self.base_definitions()
        cfg = Config(base)
        self._errors = []
        val = cfg._get_boolean("check-me", default=True)
        self.assertEqual(0, cfg.errored)
        self.assertTrue(val)

    def test_02a_core_get_int(self):
        """
        Ensure that _get_boolean handles all allowed formats.
        """
        base = self.base_definitions()
        base['check-me'] = "42"
        cfg = Config(base)
        self._errors = []
        val = cfg._get_int("check-me")
        self.assertEqual(0, cfg.errored)
        self.assertEqual(42, val)

    def test_02b_core_get_int_required(self):
        """
        Ensure that specifying 'required=True' forces the definition of a parameter.
        """
        base = self.base_definitions()
        cfg = Config(base)
        self._errors = []
        val = cfg._get_int("check-me", required=True)
        self.assertEqual(1, cfg.errored)
        assert "The config option `check-me` is a required number" in cfg.errors[0]
        self.assertEqual(0, val)  # if error, return base default

    def test_02c_core_get_int_default(self):
        """
        Ensure that a specified default value is used if the parameter is not suppled.
        """
        base = self.base_definitions()
        cfg = Config(base)
        self._errors = []
        val = cfg._get_int("check-me", default=100)
        self.assertEqual(0, cfg.errored)
        self.assertEqual(100, val)

    def test_02d_core_get_int_verify_func_passed(self):
        """
        Ensure that a specified value passes a supplied validation function.
        """
        base = self.base_definitions()
        base['check-me'] = "42"
        cfg = Config(base)
        self._errors = []
        val = cfg._get_int("check-me", verify_func=lambda x: 0 < x <= 100)
        self.assertEqual(0, cfg.errored)
        self.assertEqual(42, val)

    def test_02e_core_get_int_verify_func_failed(self):
        """
        Ensure that a specified default that fails the validation function is detected and returns the validation
        message.
        """
        base = self.base_definitions()
        base['check-me'] = "420"
        cfg = Config(base)
        self._errors = []
        val = cfg._get_int("check-me", verify_func=lambda x: 0 < x <= 100, requirement_message="a valid percent")
        self.assertEqual(1, cfg.errored)
        self.assertEqual(0, val)
        assert "The config option `check-me` is a number and must be a valid percent." in cfg.errors[0]

    def test_02f_core_get_int_bogus(self):
        """
        Ensure that a specifying a non-integer is detected.
        """
        base = self.base_definitions()
        base['check-me'] = "BOGUS"
        cfg = Config(base)
        self._errors = []
        val = cfg._get_int("check-me")
        self.assertEqual(1, cfg.errored)
        assert "The config option `check-me` is a number." in cfg.errors[0]
        self.assertEqual(0, val)

    def test_02g_core_get_int_bogus_float(self):
        """
        Ensure that a specifying a non-integer is detected.
        """
        base = self.base_definitions()
        base['check-me'] = "34.6"
        cfg = Config(base)
        self._errors = []
        val = cfg._get_int("check-me")
        self.assertEqual(1, cfg.errored)
        assert "The config option `check-me` is a number." in cfg.errors[0]
        self.assertEqual(0, val)

    def test_03a_core_get_string(self):
        """
        Ensure that _get_string reads in the string as provided, with default behavior to strip it.
        """
        base = self.base_definitions()
        base['check-me'] = "    Hit Me   "
        cfg = Config(base)
        self._errors = []
        val = cfg._get_string("check-me")
        self.assertEqual(0, cfg.errored)
        self.assertEqual("Hit Me", val)

    def test_03b_core_get_string_required(self):
        """
        Ensure that specifying 'required=True' forces the definition of a parameter.
        """
        base = self.base_definitions()
        cfg = Config(base)
        self._errors = []
        val = cfg._get_string("check-me", required=True)
        self.assertEqual(1, cfg.errored)
        assert "The config option `check-me` is required" in cfg.errors[0]
        self.assertEqual("", val)  # if error, return base default

    def test_03c_core_get_string_default(self):
        """
        Ensure that a specified default value is used if the parameter is not suppled.
        """
        base = self.base_definitions()
        cfg = Config(base)
        self._errors = []
        val = cfg._get_string("check-me", default="/usr/bin/foobar")
        self.assertEqual(0, cfg.errored)
        self.assertEqual("/usr/bin/foobar", val)

    def test_03d_core_get_string_valid(self):
        """
        Ensure that if valid list is supplied, a matching string is accepted without problems.
        """
        base = self.base_definitions()
        base['check-me'] = "Beta "
        cfg = Config(base)
        self._errors = []
        val = cfg._get_string("check-me", valid=["Alpha", "Beta", "Gamma"])
        self.assertEqual(0, cfg.errored)
        self.assertEqual("Beta", val)

    def test_03d_core_get_string_valid_not_listed(self):
        """
        Ensure that if valid list is supplied, a non-matching string is detected.
        """
        base = self.base_definitions()
        base['check-me'] = "Delta "
        cfg = Config(base)
        self._errors = []
        val = cfg._get_string("check-me", valid=["Alpha", "Beta", "Gamma"])
        self.assertEqual(1, cfg.errored)
        assert "The config option `check-me` must be one of ['Alpha', 'Beta', 'Gamma']" in cfg.errors[0]
        self.assertEqual("", val)

    def test_03e_core_get_string_valid_not_listed_with_unmatched_ok(self):
        """
        Ensure that if valid list is supplied with `unmatched_ok`, a non-matching string is replaced with the default
        but no error is reported.
        """
        base = self.base_definitions()
        base['check-me'] = "Delta "
        cfg = Config(base)
        self._errors = []
        val = cfg._get_string("check-me", valid=["Alpha", "Beta", "Gamma"], unmatched_ok=True)
        self.assertEqual(0, cfg.errored)
        self.assertEqual("", val)

    def test_03f_core_get_string_to_upper(self):
        """
        Ensure that if to_upper=True, the resulting string is uppercased.
        """
        base = self.base_definitions()
        base['check-me'] = "test"
        cfg = Config(base)
        self._errors = []
        val = cfg._get_string("check-me", to_upper=True)
        self.assertEqual(0, cfg.errored)
        self.assertEqual("TEST", val)

    def test_03g_core_get_string_to_lower(self):
        """
        Ensure that if to_lower=True, the resulting string is lowercased.
        """
        base = self.base_definitions()
        base['check-me'] = "TEST"
        cfg = Config(base)
        self._errors = []
        val = cfg._get_string("check-me", to_lower=True)
        self.assertEqual(0, cfg.errored)
        self.assertEqual("test", val)

    def test_03h_core_get_string_to_lower_and_to_upper(self):
        """
        Ensure that if both to_lower and to_upper is true, an error is raised but to_upper takes precedence.
        """
        base = self.base_definitions()
        base['check-me'] = "Test"
        cfg = Config(base)
        self._errors = []
        val = cfg._get_string("check-me", to_lower=True, to_upper=True)
        self.assertEqual(1, cfg.errored)
        assert "Only specify one of `to_upper` and `to_lower`" in cfg.errors[0]
        self.assertEqual("TEST", val)

    # NOTE: Can't test `hidden` at this time

    def test_04a_config_minimal(self):
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
        cfg = Config(self.base_definitions())
        self.assertEqual(0, cfg.errored)

        self.assertEqual('/usr/share/cb/integrations/cb-taxii-connector/cache', cfg.cache_path)
        self.assertEqual('/carbonblack.png', cfg.cb_image_path)  # fixed
        self.assertFalse(cfg.debug)
        self.assertEqual('taxii', cfg.display_name)
        self.assertEqual('taxiiintegration', cfg.feed_name)
        self.assertEqual(22, cfg.feed_retrieval_minutes)
        self.assertEqual('127.0.0.1', cfg.host_address)
        self.assertIsNone(cfg.https_proxy)
        self.assertEqual('/taxii.png', cfg.integration_image_path)
        self.assertEqual('/taxii-small.png', cfg.integration_image_small_path)
        self.assertEqual('/taxii/json', cfg.json_feed_path)
        self.assertEqual('0.0.0.0', cfg.listen_address)
        self.assertEqual(4242, cfg.listen_port)
        self.assertEqual(10485760, cfg.log_file_size)
        self.assertEqual('INFO', cfg.log_level)
        self.assertTrue(cfg.multi_core)
        self.assertFalse(cfg.pretty_print_json)
        self.assertEqual('DEADBEEF0000000000000000CAFEBABE', cfg.server_token)
        self.assertEqual('https://127.0.0.1', cfg.server_url)
        self.assertFalse(cfg.skip_cb_sync)
        self.assertTrue(cfg.use_feed_stream)

    def test_04b_config_empty(self):
        """
        If we supply nothing, ensure we get the expected number of errors.

        """
        cfg = Config({})
        self.assertEqual(3, cfg.errored)

    def test_05_cache_folder(self):
        """
        Ensure 'cache_folder' can be defined.
        """
        base = self.base_definitions()
        base['cache_folder'] = "/usr/bin/foobar"
        cfg = Config(base)
        self.assertEqual(0, cfg.errored)
        self.assertEqual("/usr/bin/foobar", cfg.cache_path)

    def test_06_debug(self):
        """
        Ensure 'debug' can be defined.
        """
        base = self.base_definitions()
        base['debug'] = "true"
        cfg = Config(base)
        self.assertEqual(0, cfg.errored)
        self.assertEqual(True, cfg.debug)

    # NOTE: feed_retrieval_minutes part of all tests as required value

    def test_07_feed_retrieval_minutes_below_1(self):
        """
        Ensure 'feed_retrieval_minutes' minimum is tracked.
        """
        base = self.base_definitions()
        base['feed_retrieval_minutes'] = "0"
        cfg = Config(base)
        self.assertEqual(1, cfg.errored)
        assert "is a required number and must be greater than 1." in cfg.errors[0]

    def test_08_host_address(self):
        """
        Ensure 'host_address' can be defined.
        """
        base = self.base_definitions()
        base['host_address'] = "https://foo.com"
        cfg = Config(base)
        self.assertEqual(0, cfg.errored)
        self.assertEqual("https://foo.com", cfg.host_address)

    def test_09_https_proxy(self):
        """
        Ensure 'https_proxy' can be defined.
        """
        base = self.base_definitions()
        base['https_proxy'] = "https://foo.com"
        cfg = Config(base)
        self.assertEqual(0, cfg.errored)
        self.assertEqual("https://foo.com", cfg.https_proxy)

    def test_10_listener_address(self):
        """
        Ensure 'listener_address' can be defined.
        """
        base = self.base_definitions()
        base['listener_address'] = "https://foo.com"
        cfg = Config(base)
        self.assertEqual(0, cfg.errored)
        self.assertEqual("https://foo.com", cfg.listen_address)

    # NOTE: listener_port part of all tests as required value

    def test_11a_listener_port_below_minimum(self):
        """
        Ensure 'listener_port' minimum is tracked.
        """
        base = self.base_definitions()
        base['listener_port'] = "-20"
        cfg = Config(base)
        self.assertEqual(1, cfg.errored)
        assert "must be a valid port number." in cfg.errors[0]

    def test_11b_listener_port_above_maximum(self):
        """
        Ensure 'listener_port' maximum is tracked.
        """
        base = self.base_definitions()
        base['listener_port'] = "70000"
        cfg = Config(base)
        self.assertEqual(1, cfg.errored)
        assert "must be a valid port number." in cfg.errors[0]

    def test_12a_log_file_size(self):
        """
        Ensure 'log_file_size' can be defined.
        """
        base = self.base_definitions()
        base['log_file_size'] = "12345678"
        cfg = Config(base)
        self.assertEqual(0, cfg.errored)
        self.assertEqual(12345678, cfg.log_file_size)

    def test_12b_log_file_size(self):
        """
        Ensure 'log_file_size' below 0 is tracked.
        """
        base = self.base_definitions()
        base['log_file_size'] = "-1"
        cfg = Config(base)
        self.assertEqual(1, cfg.errored)
        assert "must be positive." in cfg.errors[0]

    def test_13a_log_level(self):
        """
        Ensure 'log_level' can be defined.
        """
        base = self.base_definitions()
        base['log_level'] = "warning"
        cfg = Config(base)
        self.assertEqual(0, cfg.errored)
        self.assertEqual("WARNING", cfg.log_level)

    def test_13b_log_level_unmatched(self):
        """
        Ensure an invalid log level reverts to INFO.
        """
        base = self.base_definitions()
        base['log_level'] = "warn"
        cfg = Config(base)
        self.assertEqual(0, cfg.errored)
        self.assertEqual("INFO", cfg.log_level)

    def test_14_multi_core(self):
        """
        Ensure 'multi_core' can be defined.
        """
        base = self.base_definitions()
        base['multi_core'] = "no"
        cfg = Config(base)
        self.assertEqual(0, cfg.errored)
        self.assertEqual(False, cfg.multi_core)

    def test_15_pretty_print_json(self):
        """
        Ensure 'multi_core' can be defined.
        """
        base = self.base_definitions()
        base['pretty_print_json'] = "YES"
        cfg = Config(base)
        self.assertEqual(0, cfg.errored)
        self.assertEqual(True, cfg.pretty_print_json)

    # NOTE: carbonblack_server_token part of all tests as required value

    def test_16_carbonblack_server_url(self):
        """
        Ensure 'carbonblack_server_url' can be defined.
        """
        base = self.base_definitions()
        base['carbonblack_server_url'] = "https://foo.com"
        cfg = Config(base)
        self.assertEqual(0, cfg.errored)
        self.assertEqual("https://foo.com", cfg.server_url)

    def test_17a_skip_cb_sync(self):
        """
        Ensure 'skip_cb_sync' can be defined.
        """
        base = self.base_definitions()
        base['skip_cb_sync'] = "T"
        cfg = Config(base)
        self.assertEqual(0, cfg.errored)
        self.assertEqual(True, cfg.skip_cb_sync)

    def test_17b_skip_cb_sync_true_no_token(self):
        """
        Ensure that if 'skip_cb_sync' is true, no token is required.
        """
        base = self.base_definitions()
        base['skip_cb_sync'] = "T"
        del base['carbonblack_server_token']
        cfg = Config(base)
        self.assertEqual(0, cfg.errored)
        self.assertEqual(True, cfg.skip_cb_sync)

    def test_18a_feed_save_mode(self):
        """
        Ensure 'feed_save_mode' can be defined.
        """
        base = self.base_definitions()
        base['feed_save_mode'] = "Stream"
        cfg = Config(base)
        self.assertEqual(0, cfg.errored)
        self.assertEqual(True, cfg.use_feed_stream)

    def test_18b_save_mode_unmatched(self):
        """
        Ensure a feed_save_mode reverts to STREAM with a bad entry.
        """
        base = self.base_definitions()
        base['feed_save_mode'] = "Saved"
        cfg = Config(base)
        self.assertEqual(1, cfg.errored)
        self.assertEqual(True, cfg.use_feed_stream)
        assert "The config option `feed_save_mode` must be one of ['STREAM', 'BULK']" in cfg.errors[0]
