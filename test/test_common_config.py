# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.
################################################################################

from unittest import TestCase, mock

from cbopensource.utilities.common_config import BoolConfigOption, CertConfigOption, CommaDelimitedListConfigOption, \
    CommonConfigException, IntConfigOption, PairedConfigOption, StringConfigOption


class TestConfig(TestCase):

    def test_01a_boolean_valid(self):
        """
        Ensure that simple BoolConfigOption works as expected.
        """
        # set of tests and expected results
        checks = [("True", True), ("TRUE", True), ("true", True),
                  ("False", False), ("FALSE", False), ("false", False)
                  ]
        problems = []

        for item in checks:
            try:
                config = {'check': item[0]}
                test = BoolConfigOption("check").parse_from_dict(config)
                if item[1] != test:
                    problems.append(f"Value `{item[0]}` did not convert to the expected `{item[1]}`")
            except CommonConfigException as err:
                problems.append(f"{err}")

            assert len(problems) == 0, "There were problems seen:\n  " + "  \n".join(problems)

    def test_01b_boolean_bogus(self):
        """
        Ensure that bogus boolean values are caught.
        """
        try:
            config = {'check': "BOGUS"}
            BoolConfigOption("check").parse_from_dict(config)
            self.fail("Did not trap bogus value for boolean")
        except CommonConfigException as err:
            assert "Only case-insensitive values of 'true' or 'false'" in str(err)

    def test_01c_boolean_missing(self):
        """
        By default, boolean value are required.
        """
        try:
            config = {}
            BoolConfigOption("check").parse_from_dict(config)
            self.fail("Did not trap missing value for boolean")
        except CommonConfigException as err:
            assert "Configuration key 'check' is required" in str(err)

    def test_01d_boolean_missing_not_required_default(self):
        """
        Ensure that a specified default value is used if the parameter is not suppled.
        """
        config = {}
        test = BoolConfigOption("check", required=False).parse_from_dict(config)
        self.assertIsNone(test)

    def test_01e_boolean_missing_not_required_default_specified(self):
        """
        Ensure that a specified default value is used if the parameter is not suppled.
        """
        config = {}
        test = BoolConfigOption("check", required=False, default=True).parse_from_dict(config)
        self.assertTrue(test)

    def test_02a_int(self):
        """
        Ensure that simple IntConfigOption works as expected.
        """
        config = {"check": "42"}
        test = IntConfigOption("check").parse_from_dict(config)
        self.assertEqual(test, 42)

    def test_02b_int_bogus(self):
        """
        Ensure that bogus int values are caught.
        """
        try:
            config = {'check': "BOGUS"}
            IntConfigOption("check").parse_from_dict(config)
            self.fail("Did not trap bogus value for int")
        except CommonConfigException as err:
            assert "Problem with configuration key 'check': invalid literal for int()" in str(err)

    def test_02c_int_bogus_float(self):
        """
        Ensure that bogus int values are caught.
        """
        try:
            config = {'check': "4.5"}
            IntConfigOption("check").parse_from_dict(config)
            self.fail("Did not trap bogus value for int")
        except CommonConfigException as err:
            assert "roblem with configuration key 'check': invalid literal for int()" in str(err)

    def test_02d_int_missing(self):
        """
        By default, int value are required.
        """
        try:
            config = {}
            IntConfigOption("check").parse_from_dict(config)
            self.fail("Did not trap missing value for int")
        except CommonConfigException as err:
            assert "Configuration key 'check' is required" in str(err)

    def test_02e_int_missing_not_required_default(self):
        """
        Ensure that a specified default value is used if the parameter is not suppled.
        """
        config = {}
        test = IntConfigOption("check", required=False).parse_from_dict(config)
        self.assertIsNone(test)

    def test_02f_int_missing_not_required_default_specified(self):
        """
        Ensure that a specified default value is used if the parameter is not suppled.
        """
        config = {}
        test = IntConfigOption("check", required=False, default=42).parse_from_dict(config)
        self.assertEqual(test, 42)

    def test_02g_int_at_specified_min(self):
        """
        Ensure that an int at the specified min is ok.
        """
        config = {'check': '3'}
        test = IntConfigOption("check", min_value=3).parse_from_dict(config)
        self.assertEqual(test, 3)

    def test_02h_int_outside_specified_min(self):
        """
        Ensure that values outside the specified minimum are trapped.
        """
        try:
            config = {"check": "1"}
            IntConfigOption("check", min_value=10).parse_from_dict(config)
            self.fail("Did not trap outside value for int")
        except CommonConfigException as err:
            assert "'check' must be between 10 and 100" in str(err)

    def test_02i_int_at_specified_max(self):
        """
        Ensure that an int at the specified max is ok.
        """
        config = {'check': '90'}
        test = IntConfigOption("check", max_value=90).parse_from_dict(config)
        self.assertEqual(test, 90)

    def test_02j_int_outside_specified_max(self):
        """
        Ensure that values outside the specified maximum are trapped.
        """
        try:
            config = {"check": "100"}
            IntConfigOption("check", max_value=95).parse_from_dict(config)
            self.fail("Did not trap outside value for int")
        except CommonConfigException as err:
            assert "'check' must be between 0 and 95 (got 100)" in str(err)

    def test_03a_string(self):
        """
        Ensure that simple StringConfigOption works as expected.
        """
        config = {"check": "Okay"}
        test = StringConfigOption("check").parse_from_dict(config)
        self.assertEqual(test, "Okay")

    def test_03b_string_missing(self):
        """
        By default, string value are required.
        """
        try:
            config = {}
            StringConfigOption("check").parse_from_dict(config)
            self.fail("Did not trap missing value for str")
        except CommonConfigException as err:
            assert "Configuration key 'check' is required" in str(err)

    def test_03c_string_missing_not_required_default(self):
        """
        Ensure that a specified default value is used if the parameter is not suppled.
        """
        config = {}
        test = StringConfigOption("check", required=False).parse_from_dict(config)
        self.assertIsNone(test)

    def test_03d_string_missing_not_required_default_specified(self):
        """
        Ensure that a specified default value is used if the parameter is not suppled.
        """
        config = {}
        test = StringConfigOption("check", required=False, default="Huh?").parse_from_dict(config)
        self.assertEqual(test, "Huh?")

    def test_03e_string_in_allowed_values(self):
        """
        Ensure that allowed values are accepted (as is).
        """
        config = {"check": "Alpha"}
        test = StringConfigOption("check", allowed_values=["Alpha", "Beta", "Gamma"]).parse_from_dict(config)
        self.assertEqual(test, "Alpha")

    def test_03f_string_in_allowed_values_bad_case(self):
        """
        Ensure that allowed values are accepted (as is).
        """
        config = {"check": "ALPHA"}
        try:
            StringConfigOption("check", allowed_values=["Alpha", "Beta", "Gamma"]).parse_from_dict(config)
            self.fail("Did not trap incorrect case value for str")
        except CommonConfigException as err:
            assert "Configuration key 'check' must be in allowed values" in str(err)

    def test_03g_string_to_upper(self):
        """
        Ensure that if to_upper=True, the resulting string is uppercased.
        """
        config = {"check": "Alpha"}
        test = StringConfigOption("check", to_upper=True).parse_from_dict(config)
        self.assertEqual(test, "ALPHA")

    def test_03h_string_hidden(self):
        """
        Ensure that if hidden=True, the string
        """
        config = {"check": "Alpha"}
        test = StringConfigOption("check", to_upper=True).parse_from_dict(config)
        self.assertEqual(test, "ALPHA")

    def test_03i_string_at_min_size(self):
        """
        Ensure that strings at a noted minimum size are ok
        """
        config = {"check": "Alpha"}
        test = StringConfigOption("check", min_len=5).parse_from_dict(config)
        self.assertEqual(test, "Alpha")

    def test_03j_string_below_minimum_size(self):
        """
        Ensure that StringConfigOption below minimum size is trapped.
        """
        config = {"check": "Alpha"}
        try:
            StringConfigOption("check", min_len=10).parse_from_dict(config)
            self.fail("Did not trap size check")
        except CommonConfigException as err:
            assert "'check' - String length 5 does not meet minimum length of 10" in str(err)

    def test_03k_string_at_maximum_size(self):
        """
        Ensure that strings at a noted maximum size are ok
        """
        config = {"check": "Alpha"}
        test = StringConfigOption("check", max_len=5).parse_from_dict(config)
        self.assertEqual(test, "Alpha")

    def test_03l_string_above_maximum_size(self):
        """
        Ensure that StringConfigOption above maximum size is trapped.
        """
        config = {"check": "Alpha"}
        try:
            StringConfigOption("check", max_len=3).parse_from_dict(config)
            self.fail("Did not trap size check")
        except CommonConfigException as err:
            assert "'check' - String length 5 exceeds maxmimum length of 3" in str(err)

    def test_03m_string__max_and_min_specified_too_small(self):
        """
        Ensure that StringConfigOption outside size scope maximum size is trapped and proper message returned
        when both max and min are specified
        """
        config = {"check": "Alpha"}
        try:
            StringConfigOption("check", min_len=6, max_len=10).parse_from_dict(config)
            self.fail("Did not trap size check")
        except CommonConfigException as err:
            assert "'check' - String length 5 not in bounds 6 -> 10" in str(err)

    def test_03n_string__max_and_min_specified_too_large(self):
        """
        Ensure that StringConfigOption outside size scope maximum size is trapped and proper message returned
        when both max and min are specified
        """
        config = {"check": "Alpha"}
        try:
            StringConfigOption("check", min_len=1, max_len=3).parse_from_dict(config)
            self.fail("Did not trap size check")
        except CommonConfigException as err:
            assert "'check' - String length 5 not in bounds 1 -> 3" in str(err)

    def test_04a_paired(self):
        """
        Ensure that PairedConfigOption works as expected with no problems.
        """
        config = {"user": "alpha", "pass": "beta"}
        check = PairedConfigOption(StringConfigOption('user', required=False), 'pass').parse_from_dict(config)
        self.assertEqual(check, "alpha")

    def test_04b_paired_missing_requirment(self):
        """
        Ensure that PairedConfigOption traps problems when a requirement is missing.
        """
        config = {"user": "alpha"}
        try:
            PairedConfigOption(StringConfigOption('user', required=False), 'pass').parse_from_dict(config)
            self.fail("Did not trap missing requirment")
        except CommonConfigException as err:
            assert "'pass' is required when 'user' is specified" in str(err)

    def test_04c_paired_requirement_empty_string(self):
        """
        Ensure that PairedConfigOption works as expected with no problems if the requirement is specified with an
        empty string (it has been defined)
        """
        config = {"user": "alpha", "pass": ""}
        check = PairedConfigOption(StringConfigOption('user', required=False), 'pass').parse_from_dict(config)
        self.assertEqual(check, "alpha")

    def test_04d_paired_requirement_empty_string_with_required_primary(self):
        """
        Ensure that PairedConfigOption works as expected with no problems if the requirement is specified with an
        empty string (it has been defined)
        """
        config = {"user": "alpha", "pass": ""}
        check = PairedConfigOption(StringConfigOption('user', required=True), 'pass').parse_from_dict(config)
        self.assertEqual(check, "alpha")

    def test_04e_paired_requirement_empty_string_with_required_primary(self):
        """
        Ensure that PairedConfigOption works as expected with no problems if the requirement is specified with an
        empty string (it has been defined)
        """
        config = {"pass": "beta"}
        check = PairedConfigOption(StringConfigOption('user', required=False), 'pass').parse_from_dict(config)
        self.assertIsNone(check)

    def test_05a_comma_delimited(self):
        """
        Ensure that CommaDelimitedListConfigOption works as expected.
        """
        config = {"check": "alpha, beta, gamma, delta"}
        test = CommaDelimitedListConfigOption("check").parse_from_dict(config)
        self.assertListEqual(test, ['alpha', 'beta', 'delta', 'gamma'])

    def test_05b_comma_delimited_no_sort(self):
        """
        Ensure that CommaDelimitedListConfigOption works as expected with sorting disabled.
        """
        config = {"check": "alpha, beta, gamma, delta"}
        test = CommaDelimitedListConfigOption("check", sort_list=False).parse_from_dict(config)
        self.assertListEqual(test, ['alpha', 'beta', 'gamma', 'delta'])

    def test_05c_comma_delimited_list_minimum_size(self):
        """
        Ensure that CommaDelimitedListConfigOption minimum size is ok.
        """
        config = {"check": "alpha, beta, gamma"}
        test = CommaDelimitedListConfigOption("check", min_len=3).parse_from_dict(config)
        self.assertListEqual(test, ['alpha', 'beta', 'gamma'])

    def test_05d_comma_delimited_list_below_minimum_size(self):
        """
        Ensure that CommaDelimitedListConfigOption below minimum size is trapped.
        """
        config = {"check": "alpha, beta, gamma"}
        try:
            CommaDelimitedListConfigOption("check", min_len=4).parse_from_dict(config)
            self.fail("Did not trap missing requirment")
        except CommonConfigException as err:
            assert "'check' - List length 3 does not meet minimum length of 4" in str(err)

    def test_05e_comma_delimited_list_maximum_size(self):
        """
        Ensure that CommaDelimitedListConfigOption maximum size is ok.
        """
        config = {"check": "alpha, beta, gamma"}
        test = CommaDelimitedListConfigOption("check", max_len=3).parse_from_dict(config)
        self.assertListEqual(test, ['alpha', 'beta', 'gamma'])

    def test_05f_comma_delimited_list_below_minimim_size(self):
        """
        Ensure that CommaDelimitedListConfigOption over maximum size is trapped.
        """
        config = {"check": "alpha, beta, gamma"}
        try:
            CommaDelimitedListConfigOption("check", max_len=2).parse_from_dict(config)
            self.fail("Did not trap missing requirment")
        except CommonConfigException as err:
            assert "'check' - List length 3 exceeds maxmimum length of 2" in str(err)

    def test_05f_comma_delimited_max_and_min_specified_too_small(self):
        """
        Ensure that CommaDelimitedListConfigOption under minimum size is trapped, and proper message when
        both sizes are specified.
        """
        config = {"check": "alpha, beta, gamma, delta, eta"}
        try:
            CommaDelimitedListConfigOption("check", min_len=10, max_len=40).parse_from_dict(config)
            self.fail("Did not trap missing requirment")
        except CommonConfigException as err:
            assert "'check' - List length 5 not in bounds 10 -> 40" in str(err)

    def test_05g_comma_delimited_max_and_min_specified_too_large(self):
        """
        Ensure that CommaDelimitedListConfigOption over maximum size is trapped, and proper message when
        both sizes are specified.
        """
        config = {"check": "alpha, beta, gamma, delta, eta"}
        try:
            CommaDelimitedListConfigOption("check", min_len=1, max_len=3).parse_from_dict(config)
            self.fail("Did not trap missing requirment")
        except CommonConfigException as err:
            assert "'check' - List length 5 not in bounds 1 -> 3" in str(err)

    def test_05h_comma_delimited_list_accepted_values(self):
        """
        Ensure that CommaDelimitedListConfigOption accepted values work.
        """
        accepted = ['alpha', 'beta', 'gamma', 'delta']
        config = {"check": "alpha, beta, gamma"}
        test = CommaDelimitedListConfigOption("check", accepted_values=accepted).parse_from_dict(config)
        self.assertListEqual(test, ['alpha', 'beta', 'gamma'])

    def test_05i_comma_delimited_list_accepted_values_bad_value(self):
        """
        Ensure that CommaDelimitedListConfigOption over maximum size is trapped, and proper message when
        both sizes are specified.
        """
        accepted = ['alpha', 'beta', 'gamma', 'delta']
        config = {"check": "alpha, beta, foobar"}
        try:
            CommaDelimitedListConfigOption("check", accepted_values=accepted).parse_from_dict(config)
            self.fail("Did not trap bad entry")
        except CommonConfigException as err:
            assert "'check' - Acceptable values (case insensitive) are: ['alpha', 'beta', 'delta', 'gamma']" in str(err)

    def test_05i_comma_delimited_validate_trim(self):
        """
        Ensure that CommaDelimitedListConfigOption string entries are trimmed.
        """
        config = {"check": "    alpha,  beta   ,gamma      "}
        test = CommaDelimitedListConfigOption("check").parse_from_dict(config)
        self.assertListEqual(test, ['alpha', 'beta', 'gamma'])

    def test_05j_comma_delimited_to_upper(self):
        """
        Ensure that CommaDelimitedListConfigOption with to_upper are properly uppercased.
        """
        config = {"check": "alpha, beta, gamma"}
        test = CommaDelimitedListConfigOption("check", to_upper=True).parse_from_dict(config)
        self.assertListEqual(test, ['ALPHA', 'BETA', 'GAMMA'])

    def test_05k_comma_delimited_list_unique(self):
        """
        Ensure that CommaDelimitedListConfigOption unique setting is allowed.
        """
        config = {"check": "alpha, beta, gamma"}
        test = CommaDelimitedListConfigOption("check", unique=True).parse_from_dict(config)
        self.assertListEqual(test, ['alpha', 'beta', 'gamma'])

    def test_05l_comma_delimited_list_unique_with_duplicates(self):
        """
        Ensure that CommaDelimitedListConfigOption with unique specified catches duplicates.
        """
        config = {"check": "alpha, beta, alpha"}
        try:
            CommaDelimitedListConfigOption("check", unique=True).parse_from_dict(config)
            self.fail("Did not trap bad entry")
        except CommonConfigException as err:
            assert "'check' - List entries must be unique" in str(err)

    def test_06a_cert_unspecified(self):
        """
        Ensure that CertConfigOption allows unspecified values.
        """
        config = {}
        test = CertConfigOption().parse_from_dict(config)
        self.assertIsNone(test)

    @mock.patch("cbopensource.driver.taxii_server_config.os.path.exists")
    def test_06b_cert_only_cert_path_default_key(self, os_path_exists):
        """
        Ensure that CertConfigOption with single source returns cert path.
        """
        os_path_exists.return_value = True
        config = {"cert": "/path/to/cert.pem"}
        test = CertConfigOption().parse_from_dict(config)
        self.assertEqual(test, "/path/to/cert.pem")

    @mock.patch("cbopensource.driver.taxii_server_config.os.path.exists")
    def test_06c_cert_only_cert_path_specified_key(self, os_path_exists):
        """
        Ensure that CertConfigOption with single source returns cert path.
        """
        os_path_exists.return_value = True
        config = {"my-cert": "/path/to/cert.pem"}
        test = CertConfigOption("my-cert").parse_from_dict(config)
        self.assertEqual(test, "/path/to/cert.pem")

    @mock.patch("os.path.exists")
    def test_06d_cert_only_cert_path_not_exists(self, os_path_exists_mock):
        """
        Ensure that CertConfigOption with single source returns cert path.
        """
        config = {"cert": "./does-not-exist.pem"}
        os_path_exists_mock.return_value = False
        try:
            CertConfigOption().parse_from_dict(config)
            self.fail("Did not trap missing cert")
        except CommonConfigException as err:
            assert "'cert' path to cert+key pair does not exist" in str(err)

    @mock.patch("cbopensource.driver.taxii_server_config.os.path.exists")
    def test_06e_cert_both_paths_specified(self, os_path_exists):
        """
        Ensure that CertConfigOption with multiple source returns cert and key path.
        """
        os_path_exists.return_value = True
        config = {"cert": "/path/to/cert.pem, /path/to/key.pem"}
        test = CertConfigOption("cert").parse_from_dict(config)
        self.assertTupleEqual(test, ("/path/to/cert.pem", "/path/to/key.pem"))

    @mock.patch("os.path.exists")
    def test_06f_cert_both_paths_specified_cert_missing(self, os_path_exists_mock):
        """
        Ensure that CertConfigOption with both sources traps missing cert.
        """
        config = {"cert": f"./does_not_exist.py, {__file__}"}
        os_path_exists_mock.return_value = False
        try:
            CertConfigOption().parse_from_dict(config)
            self.fail("Did not trap missing cert")
        except CommonConfigException as err:
            assert "'cert' cert path './does_not_exist.py' does not exist!" in str(err)

    @mock.patch("os.path.exists")
    def test_06g_cert_both_paths_specified_key_missing(self, os_path_exists_mock):
        os_path_exists_mock.side_effect = [True, False]
        """
        Ensure that CertConfigOption with both sources traps missing key.
        """
        config = {"cert": f"{__file__}, ./does_not_exist.py"}
        try:
            CertConfigOption().parse_from_dict(config)
            self.fail("Did not trap missing key")
        except CommonConfigException as err:
            assert "'cert' key path './does_not_exist.py' does not exist!" in str(err)

    def test_06h_cert_empty_string(self):
        """
        Ensure that CertConfigOption with empty string is detected.
        """
        config = {"cert": ""}
        try:
            CertConfigOption().parse_from_dict(config)
            self.fail("Did not trap missing cert")
        except CommonConfigException as err:
            assert "'cert' must be specified as the path to a .pem encoded" in str(err)

    @mock.patch("cbopensource.driver.taxii_server_config.os.path.exists")
    def test_06i_cert_three_entries(self, os_path_exists):
        """
        Ensure that CertConfigOption with three cert entries.
        """
        os_path_exists.return_value = True
        config = {"cert": "/path/to/cert.pem, /path/to/key.pem, /path/to/cert.pem"}
        try:
            CertConfigOption().parse_from_dict(config)
            self.fail("Did not trap missing cert")
        except CommonConfigException as err:
            assert "'cert' must be specified as the path to a .pem encoded" in str(err)
