# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.
################################################################################

import unittest
from unittest import mock

from cbopensource.driver.taxii_server_config import ServerVersion, TaxiiServerConfiguration
from cbopensource.utilities.common_config import CommonConfigException
from taxii2client.common import TokenAuth


class TaxiiServerConfigTests(unittest.TestCase):

    def test_01a_server_config_parsed(self):
        conf = {"url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}

        conf_as_dict = TaxiiServerConfiguration.parse(conf)
        self.assertEqual("http://localhost:5000/taxii2", conf_as_dict['url'])
        self.assertEqual("user", conf_as_dict['user'])
        self.assertEqual("pass", conf_as_dict['password'])

    def test_01b_server_config_inited(self):
        conf = {"url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}

        conf_as_dict = TaxiiServerConfiguration.parse(conf)
        self.assertEqual("http://localhost:5000/taxii2", conf_as_dict['url'])
        self.assertEqual("user", conf_as_dict['user'])
        self.assertEqual("pass", conf_as_dict['password'])

    def test_02a_server_config_as_object(self):
        conf = {"url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}

        tsc = TaxiiServerConfiguration.parse(conf)
        self.assertEqual("http://localhost:5000/taxii2", tsc['url'])
        self.assertEqual("user", tsc['user'])
        self.assertEqual("pass", tsc['password'])

    def test_02b_server_config_as_object_get(self):
        conf = {"url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}

        tsc = TaxiiServerConfiguration.parse(conf)
        assert 'verify' not in tsc


    def test_03_server_config_defaults(self):
        conf = {"url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}

        tsc = TaxiiServerConfiguration.parse(conf)
        self.assertEqual("http://localhost:5000/taxii2", tsc['url'])
        self.assertEqual("user", tsc['user'])
        self.assertEqual("pass", tsc['password'])
        self.assertEqual(TaxiiServerConfiguration.DEFAULT_SCORE, tsc["score"])
        self.assertEqual(TaxiiServerConfiguration.DEFAULT_PAGINATION, tsc["pagination"])
        assert 'collections' not in tsc
        assert 'version' not in tsc

    # NOTE: Since we have defaults handled in the test above, only differences will be checked in folowing tests

    def test_04a_server_config_version_20(self):
        conf = {"version": "v20", "url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}

        tsc = TaxiiServerConfiguration.parse(conf)
        self.assertEqual(ServerVersion["V20"], tsc["version"])

    def test_04b_server_config_version_21(self):
        conf = {"version": "v21", "url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}

        tsc = TaxiiServerConfiguration.parse(conf)
        self.assertEqual(ServerVersion["V21"], tsc["version"])

    def test_04c_server_config_version_bad(self):
        conf = {"version": "v23", "url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}
        try:
            TaxiiServerConfiguration.parse(conf)
            self.fail("Did not see expected exception!")
        except CommonConfigException as err:
            assert "Version 'V23' not supported, supported versions are V21 and V20" in str(err)

    def test_05_server_config_token(self):
        conf = {"url": "http://localhost:5000/taxii2", "token": "averysecrettoken"}

        tsc = TaxiiServerConfiguration.parse(conf)
        assert 'user' not in tsc
        assert 'password' not in tsc
        self.assertEqual(type(tsc['token']), TokenAuth)
        self.assertEqual("averysecrettoken", tsc['token'].key)

    def test_06a_server_config_pagination(self):
        conf = {"pagination": '77', "url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}

        tsc = TaxiiServerConfiguration.parse(conf)
        self.assertEqual(77, tsc["pagination"])

    def test_06b_server_config_pagination_below_low_bounds(self):
        conf = {"pagination": str(TaxiiServerConfiguration.PAGINATION_LOW_BOUNDS - 1), "url": "http://localhost:5000/taxii2",
                "username": "user", "password": "pass"}

        try:
            TaxiiServerConfiguration.parse(conf)
            self.fail("Did not see expected exception!")
        except CommonConfigException as err:
            assert "'pagination' must be between 10 and 1000 (got 9)" in str(err)

    def test_06c_server_config_pagination_above_high_bounds(self):
        conf = {"pagination": str(TaxiiServerConfiguration.PAGINATION_HIGH_BOUNDS + 1),
                "url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}

        try:
            TaxiiServerConfiguration.parse(conf)
            self.fail("Did not see expected exception!")
        except CommonConfigException as err:
            assert "'pagination' must be between 10 and 1000 (got 1001)" in str(err)

    def test_06d_server_config_pagination_bad_value(self):
        conf = {"pagination": "afdsa", "url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}

        try:
            TaxiiServerConfiguration.parse(conf)
            self.fail("Did not see expected exception!")
        except CommonConfigException as err:
            assert "Problem with configuration key 'pagination': invalid literal for int()" in str(err)

    def test_07a_server_config_collections(self):
        conf = {"collections": "collection-id-123456", "url": "http://localhost:5000/taxii2", "username": "user",
                "password": "pass"}

        tsc = TaxiiServerConfiguration.parse(conf)
        self.assertListEqual(["collection-id-123456"], tsc['collections'])

    def test_07b_server_config_collections_many(self):
        conf = {"collections": "collection-id-123456,collection-id-21234214321,colleciton-id-134124321",
                "url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}

        tsc = TaxiiServerConfiguration.parse(conf)
        self.assertListEqual(["collection-id-123456", "collection-id-21234214321", "colleciton-id-134124321"],
                             tsc['collections'])

    def test_07c_server_config_collections_uniqueness(self):
        conf = {"collections": "collection-id-123456,collection-id-123456,colleciton-id-134124321",
                "url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}

        try:
            TaxiiServerConfiguration.parse(conf)
            self.fail("Did not see expected exception!")
        except CommonConfigException as err:
            assert "'collections' - List entries must be unique" in str(err)

    def test_08a_server_config_ioc_types(self):
        conf = {"ioc_types": "address,hash,domain", "collections": "collection-id-123456",
                "url": "http://localhost:5000/taxii2", "username": "user",
                "password": "pass"}

        tsc = TaxiiServerConfiguration.parse(conf)
        self.assertListEqual(tsc["ioc_types"], ["address", "domain", "hash"])

    def test_08b_server_config_ioc_types_invalid(self):
        conf = {"ioc_types": "address,hash,ja3", "url": "http://localhost:5000/taxii2", "username": "user",
                "password": "pass"}

        try:
            TaxiiServerConfiguration.parse(conf)
            self.fail("Did not see expected exception!")
        except CommonConfigException as err:
            assert "'ioc_types' - Acceptable values (case insensitive) are: ['address', 'domain', 'hash']" in str(err)

    # NOTE: cannot check ioc_type entries over max count as this is trapped by uniqueness check!

    def test_09a_server_config_password_username_paired(self):
        conf = {"url": "http://localhost:5000/taxii2", "password": "pass"}

        try:
            TaxiiServerConfiguration.parse(conf)
            self.fail("Did not see expected exception!")
        except CommonConfigException as err:
            assert "'username' is required when 'password' is specified" in str(err)

    def test_09b_server_config_username_password_paired(self):
        conf = {"url": "http://localhost:5000/taxii2", "username": "pass"}

        try:
            TaxiiServerConfiguration.parse(conf)
            self.fail("Did not see expected exception!")
        except CommonConfigException as err:
            assert "'password' is required when 'username' is specified" in str(err)

    def test_10a_server_config_url_required(self):
        conf = {"password": "pass", "username": "user"}

        try:
            TaxiiServerConfiguration.parse(conf)
            self.fail("Did not see expected exception!")
        except CommonConfigException as err:
            assert "Configuration key 'url' is required" in str(err)

    def test_10b_server_config_url_format(self):
        conf = {"url": "htp://afdsfdasfdsa!$%", "password": "pass", "username": "user"}

        try:
            TaxiiServerConfiguration.parse(conf)
            self.fail("Did not see expected exception!")
        except CommonConfigException as err:
            assert "Server url must match required format http(s)://<server>[:port]/taxii2" in str(err)

    def test_11a_server_config_score(self):
        conf = {"score": '25', "url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}

        tsc = TaxiiServerConfiguration.parse(conf)
        self.assertEqual(25, tsc["score"])

    def test_11b_server_config_score_bad_value(self):
        conf = {"score": "afdsa", "url": "http://localhost:5000/taxii2", "username": "user", "password": "pass"}

        try:
            TaxiiServerConfiguration.parse(conf)
            self.fail("Did not see expected exception!")
        except CommonConfigException as err:
            assert "Problem with configuration key 'score': invalid literal for int()" in str(err)

    @mock.patch("cbopensource.driver.taxii_server_config.os.path.exists")
    def test_12a_server_config_cert(self, os_path_exists):
        os_path_exists.return_value = True
        conf = {"url": "http://localhost:5000/taxii2", "cert": "/path/to/cert.pem", "score": '99',
                "verify": 'true'}

        tsc = TaxiiServerConfiguration.parse(conf)
        self.assertEqual("/path/to/cert.pem", tsc["cert"])

    @mock.patch("os.path.exists")
    def test_12b_server_config_cert_and_key(self, os_path_exists_mock):
        os_path_exists_mock.return_value = True
        conf = {"url": "http://localhost:5000/taxii2", "cert": "/path/to/cert,/path/to/key", "score": '99',
                "verify": 'true'}

        tsc = TaxiiServerConfiguration.parse(conf)
        self.assertTupleEqual(("/path/to/cert", "/path/to/key"), tsc['cert'])

    @mock.patch("os.path.exists")
    def test_12c_server_config_cert_does_not_exist(self, os_path_exists_mock):
        os_path_exists_mock.return_value = False
        conf = {"url": "http://localhost:5000/taxii2", "cert": "/path/to/nothing", "score": '99',
                "verify": 'true'}

        try:
            TaxiiServerConfiguration.parse(conf)
            self.fail("Did not see expected exception!")
        except CommonConfigException as err:
            assert "does not exist" in str(err)

    @mock.patch("cbopensource.driver.taxii_server_config.os.path.exists")
    def test_12d_server_config_cert_too_many_entries(self, os_path_exists):
        os_path_exists.return_value = True
        conf = {"url": "http://localhost:5000/taxii2",
                "cert": "/path/to/cert, /path/to/other, /yet/another/path", "score": '99',
                "verify": 'true'}

        try:
            TaxiiServerConfiguration.parse(conf)
            self.fail("Did not see expected exception!")
        except CommonConfigException as err:
            assert ("'cert' must be specified as the path to a .pem encoded cert+key pair or the comma separated"
                    " paths to a cert and a key file") in str(err)

    def test_13_server_config_verify_bad(self):
        conf = {"url": "http://localhost:5000/taxii2", "score": '99', "verify": 'trueafdsa'}

        try:
            TaxiiServerConfiguration.parse(conf)
            self.fail("Did not see expected exception!")
        except CommonConfigException as err:
            assert ("Problem with configuration key 'verify': Only case-insensitive values "
                    "of 'true' or 'false' are allowed") in str(err)


if __name__ == '__main__':
    unittest.main()
