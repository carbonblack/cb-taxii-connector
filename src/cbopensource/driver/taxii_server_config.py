# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.
################################################################################

# noinspection PyUnresolvedReferences
import os
import re
from enum import Enum

from taxii2client.common import TokenAuth
from taxii2client.v20 import Server as ServerV20
from taxii2client.v21 import Server as ServerV21

from cbopensource.utilities.common_config import BoolConfigOption, CertConfigOption, CommaDelimitedListConfigOption, \
    CommonConfigBase, CommonConfigException, CommonConfigOptionBase, IntConfigOption, PairedConfigOption, \
    StringConfigOption

__all__ = ["TaxiiURLConfigOption", "ServerVersion", "ServerVersionConfigOption",
           "TaxiiServerConfiguration"]


class TaxiiURLConfigOption(CommonConfigOptionBase):
    @staticmethod
    def taxii_url_checker(value):
        matched = re.search(r"https?://\S+(:\d{1,5})?", value)
        if matched is None:
            raise CommonConfigException(f"Server url must match required format http(s)://<server>[:port]/taxii2")

    def __init__(self):
        super().__init__('url', str, bounds_checker=self.taxii_url_checker)


class ServerVersion(Enum):
    V21 = 1
    V20 = 0

    @staticmethod
    def get_server_for_version(version):
        if version == ServerVersion.V20:
            return ServerV20
        else:
            return ServerV21

    @staticmethod
    def from_string(str_version):
        return ServerVersion[str_version.upper()]

    @staticmethod
    def check_string_version(str_version):
        if not str_version.upper() in ["V20", "V21"]:
            raise CommonConfigException(f"Version '{str_version.upper()}' "
                                        f"not supported, supported versions are V21 and V20")


class ServerVersionConfigOption(CommonConfigOptionBase):
    def __init__(self):
        super().__init__('version', str, bounds_checker=ServerVersion.check_string_version, required=False,
                         transform=ServerVersion.from_string, allowed_values=[ServerVersion.V20, ServerVersion.V21])


class TaxiiServerConfiguration(CommonConfigBase):
    """
    The class handles the configuration of a single TAXII connection stanza.
    """
    DEFAULT_SCORE = 75
    DEFAULT_PAGINATION = 100
    PAGINATION_LOW_BOUNDS = 10
    PAGINATION_HIGH_BOUNDS = 1000

    # Schema definitions
    config_schema = {
        "cert": CertConfigOption(),
        "collections": CommaDelimitedListConfigOption('collections', unique=True, required=False, default=None,
                                                      sort_list=False),
        "ioc_types": CommaDelimitedListConfigOption('ioc_types', unique=True, required=False, default=None,
                                                    accepted_values=['hash', 'address', 'domain'], max_len=3),
        "pagination": IntConfigOption('pagination', min_value=PAGINATION_LOW_BOUNDS, max_value=PAGINATION_HIGH_BOUNDS,
                                      required=False, default=100),
        "password": PairedConfigOption(StringConfigOption('password', required=False), 'username'),
        "score": IntConfigOption('score', min_value=1, max_value=100, default=DEFAULT_SCORE),
        "token": StringConfigOption("token", required=False, max_len=156, transform=TokenAuth),
        "url": TaxiiURLConfigOption(),
        "user": PairedConfigOption(StringConfigOption('username', required=False), 'password'),
        "verify": BoolConfigOption('verify', required=False, default=None),
        "version": ServerVersionConfigOption(),
    }
