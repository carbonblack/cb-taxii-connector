# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.
################################################################################

import logging
import os

from cbopensource.constant import GiB, MiB
from cbopensource.utilities.common_config import BoolConfigOption, CommonConfigBase, CommonConfigException, \
    DerivativeConfigOption, IntConfigOption, StringConfigOption

_logger = logging.getLogger(__name__)

__all__ = ["TaxiiConnectorConfigurationException", "TaxiiConnectorConfiguration"]


class TaxiiConnectorConfigurationException(CommonConfigException):
    """
    Exception class for usage errors with TAXII configuration.
    """
    pass


def _derive_use_feed_stream(conf) -> bool:
    return conf.get('feed_save_mode', 'STREAM').upper() == 'STREAM'


class TaxiiConnectorConfiguration(CommonConfigBase):
    """
    Class to manage The overall taxii operation.
    """
    DIRECTORY = "/usr/share/cb/integrations/cb-taxii-connector/content"
    DISPLAY_NAME = "taxii"
    CB_IMAGE_PATH = "/carbonblack.png"
    FEED_NAME = "taxiiintegration"
    INTEGRATION_IMAGE_PATH = "/taxii.png"
    JSON_FEED_PATH = "/taxii/json"
    INTEGRATION_IMAGE_SMALL_PATH = "/taxii-small.png"

    # Schema definitions
    config_schema = {
        "cache_folder": StringConfigOption('cache_folder', required=False,
                                           default="/usr/share/cb/integrations/cb-taxii-connector/cache",
                                           transform=os.path.abspath),
        "carbonblack_server_token": StringConfigOption("carbonblack_server_token", required=True),
        "carbonblack_server_url": StringConfigOption("carbonblack_server_url", default="https://127.0.0.1",
                                                     required=False),
        "debug": BoolConfigOption('debug', required=False, default=False),
        # allowed range: 1 minute to 1 month
        "feed_retrieval_minutes": IntConfigOption('feed_retrieval_minutes', min_value=1, max_value=1440 * 30),
        "feed_save_mode": StringConfigOption('feed_save_mode', default='STREAM', required=False,
                                             allowed_values=['STREAM', 'BULK'], to_upper=True),
        'use_feed_stream': DerivativeConfigOption('use_feed_stream', bool, _derive_use_feed_stream),
        "host_address": StringConfigOption('host_address', default="127.0.0.1", required=False),
        "https_proxy": StringConfigOption('https_proxy', default=None, required=False),
        "listener_address": StringConfigOption('listener_address', default="0.0.0.0", required=False),
        "listener_port": IntConfigOption('listener_port', min_value=1, max_value=65535),
        "log_file_size": IntConfigOption('log_file_size', default=10 * MiB, min_value=1 * MiB, max_value=1 * GiB),
        "log_level": StringConfigOption('log_level', default="INFO", required=False,
                                        allowed_values=["DEBUG", "INFO", "WARNING", "ERROR"],
                                        to_upper=True),

        "multi_core": BoolConfigOption('multi_core', default=True),
        "pretty_print_json": BoolConfigOption('pretty_print_json', required=False, default=False),
        "skip_cb_sync": BoolConfigOption('skip_cb_sync', default=False),
    }
