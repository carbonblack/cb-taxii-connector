#  coding: utf-8
#  VMware Carbon Black EDR Taxii Connector © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################

import configparser
import datetime
import logging
import os
from typing import Dict, List, Union

_logger = logging.getLogger(__name__)

__all__ = ["parse_config", "TaxiiConfigurationException"]


class TaxiiConfigurationException(Exception):
    """
    Base class for exceptions thrown due to fatal taxii configuration problems.
    """
    pass


def parse_config(config_file_path: str, strict_mode: bool = False) -> Dict[str, Union[str, List[Dict]]]:
    """
    Read a configuration file into a local dictionary for easier access.

    :param config_file_path: path to the config file
    :param strict_mode: If True, be harsher with config problems
    :return: compiled configuration dictionary
    :raises TaxiiConfigurationException:
    """
    config_defaults = { 'cbonfig':
        { "server_url": "https://127.0.0.1",
          "auth_token": None,
          "http_proxy_url": None,
          "https_proxy_url": None,
          "reports_limit": "10000",
          "reset_start_date": "False" }}

    config = configparser.RawConfigParser(defaults=config_defaults)

    if config_file_path is None:
        raise TaxiiConfigurationException("Config File: must be specified")

    if not os.path.exists(config_file_path):
        raise TaxiiConfigurationException(f"Config File: {config_file_path} does not exist")

    config.read(config_file_path)

    server_url = config.get("cbconfig", "server_url")
    api_token = config.get("cbconfig", "auth_token")
    http_proxy_url = config.get("cbconfig", 'http_proxy_url', fallback=None)
    https_proxy_url = config.get("cbconfig", 'https_proxy_url', fallback=None)

    sites = []

    for section in config.sections():

        _logger.debug(f"Reading config section: '" + section + "' ...")

        # exclude cbconfig stanza -- all others are sites
        if section.lower() == 'cbconfig':
            continue

        # get site and strip off preceeding http(s):// if necessary
        try:
            site = config.get(section, "site").lower()
        except configparser.NoOptionError:
            raise TaxiiConfigurationException(f"Config File: section `{section}` has no `site` entry (required)")

        # verify site present!
        if not site:
            raise TaxiiConfigurationException(f"Config File: `site` must be defined for section `{section}`")

        # Sanity check and normalization
        if site.startswith("https://"):
            site = site[8:]

        if site.startswith("http://"):
            site = site[7:]

        if site.endswith("/"):
            site = site.strip("/")

        # validate output_path (requred for feed creatiion)
        try:
            output_path = config.get(section, "output_path")
        except configparser.NoOptionError:
            raise TaxiiConfigurationException(f"Config File: section `{section}` has no `output_path` entry (required)")
        if not output_path:
            raise TaxiiConfigurationException(f"Config File: `output_path` must be defined for section `{section}`")

        if not os.path.exists(output_path):
            if strict_mode:
                raise TaxiiConfigurationException(
                    f"Config File: `output_path` for section `{section}` must already exist")
            else:
                os.mkdir(output_path)

        # validate icon info for sanity
        icon_link = config.get(section, "icon_link", fallback="")  # fallback to empty string, if not provided
        if icon_link and not os.path.exists(icon_link):
            raise TaxiiConfigurationException(f"Config File: `icon_link` for section `{section}` must exist")

        username = config.get(section, "username")  # none allowed
        password = config.get(section, "password")  # none allowed

        try:
            feeds_enable = config.getboolean(section, "feeds_enable")
        except configparser.NoOptionError:
            _logger.info(f"Config File: section `{section}` has no `feeds_enable` entry -- defaulting to False")
            feeds_enable = False
        except ValueError:
            raise TaxiiConfigurationException(f"Config File: `feeds_enable` for section `{section}`"
                                              " must be true or false")

        if config.has_option(section, "ioc_exclusions"):
            ioc_exclusions = config.get(section, "ioc_exclusions")
        else:
            ioc_exclusions = []


        if config.has_option(section, "collections"):
            collections = config.get(section, "collections")
        else:
            collections = "*"

        if config.has_option(section, "default_score"):
            try:
                default_score = config.getint(section, "default_score")
            except ValueError:
                raise TaxiiConfigurationException(f"Config File: `default_score` for section `{section}`"
                                                  " must be an integer")
        else:
            default_score = 50
        # if strict, limit values between 1 and 100
        if default_score < 1 or default_score > 100:
            if strict_mode:
                raise TaxiiConfigurationException(f"Config File: `default_score` for section `{section}`"
                                                  " must be between 1 and 100 (inclusive)")
            else:
                _logger.warning(f"Config File: `default_score` for section `{section}`"
                                " must be between 1 and 100 (inclusive)")

        try:
            reset_start_date = config.getboolean(section, "reset_start_date")
        except configparser.NoOptionError:
            _logger.info(f"Config File: section `{section}` has no `reset_start_date` entry -- defaulting to False")
            reset_start_date = False
        except ValueError:
            raise TaxiiConfigurationException(f"Config File: `reset_start_date` for section `{section}`"
                                              " must be true or false")

        if config.has_option(section, "start_date"):
            start_date = config.get(section, "start_date")
        else:
            start_date = "2016-12-01 00:00:00"
        try:
            datetime.datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            raise TaxiiConfigurationException(f"Config File: `start_date` for section `{section}`"
                                              " must be in the format `%Y-%m-%d %H:%M:%S`")

        if config.has_option(section, "use_https"):
            try:
                use_https = config.getboolean(section, "use_https")
            except ValueError:
                raise TaxiiConfigurationException(f"Config File: `use_https` for section `{section}`"
                                                  " must be true or false")
        else:
            use_https = False

        cert_file = None
        key_file = None

        if config.has_option(section, "cert_file") and config.has_option(section, "key_file"):
            cert_file = config.get(section, "cert_file").strip()
            if cert_file == "":
                cert_file = None
            elif not os.path.exists(cert_file):
                _logger.error(f"Cert file supplied but doesn't exist: {cert_file}")

            key_file = config.get(section, "key_file").strip()
            if key_file == "":
                key_file = None
            elif not os.path.exists(key_file):
                _logger.error(f"Key file supplied but doesn't exist: {key_file}")
        elif (config.has_option(section, "cert_file") and not config.has_option(section, "key_file")) or \
                (not config.has_option(section, "cert_file") and config.has_option(section, "key_file")):
            raise TaxiiConfigurationException(f"Config File: both `cert_file` and `key_file` for section `{section}`"
                                              " must be specified")

        if config.has_option(section, "minutes_to_advance"):
            try:
                minutes_to_advance = int(config.get(section, "minutes_to_advance"))
            except ValueError:
                raise TaxiiConfigurationException(f"Config File: `minutes_to_advance` for section `{section}`"
                                                  " must be an integer")
        else:
            minutes_to_advance = 60
        if minutes_to_advance < 1:
            raise TaxiiConfigurationException(f"Config File: `minutes_to_advance` for section `{section}`"
                                              " must be at least 1")

        ssl_verify = True
        if config.has_option(section, "ssl_verify"):
            try:
                ssl_verify = config.getboolean(section, "ssl_verify")
            except ValueError:
                raise TaxiiConfigurationException(f"Config File: `ssl_verify` for section `{section}`"
                                                  " must be true or false")

        discovery_path = "/services/discovery"
        if config.has_option(section, "discovery_path"):
            discovery_path = config.get(section, "discovery_path")

        collection_management_path = ''
        if config.has_option(section, 'collection_management_path'):
            collection_management_path = config.get(section, 'collection_management_path')

        poll_path = ''
        if config.has_option(section, 'poll_path'):
            poll_path = config.get(section, 'poll_path')

        ca_cert = None
        if config.has_option(section, 'ca_cert'):
            ca_cert = config.get(section, 'ca_cert')

        #
        # Added the ability to limit the number of reports per collection
        #

        # initialized above with a default of 10000
        try:
            reports_limit = config.getint(section, 'reports_limit')
        except ValueError:
            raise TaxiiConfigurationException(f"Config File: `reports_limit` for section `{section}`"
                                              " must be an integer")
        except configparser.NoOptionError:
            reports_limit = 10000
        if reports_limit < 1:
            raise TaxiiConfigurationException(f"Config File: `reports_limit` for section `{section}`"
                                              " must be at least 1")

        _logger.info("Configured Site: %s Path: %s" % (site, output_path))

        sites.append({"site": site,
                      "reset_start_date": reset_start_date,
                      "output_path": output_path,
                      "username": username,
                      "password": password,
                      "collections": collections,
                      "icon_link": icon_link,
                      "feeds_enable": feeds_enable,
                      "ioc_exclusions": ioc_exclusions,
                      "start_date": start_date,
                      "use_https": use_https,
                      "key_file": key_file,
                      "cert_file": cert_file,
                      "minutes_to_advance": minutes_to_advance,
                      "ssl_verify": ssl_verify,
                      "ca_cert": ca_cert,
                      "discovery_path": discovery_path,
                      "collection_management_path": collection_management_path,
                      "poll_path": poll_path,
                      "default_score": default_score,
                      "reports_limit": reports_limit})


    if len(sites) == 0:
        _logger.warning("No sites specified in configuration -- nothing will be done!")
    return {'server_url': server_url,
            'api_token': api_token,
            'sites': sites,
            'http_proxy_url': http_proxy_url,
            'https_proxy_url': https_proxy_url}
