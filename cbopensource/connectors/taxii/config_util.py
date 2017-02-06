import logging
import ConfigParser
import os
import sys

logger = logging.getLogger(__name__)


def parse_config(config_file_path):

    config = ConfigParser.ConfigParser()
    if not os.path.exists(config_file_path):
        logger.error("Config File: {} does not exist".format(config_file_path))
        sys.exit(-1)

    config.read(config_file_path)

    server_url = "https://127.0.0.1"
    if config.has_section("cbconfig"):
        if config.has_option("cbconfig", "server_url"):
            server_url = config.get("cbconfig", "server_url")

    api_token = None
    if config.has_option("cbconfig", "auth_token"):
        api_token = config.get("cbconfig", "auth_token")

    sites = []

    for section in config.sections():
        #
        # exclude cbconfig stanza
        #
        if section.lower() == 'cbconfig':
            continue

        #
        # get site and strip off preceeding http(s):// if necessary
        #
        site = config.get(section, "site").lower()

        #
        # Sanity check
        #
        if site.startswith("https://"):
            site = site[8:]

        if site.startswith("http://"):
            site = site[7:]

        if site.endswith("/"):
            site = site.strip("/")

        output_path = config.get(section, "output_path")
        icon_link = config.get(section, "icon_link")
        username = config.get(section, "username")
        password = config.get(section, "password")
        feeds_enable = config.getboolean(section, "feeds_enable")
        collections = config.get(section, "collections") if config.has_option(section, "collections") else "*"

        if config.has_option(section, "start_date"):
            start_date = config.get(section, "start_date")
        else:
            start_date = "2016-12-01 00:00:00"

        if config.has_option(section, "use_https"):
            use_https = config.getboolean(section, "use_https")
        else:
            use_https = False

        cert_file = None
        key_file = None

        if config.has_option(section, "cert_file") and config.has_option(section, "key_file"):
            cert_file = config.get(section, "cert_file").strip()
            if cert_file == "":
                cert_file = None
            elif not os.path.exists(cert_file):
                logger.error("Cert file supplied but doesn't exist: %s" % (cert_file))

            key_file = config.get(section, "key_file").strip()
            if key_file == "":
                cert_file = None
            elif not os.path.exists(key_file):
                logger.error("Key file supplied but doesn't exist: %s" % (key_file))

        if config.has_option(section, "minutes_to_advance"):
            minutes_to_advance = int(config.get(section, "minutes_to_advance"))
        else:
            minutes_to_advance = 60

        ssl_verify = True
        if config.has_option(section, "ssl_verify"):
            ssl_verify = config.getboolean(section, "ssl_verify")

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

        logger.info("Configured Site: %s Path: %s" % (site, output_path))

        sites.append({"site": site,
                      "output_path": output_path,
                      "username": username,
                      "password": password,
                      "collections": collections,
                      "icon_link": icon_link,
                      "feeds_enable": feeds_enable,
                      "start_date": start_date,
                      "use_https": use_https,
                      "key_file": key_file,
                      "cert_file": cert_file,
                      "minutes_to_advance": minutes_to_advance,
                      "ssl_verify": ssl_verify,
                      "ca_cert": ca_cert,
                      "discovery_path": discovery_path,
                      "collection_management_path": collection_management_path,
                      "poll_path": poll_path})

        return {'server_url': server_url, 'api_token': api_token, 'sites': sites}
