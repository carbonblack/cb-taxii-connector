# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.
################################################################################

import ipaddress
import itertools
from datetime import datetime
from urllib.parse import urlparse, urljoin

from stix2patterns.v21.grammars.STIXPatternListener import STIXPatternListener
from stix2patterns.v21.pattern import Pattern


class IOCPatternParser(object):

    def __init__(self, ioc_type_edr):
        self.edr_ioc_type = ioc_type_edr

    @property
    def key(self):
        return self.edr_ioc_type

    def parse(self, raw_value):
        raise NotImplementedError("must implement parse() in subclasses")


class IPV4Parser(IOCPatternParser):

    def __init__(self):
        super().__init__("ipv4")

    def parse(self, raw_value):
        ioc_value_trimmed = raw_value.strip("'")
        if "/32" in ioc_value_trimmed:
            return ioc_value_trimmed[:-3]
        if "/" not in ioc_value_trimmed:
            return ioc_value_trimmed
        network = ipaddress.IPv4Network(ioc_value_trimmed, strict=False)
        hosts = (format(host) for host in itertools.islice(network.hosts(), 256))
        return hosts


class IPV6Parser(IOCPatternParser):

    def __init__(self):
        super().__init__("ipv6")

    def parse(self, raw_value):
        ioc_value_trimmed = raw_value.strip("'")
        if "/128" in ioc_value_trimmed:
            return ioc_value_trimmed[:-4]
        if "/" not in ioc_value_trimmed:
            return ioc_value_trimmed
        network = ipaddress.IPv6Network(ioc_value_trimmed, strict=False)
        hosts = (format(host) for host in itertools.islice(network.hosts(), 256))
        return hosts


class URLParser(IOCPatternParser):

    def __init__(self):
        super().__init__("dns")

    def parse(self, raw_value):
        ioc_value_trimmed = raw_value.strip("'")
        return urlparse(ioc_value_trimmed).netloc


class DomainParser(IOCPatternParser):

    def __init__(self):
        super().__init__("dns")

    def parse(self, raw_value):
        return raw_value.strip("'")


class MD5Parser(IOCPatternParser):

    def __init__(self):
        super().__init__("md5")

    def parse(self, raw_value):
        return raw_value.strip("'")


class SHA256Parser(IOCPatternParser):

    def __init__(self):
        super().__init__("sha256")

    def parse(self, raw_value):
        return raw_value.strip("'")


class ObjectPathToIOCParserMap(object):
    hash_parsers = {"file:hashes.'SHA-256'": SHA256Parser(),
                    "artifact:hashes.'SHA-256'": SHA256Parser(),
                    "artifact:hashes.'MD5'": MD5Parser(),
                    "file:hashes.'MD5'": MD5Parser()}
    address_parsers = {"ipv4-addr:value": IPV4Parser(), "ipv6-addr:value": IPV6Parser()}
    domain_parsers = {
        'url:value': URLParser(),
        'domain-name:value': DomainParser()}
    DEFAULT_IOC_TYPES = ['address', 'hash', 'domain']

    DEFAULT_ALL_PARSERS = {}
    DEFAULT_ALL_PARSERS.update(hash_parsers)
    DEFAULT_ALL_PARSERS.update(address_parsers)
    DEFAULT_ALL_PARSERS.update(domain_parsers)

    @staticmethod
    def get_parsers_for_ioc_types(ioc_types=None):
        if not ioc_types:
            return ObjectPathToIOCParserMap.DEFAULT_ALL_PARSERS
        parsers = {}
        if 'hash' in ioc_types:
            parsers.update(ObjectPathToIOCParserMap.hash_parsers)
        if 'domain' in ioc_types:
            parsers.update(ObjectPathToIOCParserMap.domain_parsers)
        if 'address' in ioc_types:
            parsers.update(ObjectPathToIOCParserMap.address_parsers)
        return parsers

    def __init__(self, ioc_types=None):
        self._parsers = ObjectPathToIOCParserMap.get_parsers_for_ioc_types(ioc_types)

    def __getitem__(self, item):
        return self._parsers.get(item, None)

    def __contains__(self, item):
        return self[item] is not None


class STIXPatternParser(STIXPatternListener):

    def __init__(self, supported_ioc_types=None):
        self._indicators = {}
        self._ioc_map = ObjectPathToIOCParserMap(supported_ioc_types)

    def enterPattern(self, ctx):
        self._indicators = {}

    def enterPropTestEqual(self, ctx):
        parts = [child.getText() for child in ctx.getChildren()]
        if parts and len(parts) == 3:
            current_ioc_key = parts[0]
            parser = self._ioc_map[current_ioc_key]
            if parser:
                parsed_iocs = parser.parse(parts[2])
                self._add_ioc(parser.key, parsed_iocs)

    def _add_ioc(self, key, value):
        if key in self._indicators:
            self._add_existing(key, value)
        else:
            self._add_new(key, value)

    def _add_existing(self, key, value):
        if isinstance(value, str):
            self._indicators[key].add(value)
        else:
            self._indicators[key].update(value)

    def _add_new(self, key, value):
        if isinstance(value, str):
            self._indicators[key] = {value}
        else:
            self._indicators[key] = set(value)

    @property
    def iocs(self):
        return self._indicators


# [{'created': '2014-05-08T09:00:00.000Z', 'id': 'indicator--cd981c25-8042-4166-8945-51178443bdac',
#   'indicator_types': ['file-hash-watchlist'], 'modified': '2014-05-08T09:00:00.000Z',
#   'name': 'File hash for Poison Ivy variant',
#   'pattern': "[file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c']",
#   'pattern_type': 'stix', 'spec_version': '2.1', 'type': 'indicator', 'valid_from': '2014-05-08T09:00:00.000000Z'},
class STIXIndicator(object):
    _TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
    _TIMESTAMP_FORMAT_FRAC = "%Y-%m-%dT%H:%M:%S.%fZ"

    @staticmethod
    def strptime(string_timestamp):
        if "." in string_timestamp:
            return datetime.strptime(string_timestamp, STIXIndicator._TIMESTAMP_FORMAT_FRAC)
        else:
            return datetime.strptime(string_timestamp, STIXIndicator._TIMESTAMP_FORMAT)

    def __init__(self, obj, collection_url, default_score=100, pattern_parser=None):
        self._id = obj['id']
        self._description = obj.get("description", "")
        self._created = STIXIndicator.strptime(obj["created"])
        self._pattern = Pattern(obj["pattern"])
        self._name = obj.get('name', None) or obj.get('description', None) or self.id
        self.score = default_score
        self.url = urljoin(collection_url, f"objects/{self.id}")
        self._report = None
        self.stix_patern_parser = pattern_parser if pattern_parser else STIXPatternParser()

    @property
    def report(self):
        if not self._report:
            self._report = self._create_threat_report()
        return self._report

    @property
    def name(self):
        return self._name

    @property
    def id(self):
        return self._id

    @property
    def description(self):
        return self._description

    @property
    def created(self):
        return self._created

    @property
    def pattern(self):
        return self._pattern

    def _create_threat_report(self):
        """
        {
            "timestamp": 1380773388,
            "iocs": {
                "ipv4": [
                    "100.2.142.8"
                ]
            },
            "link": "https://www.dan.me.uk/tornodes",
            "id": "TOR-Node-100.2.142.8",
            "title": "As of Wed Oct  2 20:09:48 2013 GMT, 100.2.142.8 has been a TOR exit for 26 days, 0:44:42. Contact: Adam Langley <agl@imperialviolet.org>",
            "score": 50
        },
        """
        self.pattern.walk(self.stix_patern_parser)
        report = {"timestamp": int(self.created.timestamp()), "id": self.id, "title": self.name,
                  "iocs": self.stix_patern_parser.iocs, "score": self.score, "link": self.url}
        return report if self.stix_patern_parser.iocs else None
