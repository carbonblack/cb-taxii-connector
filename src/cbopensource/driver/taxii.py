import json
import logging
from datetime import datetime
from itertools import chain
from urllib.parse import urlparse

from stix2patterns.pattern import Pattern
from stix2patterns.v21.grammars.STIXPatternListener import STIXPatternListener
from taxii2client.common import TokenAuth
from taxii2client.v21 import Server, as_pages

logger = logging.getLogger(__name__)


class IOCPatternParser(STIXPatternListener):
    SUPPORTED_OBJECT_PATHS = {"ipv4-addr:value": "ipv4", "ipv6-addr:value": "ipv6", "file:hashes.'SHA-256'": "sha256",
                              "file:hashes.'MD5'": "md5", 'url:value': "dns"}

    def __init__(self):
        self._iocs = {}

    def enterPropTestEqual(self, ctx):
        logger.debug(ctx.getText())
        parts = [child.getText() for child in ctx.getChildren()]
        if parts and parts[0] in IOCPatternParser.SUPPORTED_OBJECT_PATHS:
            self._add_parts_to_iocs(parts)

    def _add_parts_to_iocs(self, parts):
        ioc_key = IOCPatternParser.SUPPORTED_OBJECT_PATHS[parts[0]]
        ioc_value = parts[2][1:-2] if ioc_key != "dns" else urlparse(parts[2][1:-2]).netloc
        self._add_ioc(ioc_key, ioc_value)

    def _add_ioc(self, key, value):
        if key in self._iocs:
            self._iocs[key].add(value)
        else:
            self._iocs[key] = {value}

    @property
    def iocs(self):
        return self._iocs


# [{'created': '2014-05-08T09:00:00.000Z', 'id': 'indicator--cd981c25-8042-4166-8945-51178443bdac', 'indicator_types': ['file-hash-watchlist'], 'modified': '2014-05-08T09:00:00.000Z', 'name': 'File hash for Poison Ivy variant', 'pattern': "[file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c']", 'pattern_type': 'stix', 'spec_version': '2.1', 'type': 'indicator', 'valid_from': '2014-05-08T09:00:00.000000Z'},
class TaxiiIndicator(object):
    _TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

    def __init__(self, obj, collection_url, default_score=100):
        self._id = obj['id']
        self._description = obj.get("description", "")
        self._created = datetime.strptime(obj['created'], TaxiiIndicator._TIMESTAMP_FORMAT)
        self._pattern = Pattern(obj["pattern"])
        self._name = obj['name']
        self.score = default_score
        self.url = collection_url + "objects/" + self.id
        self._report = None

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
        ioc_listener = IOCPatternParser()
        self.pattern.walk(ioc_listener)
        report = {"timestamp": int(self.created.timestamp()), "id": self.id, "title": self.name,
                  "iocs": ioc_listener.iocs, "score": self.score, "link": self.url}
        return report


class TaxiiConfigurationException(Exception):
    def __init__(self, msg):
        super(TaxiiConfigurationException).__init__(msg)


class TaxiiIndicatorCollection(object):
    def __init__(self, base_collection, score):
        self._base_collection = base_collection
        self._score = score

    def __getattr__(self, item):
        return self._base_collection.__getattribute__(item)

    def _paginated_indicator_request(self, pagination=10, added_after=None):
        if added_after:
            as_pages(self.get_objects, per_request=pagination, type=['indicator'], added_after=added_after)
        return as_pages(self.get_objects, per_request=pagination, type=['indicator'])

    def stream_indicators(self, added_after=None, pagination=10):
        for page in self._paginated_indicator_request(pagination, added_after):
            if page and 'objects' in page:
                for obj in page['objects']:
                    yield TaxiiIndicator(obj, default_score=self._score, collection_url=self.url).report


class TaxiiServer(object):
    def __init__(self, server_config, default_score=50, pagination_count=10):
        server_kwargs = {}
        if "token" in server_config:
            server_kwargs["auth"] = TokenAuth(server_config["token"])
        elif 'username' in server_config and 'password' in server_config:
            server_kwargs["user"] = server_config["username"]
            server_kwargs['password'] = server_config["password"]
        if 'url' in server_config:
            server_kwargs["url"] = server_config["url"]
        else:
            raise TaxiiConfigurationException("Must provide url for each server")
        self._score = server_config['score'] if 'score' in server_config else default_score
        self._pagination_count = pagination_count
        self._server = Server(**server_kwargs)
        self._collections = None

    def _get_collections(self):
        return [TaxiiIndicatorCollection(collection, score=self._score) for api_root in self.api_roots for collection in
                api_root.collections if collection.can_read]

    @property
    def collections(self):
        if not self._collections:
            self._collections = self._get_collections()
        return self._collections

    def verify_connected(self):
        try:
            self.refresh()
            logger.info(f"Connected to server {self.title}")
        except Exception:
            logger.error("Unable to connect to server...")
            raise Exception

    def __getattr__(self, item):
        return self._server.__getattribute__(item)


class TaxiiDriver(object):

    def __init__(self, servers):
        self._servers = (TaxiiServer(server) for server in servers)

    @property
    def servers(self):
        return self._servers

    def test_connections(self):
        for server in self.servers:
            server.verify_connected()

    def generate_reports(self):
        return chain(*[collection.stream_indicators() for server in self.servers for collection in server.collections])

    def write_reports(self, stream):
        reports = self.generate_reports()
        for report in reports:
            stream.write(report)
        return stream.complete

