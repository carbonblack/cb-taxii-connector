# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.
################################################################################

import logging
from itertools import chain
from typing import Dict, List

from taxii2client.v21 import as_pages

from cbopensource.driver.taxii_parser import STIXIndicator, STIXPatternParser
from cbopensource.driver.taxii_server_config import ServerVersion

logger = logging.getLogger(__name__)


class TaxiiIndicatorCollection(object):
    """
    This class manages the how we deal with TAXII information.
    """

    def __init__(self, base_collection, score: int, parser: STIXPatternParser = None, pagination: int = 10):
        """
        Initialize the class.

        :param base_collection: TODO: type and/or describe
        :param score: the feed score
        :param parser: STIX pattern parser to use (or derivative)
        :param pagination: feeds per page
        """
        self._base_collection = base_collection
        self._score = score
        self._pagination = pagination
        self._parser = parser if parser else STIXPatternParser()

    def __getattr__(self, item):
        return self._base_collection.__getattribute__(item)

    # ----------------------------------------------------------------------

    def _paginated_indicator_request(self, added_after=None):
        """
        Internal method to get reports.

        :param added_after:
        :return:
        """
        if added_after:
            as_pages(self.get_objects, per_request=self._pagination, type=['indicator'], added_after=added_after)
        return as_pages(self.get_objects, per_request=self._pagination, type=['indicator'])

    # ----------------------------------------------------------------------

    def stream_indicators(self, added_after=None):
        for page in self._paginated_indicator_request(added_after):
            if page and 'objects' in page:
                for obj in page['objects']:
                    if has_stix_pattern_type(obj):
                        try:
                            report = STIXIndicator(obj, default_score=self._score, collection_url=self.url,
                                                   pattern_parser=self._parser).report
                            if report:
                                yield report
                        except Exception as ex:
                            logger.debug(f"Error parsing STIX indicator: {ex}")


def has_stix_pattern_type(obj: Dict) -> bool:
    """
    Determine if this has a stix pattern.

    :param obj:
    :return: True if stix pattern type and pattern exists
    """
    return obj.get("pattern_type", "stix") == "stix" and obj.get("pattern", None) is not None


class TaxiiServer(object):

    def __init__(self, ioc_types=None, score: int = 50, pagination: int = 100, collections=None, version: int = None,
                 **kwargs):
        """
        Initialize the class.

        :param ioc_types:
        :param score: feed score to use
        :param pagination: feed pagination
        :param collections: list of collections
        :param version: server version to use
        :param kwargs: other optional parameters
        """
        self._score = score
        self._pagination_count = pagination
        self._server = ServerVersion.get_server_for_version(version)(**kwargs)
        self._collection_ids = {collection: True for collection in collections} if collections is not None else {}
        self._collections = None
        self._ioc_types = ioc_types

    @staticmethod
    def get_server_from_conf(config: dict) -> 'TaxiiServer':
        """
        Return a TaxiiServer object based on th supplied server configuration.

        :param config: server config in Dict form
        :return: TaxiiServer() object
        """
        server = TaxiiServer(**config)
        server.verify_connected()
        return server

    def _get_collections(self):
        all_collections = self._get_all_collections()
        return filter(lambda collection: collection.id in self._collection_ids,
                      all_collections) if self._collection_ids else all_collections

    def _get_all_collections(self):
        collections = []
        for api_root in self.api_roots:
            for collection in api_root.collections:
                if collection.can_read:
                    collections.append(TaxiiIndicatorCollection(collection, score=self._score,
                                                                pagination=self.pagination_count,
                                                                parser=STIXPatternParser(self._ioc_types)))
        return collections

    @property
    def collections(self):
        if not self._collections:
            self._collections = self._get_collections()
        return self._collections

    def verify_connected(self):
        try:
            self.refresh()
            logger.info(f"Connected to server {self.title}")
        except Exception as ex:
            logger.error(f"Unable to connect to server... {ex}")
            raise Exception

    def __getattr__(self, item):
        return self._server.__getattribute__(item)

    @property
    def pagination_count(self) -> int:
        """Return the current pagenation count setting."""
        return self._pagination_count


class TaxiiDriver(object):
    """
    This class manages the actual TAXII driver.
    """

    def __init__(self, servers: List[Dict]):
        """
        Initialize the class.

        :param servers: list of server configurations, in dict form
        """
        self._servers = [TaxiiServer.get_server_from_conf(server) for server in servers]

    @property
    def servers(self) -> List[TaxiiServer]:
        """Return the list of server configurations."""
        return self._servers

    def test_connections(self) -> None:
        """
        Verify that all servers can be connected to.
        """
        for server in self.servers:
            server.verify_connected()

    @property
    def collections(self):
        """Return list of server collections."""
        return list(collection for server in self.servers for collection in server.collections)

    def generate_reports(self):
        return chain(
            *[collection.stream_indicators() for collection in self.collections])

    def write_reports(self, stream):
        reports = self.generate_reports()
        for report in reports:
            stream.write(report)
        stream.complete = True
        return True
