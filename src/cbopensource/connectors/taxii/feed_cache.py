# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.
################################################################################

import errno
import gc
import logging
import os
import shutil
import textwrap
import threading
# noinspection PyProtectedMember
from timeit import default_timer as timer
from typing import Dict, List, Optional, Union

import cbint.utils.feed
import simplejson as json
from jinja2 import Template

from cbopensource.connectors.taxii.taxii_connector_config import TaxiiConnectorConfiguration

_logger = logging.getLogger(__name__)


class SetEncoder(json.JSONEncoder):
    """
    Class to handle JSON encoding of sets.
    """

    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


class FeedCacheBase(object):
    """Manages the feed data that is cached on disk.

    Going forward, instead of keeping a feed in memory, it is now stored on disk.  This is to reduce memory
    footprint of long running process.
    """
    _feed_cache_new_file = "feed.cache_new"
    _feed_cache_file = "feed.cache"
    # noinspection PyUnusedName
    _reports_cache_file = "reports.cache"

    def __init__(self, config: TaxiiConnectorConfiguration, location: str, lock=None):
        """
        Initialize the class.

        :param config: taxii configuration object
        :param location: location of the cache
        :param lock: lock function (default threading.RLock())
        """
        self._config = config
        self._location = location
        self._internal_lock = not lock
        self._lock = lock or threading.RLock()
        self._exists = False

    def __del__(self):
        if self._internal_lock:
            del self._lock
        del self._config
        del self._location

    # ----------------------------------------------------------------------

    # noinspection PyUnusedFunction
    @property
    def lock(self):
        """
        :return: the mutex lock used for the cache
        """
        return self._lock

    @property
    def location(self) -> str:
        """
        :return: the location of the cache
        """
        return self._location

    @property
    def file_name(self) -> str:
        """
        :return: the name of the cache file
        """
        return self._feed_cache_file

    def _ensure_location_exists(self) -> None:
        """
        Private method to ensure that the cache location exists, creating if need be.

        NOTE: This was taken from cbint.utils.filesystem to reduce the imports.
        """
        if not os.path.exists(self._location):
            try:
                os.makedirs(self._location)
            except OSError as exception:
                if exception.errno != errno.EEXIST:
                    raise

    def _swap_file_cache(self) -> None:
        """
        Private method to swap feed cacahes.
                """
        with self._lock:
            # This is a quick operation that will not leave the file in an invalid state.
            shutil.move(os.path.join(self._location, self._feed_cache_new_file),
                        os.path.join(self._location, self._feed_cache_file))


class FeedStreamBase(object):
    """
    A Feed Stream is used to save a feed bit by bit instead of all at once.
    """

    def __init__(self):
        """
        Initialize the class.
        """
        self._complete = False
        self._report_count = 0
        self._ioc_count = 0

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # ----------------------------------------------------------------------

    @property
    def complete(self) -> bool:
        """
        Determines if feed storage has completed.  If this is not set to true by the time close() or __exit() is called,
        it is assumed the writing of the feed was not completed and therefore is scrapped.
        """
        return self._complete

    @complete.setter
    def complete(self, value: bool) -> None:
        """
        Set the Complete state.

        :param value: the new value
        """
        self._complete = value

    @property
    def report_count(self) -> int:
        """
        :return: number of reports
        """
        return self._report_count

    @property
    def ioc_count(self) -> int:
        """
        :return: number of iocs
        """
        return self._ioc_count

    # ----------------------------------------------------------------------

    def open(self) -> None:
        raise NotImplementedError()

    def close(self) -> None:
        raise NotImplementedError()

    def write(self, report):
        raise NotImplementedError()


class FeedStream(FeedCacheBase, FeedStreamBase):
    """
    Allows reports to be written in a streamed way instead of all at once to save memory.
    """

    _feed_header_template = Template(textwrap.dedent("""
        ],
        "feedinfo": {
            "category": "Partner",
            "provider_url": "https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti",
            "display_name": "{{display_name}}",
            "name": "taxiiintegration",
            "tech_data": "There are no requirements to share any data to receive this feed.",
            "summary": "Threat intelligence data provided by taxii to the VMware Carbon Black Community",
            "icon_small": "{{icon_small}}",
            "icon": "{{icon}}",
            "num_reports": {{num_reports}}
        }
        }"""))

    def __init__(self, config: TaxiiConnectorConfiguration, location: str, lock):
        FeedCacheBase.__init__(self, config, location, lock)
        FeedStreamBase.__init__(self)

        # the file stream
        self._file = None

    def open(self) -> None:
        """
        Open a new file for streaming.
        """
        if self._file:
            raise IOError("Stream is already open.  Cannot open a new stream until this one is closed.")

        self._report_count = 0
        self._ioc_count = 0
        self._complete = False

        self._ensure_location_exists()
        self._file = open(os.path.join(self._location, self._feed_cache_new_file), "w")

        # We have to write the reports first and then the feed info because the number of reports is not yet known.
        self._file.write(textwrap.dedent("""
            {
            "reports":
            ["""))

    def close(self) -> None:
        """
        Close the currently open stream file.
        """
        if not self._file:
            raise IOError("Stream must be opened before it can be closed.")

        try:
            self._file.write(self._feed_header_template.render(
                display_name=self._config.DISPLAY_NAME,
                icon_small=cbint.utils.feed.generate_icon(
                    "{}/{}".format(self._config.DIRECTORY, self._config.INTEGRATION_IMAGE_SMALL_PATH)),
                icon=cbint.utils.feed.generate_icon(
                    "{}/{}".format(self._config.DIRECTORY, self._config.INTEGRATION_IMAGE_PATH)),
                num_reports=self._report_count
            ))
        finally:
            self._file.close()
            self._file = None

        if self._complete:
            self._swap_file_cache()

    def write(self, report: Dict) -> None:
        """
        Write a report top the current stream file.

        :param report: feed report to add
        """
        if not self._file:
            raise IOError("Stream must be opened before it can be written to.")

        report_text = json.dumps(report, indent=2 if self._config['pretty_print_json'] else None, cls=SetEncoder)
        self._file.write(f"{',' if self._report_count else ''}\n{report_text}")

        self._report_count += 1
        for ioc_list in report["iocs"].values():
            self._ioc_count += len(ioc_list)


class FeedCache(FeedCacheBase):
    """
    Manages the feed data that is cached on disk.

    Going forward, instead of keeping a feed in memory, it is now stored on disk.  This is to reduce memory
    footprint of long running process.
    """

    def __init__(self, config: TaxiiConnectorConfiguration, location: str, lock):
        super(FeedCache, self).__init__(config, location, lock)

    # ----------------------------------------------------------------------

    @property
    def exists(self):
        """
        :return: True if cache exists
        """
        return self.verify()

    # ----------------------------------------------------------------------

    def verify(self) -> bool:
        """
        Checks to see if the feed cache exists on disk.
        Once it is determined to exist, it is never checked again.

        :return: True if it exists
        """
        if self._exists:
            return True

        self._ensure_location_exists()
        with self._lock:
            if not os.path.isfile(os.path.join(self._location, "feed.cache")):
                if os.path.isfile(os.path.join(self._location, "reports.cache")):
                    _logger.warning("Feed cache file missing.  Reading report cache to create feed.")
                    try:
                        with open(os.path.join(self._location, "reports.cache"), "r") as f:
                            reports = json.loads(f.read())
                            if self.write_reports(reports):
                                self._exists = True
                    except (IOError, OSError) as e:
                        _logger.warning("Could not read from reports cache: {0}".format(e))
                else:
                    _logger.warning("Feed cache and report cache missing.  Instance appears new.")
            else:
                self._exists = True
        gc.collect()
        return self._exists

    def generate_feed(self, reports: List[Dict] = None) -> Dict:
        """
        Generate a feed definition.

        :param reports: list of report definitions
        :return: defined feed
        """
        reports = list(reports)
        feed = cbint.utils.feed.generate_feed(
            self._config.FEED_NAME,
            summary="Threat intelligence data provided by taxii to the VMware Carbon Black Community",
            tech_data="There are no requirements to share any data to receive this feed.",
            provider_url="https://www.oasis-open.org/",
            icon_path=f"{self._config.DIRECTORY}/{self._config.INTEGRATION_IMAGE_PATH}",
            small_icon_path=f"{self._config.DIRECTORY}/{self._config.INTEGRATION_IMAGE_SMALL_PATH}",
            display_name=self._config.DISPLAY_NAME,
            category="Partner")
        feed['reports'] = reports
        feed['feedinfo']['num_reports'] = len(reports)
        return feed

    def write_reports(self, reports: List[Dict]) -> bool:
        """
        Write feed and reports to disk.

        :param reports:
        :return: True if successful
        """
        self._ensure_location_exists()
        feed = self.generate_feed(reports)
        success = self.write_feed(feed)
        del feed
        gc.collect()
        return success

    def write_feed(self, feed: Dict) -> bool:
        """
        Write a feed object to file.

        :param feed: feed to be written
        :return: True if successful
        """
        _logger.debug("Writing to feed cache.")
        write_start = timer()
        try:
            self._ensure_location_exists()
            with open(os.path.join(self._location, self._feed_cache_new_file), "w") as f:
                if self._config['pretty_print_json']:
                    f.write(json.dumps(feed, indent=2, cls=SetEncoder))
                else:
                    f.write(json.dumps(feed, cls=SetEncoder))
                del feed
            self._swap_file_cache()
            self._exists = True
            _logger.debug("Finished writing feed to cache ({0:.3f} seconds).".format(timer() - write_start))

        except (IOError, OSError) as e:
            _logger.error("Failed to write to feed cache: {}".format(e))
            return False
        return True

    def read(self, as_text: bool = False) -> Optional[Union[str, Dict]]:
        """
        Read a feed from the file cache.

        :param as_text: If True, return as text instead of object
        :return: feed information as text or feed dictionary
        """
        if not self.exists:
            return None
        with self._lock:
            try:
                with open(os.path.join(self._location, self._feed_cache_file), "r") as f:
                    return f.read() if as_text else json.loads(f.read())
            except (IOError, OSError) as e:
                _logger.exception("Could not read from feed cache: {0}".format(e))
        return None

    def create_stream(self) -> FeedStream:
        """
        Create a new feed stream.

        :return: FeedStream() object
        """
        return FeedStream(self._config, self._location, self._lock)
