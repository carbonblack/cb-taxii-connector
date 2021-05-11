import errno
import gc
import logging
import os
import shutil
import textwrap
import threading
# noinspection PyProtectedMember
from timeit import default_timer as timer

import cbint.utils.feed
import simplejson as json
from jinja2 import Template

_logger = logging.getLogger(__name__)


class SetEncoder(json.JSONEncoder):
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

    def __init__(self, config, location, lock=None):
        self._config = config
        self._location = location
        self._internal_lock = not lock
        self._lock = lock or threading.RLock()
        self._exists = False

    # noinspection PyUnusedFunction
    @property
    def lock(self):
        """This is the mutex used to access the cache file."""
        return self._lock

    @property
    def location(self):
        return self._location

    @property
    def file_name(self):
        return self._feed_cache_file

    def _ensure_location_exists(self):
        """This was taken from cbint.utils.filesystem to reduce the imports."""
        if not os.path.exists(self._location):
            try:
                os.makedirs(self._location)
            except OSError as exception:
                if exception.errno != errno.EEXIST:
                    raise

    def _swap_file_cache(self):
        with self._lock:
            # This is a quick operation that will not leave the file in an invalid state.
            shutil.move(os.path.join(self._location, self._feed_cache_new_file),
                        os.path.join(self._location, self._feed_cache_file))

    def __del__(self):
        if self._internal_lock:
            del self._lock
        del self._config
        del self._location


class FeedStreamBase(object):
    """A Feed Stream is used to save a feed bit by bit instead of all at once."""

    def __init__(self):
        self._complete = False
        self._report_count = 0
        self._ioc_count = 0

    def __enter__(self):
        self.open()
        return self

    def open(self):
        raise NotImplementedError()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        raise NotImplementedError()

    @property
    def complete(self):
        """
        Determines if feed storage has completed.  If this is not set to true by the time close() or __exit() is called,
        it is assumed the writing of the feed was not completed and therefore is scrapped.
        """
        return self._complete

    @complete.setter
    def complete(self, value):
        self._complete = value

    @property
    def report_count(self):
        return self._report_count

    @property
    def ioc_count(self):
        return self._ioc_count

    def write(self, report):
        raise NotImplementedError()


class FeedStream(FeedCacheBase, FeedStreamBase):
    """Allows reports to be written in a streamed way instead of all at once to save memory."""

    _feed_header_template = Template(textwrap.dedent("""
        ],
        "feedinfo": {
            "category": "Partner",
            "provider_url": "http://www.taxii.com/",
            "display_name": "{{display_name}}",
            "name": "taxiiintegration",
            "tech_data": "There are no requirements to share any data to receive this feed.",
            "summary": "Threat intelligence data provided by taxii to the VMware Carbon Black Community",
            "icon_small": "{{icon_small}}",
            "icon": "{{icon}}",
            "num_reports": {{num_reports}}
        }
        }"""))

    def __init__(self, config, location, lock):
        FeedCacheBase.__init__(self, config, location, lock)
        FeedStreamBase.__init__(self)
        self._file = None

    def open(self):
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

    def close(self):
        if not self._file:
            raise IOError("Stream must be opened before it can be closed.")
        try:
            self._file.write(self._feed_header_template.render(
                display_name=self._config.display_name,
                icon_small=cbint.utils.feed.generate_icon(
                    "{}/{}".format(self._config.directory, self._config.integration_image_small_path)),
                icon=cbint.utils.feed.generate_icon(
                    "{}/{}".format(self._config.directory, self._config.integration_image_path)),
                num_reports=self._report_count
            ))
        finally:
            self._file.close()
            self._file = None
        if self._complete:
            self._swap_file_cache()

    def write(self, report):
        if not self._file:
            raise IOError("Stream must be opened before it can be written to.")
        report_text = json.dumps(report, indent=2 if self._config.pretty_print_json else None, cls=SetEncoder)
        self._file.write("{}\n{}".format("," if self._report_count else "", report_text))

        self._report_count += 1
        for ioc_list in report["iocs"].values():
            self._ioc_count += len(ioc_list)


class FeedCache(FeedCacheBase):
    """Manages the feed data that is cached on disk.

    Going forward, instead of keeping a feed in memory, it is now stored on disk.  This is to reduce memory
    footprint of long running process.
    """

    def __init__(self, config, location, lock):
        super(FeedCache, self).__init__(config, location, lock)

    def verify(self):
        """Checks to see if the feed cache exists on disk.
        Once it is determined to exist, it is never checked again.
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

    @property
    def exists(self):
        return self.verify()

    def generate_feed(self, reports=None):
        """
        Generate a feed definition.
        :param reports: list of report definitions
        :return: defined feed
        """
        reports = list(reports)
        feed = cbint.utils.feed.generate_feed(
            self._config.feed_name,
            summary="Threat intelligence data provided by taxii to the VMware Carbon Black Community",
            tech_data="There are no requirements to share any data to receive this feed.",
            provider_url="https://www.oasis-open.org/",
            icon_path="{}/{}".format(self._config.directory, self._config.integration_image_path),
            small_icon_path="{}/{}".format(self._config.directory, self._config.integration_image_small_path),
            display_name=self._config.display_name,
            category="Partner")
        feed['reports'] = reports
        feed['feedinfo']['num_reports'] = len(reports)
        return feed

    def write_reports(self, reports):
        self._ensure_location_exists()
        feed = self.generate_feed(reports)
        success = self.write_feed(feed)
        del feed
        gc.collect()
        return success

    def write_feed(self, feed):
        _logger.debug("Writing to feed cache.")
        write_start = timer()
        try:
            self._ensure_location_exists()
            with open(os.path.join(self._location, self._feed_cache_new_file), "w") as f:
                if self._config.pretty_print_json:
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

    def read(self, as_text=False):
        if not self.exists:
            return None
        with self._lock:
            try:
                with open(os.path.join(self._location, self._feed_cache_file), "r") as f:
                    return f.read() if as_text else json.loads(f.read())
            except (IOError, OSError) as e:
                _logger.exception("Could not read from feed cache: {0}".format(e))
        return None

    def create_stream(self):
        return FeedStream(self._config, self._location, self._lock)
