#
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.
#

import functools
import gc
import logging
import os
import signal
import sys
import threading
import time
import traceback
from logging.handlers import RotatingFileHandler
from multiprocessing import Process, Value
from time import gmtime, strftime
# noinspection PyProtectedMember
from timeit import default_timer as timer
import cbint
from cbint.utils import cbserver, feed, flaskfeed
import flask
import simplejson
from cbapi.errors import ServerError
from cbapi.example_helpers import get_object_by_name_or_id
from cbapi.response import CbResponseAPI, Feed
from cbint.utils.daemon import CbIntegrationDaemon

from cbopensource.driver.taxii import TaxiiDriver
from cbopensource.constant import MiB
from . import version
from .config import Config
from .feed_cache import FeedCache

sys.modules['json'] = simplejson

logger = logging.getLogger(__name__)


# noinspection PySameParameterValue
def log_option_value(label, value, padding=27):
    logger.info("{0:{2}}: {1}".format(label, value, padding))


class TimeStamp(object):
    def __init__(self, stamp=False):
        self._value = gmtime() if stamp else None

    def stamp(self):
        """
        Stamps the value of this TimeStamp with the current time.
        """
        self._value = gmtime()

    # noinspection PyUnusedFunction
    def clone(self):
        ts = TimeStamp()
        ts._value = self._value
        return ts

    def __str__(self):
        if not self._value:
            return "Never"
        return strftime("%a, %d %b %Y %H:%M:%S +0000", self._value)

    def __repr__(self):
        return "TimeStamp({0})".format(self.__str__())


def return_value_to_shared_value(func):
    @functools.wraps(func)
    def wrapped_func(*args, **kwargs):
        shared_return = kwargs.pop("shared_return", None)
        returned_value = func(*args, **kwargs)
        if shared_return:
            shared_return.value = returned_value
        return returned_value

    return wrapped_func


class CarbonBlackTaxiiBridge(CbIntegrationDaemon):
    def __init__(self, name, configfile, logfile=None, pidfile=None, debug=False):

        CbIntegrationDaemon.__init__(self, name, configfile=configfile, logfile=logfile, pidfile=pidfile, debug=debug)

        # noinspection PyUnresolvedReferences
        self.flask_feed = cbint.utils.flaskfeed.FlaskFeed(__name__, False, Config.directory)
        self._config = None
        self.taxii_servers = []
        self.api_urns = {}
        self.validated_config = False
        self.cb = None
        self.sync_needed = False
        self.feed_lock = threading.RLock()
        self.logfile = logfile
        self.debug = debug
        self._log_handler = None
        self.logger = logger
        self.process = None
        self.feed_cache = None

        self.flask_feed.app.add_url_rule(Config.cb_image_path, view_func=self.handle_cb_image_request)
        self.flask_feed.app.add_url_rule(Config.integration_image_path,
                                         view_func=self.handle_integration_image_request)
        self.flask_feed.app.add_url_rule(Config.json_feed_path, view_func=self.handle_json_feed_request,
                                         methods=['GET'])
        self.flask_feed.app.add_url_rule("/", view_func=self.handle_index_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/feed.html", view_func=self.handle_html_feed_request, methods=['GET'])

        self.initialize_logging()

        logger.debug("generating feed metadata")

        with self.feed_lock:
            self.last_sync = TimeStamp()
            self.last_successful_sync = TimeStamp()
            self.feed_ready = False

        signal.signal(signal.SIGTERM, self._sigterm_handler)

    def initialize_logging(self):
        if not self.logfile:
            log_path = "/var/log/cb/integrations/%s/" % self.name
            cbint.utils.filesystem.ensure_directory_exists(log_path)
            self.logfile = "%s%s.log" % (log_path, self.name)

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        root_logger.handlers = []

        rlh = RotatingFileHandler(self.logfile, maxBytes=10 * MiB, backupCount=10)
        rlh.setFormatter(logging.Formatter(fmt="%(asctime)s - %(levelname)-7s - %(module)s - %(message)s"))
        self._log_handler = rlh
        root_logger.addHandler(rlh)

        self.logger = root_logger

    @property
    def integration_name(self):
        return 'Cb Taxii Connector {0}'.format(version.__version__)

    def serve(self):
        if self._config.https_proxy:
            os.environ['HTTPS_PROXY'] = self._config.https_proxy
            os.environ['no_proxy'] = '127.0.0.1,localhost'

        address = self._config.listen_address
        port = self._config.listen_port
        logger.info("starting flask server: %s:%s" % (address, port))
        self.flask_feed.app.run(port=port, debug=self.debug,
                                host=address, use_reloader=False)

    def handle_json_feed_request(self):
        self._report_memory_usage("hosting")
        return flask.send_from_directory(self.feed_cache.location, self.feed_cache.file_name,
                                         mimetype='application/json')

    def handle_html_feed_request(self):
        feed = self.feed_cache.read()
        if not feed:
            return flask.Response(status=404)

        html = self.flask_feed.generate_html_feed(feed, self._config.display_name)
        del feed
        gc.collect()
        return html

    def handle_index_request(self):
        with self.feed_lock:
            index = self.flask_feed.generate_html_index(self.feed_cache.generate_feed(), self._config.options,
                                                        self._config.display_name, self._config.cb_image_path,
                                                        self._config.integration_image_path,
                                                        self._config.json_feed_path, str(self.last_sync))
        return index

    def handle_cb_image_request(self):
        return self.flask_feed.generate_image_response(image_path="%s%s" % (self._config.directory,
                                                                            self._config.cb_image_path))

    def handle_integration_image_request(self):
        return self.flask_feed.generate_image_response(image_path="%s%s" %
                                                                  (self._config.directory,
                                                                   self._config.integration_image_path))

    def on_starting(self):
        self.feed_cache.verify()

    def run(self):
        logger.info("starting VMware Carbon Black EDR <-> taxii Connector | version %s" % version.__version__)
        logger.debug("starting continuous feed retrieval thread")
        work_thread = threading.Thread(target=self.perform_continuous_feed_retrieval)
        work_thread.setDaemon(True)
        work_thread.start()

        logger.debug("starting flask")
        self.serve()

    def validate_config(self):
        if self.validated_config:
            return True

        self.validated_config = True
        logger.debug("Loading configuration options...")

        try:
            if 'bridge' not in self.options:
                raise ValueError("Configuration does not contain a [bridge] section")

            self._config = Config(self.options['bridge'])
            if self._config.errored:
                return False

            self.debug = self._config.debug
            self.logger.setLevel(logging.DEBUG if self.debug else logging.getLevelName(self._config.log_level))
            self._log_handler.maxBytes = self._config.log_file_size

            taxii_server_sections = list(filter(lambda section: section != 'bridge', self.cfg.sections()))
            if not taxii_server_sections:
                raise ValueError("Configuration does not contain section(s) defining a taxii server")
            self.taxii_servers = (self.cfg[server_section] for server_section in taxii_server_sections)

            ca_file = os.environ.get("REQUESTS_CA_BUNDLE", None)
            log_option_value("CA Cert File", ca_file if ca_file else "No CA Cert file found.")

            self.feed_cache = FeedCache(self._config, self._config.cache_path, self.feed_lock)

            if not self._config.skip_cb_sync:
                try:
                    self.cb = CbResponseAPI(url=self._config.server_url,
                                            token=self._config.server_token,
                                            ssl_verify=False,
                                            integration_name=self.integration_name)
                    self.cb.info()
                except Exception as e:
                    raise ValueError("Could not connect to Cb Response server: {0}".format(e))

        except ValueError as e:
            sys.stderr.write("Configuration Error: {}\n".format(e))
            logger.error(e)
            return False

        return True

    # noinspection PyUnusedLocal
    @staticmethod
    def _report_memory_usage(title):
        gc.collect()
        # import psutil
        # m = psutil.Process().memory_info()
        # print("({:<10}) [{}] Memory Usage: [{:14,}] [{:14,}] [{:14,}]".format(title, psutil.Process().pid, m.rss,
        #                                                                       m.data, m.vms))

    @return_value_to_shared_value
    def _do_write_reports(self):
        start = timer()
        self._report_memory_usage("writing")
        with self.feed_cache.create_stream() as feed_stream:
            tc = TaxiiDriver(self.taxii_servers)
            if tc.write_reports(feed_stream):
                self.last_successful_sync.stamp()
                logger.info("Successfully retrieved data at {0} ({1:.3f} seconds total)".format(
                    self.last_successful_sync, timer() - start))
                self._report_memory_usage("saved")
                return True
            else:
                logger.warning("Failed to retrieve data at {0} ({1:.3f} seconds total)".format(
                    TimeStamp(True), timer() - start))
        return False

    @return_value_to_shared_value
    def _do_retrieve_reports(self):
        start = timer()
        self._report_memory_usage("reading")
        tc = TaxiiDriver(self.taxii_servers)
        reports = tc.generate_reports()
        self._report_memory_usage("generated")
        logger.debug("Retrieved reports ({0:.3f} seconds).".format(timer() - start))
        if reports:
            # Instead of rewriting the cache file directly, we're writing to a temporary file
            # and then moving it onto the cache file so that we don't have a situation where
            # the cache file is only partially written and corrupt or empty.
            if self.feed_cache.write_reports(reports):
                self.last_successful_sync.stamp()
                del reports
                logger.info("Successfully retrieved data at {0} ({1:.3f} seconds total)".format(
                    self.last_successful_sync, timer() - start))
                self._report_memory_usage("saved")
                return True
            else:
                logger.warning("Failed to retrieve data at {0} ({1:.3f} seconds total)".format(
                    TimeStamp(True), timer() - start))
        return False

    # noinspection PyShadowingNames,PyUnusedLocal
    def _sigterm_handler(self, signal, frame):
        logger.info("Process shutting down...")
        if self.process:
            logger.info("Sub-process found.  Terminating...")
            self.process.terminate()
            logger.info("Sub-process terminated.")
        sys.exit()

    def _retrieve_reports(self):
        if self._config.multi_core:
            success = Value('B', False)
            self._report_memory_usage("before")
            process = Process(
                target=self._do_write_reports if self._config.use_feed_stream else self._do_retrieve_reports,
                kwargs={'shared_return': success})
            process.start()
            self.process = process
            while process.is_alive():
                process.join(timeout=1)
            self.process = None
            self._report_memory_usage("after")
            return success.value
        return self._do_retrieve_reports()

    def perform_continuous_feed_retrieval(self, loop_forever=True):
        # noinspection PyBroadException
        try:
            self.validate_config()

            cbint.utils.filesystem.ensure_directory_exists(self._config.cache_path)

            while True:
                logger.info("Starting feed retrieval.")
                errored = True

                try:
                    success = self._retrieve_reports()
                    if success:
                        self._sync_cb_feed()
                        errored = False
                except Exception as e:
                    logger.exception("Error occurred while attempting to retrieve feed: {0}".format(e))
                gc.collect()

                self.last_sync.stamp()
                logger.debug("Feed report retrieval completed{0}.".format(" (Errored)" if errored else ""))

                if not loop_forever:
                    return self.feed_cache.read(as_text=True)

                # Full sleep interval is taken between feed retrieval work.
                time.sleep(self._config.feed_retrieval_minutes * 60)

        except Exception:
            # If an exception makes us exit then log what we can for our own sake
            logger.fatal("FEED RETRIEVAL LOOP IS EXITING! Daemon should be restarted to restore functionality! ")
            logger.fatal("Fatal Error Encountered:\n %s" % traceback.format_exc())
            sys.stderr.write("FEED RETRIEVAL LOOP IS EXITING! Daemon should be restarted to restore functionality!\n")
            sys.stderr.write("Fatal Error Encountered:\n %s\n" % traceback.format_exc())
            sys.exit(3)

    def _sync_cb_feed(self):
        if self._config.skip_cb_sync:
            return

        try:
            feeds = get_object_by_name_or_id(self.cb, Feed, name=self._config.feed_name)
        except Exception as e:
            logger.error(e)
            feeds = None

        if not feeds:
            logger.info("Feed {} was not found, so we are going to create it".format(self._config.feed_name))
            f = self.cb.create(Feed)
            f.feed_url = "http://{0}:{1}/taxii/json".format(
                self._config.host_address,
                self._config.listen_port)
            f.enabled = True
            f.use_proxy = False
            f.validate_server_cert = False
            try:
                f.save()
            except ServerError as se:
                if se.error_code == 500:
                    logger.info("Could not add feed:")
                    logger.info(
                        " Received error code 500 from server. "
                        "This is usually because the server cannot retrieve the feed.")
                    logger.info(
                        " Check to ensure the Cb server has network connectivity and the credentials are correct.")
                else:
                    logger.info("Could not add feed: {0:s}".format(str(se)))
            except Exception as e:
                logger.info("Could not add feed: {0:s}".format(str(e)))
            else:
                logger.info("Feed data: {0:s}".format(str(f)))
                logger.info("Added feed. New feed ID is {0:d}".format(f.id))
                f.synchronize(False)

        elif len(feeds) > 1:
            logger.warning("Multiple feeds found, selecting Feed id {}".format(feeds[0].id))

        elif feeds:
            feed_id = feeds[0].id
            logger.info("Feed {} was found as Feed ID {}".format(self._config.feed_name, feed_id))
            feeds[0].synchronize(False)
