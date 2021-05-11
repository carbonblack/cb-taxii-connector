# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.
################################################################################

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
from typing import Any, Dict, List, Optional, Union

import cbint
import flask
import simplejson
from cbapi.errors import ServerError
from cbapi.example_helpers import get_object_by_name_or_id
from cbapi.response import CbResponseAPI, Feed
from cbint.utils import cbserver, flaskfeed
from cbint.utils.daemon import CbIntegrationDaemon

from cbopensource.constant import MiB
from cbopensource.driver.taxii import TaxiiDriver
# override JSON used
from cbopensource.driver.taxii_server_config import TaxiiServerConfiguration
from . import version
from .feed_cache import FeedCache
from .taxii_connector_config import TaxiiConnectorConfiguration, TaxiiConnectorConfigurationException

sys.modules['json'] = simplejson

_logger = logging.getLogger(__name__)

__all__ = ['log_option_value', 'TimeStamp', 'CarbonBlackTaxiiBridge']


# noinspection PySameParameterValue
def log_option_value(label: str, value: Union[str, int], padding: int = 27) -> None:
    """
    Info log display of a given option.

    :param label: Option label
    :param value: option value
    :param padding: padding
    """
    _logger.info(f"{label:{padding}}: {value}")


class TimeStamp(object):
    """
    Class to store and work with timestamps.
    """

    def __init__(self, stamp: bool = False):
        """
        Initialize the class.

        :param stamp: If True, initialize with the current GMT time
        """
        self._value = None
        if stamp:
            self.stamp()

    def __str__(self):
        if not self._value:
            return "Never"
        return strftime("%a, %d %b %Y %H:%M:%S +0000", self._value)

    def __repr__(self):
        return "TimeStamp({0})".format(self.__str__())

    # --------------------------------------------------------------------------------

    def stamp(self) -> None:
        """
        Stamps the value of this TimeStamp with the current GMT time.
        """
        self._value = gmtime()

    # noinspection PyUnusedFunction
    def clone(self) -> 'TimeStamp':
        """
        Create a cloned object.

        :return: New object with the same timestamp.
        """
        ts = TimeStamp()
        ts._value = self._value
        return ts


class CarbonBlackTaxiiBridge(CbIntegrationDaemon):
    """
    Class to manage the bridge bewteen EDR and the Taxii services.
    """

    def __init__(self, name: str, configfile: str, logfile: str = None, pidfile: str = None, debug: bool = False):
        """
        Initialize the class.

        :param name: name of the connector
        :param configfile: path to the config file
        :param logfile: path to the log file
        :param pidfile: path to the PID file
        :param debug: If True, execute in DEBUG mode
        """

        CbIntegrationDaemon.__init__(self, name, configfile=configfile, logfile=logfile, pidfile=pidfile, debug=debug)
        # NOTE: at this point, 'self.cfg' contains the RawConfigParser() object based on the supplied config.ini
        #       'self.options' contains a Dict parsed from the 'self.cfg' with a key for each stanza

        self.flask_feed = flaskfeed.FlaskFeed(__name__, False, TaxiiConnectorConfiguration.DIRECTORY)
        self._config: Optional[TaxiiConnectorConfiguration] = None
        self.taxii_servers: List[Dict] = []
        self.api_urns = {}
        self.validated_config = False
        self.cb: Optional[CbResponseAPI] = None
        self.sync_needed = False
        self.feed_lock = threading.RLock()
        self.logfile = logfile
        self.debug = debug
        self._log_handler = None
        self.logger = _logger
        self.process = None
        self.feed_cache = None

        self.flask_feed.app.add_url_rule(TaxiiConnectorConfiguration.CB_IMAGE_PATH,
                                         view_func=self.handle_cb_image_request)
        self.flask_feed.app.add_url_rule(TaxiiConnectorConfiguration.INTEGRATION_IMAGE_PATH,
                                         view_func=self.handle_integration_image_request)
        self.flask_feed.app.add_url_rule(TaxiiConnectorConfiguration.JSON_FEED_PATH,
                                         view_func=self.handle_json_feed_request,
                                         methods=['GET'])
        self.flask_feed.app.add_url_rule("/", view_func=self.handle_index_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/feed.html", view_func=self.handle_html_feed_request, methods=['GET'])

        self.initialize_logging()

        _logger.debug("generating feed metadata")

        with self.feed_lock:
            self.last_sync = TimeStamp()
            self.last_successful_sync = TimeStamp()
            self.feed_ready = False

        signal.signal(signal.SIGTERM, self._sigterm_handler)

    def initialize_logging(self) -> None:
        """
        Initialize the bridge logging.
        """
        if not self.logfile:
            log_path = f"/var/log/cb/integrations/{self.name}/"
            # noinspection PyUnresolvedReferences
            cbint.utils.filesystem.ensure_directory_exists(log_path)
            self.logfile = f"{log_path}{self.name}.log"

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        root_logger.handlers = []

        rlh = RotatingFileHandler(self.logfile, maxBytes=10 * MiB, backupCount=10)
        rlh.setFormatter(logging.Formatter(fmt="%(asctime)s - %(levelname)-7s - %(module)s - %(message)s"))
        self._log_handler = rlh
        root_logger.addHandler(rlh)

        self.logger = root_logger

    @property
    def integration_name(self) -> str:
        """
        :return: The integration name and version
        """
        return f'Cb Taxii Connector {version.__version__}'

    def serve(self) -> None:
        """
        Start the server.
        """
        if self._config.https_proxy:
            os.environ['HTTPS_PROXY'] = self._config.https_proxy
            os.environ['no_proxy'] = '127.0.0.1,localhost'

        address = self._config.listener_address
        port = self._config.listener_port
        _logger.info(f"starting flask server: {address}:{port}")
        self.flask_feed.app.run(port=port, debug=self.debug, host=address, use_reloader=False)

    def handle_json_feed_request(self):
        """
        Handle a JSON feed request.

        TODO: properly type return!
        :return:
        """
        self._report_memory_usage("hosting")
        return flask.send_from_directory(self.feed_cache.location, self.feed_cache.file_name,
                                         mimetype='application/json')

    def handle_html_feed_request(self):
        """
        Handle an HTML feed request.

        TODO: properly type return!
        :return:
        """
        the_feed = self.feed_cache.read()
        if not the_feed:
            return flask.Response(status=404)

        html = self.flask_feed.generate_html_feed(the_feed, self._config.DISPLAY_NAME)
        del the_feed
        gc.collect()
        return html

    def handle_index_request(self):
        """
        Handle an index request.

        TODO: properly type return!
        :return:
        """
        with self.feed_lock:
            index = self.flask_feed.generate_html_index(self.feed_cache.generate_feed(), self._config.options,
                                                        self._config.DISPLAY_NAME, self._config.CB_IMAGE_PATH,
                                                        self._config.INTEGRATION_IMAGE_PATH,
                                                        self._config.JSON_FEED_PATH, str(self.last_sync))
        return index

    def handle_cb_image_request(self):
        """
        Handle a CB image request.

        TODO: properly type return!
        :return:
        """
        return self.flask_feed.generate_image_response(
            image_path=f"{self._config.DIRECTORY}{self._config.CB_IMAGE_PATH}")

    def handle_integration_image_request(self):
        """
        Handle an integration image request.

        TODO: properly type return!
        :return:
        """
        return self.flask_feed.generate_image_response(image_path=(f"{self._config.DIRECTORY}"
                                                                   f"{self._config.INTEGRATION_IMAGE_PATH}"))

    def on_starting(self) -> None:
        """
        On startup, check the feed cache.
        """
        self.feed_cache.verify()

    def run(self) -> None:
        """
        Begin execution of the service.
        """
        _logger.info(f"starting VMware Carbon Black EDR <-> taxii Connector | version {version.__version__}")
        _logger.debug("starting continuous feed retrieval thread")
        work_thread = threading.Thread(target=self.perform_continuous_feed_retrieval)
        work_thread.setDaemon(True)
        work_thread.start()

        _logger.debug("starting flask")
        self.serve()

    def validate_config(self) -> bool:
        """
        Validate internal configuration.  If already validated, we simply return.

        :return: True if valid, False otherwise
        :raises: ValueError if there are configuration problems
        """
        if self.validated_config:
            return True

        self.validated_config = True
        _logger.debug("Loading configuration options...")

        try:
            if 'bridge' not in self.options:
                raise ValueError("Configuration does not contain a [bridge] section")

            # NOTE: 'bridge' contains the connector settings
            try:
                self._config = TaxiiConnectorConfiguration.parse(self.options['bridge'])
            except TaxiiConnectorConfigurationException:
                return False

            self.debug = self._config['debug']
            self.logger.setLevel(logging.DEBUG if self.debug else logging.getLevelName(self._config['log_level']))
            self._log_handler.maxBytes = self._config['log_file_size']

            # NOTE: All other option keys besides 'bridge' contain settings for each taxii server
            taxii_server_sections = list(filter(lambda section: section != 'bridge', self.cfg.sections()))
            if not taxii_server_sections:
                raise ValueError("Configuration does not contain section(s) defining a taxii server")
            self.taxii_servers = [TaxiiServerConfiguration.parse(self.cfg[server_section]).dict for server_section
                                  in taxii_server_sections]

            ca_file = os.environ.get("REQUESTS_CA_BUNDLE", None)
            log_option_value("CA Cert File", ca_file if ca_file else "No CA Cert file found.")

            self.feed_cache = FeedCache(self._config, self._config['cache_folder'], self.feed_lock)

            if not self._config['skip_cb_sync']:
                try:
                    self.cb = CbResponseAPI(url=self._config['carbonblack_server_url'],
                                            token=self._config['carbonblack_server_token'],
                                            ssl_verify=False,
                                            integration_name=self.integration_name)
                    self.cb.info()
                except Exception as e:
                    raise ValueError(f"Could not connect to Cb Response server: {e}")

        except ValueError as e:
            sys.stderr.write(f"Configuration Error: {e}\n")
            _logger.error(e)
            return False

        return True

    # noinspection PyUnusedLocal
    @staticmethod
    def _report_memory_usage(title: str) -> None:
        """
        Private method to report current memory usage.

        NOTE: currently stubbed to only perform garbage collection.
        :param title: title of the report
        """
        gc.collect()

    @staticmethod
    def handle_shared_return(shared_return, value: Any) -> Any:
        """
        Set a value parameter on a shared return object (if provided), or juet return it.
        :param shared_return:
        :param value:
        :return:
        """
        if shared_return is not None:
            shared_return.value = value
        return value

    def _do_write_reports(self, shared_return=None) -> bool:
        """
        Private method to write TAXII reports.

        :return: True if successful
        """
        start = timer()
        self._report_memory_usage("writing")
        with self.feed_cache.create_stream() as feed_stream:
            tc = TaxiiDriver(self.taxii_servers)
            if tc.write_reports(feed_stream):
                self.last_successful_sync.stamp()
                _logger.info("Successfully retrieved data at {0} ({1:.3f} seconds total)".format(
                    self.last_successful_sync, timer() - start))
                self._report_memory_usage("saved")
                return self.handle_shared_return(shared_return, True)
            else:
                _logger.warning("Failed to retrieve data at {0} ({1:.3f} seconds total)".format(
                    TimeStamp(True), timer() - start))
        return self.handle_shared_return(shared_return, False)

    def _do_retrieve_reports(self, shared_return=None) -> bool:
        """
        Private method to retrieve TAXII reports.

        :return: True if successful
        """
        start = timer()
        self._report_memory_usage("reading")
        tc = TaxiiDriver(self.taxii_servers)
        reports = tc.generate_reports()
        self._report_memory_usage("generated")
        _logger.debug("Retrieved reports ({0:.3f} seconds).".format(timer() - start))
        if reports:
            # Instead of rewriting the cache file directly, we're writing to a temporary file
            # and then moving it onto the cache file so that we don't have a situation where
            # the cache file is only partially written and corrupt or empty.
            if self.feed_cache.write_reports(reports):
                self.last_successful_sync.stamp()
                del reports
                _logger.info("Successfully retrieved data at {0} ({1:.3f} seconds total)".format(
                    self.last_successful_sync, timer() - start))
                self._report_memory_usage("saved")
                self.handle_shared_return(shared_return, True)
            else:
                _logger.warning("Failed to retrieve data at {0} ({1:.3f} seconds total)".format(
                    TimeStamp(True), timer() - start))
        return self.handle_shared_return(shared_return, False)

    # noinspection PyUnusedLocal
    def _sigterm_handler(self, the_signal, frame) -> None:
        """
        Private method to handle termination signals.

        :param the_signal: the signal received
        :param frame: the current stack frame
        """
        _logger.info("Process shutting down...")
        if self.process:
            _logger.info("Sub-process found.  Terminating...")
            self.process.terminate()
            _logger.info("Sub-process terminated.")
        sys.exit()

    def _retrieve_reports(self) -> bool:
        """
        Private metheod to write or retrieve reports, depending on multi-core status and/or use of a feed stream.

        :return: True if successful
        """
        if self._config['multi_core']:
            success = Value('B', False)
            self._report_memory_usage("before")
            process = Process(
                target=self._do_write_reports if self._config['use_feed_stream'] else self._do_retrieve_reports,
                kwargs={'shared_return': success})
            process.start()
            self.process = process
            while process.is_alive():
                process.join(timeout=1)
            self.process = None
            self._report_memory_usage("after")
            return success.value
        return self._do_retrieve_reports()

    def perform_continuous_feed_retrieval(self, loop_forever=True) -> str:
        """
        Method to poll the feeds one time or continuously (until terminated).

        :param loop_forever: If True, loop until terminated
        :return: feed cache, if not looping
        """
        try:
            self.validate_config()

            # noinspection PyUnresolvedReferences
            cbint.utils.filesystem.ensure_directory_exists(self._config['cache_folder'])

            while True:
                _logger.info("Starting feed retrieval.")
                errored = True

                try:
                    success = self._retrieve_reports()
                    if success:
                        self._sync_cb_feed()
                        errored = False
                except Exception as e:
                    _logger.exception("Error occurred while attempting to retrieve feed: {0}".format(e))
                gc.collect()

                self.last_sync.stamp()
                _logger.debug("Feed report retrieval completed{0}.".format(" (Errored)" if errored else ""))

                if not loop_forever:
                    return self.feed_cache.read(as_text=True)

                # Full sleep interval is taken between feed retrieval work.
                time.sleep(self._config['feed_retrieval_minutes'] * 60)

        except Exception as err:
            # If an exception makes us exit then log what we can for our own sake
            _logger.fatal("FEED RETRIEVAL LOOP IS EXITING! Daemon should be restarted to restore functionality!")
            _logger.fatal(f"Fatal Error Encountered:\n{err}\n{traceback.format_exc()}")
            sys.stderr.write("FEED RETRIEVAL LOOP IS EXITING! Daemon should be restarted to restore functionality!\n")
            sys.stderr.write(f"Fatal Error Encountered:\n{err}\n{traceback.format_exc()}")
            sys.exit(3)

    def _sync_cb_feed(self) -> None:
        """
        Private method to sync EDR feeds.
        """
        if self._config['skip_cb_sync']:
            return

        try:
            feeds = get_object_by_name_or_id(self.cb, Feed, name=self._config.FEED_NAME)
        except Exception as e:
            _logger.error(e)
            feeds = None

        if not feeds:
            _logger.info(f"Feed {self._config.FEED_NAME} was not found, so we are going to create it")
            f = self.cb.create(Feed)
            # noinspection HttpUrlsUsage
            f.feed_url = f"http://{self._config['host_address']}:{self._config['listener_port']}/taxii/json"
            f.enabled = True
            f.use_proxy = False
            f.validate_server_cert = False
            try:
                f.save()
            except ServerError as se:
                if se.error_code == 500:
                    _logger.info("Could not add feed:")
                    _logger.info(
                        " Received error code 500 from server. "
                        "This is usually because the server cannot retrieve the feed.")
                    _logger.info(
                        " Check to ensure the Cb server has network connectivity and the credentials are correct.")
                else:
                    _logger.info(f"Could not add feed: {str(se)}")
            except Exception as e:
                _logger.info(f"Could not add feed: {str(e)}")
            else:
                _logger.info(f"Feed data: {str(f)}")
                _logger.info(f"Added feed. New feed ID is {f.id}")
                f.synchronize(False)

        elif len(feeds) > 1:
            _logger.warning(f"Multiple feeds found, selecting first one (Feed id {feeds[0].id})")

        elif feeds:
            feed_id = feeds[0].id
            _logger.info(f"Feed {self._config.FEED_NAME} was found as Feed ID {feed_id}")
            feeds[0].synchronize(False)
