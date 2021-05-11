import logging
import os
import sys
from cbopensource.constant import MiB

_logger = logging.getLogger(__name__)


class Config(object):
    # noinspection PyUnusedName
    feed_name = "taxiiintegration"
    # noinspection PyUnusedName
    display_name = "taxii"
    cb_image_path = "/carbonblack.png"
    integration_image_path = "/taxii.png"
    # noinspection PyUnusedName
    integration_image_small_path = "/taxii-small.png"
    json_feed_path = "/taxii/json"
    directory = "/usr/share/cb/integrations/cb-taxii-connector/content"

    def __init__(self, config_options):
        self._options = config_options
        self._errors = []
        self.debug = self._get_boolean('debug', False)
        self.log_level = self._get_string('log_level', default="INFO", valid=["DEBUG", "INFO", "WARNING", "ERROR"],
                                          unmatched_ok=True, to_upper=True)
        self.log_file_size = self._get_int('log_file_size', default=10 * MiB,
                                           verify_func=lambda x: x > 0, requirement_message="positive")
        self.pretty_print_json = self._get_boolean('pretty_print_json')
        self.multi_core = self._get_boolean('multi_core', default=True)
        self.use_feed_stream = self._get_string('feed_save_mode', default='STREAM',
                                                valid=['STREAM', 'BULK'], to_upper=True) == 'STREAM'
        self.cache_path = self._get_string('cache_folder',
                                           default="/usr/share/cb/integrations/cb-taxii-connector/cache")
        self.listen_port = self._get_int('listener_port', required=True, verify_func=lambda x: 0 < x <= 65535,
                                         requirement_message="a valid port number")
        self.listen_address = self._get_string('listener_address', default="0.0.0.0")
        self.host_address = self._get_string('host_address', default="127.0.0.1")
        # noinspection PyTypeChecker
        self.https_proxy = self._get_string('https_proxy', default=None)
        self.feed_retrieval_minutes = self._get_int('feed_retrieval_minutes', required=True,
                                                    verify_func=lambda x: x > 0, requirement_message="greater than 1")
        self.skip_cb_sync = self._get_boolean('skip_cb_sync', default=False)
        self.server_url = self._get_string("carbonblack_server_url", default="https://127.0.0.1")
        self.server_token = self._get_string("carbonblack_server_token", required=not self.skip_cb_sync, hidden=True)

        if not self.cache_path.startswith('/'):
            self.cache_path = os.path.join(os.getcwd(), self.cache_path)

    def __getitem__(self, key):
        return self._options[key]

    def get(self, key, default=None):
        return self._options.get(key, default)

    @property
    def options(self):
        return self._options

    @property
    def errored(self):
        return len(self._errors)

    @property
    def errors(self):
        return self._errors

    @staticmethod
    def _log_option_value(label, value, hidden=False, padding=27):
        _logger.info("{0:{2}}: {1}".format(label, len(str(value)) * '*' if hidden else value, padding))

    def _log_error(self, message):
        sys.stderr.write("Configuration Error: {}\n".format(message))
        _logger.error(message)
        self._errors.append(message)

    def _get_boolean(self, label, default=False, required=False):
        """
        Convert a configuration parameter value designated as boolean into an actual boolean value.

        True (case insensitive):
            t, true, 1 on
        False (case insensitive):
            anything else

        :param label: the parameter name
        :param default: default value if not specified (False)
        :param required: True if required
        :return: boolean value (default if there was an error)
        """
        if required and (label not in self._options or not self._options[label]):
            self._log_error("The config option `{}`".format(label) +
                            " is required and must be one of [True, False, T, F, 1, 0, On, Off, Yes, No].")
        value = self._options.get(label, 't' if default else 'f').lower() in ['t', 'true', '1', 'on', 'yes']
        self._log_option_value(label, value)
        return value

    def _get_int(self, label, default=0, required=False, verify_func=None, requirement_message=""):
        """
        Convert a configuration parameter value designated as integer into an actual int value.

        :param label: the parameter name
        :param default: default value if not specified (0)
        :param required: True if required
        :param verify_func: function used to verify integer value range; if None no validation
        :param requirement_message: message abount allowed numeric range
        :return: integer value (default if there was an error)
        """
        error_message = "The config option `{}` is a{} number{}.".format(
            label, " required" if required else "",
            " and must be {}".format(requirement_message) if requirement_message and verify_func is not None else "")
        if required and label not in self._options:
            self._log_error(error_message)
            return default
        try:
            value = self._options.get(label, str(default))
            value = int(value)
        except ValueError:
            self._log_error(error_message)
            return default
        if verify_func is not None:
            if not verify_func(value):
                self._log_error(error_message)
                return default
        self._log_option_value(label, value)
        return value

    def _get_string(self, label, default="", required=False, valid=None, unmatched_ok=False, to_upper=False,
                    to_lower=False, hidden=False):
        """
        Get the value of a configuration parameter as a string.

        :param label: the parameter name
        :param default: the default value if not supplied ("") -- if None, it is passed through unmolested
        :param required: True if required (False)
        :param valid: If defined, list of allow values (None)
        :param unmatched_ok: if True and valid is defined, don't return an error if not one of the allowed
                             values (False)
        :param to_upper: if True, convert to upper case (False)
        :param to_lower: if True, convert to lower case (False)
        :param hidden: if True on any option logging value will be replaced with "******" (False)
        :return: string value (default if there was an error)
        """
        if valid is None:
            valid = []
        error_message = "The config option `{}`{}{}{}".format(label,
                                                              " is required" if required else "",
                                                              " and " if required and valid else "",
                                                              "" if not valid else " must be one of {}".format(valid))
        if to_upper and to_lower:
            self._log_error("Only specify one of `to_upper` and `to_lower`")

        if required and (label not in self._options or not self._options[label]):
            self._log_error(error_message)
            return default
        value = self._options.get(label, default)
        if value is not None:
            value = value.upper() if to_upper else value.lower() if to_lower else value
            value = value.strip()
        if valid and value not in valid:
            if unmatched_ok:
                value = default
            else:
                self._log_error(error_message)
                return default
        self._log_option_value(label, value, hidden)
        return value

