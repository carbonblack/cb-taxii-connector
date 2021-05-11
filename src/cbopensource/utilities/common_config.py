# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.
################################################################################

import os
from functools import partial
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

__all__ = ["CommonConfigException", "CommonConfigOptionBase", "StringConfigOption", "BoolConfigOption",
           "PairedConfigOption", "IntConfigOption", "CommaDelimitedListConfigOption", "CertConfigOption",
           "CommonConfigBase", "DerivativeConfigOption"]


class CommonConfigException(Exception):
    """
    Exception class for usage errors with the Common Configuration system.
    """
    pass


# ----- Configuration Parameter Classes --------------------------------------------------

class CommonConfigOptionBase(object):
    """
    Base class for handling configuration options.
    """

    def __init__(self, key: str, key_type: Callable, bounds_checker: Callable = None, required: bool = True,
                 default: Any = None, transform: Callable = None, allowed_values: List[Any] = None,
                 to_upper: bool = False, sort_list: bool = True):
        """
        Initialize the class.

        :param key: name of the configuration option
        :param key_type: type of the option
        :param bounds_checker: if defined, function to validate value bounds
        :param required: if True, must be specified in the configuration
        :param default: default value, if not specified (and not required)
        :param transform: if defined, function to perform any value transformations
        :param allowed_values: if defined, list of allowed values
        :param to_upper: for string types only, if True convert to all upper case before any value checks
        :param sort_list: for list types only, if True sort the list
        """
        self.key = key
        self.keyType = key_type
        self.boundsChecker = bounds_checker
        self.required = required
        self.default = default
        self.transform = transform
        self.allowed_values = allowed_values
        self.to_upper = to_upper
        self.sort_list = sort_list

    def __str__(self):
        # noinspection PyUnresolvedReferences
        return f"{self.key} ({self.keyType.__class__})"

    def parse_from_dict(self, source: Dict) -> Any:
        """
        Get the defined key from the supplied configuration.  It is assumed that the dict config is grabed from
        a file source, with both keys and values defined as strings, with the configuration class schema instructing
        how to parse the value.

        :param source: the source configuration as a Dict
        :return: the value or any default
        """
        if self.key in source:
            raw_value = source[self.key]
            if len(raw_value.strip()) != 0:
                try:
                    value = self.keyType(raw_value)
                except Exception as err:
                    raise CommonConfigException(f"Problem with configuration key '{self.key}': {str(err)}")

                if self.boundsChecker is not None:
                    self.boundsChecker(value)

                transformed_value = self.transform(value) if self.transform else value

                if self.to_upper and self.keyType == str:
                    transformed_value = transformed_value.upper()

                if self.allowed_values and transformed_value not in self.allowed_values:
                    raise CommonConfigException(
                        f"Configuration key '{self.key}' must be in allowed values {self.allowed_values}")
                return transformed_value
        if self.default is not None:
            return self.default
        elif self.required:
            raise CommonConfigException(f"Configuration key '{self.key}' is required")
        else:
            return None


class StringConfigOption(CommonConfigOptionBase):
    """
    Child class to specifically handle string options.
    """

    def __init__(self, key: str, required: bool = True, default: str = None, min_len: int = None, max_len: int = None,
                 transform: Callable = None, allowed_values: List[Any] = None, to_upper: bool = False):
        """
        Initialize the class.

        :param key: name of the option
        :param required: if True, must be specified in the configuration
        :param default: default value, if not specified (and not required)
        :param min_len: if specified, minimum allowed length
        :param max_len: if specified, maximum allowed length
        :param transform: if defined, function to do any value transformation
        :param allowed_values: if defined, list of allowed values
        :param to_upper: if True, make upper case before other checks
        """
        super().__init__(key, str, required=required,
                         bounds_checker=partial(self.string_length_checker, name=key, min_len=min_len, max_len=max_len),
                         transform=transform, allowed_values=allowed_values, to_upper=to_upper, default=default)

    # ----------------------------------------------------------------------

    @staticmethod
    def string_length_checker(value: str, name: str, min_len: int = None, max_len: int = None) -> None:
        """
        Pre-defined boundry checking function to flag outsized string values.

        :param value: The value to be checked
        :param name: the name of the option
        :param min_len: if specified, minimum allowed length
        :param max_len: if specified, maximum allowed length
        """
        length = len(value)

        if min_len is not None:
            if max_len and (not min_len <= length <= max_len):
                raise CommonConfigException(
                    f"'{name}' - String length {length} not in bounds {min_len} -> {max_len}")
            elif min_len > length:
                raise CommonConfigException(
                    f"'{name}' - String length {length} does not meet minimum length of {min_len} ")
        elif max_len and length > max_len:
            raise CommonConfigException(
                f"'{name}' - String length {length} exceeds maxmimum length of {max_len}")


class BoolConfigOption(CommonConfigOptionBase):
    """
    Child class to specifically handle boolean options.
    """

    class BooleanConverter(object):
        """
        Class to convert boolean values from the configuration.
        """

        def __call__(self, raw_value) -> bool:
            """
            True (case insensitive):
                t, true, 1, on, yes
            False (case insensitive):
                anything else

            :param raw_value:
            :return:
            """
            converted = str(raw_value).strip().lower()
            if converted not in ['true', 'false']:
                raise CommonConfigException(f"Only case-insensitive values of 'true' or 'false' are allowed "
                                            f"for boolean configuration (supplied '{raw_value}')")

            return True if converted == "true" else False

        def __str__(self):
            return 'boolean - [true or false]'

    def __init__(self, key: str, required: bool = True, default: bool = None):
        """
        Initialize the class.

        :param key: option name
        :param required: if True, must be specified in the configuration (default False)
        :param default: default value, if not specified and not required
        """
        super().__init__(key, self.BooleanConverter(), required=required, default=default)


class PairedConfigOption(object):
    """
    Child class to specifically handle paired object options.
    """

    def __init__(self, option_class: CommonConfigOptionBase, pair_key_name: str):
        """
        Initialize the class.

        :param option_class: option class to use
        :param pair_key_name: paired option name
        """
        self.option = option_class
        self.pair_key_name = pair_key_name

    def parse_from_dict(self, source: Dict) -> Any:
        """
        Get the defined key from the supplied configuration, if the paired key is also defined.

        :param source: the source configuration
        :return: value of
        """
        first = self.option.parse_from_dict(source)
        second = source.get(self.pair_key_name, None)
        if first is not None and second is None:
            raise CommonConfigException(f"'{self.pair_key_name}' is required when '{self.option.key}' is specified")
        else:
            return first


class IntConfigOption(CommonConfigOptionBase):
    """
    Child class to specifically handle int options.
    """

    def __init__(self, key: str, required: bool = True, default: int = None, min_value: int = 0, max_value: int = 100):
        """
        Initialize the class.

        :param key: option name
        :param required: if True, must be specified in the configuration
        :param default: default value, if not specified (and not required)
        :param min_value: minimum allowed value
        :param max_value: maximum allowed value
        """
        super().__init__(key, int, required=required,
                         bounds_checker=partial(self.int_range_checker, name=key, min_value=min_value,
                                                max_value=max_value),
                         default=default)

    # ----------------------------------------------------------------------

    @staticmethod
    def int_range_checker(value, name, min_value=0, max_value=100) -> None:
        """
        Pre-defined boundry checking function to flag int values outside a given range.

        :param value: The value to be checked
        :param name: the name of the option
        :param min_value: minimum allowed value
        :param max_value: maximum allowed value
        """
        if not (min_value <= value <= max_value):
            raise CommonConfigException(f"'{name}' must be between {min_value} and {max_value} (got {value})")


class DerivativeConfigOption(CommonConfigOptionBase):
    """
    Child class to handle derivative options.
    """
    def __init__(self, key: str, key_type: Any, derivation_function:Callable):
        """
        Initialize the class.

        NOTE: The deriving function must be coded to handle any situation where any config value are missing!
        :param key: option name
        :param key_type: option type
        :param derivation_function: function used to manipulate the value based on the configuration
        """
        super().__init__(key, key_type)
        self.derivation = derivation_function

    def parse_from_dict(self, source: Dict) -> Any:
        """
        Parse the option's value from the supplied config directory.

        :param source: configuration as a Dict
        :return: option value
        """
        derived_value = self.derivation(source)
        return derived_value


class CommaDelimitedListConfigOption(CommonConfigOptionBase):
    """
    Child class to specifically handle comma-separated lists.
    """

    class CommaDelimitedList(object):
        """
        Class to convert comma-separated lists from the configuration.

        FUTURE: Allow ability to have lists of ints as well as list of strings
        """

        def __init__(self, name, min_len: int = None, max_len: int = None, unique: bool = False,
                     accepted_values: List[Any] = None, sort_list: bool = True, to_upper: bool = False):
            """
            Initialize the class.

            :param name: name of the list
            :param min_len: if specified, minimum allowed length
            :param max_len: if specified, maximum allowed length
            :param unique: if True, list values must be unique
            :param accepted_values: if specified, list of allowed values
            :param sort_list: If True, list is always returned sorted
            :param to_upper: If True, uppercase list items (default False)
            """
            self.name = name
            self.min = min_len if min_len is None else int(min_len)
            self.max = max_len if max_len is None else int(max_len)
            self.unique = unique
            self.accepted_values = {value.lower(): True for value in accepted_values} if accepted_values else None
            self.sort_list = sort_list
            self.to_upper = to_upper

        def __call__(self, raw_value):
            if self.to_upper:
                split_string_elements = (split_value.strip().upper() for split_value in raw_value.split(","))
            else:
                split_string_elements = (split_value.strip() for split_value in raw_value.split(","))

            if self.sort_list:
                split_string_elements = sorted(split_string_elements)
            return list(filter(lambda split_string_part: split_string_part, split_string_elements))

        def __str__(self):
            return "comma delimited list" if not self.unique else "comma delimited list of unique items"

        # ------------------------------------------------------------

        def bounds_check(self, value_as_list):
            list_length = len(value_as_list)
            if self.accepted_values and not all(
                    map(lambda value: value.lower() in self.accepted_values, value_as_list)):
                raise CommonConfigException(f"'{self.name}' - Acceptable values (case insensitive) are: "
                                            f"{sorted(list(self.accepted_values.keys()))}")

            if self.unique and len(set(value_as_list)) != list_length:
                raise CommonConfigException(f"'{self.name}' - List entries must be unique")

            if self.min is not None:
                if self.max and (not self.min <= list_length <= self.max):
                    raise CommonConfigException(
                        f"'{self.name}' - List length {list_length} not in bounds {self.min} -> {self.max}")
                elif self.min > list_length:
                    raise CommonConfigException(
                        f"'{self.name}' - List length {list_length} does not meet minimum length of {self.min} ")
            elif self.max and list_length > self.max:
                raise CommonConfigException(
                    f"'{self.name}' - List length {list_length} exceeds maxmimum length of {self.max}")

    def __init__(self, key: str, default: List[Any] = None, unique: bool = False, required: bool = False, min_len=None,
                 max_len=None, accepted_values: List[Any] = None, sort_list: bool = True, to_upper: bool = False):
        """
        Initialize the class.

        :param key: option name
        :param default: default value, if not specified (and not required)
        :param unique: if True, list values must be unique
        :param required: if True, must be specified in the configuration
        :param min_len: if specified, minimum allowed length
        :param max_len: if specified, maximum allowed length
        :param accepted_values: if specified, list of allowed values
        :param sort_list: If True, list is always returned sorted
        :param to_upper: If True, uppercase list items (default False)
        """
        type_and_checker = self.CommaDelimitedList(key, min_len, max_len, unique, accepted_values=accepted_values,
                                                   sort_list=sort_list, to_upper=to_upper)
        super().__init__(key, type_and_checker, bounds_checker=type_and_checker.bounds_check, default=default,
                         required=required, sort_list=sort_list, to_upper=to_upper)


class CertConfigOption(CommonConfigOptionBase):
    """
    Child class to specifically handle certificates.
    """

    def __init__(self, key: str = None):
        """
        Initialize the class.

        :param key: name of the key, defaults to 'cert' if not specified
        """
        super().__init__(key="cert" if key is None else key, key_type=str)
        self.key = "cert" if key is None else key

    # ----------------------------------------------------------------------

    def parse_from_dict(self, source: Dict) -> Optional[Union[str, Tuple[str, str]]]:
        """
        Get the certificate paths from the supplied configuration.

        :param source: the source configuration
        :return: cert path, tuple of (cert path, key path), or None if no certs
        """
        cert_raw_string = source.get(self.key, None)
        if cert_raw_string is not None:
            split_cert_parts = [split_value.strip() for split_value in cert_raw_string.split(",")]
            if len(cert_raw_string) == 0 or len(split_cert_parts) > 2:
                raise CommonConfigException(f"'{self.key}' must be specified as the path to a .pem encoded "
                                            f"cert+key pair or the comma separated paths to a cert and a key file")
            elif len(split_cert_parts) == 1:
                if not os.path.exists(cert_raw_string):
                    raise CommonConfigException(f"'{self.key}' path to cert+key pair does not exist")
                else:
                    return cert_raw_string
            elif len(split_cert_parts) == 2:
                cert_path = split_cert_parts[0]
                key_path = split_cert_parts[1]
                if not (os.path.exists(cert_path)):
                    raise CommonConfigException(f"'{self.key}' cert path '{cert_path}' does not exist!")
                if not (os.path.exists(key_path)):
                    raise CommonConfigException(f"'{self.key}' key path '{key_path}' does not exist!")
                return cert_path, key_path
        else:
            return None


# ----- Configuration Classes --------------------------------------------------

class CommonConfigBase(object):
    """
    Base class for handling configuration sets.
    """

    config_schema = None

    def __init__(self, underlying_dictionary:Dict):
        """Supply the underlying dictionary directly."""
        self._underlying_dictionary = underlying_dictionary

    def __getattr__(self, item:str):
        """Get dictionary item as a property; i.e. `config.prop`."""
        return self._underlying_dictionary.get(item, None)

    def __getitem__(self, item:str):
        """Get dictionary item as an item; i.e. `config[prop]`."""
        return self._underlying_dictionary.get(item, None)

    def __contains__(self, item:str):
        """Returns True if the specified key is in the underlying dictionary."""
        return item in self._underlying_dictionary

    def __str__(self):
        return str(self._underlying_dictionary)

    @property
    def dict(self):
        return self._underlying_dictionary

    @classmethod
    def parse(cls, source: Dict) -> 'CommonConfigBase':
        """
        Parse the source configuration file using the currently defined schema, returning the configuration
        that is filtered out.

        :param source: source dict containg all configuration information
        :return: dict of filtered parameters
        """
        if cls.config_schema is None:
            raise CommonConfigException(f"{cls} has no defined schema!")

        parsed_configuration = {}

        for kwarg_key, config_opt in cls.config_schema.items():
            value = config_opt.parse_from_dict(source)
            if value is not None:
                parsed_configuration[kwarg_key] = value

        return cls(parsed_configuration)
