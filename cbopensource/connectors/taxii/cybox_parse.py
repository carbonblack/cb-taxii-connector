#  coding: utf-8
#  VMware Carbon Black EDR Taxii Connector © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################

import ipaddress
import logging
import string
import uuid
from typing import Any, Callable, Dict, List, Optional

from cybox.common import ObjectProperties
from cybox.core.observable import Observable
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from stix.report import Indicator

_logger = logging.getLogger(__name__)

# Used by validate_domain_name function
domain_allowed_chars = string.printable[:-6]


# ----- Validate methods ----------------------------------------------------- #

def validate_domain_name(domain_name: str) -> bool:
    """
    Validate a domain name to ensure validity and saneness.

    NOTE: by the rules in RFC 1035, some of these check are bogus and allow invalid domains!  Needs to be addressed!

    :param domain_name: The domain name to check
    :return: True if valid, otherwise false
    """
    # As per RFC 1035, Domain names--Implementation and specification, P. Mockapetris (Nov 1987)
    if len(domain_name) > 253:
        _logger.warning(f"Excessively long domain name `{domain_name}` in IOC list")
        return False

    if not all([c in domain_allowed_chars for c in domain_name]):
        _logger.warning(f"Malformed domain name `{domain_name}` in IOC list")
        return False

    parts = domain_name.split('.')
    if len(parts) == 0:
        _logger.warning("Empty domain name found in IOC list")
        return False
    if len(parts) == 1:
        _logger.warning("Domanin names must have at least 1 octet")
        return False

    for part in parts:
        if len(part) < 1 or len(part) > 63:
            _logger.warning(f"Invalid label length `{part}` in domain name {domain_name} for report")
            return False

    return True


def validate_md5sum(md5: str) -> bool:
    """
    Validate md5sum for saneness.

    :param md5: md5sum to valiate
    :return: True if valid, otherwise false
    """
    if 32 != len(md5):
        _logger.warning(f"Invalid md5 length for md5 `{md5}`")
        return False

    if not md5.isalnum():
        _logger.warning(f"Malformed md5 `{md5}` in IOC list")
        return False

    for c in "ghijklmnopqrstuvwxyz":
        if c in md5 or c.upper() in md5:
            _logger.warning(f"Malformed md5 {md5} in IOC list")
            return False

    return True


def validate_sha256(sha256: str) -> bool:
    """
    Validate sha256 for saneness.

    :param sha256: sha256 to valiate
    :return: True if valid, otherwise false
    """
    if 64 != len(sha256):
        _logger.warning(f"Invalid sha256 length for sha256 {sha256}")
        return False

    if not sha256.isalnum():
        _logger.warning(f"Malformed sha256 {sha256} in IOC list")
        return False

    for invalid_hash_character in "ghijklmnopqrstuvwxyz":
        if invalid_hash_character in sha256 or invalid_hash_character.upper() in sha256:
            _logger.warning(f"Malformed sha256 {sha256} in IOC list")
            return False

    return True


def validate_ip_address(ip_string: str) -> bool:
    """
    Check a provided IP address for valid formatting.

    :param ip_string: ip to be validated
    :return: True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def sanitize_id(the_id: str) -> str:
    """
    Ids may only contain a-z, A-Z, 0-9, - and must have one character.

    :param the_id: the ID to be sanitized
    :return: sanitized ID
    """
    return the_id.replace(':', '-')


def cybox_parse_observable(observable: Observable, indicator: Optional[Indicator], timestamp: int,
                           score: int) -> List[Dict[str, Any]]:
    """
    Parse cybox observables.

    :param observable: cybox observable
    :param indicator: stix report indicator (optional)
    :param timestamp: epoch time in seconds (UTC)
    :param score: score
    :return:
    """
    if observable.observable_composition:
        reports = []
        for composed_observable in observable.observable_composition.observables:
            reports.extend(_cybox_parse_observable(composed_observable, indicator, timestamp, score))
        return reports
    else:
        return _cybox_parse_observable(observable, indicator, timestamp, score)


def _cybox_parse_observable(observable: Observable, indicator: Optional[Indicator],
                            timestamp: int, score: int) -> List[Dict[str, Any]]:
    """
    parses a cybox observable and returns a list of iocs.
    :param observable: the cybox obserable to parse
    :return: list of observables
    """
    reports = []

    if observable.object_ and observable.object_.properties:
        the_props = observable.object_.properties
    else:
        return reports

    #
    # sometimes the description is None
    #
    description = ''
    if observable.description and observable.description.value:
        description = str(observable.description.value)

    #
    # if description is an empty string, then use the indicator's description
    # NOTE: This was added for RecordedFuture
    #

    if not description and indicator and indicator.description:
        description = str(indicator.description.value)

    #
    # use the first reference as a link
    # NOTE: This was added for RecordedFuture
    #
    link = ''
    if indicator and indicator.producer and indicator.producer.references:
        for reference in indicator.producer.references:
            link = reference
            break

    #
    # Sometimes the title is None, so generate a random UUID
    #

    if observable.title:
        title = observable.title
    else:
        title = str(uuid.uuid4())

    def append_report_if_iocs_found(props: ObjectProperties, target_key: str, ioc_label: str,
                                    validator: Callable) -> None:
        """
        Create a ioc entry.

        :param props: the property of interest
        :param target_key: the property target
        :param ioc_label: the ioc label
        :param validator: property value validation function
        """
        iocs = get_iocs_from_props(props, target_key=target_key, ioc_label=ioc_label, validator=validator)
        if len(iocs) > 0:
            reports.append({'iocs': iocs,
                            'id': sanitize_id(observable.id_),
                            'description': description,
                            'title': title,
                            'timestamp': timestamp,
                            'link': link,
                            'score': score})

    if type(the_props) == DomainName:
        if the_props.value and the_props.value.value:
            _logger.debug(f"Found DOMAIN: {the_props.value.value}")
            append_report_if_iocs_found(the_props.value, target_key="value", ioc_label="dns",
                                        validator=validate_domain_name)

    elif type(the_props) == Address:
        if the_props.category == 'ipv4-addr' and the_props.address_value:
            _logger.debug(f"Found IPV4: {the_props.address_value}")
            append_report_if_iocs_found(the_props.address_value, target_key="value", ioc_label="ipv4",
                                        validator=validate_ip_address)

        if the_props.category == 'ipv6-addr' and the_props.address_value:
            _logger.debug(f"Found IPV6: {the_props.address_value}")
            append_report_if_iocs_found(the_props.address_value, target_key="value", ioc_label="ipv6",
                                        validator=validate_ip_address)

    elif type(the_props) == File:
        if the_props.md5:
            _logger.debug(f"Found MD5: {the_props.md5}")
            append_report_if_iocs_found(the_props, target_key="md5", ioc_label="md5", validator=validate_md5sum)
        if the_props.sha256:
            _logger.debug(f"Found SHA256: {the_props.sha256}")
            append_report_if_iocs_found(the_props, target_key="sha256", ioc_label="sha256", validator=validate_sha256)

    return reports


def get_iocs_from_props(props: ObjectProperties, target_key: str = "sha256", ioc_label: str = "sha256",
                        validator: Callable = validate_sha256) -> Dict[str, List[str]]:
    """
    Get the IOC entry from STIX properties.

    :param props: the property of interest
    :param target_key: the property target
    :param ioc_label: the ioc label
    :param validator: property value validation function
    :return: Dictionary of ioc lists
    """
    iocs = {ioc_label: []}
    target_prop = getattr(props, target_key)
    if type(target_prop) is list:
        for entry in target_prop:
            if validator(entry):
                iocs[ioc_label].append(entry.strip())
    else:
        if hasattr(target_prop, 'value'):
            stripped_prop_value = target_prop.value.strip()
        else:
            stripped_prop_value = target_prop.strip()
        if validator(stripped_prop_value):
            iocs[ioc_label].append(stripped_prop_value)
    return iocs
