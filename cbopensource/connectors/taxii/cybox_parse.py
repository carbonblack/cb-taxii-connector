from cybox.objects.domain_name_object import DomainName
from cybox.objects.address_object import Address
from cybox.objects.file_object import File

import logging
import string
import ipaddress
import uuid

logger = logging.getLogger(__name__)

#
# Used by validate_domain_name function
#
domain_allowed_chars = string.printable[:-6]


def validate_domain_name(domain_name):
    """
    Validate a domain name to ensure validity and saneness
    :param domain_name: The domain name to check
    :return: True or False
    """
    if len(domain_name) > 255:
        logger.warn("Excessively long domain name {} in IOC list".format(domain_name))
        return False

    if not all([c in domain_allowed_chars for c in domain_name]):
        logger.warn("Malformed domain name {} in IOC list".format(domain_name))
        return False

    parts = domain_name.split('.')
    if 0 == len(parts):
        logger.warn("Empty domain name found in IOC list")
        return False

    for part in parts:
        if len(part) < 1 or len(part) > 63:
            logger.warn("Invalid label length {} in domain name {} for report %s".format(part, domain_name))
            return False

    return True


def validate_md5sum(md5):
    """
    Validate md5sum
    :param md5: md5sum to valiate
    :return: True or False
    """
    if 32 != len(md5):
        logger.warn("Invalid md5 length for md5 {}".format(md5))
        return False
    if not md5.isalnum():
        logger.warn("Malformed md5 {} in IOC list".format(md5))
        return False
    for c in "ghijklmnopqrstuvwxyz":
        if c in md5 or c.upper() in md5:
            logger.warn("Malformed md5 {} in IOC list".format(md5))
            return False

    return True


def validate_sha256(sha256):
    """
    Validate md5sum
    :param md5: md5sum to valiate
    :return: True or False
    """
    if 64 != len(sha256):
        logger.warn("Invalid sha256 length for sha256 {}".format(sha256))
        return False
    if not sha256.isalnum():
        logger.warn("Malformed sha256 {} in IOC list".format(sha256))
        return False
    for invalid_hash_character in "ghijklmnopqrstuvwxyz":
        if invalid_hash_character in sha256 or invalid_hash_character.upper() in sha256:
            logger.warn("Malformed sha256 {} in IOC list".format(sha256))
            return False

    return True


def sanitize_id(id):
    """
    Ids may only contain a-z, A-Z, 0-9, - and must have one character
    :param id: the ID to be sanitized
    :return: sanitized ID
    """
    return id.replace(':', '-')


def validate_ip_address(ip_string):
    try:
        ipaddress.ip_address(unicode(ip_string))
        return True
    except ValueError:
        return False

def cybox_parse_observable(observable, indicator, timestamp, score):
    if observable.observable_composition:
        reports = []
        for composed_observable in observable.observable_composition.observables:
            reports.extend(_cybox_parse_observable(composed_observable, indicator, timestamp, score))
        return reports
    else:
        return _cybox_parse_observable(observable, indicator, timestamp, score)

def _cybox_parse_observable(observable, indicator, timestamp, score):
    """
    parses a cybox observable and returns a list of iocs.
    :param observable: the cybox obserable to parse
    :return: list of observables
    """
    reports = []

    if observable.object_ and observable.object_.properties:
        props = observable.object_.properties
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

    def append_report_if_iocs_found(props, target_key, ioc_label, validator):
        iocs = get_iocs_from_props(
            props, target_key=target_key, ioc_label=ioc_label, validator=validator)
        if len(iocs) > 0:
            reports.append({'iocs': iocs,
                            'id': sanitize_id(observable.id_),
                            'description': description,
                            'title': title,
                            'timestamp': timestamp,
                            'link': link,
                            'score': score})

    if type(props) == DomainName:
        if props.value and props.value.value:
            append_report_if_iocs_found(
                props.value, target_key="value", ioc_label="dns", validator=validate_domain_name)

    elif type(props) == Address:
        if props.category == 'ipv4-addr' and props.address_value:
            append_report_if_iocs_found(
                props.address_value, target_key="value", ioc_label="ipv4", validator=validate_ip_address)

        if props.category == 'ipv6-addr' and props.address_value:
            append_report_if_iocs_found(
                props.address_value, target_key="value", ioc_label="ipv6", validator=validate_ip_address)

    elif type(props) == File:
        if props.md5:
            append_report_if_iocs_found(
                props, target_key="md5", ioc_label="md5", validator=validate_md5sum)
        if props.sha256:
            append_report_if_iocs_found(
                props, target_key="sha256", ioc_label="sha256", validator=validate_sha256)

    return reports


def get_iocs_from_props(props, target_key="sha256", ioc_label="sha256", validator=validate_sha256):
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
