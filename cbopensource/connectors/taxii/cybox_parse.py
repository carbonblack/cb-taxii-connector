from cybox.objects.domain_name_object import DomainName
from cybox.objects.address_object import Address
from cybox.objects.file_object import File

import logging
import string
import socket

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


def sanitize_id(id):
    """
    Ids may only contain a-z, A-Z, 0-9, - and must have one character
    :param id: the ID to be sanitized
    :return: sanitized ID
    """
    return id.replace(':', '-')


def validate_ip_address(ip_address):
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error:
        return False


def cybox_parse_observable(observable, timestamp):
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

    if observable.description:
        description = observable.description.value
    else:
        description = ''

    if type(props) == DomainName:
        if props.value and props.value.condition and props.value.condition.lower().strip() == 'equals':
            domain_name = props.value.value.strip()
            iocs = {'dns': []}
            iocs['dns'].append(domain_name)

            if validate_domain_name(domain_name):
                reports.append({'iocs': iocs,
                                'id': sanitize_id(observable.id_),
                                'description': description,
                                'title': observable.title,
                                'timestamp': timestamp,
                                'link': '',
                                'score': 50})

    elif type(props) == Address:
        if props.category == 'ipv4-addr' and props.address_value and validate_ip_address(props.address_value.value):
            ip_address = props.address_value.value
            iocs = {'ipv4': []}
            iocs['ipv4'].append(ip_address)

            reports.append({'iocs': iocs,
                            'id': sanitize_id(observable.id_),
                            'description': description,
                            'title': observable.title,
                            'timestamp': timestamp,
                            'link': '',
                            'score': 50})

    elif type(props) == File:
        if props.md5 and validate_md5sum(props.md5):
            iocs = {'md5': []}
            iocs['md5'].append(props.md5)
            reports.append({'iocs': iocs,
                            'id': sanitize_id(observable.id_),
                            'description': description,
                            'title': observable.title,
                            'timestamp': timestamp,
                            'link': '',
                            'score': 50})

    # else:
    #    print type(props), "Not supported"
    return reports
