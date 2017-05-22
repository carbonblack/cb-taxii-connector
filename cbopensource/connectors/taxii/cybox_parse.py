from cybox.objects.domain_name_object import DomainName
from cybox.objects.address_object import Address
from cybox.objects.file_object import File

import logging
import string
import socket
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

def cybox_parse_observable(observable, indicator, timestamp, score):
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
        description = observable.description.value

    #
    # if description is an empty string, then use the indicator's description
    # NOTE: This was added for RecordedFuture
    #

    if not description and indicator and indicator.description:
        description = indicator.description.value


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


    if type(props) == DomainName:
        if props.value and props.value.condition and props.value.condition.lower().strip() == 'equals':
            iocs = {'dns': []}
            #
            # Sometimes props.value.value is a list
            #
            if type(props.value.value) is list:
                for domain_name in props.value.value:
                    if validate_domain_name(domain_name.strip()):
                        iocs['dns'].append(domain_name.strip())
            else:
                domain_name = props.value.value.strip()
                if validate_domain_name(domain_name):
                    iocs['dns'].append(domain_name)
                    reports.append({'iocs': iocs,
                                    'id': sanitize_id(observable.id_),
                                    'description': description,
                                    'title': title,
                                    'timestamp': timestamp,
                                    'link': link,
                                    'score': 50})

    elif type(props) == Address:
        if props.category == 'ipv4-addr' and props.address_value:
            iocs = {'ipv4': []}

            #
            # Sometimes props.address_value.value is a list vs a string
            #
            if type(props.address_value.value) is list:
                for ip in props.address_value.value:
                    if validate_ip_address(ip.strip()):
                        iocs['ipv4'].append(ip.strip())
            else:
                ipv4 = props.address_value.value.strip()
                if validate_ip_address(ipv4):
                    iocs['ipv4'].append(ipv4)

            reports.append({'iocs': iocs,
                            'id': sanitize_id(observable.id_),
                            'description': description,
                            'title': title,
                            'timestamp': timestamp,
                            'link': link,
                            'score': score})

    elif type(props) == File:
        iocs = {'md5': []}
        if props.md5:
            if type(props.md5) is list:
                for md5 in props.md5:
                    if validate_md5sum(md5.strip()):
                        iocs['md5'].append(md5.strip())
            else:
                md5 = props.md5.strip()
                if validate_md5sum(md5):
                    iocs['md5'].append(md5)

            reports.append({'iocs': iocs,
                            'id': sanitize_id(observable.id_),
                            'description': description,
                            'title': title,
                            'timestamp': timestamp,
                            'link': link,
                            'score': score})

    return reports
