#!/usr/bin/env python
#
# The MIT License (MIT)
#
# Copyright (c) 2015 Bit9 + Carbon Black
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
import cgi

from util import cleanup_string
from lxml import etree
import time
from dateutil import parser
import libtaxii as taxii
import libtaxii.clients as taxii_clients
import libtaxii.messages_11 as tm11
import libtaxii.messages_10 as tm10
import cybox
import stix.bindings.stix_core as stix_core_binding
import socket
import string
import traceback
import requests


class UnauthorizedException(Exception):
    def __init__(self, text):
        self.text = str(text)

    def __str__(self):
        return "UnauthorizedException: %s" % self.text


class TaxiiClient(object):
    def __init__(self, base_domain, username, password, use_https=False, key_file=None, cert_file=None,
                 ssl_verify=True, discovery_request_uri="/taxii-discovery-service", poll_request_uri="/taxii-data"):
        """
        Takes a config filepath to read credential information.
        """
        self.base_domain = base_domain
        self.discovery_request_uri = discovery_request_uri
        self.poll_request_uri = poll_request_uri
        if use_https:
            self.base_url = "https://%s" % self.base_domain
        else:
            self.base_url = "http://%s" % self.base_domain

        self.content_type_map = {
            taxii.VID_TAXII_XML_10: 'application/xml',
            taxii.VID_TAXII_XML_11: 'application/xml',
            taxii.VID_CERT_EU_JSON_10: 'application/json'
        }

        self.services_map = {
            taxii.VID_TAXII_XML_10: taxii.VID_TAXII_SERVICES_10,
            taxii.VID_TAXII_XML_11: taxii.VID_TAXII_SERVICES_11,
            taxii.VID_CERT_EU_JSON_10: taxii.VID_TAXII_SERVICES_10
        }

        self.username = username
        self.password = password
        self.key_file = None
        self.cert_file = None
        self.use_https = use_https
        self.ssl_verify = ssl_verify
        if self.use_https:
            self.key_file = key_file
            self.cert_file = cert_file

        self.headers = {"Content-Type": "application/xml",
                        "User-Agent": "carbonblack-taxii-connector",
                        "Accept": "application/xml",
                        "X-TAXII-Accept": "TAXII_1.0/TAXII_XML_BINDING_1.0",
                        "X-TAXII-Content-Type": "TAXII_1.0/TAXII_XML_BINDING_1.0",
                        "Connection": "keep-alive",
                        "Accept-Encoding": "gzip, deflate"
        }
        if self.use_https:
            self.headers["X-TAXII-Protocol"] = taxii.VID_TAXII_HTTPS_10
        else:
            self.headers["X-TAXII-Protocol"] = taxii.VID_TAXII_HTTP_10

        self.session = self.__instantiate_http_client()

    def __instantiate_http_client(self):
        s = requests.Session()
        if self.username and self.password:
            s.auth = (self.username, self.password)

        if self.key_file and self.cert_file:
            s.cert = (self.cert_file, self.key_file)

        s.headers = self.headers
        s.verify = self.ssl_verify

        return s

    def taxii_request(self, path, message_binding, request_data, content_type=None):
        try:
            post_data = request_data.to_xml()
            resp = self.do_taxii_request(path, message_binding, post_data, content_type)
        except requests.HTTPError as he:
            return tm11.StatusMessage(message_id='0', in_response_to=request_data.message_id,
                                      status_type=taxii.ST_FAILURE, message="HTTP error: %s" % he.message)
        except requests.ConnectionError as ce:
            return tm11.StatusMessage(message_id='0', in_response_to=request_data.message_id,
                                      status_type=taxii.ST_FAILURE, message="Could not connect: %s" % ce.message)
        except AttributeError as ae:
            return tm11.StatusMessage(message_id='0', in_response_to=request_data.message_id,
                                      status_type=taxii.ST_FAILURE, message="Request data invalid: %s" % ae.message)
        except Exception as e:
            raise e
        else:
            taxii_content_type = resp.headers.get('X-TAXII-Content-Type')
            _, params = cgi.parse_header(resp.headers.get('Content-Type'))
            response_message = resp.content

            if taxii_content_type is None:  # Treat it as a Failure Status Message, per the spec
                message = []
                header_tuples = resp.headers
                for k, v in header_tuples.iteritems():
                    message.append(k + ': ' + v + '\r\n')
                message.append('\r\n')
                message.append(response_message)

                m = ''.join(message)

                return tm11.StatusMessage(message_id='0', in_response_to=request_data.message_id,
                                          status_type=taxii.ST_FAILURE, message=m)
            elif taxii_content_type == taxii.VID_TAXII_XML_10:  # It's a TAXII XML 1.0 message
                return tm10.get_message_from_xml(response_message)
            elif taxii_content_type == taxii.VID_TAXII_XML_11:  # It's a TAXII XML 1.1 message
                return tm11.get_message_from_xml(response_message)
            else:
                raise ValueError('Unsupported X-TAXII-Content-Type: %s' % taxii_content_type)

    def do_taxii_request(self, path, message_binding, post_data, content_type=None):
        headers = {}
        headers["X-TAXII-Content-Type"] = message_binding

        if content_type:
            headers["Content-Type"] = content_type
        else:
            if message_binding not in self.content_type_map:
                raise ValueError("content_type not specified, and the message_binding is unrecognized")
            headers["Content-Type"] = self.content_type_map[message_binding]

        headers["X-TAXII-Services"] = self.services_map[message_binding]

        uri = self.base_url + path

        if post_data:
            resp = self.session.post(uri, post_data, headers=headers, verify=self.ssl_verify)
        else:
            resp = self.session.get(uri, headers=headers, verify=self.ssl_verify)

        return resp

    def enumerate_collections(self, _logger):
        collection_request = tm11.CollectionInformationRequest(tm11.generate_message_id())
        message = self.taxii_request(self.discovery_request_uri, taxii.VID_TAXII_XML_11, collection_request)
        if type(message) == tm11.StatusMessage:
            t = message.to_text()
            x = getattr(message, 'status_type', None)
            if x:
                _logger.warn("Message response: %s" % x)
            raise UnauthorizedException(t)

        x = message.to_dict()
        return x.get('collection_informations', [])

    def retrieve_collection(self, collection_name, start_date, end_date):
        poll_params1 = tm11.PollParameters(
                allow_asynch=False,
                response_type=tm11.RT_FULL,
                content_bindings=[tm11.ContentBinding(binding_id=taxii.CB_STIX_XML_11)])

        poll_request = tm11.PollRequest(tm11.generate_message_id(),
                                        exclusive_begin_timestamp_label=start_date,
                                        inclusive_end_timestamp_label=end_date,
                                        collection_name=collection_name,
                                        poll_parameters=poll_params1)

        http_resp = self.do_taxii_request(self.poll_request_uri, taxii.VID_TAXII_XML_11, poll_request.to_xml())
        return http_resp.content


def total_seconds(td):
    return time.mktime(td.timetuple())


def observable_to_json(observable, enable_ip_ranges, logger):
    iocs = {}
    try:
        if observable.Object:
            object = observable.Object
            props = object.Properties

            if type(props) == cybox.bindings.domain_name_object.DomainNameObjectType:

                if props.Value:
                    if props.Value.condition:
                        if props.Value.condition.lower().strip() == 'equals':
                            iocs['dns'] = [str(props.Value.valueOf_).strip()]
                        else:
                            logger.warn("Props value condition for dns: %s" % props.Value.condition)
                    else:
                        iocs['dns'] = [str(props.Value.valueOf_).strip()]
                else:
                    logger.warn("Props.value is None!")

            elif type(props) == cybox.bindings.address_object.AddressObjectType:
                if props.category != 'ipv4-net' and props.category != 'ipv4-addr':
                    return iocs

                hits = []
                if props.Address_Value.delimiter:
                    if props.Address_Value.apply_condition:
                        if props.Address_Value.apply_condition.lower().strip() == 'any':
                            delim = props.Address_Value.delimiter
                            hits = props.Address_Value.valueOf_.split(delim)
                        else:
                            logger.warn(
                                "props.Address_Value.apply_condition: %s" % props.Address_Value.apply_condition.lower().strip())
                    else:
                        logger.warn("pops.Address_Value.apply_condition == None!")

                else:
                    hits = [str(props.Address_Value.valueOf_).strip()]

                if len(hits) == 2:
                    if props.Address_Value.condition.lower().strip() == 'inclusivebetween':
                        if enable_ip_ranges:
                            index_type = "events"
                            search_query = \
                                "cb.urlver=1&q=ipaddr%%3A%%5B%s%%20TO%%20%s%%5D&sort=start%%20desc&rows=10&start=0" \
                                % (hits[0], hits[1])
                            iocs['query'] = [{'index_type': index_type, 'search_query': search_query}]
                    else:
                        logger.warn("ipv4, condition: %s" % props.Address_Value.condition)
                elif len(hits) == 1:
                    iocs['ipv4'] = hits  # (props.Address_Value.condition, hits)

            elif type(props) == cybox.bindings.file_object.FileObjectType:
                if props.Hashes is not None:
                    for hash in props.Hashes.Hash:
                        hash_type = hash.Type.valueOf_.lower().strip()
                        if hash_type == 'md5':
                            iocs['md5'] = [str(hash.Simple_Hash_Value.valueOf_).strip()]
    except:
        logger.warn("Caught exception parsing observable: %s" % traceback.format_exc())
    return iocs


domain_allowed_chars = string.printable[:-6]


def validate_iocs(iocs, id, logger=None):
    # validate all md5 fields are 32 characters, just alphanumeric, and
    # do not include [g-z] and [G-Z] meet the alphanumeric criteria but are not valid in a md5

    if "md5" in iocs:
        valid_md5s = []
        for md5 in iocs.get("md5", []):
            md5 = md5.strip()
            if 32 != len(md5):
                if logger:
                    logger.warn("Invalid md5 length for md5 (%s) for report %s" % (md5, id))
                continue
            if not md5.isalnum():
                if logger:
                    logger.warn("Malformed md5 (%s) in IOC list for report %s" % (md5, id))
                continue
            for c in "ghijklmnopqrstuvwxyz":
                if c in md5 or c.upper() in md5:
                    if logger:
                        logger.warn("Malformed md5 (%s) in IOC list for report %s" % (md5, id))
                    continue
            valid_md5s.append(md5)

        if len(valid_md5s) > 0:
            iocs["md5"] = valid_md5s
        else:
            del iocs["md5"]

    # validate all IPv4 fields pass socket.inet_ntoa()
    if "ipv4" in iocs:
        valid_ipv4s = []

        for ip in iocs.get("ipv4", []):
            ip = ip.strip()
            try:
                socket.inet_aton(ip)
                valid_ipv4s.append(ip)
            except socket.error:
                if logger:
                    logger.warn("Malformed IPv4 (%s) addr in IOC list for report %s" % (ip, id))

        if len(valid_ipv4s) > 0:
            iocs["ipv4"] = valid_ipv4s
        else:
            del iocs["ipv4"]

    if "dns" in iocs:
        valid_domains = []

        # validate all lowercased domains have just printable ascii
        # 255 chars allowed in dns; all must be printables, sans control characters
        # hostnames can only be A-Z, 0-9 and - but labels can be any printable.  See
        # O'Reilly's DNS and Bind Chapter 4 Section 5:
        # "Names that are not host names can consist of any printable ASCII character."
        for domain in iocs.get("dns", []):
            domain = domain.strip()
            if len(domain) > 255:
                if logger:
                    logger.warn(
                            "Excessively long domain name (%s) in IOC list for report %s" % (domain, id))
                continue

            if not all([c in domain_allowed_chars for c in domain]):
                if logger:
                    logger.warn(
                            "Malformed domain name (%s) in IOC list for report %s" % (domain, id))
                continue

            labels = domain.split('.')
            if 0 == len(labels):
                if logger:
                    logger.warn("Empty domain name in IOC list for report %s" % (id))
                continue
            cont_again = False
            for label in labels:
                if len(label) < 1 or len(label) > 63:
                    if logger:
                        logger.warn("Invalid label length (%s) in domain name (%s) for report %s" % (
                            label, domain, id))
                    cont_again = True
                    break
            if cont_again:
                continue
            valid_domains.append(domain)
        if len(valid_domains) > 0:
            iocs["dns"] = valid_domains
        else:
            del iocs["dns"]

    # CHECK FOR EMPTY IOCS
    if len(iocs.get('dns', [])) == 0 and \
                    len(iocs.get('ipv4', [])) == 0 and \
                    len(iocs.get('md5', [])) == 0 and \
                    len(iocs.get('query', [])) == 0:
        return {}

    return iocs


def stix_element_to_reports(elem, site, site_url, collection, enable_ip_ranges, logger):
    stix_package_obj = stix_core_binding.STIXType().factory()
    stix_package_obj.build(elem)

    # TODO -- more ways to find timestamp
    # TODO -- create query for range stuff
    # TODO -- indicators?
    # TODO -- handle more conditions

    reports = []

    if stix_package_obj.Observables:
        observables = stix_package_obj.Observables
        for observable in observables.Observable:
            data = {}
            if observable.Observable_Composition:
                iocs = {}
                if observable.Observable_Composition.operator.lower().strip() != 'or':
                    if logger:
                        logger.warn("OPERATOR - %s - %s" % (site, observable.Observable_Composition.operator))
                    continue

                for subobserv in observable.Observable_Composition.Observable:
                    subdata = observable_to_json(subobserv, enable_ip_ranges, logger)
                    iocs.update(subdata)

                if len(iocs) > 0:
                    # TODO - validate IOCs
                    #                        iocs = validate_iocs(iocs, id, logger)
                    if logger:
                        logger.warn("%s - Composite - %s" % (site, data))
                        # TODO -- INCLUDE THESE!!!

            else:  # INDIVIDUAL
                id = cleanup_string(observable.id)
                iocs = observable_to_json(observable, enable_ip_ranges, logger)
                iocs = validate_iocs(iocs, id, logger)
                if len(iocs) > 0:
                    timestamp = str(stix_package_obj.timestamp)
                    timestamp = parser.parse(timestamp)
                    epoch_seconds = total_seconds(timestamp)
                    data['id'] = id
                    data['score'] = 50
                    data['link'] = site_url
                    data['iocs'] = iocs
                    if observable.Description:
                        data['title'] = observable.Description.valueOf_
                    else:
                        data['title'] = '%s entry %s' % (site, id)
                    data['timestamp'] = int(epoch_seconds)
                    # logger.debug("IOCS, %s-%s, %s" % (site, collection, data))
                    reports.append(data)
    return reports


def fast_xml_iter(context, func, site, site_url, collection, enable_ip_ranges, logger):
    count = 0
    results = []
    try:
        for event, elem in context:
            results.extend(func(elem, site, site_url, collection, enable_ip_ranges, logger))
            count += 1
            elem.clear()
            while elem.getprevious() is not None:
                del elem.getparent()[0]
    except etree.XMLSyntaxError:
        pass
    del context
    return results
