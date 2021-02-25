from flask import Flask, jsonify, request, make_response

app = Flask(__name__)


@app.route('/api/info')
def api_info():
    return jsonify({"version": "7.4.99999"})


@app.route('/api/v1/storage/events/partition')
def api_storage_events_partition():
    return jsonify({"cbevents_2017_03_18_1807": {
        "status": "warm",
        "info": {
            "sizeInBytes": 6132115,
            "startDate": "2017-03-18T18:07:50.758813Z",
            "partitionId": 97639495827456,
            "endDate": "2017-04-07T18:18:31.493403Z",
            "deletedDocs": 0,
            "maxDoc": 1432,
            "userMounted": False,
            "isLegacy": False,
            "segmentCount": 7,
            "numDocs": 1432,
            "dir": "/var/cb/data/solr5/cbevents/cbevents_2017_03_18_1807",
            "schema": "cbevents_v1"
        },
        "name": "cbevents_2017_03_18_1807"
    },
        "writer": {
            "status": "hot",
            "info": {
                "sizeInBytes": 825878,
                "startDate": "2017-04-10T18:18:29.834738Z",
                "partitionId": 97769770844160,
                "endDate": None,
                "deletedDocs": 0,
                "maxDoc": 355,
                "userMounted": False,
                "isLegacy": False,
                "segmentCount": 9,
                "numDocs": 355,
                "dir": "/var/cb/data/solr5/cbevents/cbevents_2017_04_10_1818",
                "schema": "cbevents_v1"
            },
            "name": "writer"
        },
        "cbevents_2017_04_07_1818": {
            "status": "warm",
            "info": {
                "sizeInBytes": 20464833,
                "startDate": "2017-04-07T18:18:27.821121Z",
                "partitionId": 97752783781888,
                "endDate": "2017-04-10T18:18:33.612997Z",
                "deletedDocs": 0,
                "maxDoc": 2780,
                "userMounted": False,
                "isLegacy": False,
                "segmentCount": 10,
                "numDocs": 2780,
                "dir": "/var/cb/data/solr5/cbevents/cbevents_2017_04_07_1818",
                "schema": "cbevents_v1"
            },
            "name": "cbevents_2017_04_07_1818"
        },
        "cbevents_2017_02_19_2012": {
            "status": "warm",
            "info": {
                "sizeInBytes": 71,
                "startDate": "2017-02-19T20:12:10.312043Z",
                "partitionId": 97487102279680,
                "endDate": "2017-03-15T18:07:34.821787Z",
                "deletedDocs": 0,
                "maxDoc": 0,
                "userMounted": False,
                "isLegacy": False,
                "segmentCount": 0,
                "numDocs": 0,
                "dir": "/var/cb/data/solr5/cbevents/cbevents_2017_02_19_2012",
                "schema": "cbevents_v1"
            },
            "name": "cbevents_2017_02_19_2012"
        },
        "cbevents_2017_03_15_1807": {
            "status": "warm",
            "info": {
                "sizeInBytes": 41374250,
                "startDate": "2017-03-15T18:07:30.854679Z",
                "partitionId": 97622507585536,
                "endDate": "2017-03-18T18:07:54.721176Z",
                "deletedDocs": 0,
                "maxDoc": 2378,
                "userMounted": False,
                "isLegacy": False,
                "segmentCount": 10,
                "numDocs": 2378,
                "dir": "/var/cb/data/solr5/cbevents/cbevents_2017_03_15_1807",
                "schema": "cbevents_v1"
            },
            "name": "cbevents_2017_03_15_1807"
        }
    })


@app.route("/api/v1/feed", methods=["POST", "GET"])
def feed():
    if request.method == "POST":
        return '', 200
    else:
        return """[
    {
        "provider_url": "https://www.bit9.com/solutions/cloud-services/",
        "ssl_client_crt": null,
        "local_rating": null,
        "requires_who": null,
        "icon_small": "",
        "id": 9,
        "category": "Bit9 + Carbon Black First Party",
        "display_name": "Bit9 Software Reputation Service Trust",
        "use_proxy": null,
        "feed_url": "https://api.alliance.carbonblack.com/feed/SRSTrust",
        "username": null,
        "validate_server_cert": null,
        "ssl_client_key": null,
        "manually_added": false,
        "password": null,
        "icon": "",
        "provider_rating": 3,
        "name": "SRSTrust",
        "tech_data": "It is necessary to share MD5s of observed binaries with the Carbon Black Alliance to use this feed",
        "requires": null,
        "enabled": true,
        "summary": "The Cb Reputation Trust feed provides a level of software trustworthness",
        "requires_what": null,
        "order": 2
    }
    ]"""


@app.route('/read-only/services/collection-management', methods=["POST"])
def collection_management():
    collection_managment_response = """<taxii_11:Collection_Information_Response xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xmlns:xmldsig="http://www.w3.org/2000/09/xmldsig#" in_response_to="26300" message_id="urn:uuid:9d0b44f5-b034-4b47-816e-de7d63fed1bc">
  <taxii_11:Collection collection_name="smoketest" collection_type="DATA_SET" available="true">
    <taxii_11:Description>smoketest Source Data</taxii_11:Description>
    <taxii_11:Content_Binding binding_id="CB_STIX_XML_111"/>
    <taxii_11:Polling_Service xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="taxii_11:ServiceInstanceType">
      <taxii_11:Protocol_Binding>urn:taxii.mitre.org:protocol:https:1.0</taxii_11:Protocol_Binding>
      <taxii_11:Address>https://localhost:5000/taxii/poll</taxii_11:Address>
      <taxii_11:Message_Binding>urn:taxii.mitre.org:message:xml:1.1</taxii_11:Message_Binding>
    </taxii_11:Polling_Service>
  </taxii_11:Collection>
</taxii_11:Collection_Information_Response>"""
    response = make_response(collection_managment_response)
    response.headers.update({"X-TAXII-Protocol": "urn:taxii.mitre.org:protocol:http:1.0",
                             "X-TAXII-Content-Type": "urn:taxii.mitre.org:message:xml:1.1",
                             "X-TAXII-Services": "urn:taxii.mitre.org:services:1.1",
                             "Content-Type": "application/xml"})
    return response


@app.route('/read-only/services/poll', methods=["POST"])
def services_poll():
    poll_response = """<taxii_11:Poll_Response xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" 
    message_id="42158"  in_response_to="20079" 
    collection_name="smoketest" more="false" result_part_number="1">
    <taxii_11:Inclusive_End_Timestamp>2014-12-19T12:00:00Z</taxii_11:Inclusive_End_Timestamp>
    <taxii_11:Record_Count partial_count="false">1</taxii_11:Record_Count>
    <taxii_11:Content_Block>
        <taxii_11:Content_Binding binding_id="urn:stix.mitre.org:xml:1.1.1"/>
        <taxii_11:Content>
            <stix:STIX_Package xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:stix="http://stix.mitre.org/stix-1" xmlns:indicator="http://stix.mitre.org/Indicator-2" xmlns:cybox="http://cybox.mitre.org/cybox-2" xmlns:DomainNameObj="http://cybox.mitre.org/objects#DomainNameObject-1" xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2" xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1" xmlns:example="http://example.com/" xsi:schemaLocation="http://stix.mitre.org/stix-1 ../stix_core.xsd     http://stix.mitre.org/Indicator-2 ../indicator.xsd     http://cybox.mitre.org/default_vocabularies-2 ../cybox/cybox_default_vocabularies.xsd     http://stix.mitre.org/default_vocabularies-1 ../stix_default_vocabularies.xsd     http://cybox.mitre.org/objects#DomainNameObject-1 ../cybox/objects/Domain_Name_Object.xsd" id="example:STIXPackage-f61cd874-494d-4194-a3e6-6b487dbb6d6e" timestamp="2014-05-08T09:00:00.000000Z" version="1.1.1">
                <stix:STIX_Header>
                    <stix:Title>Example watchlist that contains domain information.</stix:Title>
                    <stix:Package_Intent xsi:type="stixVocabs:PackageIntentVocab-1.0">Indicators - Watchlist</stix:Package_Intent>
                </stix:STIX_Header>
                <stix:Indicators>
                    <stix:Indicator xsi:type="indicator:IndicatorType" id="example:Indicator-2e20c5b2-56fa-46cd-9662-8f199c69d2c9" timestamp="2014-05-08T09:00:00.000000Z">
                        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Domain Watchlist</indicator:Type>
                        <indicator:Description>Sample domain Indicator for this watchlist</indicator:Description>
                        <indicator:Observable id="example:Observable-87c9a5bb-d005-4b3e-8081-99f720fad62b">
                            <cybox:Object id="example:Object-12c760ba-cd2c-4f5d-a37d-18212eac7928">
                                <cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType" type="FQDN">
                                    <DomainNameObj:Value condition="Equals" apply_condition="ANY">malicious1.example.com##comma##malicious2.example.com##comma##malicious3.example.com</DomainNameObj:Value>
                                </cybox:Properties>
                            </cybox:Object>
                        </indicator:Observable>
                    </stix:Indicator>
                </stix:Indicators>
            </stix:STIX_Package>
        </taxii_11:Content>
    </taxii_11:Content_Block>
</taxii_11:Poll_Response>"""
    response = make_response(poll_response)
    response.headers.update({"X-TAXII-Protocol": "urn:taxii.mitre.org:protocol:http:1.0",
                             "X-TAXII-Content-Type": "urn:taxii.mitre.org:message:xml:1.1",
                             "X-TAXII-Services": "urn:taxii.mitre.org:services:1.1",
                             "Content-Type": "application/xml"})
    return response
