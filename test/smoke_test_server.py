from flask import Flask, jsonify, request

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
        "enabled": True,
        "summary": "The Cb Reputation Trust feed provides a level of software trustworthness",
        "requires_what": null,
        "order": 2
    }
    ]"""
