# VMware Carbon Black - STIX/TAXII 2 Connector (CentOS 6/7/8)

VMware Carbon Black EDR provides integration with STIX/TAXII version 2.0/2.1 servers.

To support this integration, Carbon Black provides an out-of-band bridge that communicates with the TAXII API.
Built with python3!

The integration can be configured to retrieve STIX Indicators from a number of specified TAXII 2.0/2.1 servers.
The integration will query the configured servers for SIX indicators, and then translate STIX-pattern indicators 
into EDR IOC format where possible to the produced a consolidated EDR threat intelligence feed.
MD5/Sha256 hashes, IP addresses and domain names included in the available STIX Indicators patterns will be included,
other indicators will be ignored.

## Installation Quickstart

As root on your EDR or other RPM based 64-bit Linux distribution server:
```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-taxii-connector
```

Once the software is installed via YUM, copy the 
`/etc/cb/integrations/taxii/connector.conf.example` file to 
`/etc/cb/integrations/taxii/connector.conf`.
 Edit this file and place your EDR API key into the 
`carbonblack_server_token` variable and your EDR server's base URL into the `carbonblack_server_url` variable.

Define a new section in the ini file for each Taxii server you wish to download STIX Indicators.
`url=` is required, and must be set to the protocol prefixed url of the server
`version=` is optional, and controls the TAXII version of the target server (v20 or v21)
`score=` can be provided to score the retrieved indicators (1-100), with the default being 75

By default the integration will pull from all available collections, but you can specify
`collections=` and indicate a comma delimited list of collection-ids to limit the integration's scope

By default, the ingegration will pull all MD5/SHA256 hashes, all ip address and domain name indicators
You can specify which types of indicator in the server's section of the configuration to limit the types of indicators
`ioc_types=` (hash,domain,address) as a comma delimited list to 

Two forms of authentication username and password or token authentication can be configured, optionally:
`username=` and `password=` can be set for the former and `token` for the later. 
`cert=` can be optionally provided to locate a .pem encoded certificate+key pair to use during TLS 
or set to a comma delimited list of the certificate file location followed by the key.
`verify=` can be optionally set to control TLS verification using `true` or `false` as boolean values.

Once you have the connector configured with the desired TAXII servers:
```
service cb-taxii-connector start
```

Any errors will be logged into `/var/log/cb/integrations/cb-taxii-connector/cb-taxii-connector.log`.  

## Troubleshooting

If you suspect a problem, please first look at the Taxii connector logs found here: 
`/var/log/cb/integrations/cb-taxii-connector/cb-taxii-connector.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

If you need detail logging, set `log_level=DEBUG` in the core configuration.

## Support

* View all API and integration offerings on the [Developer Network](https://developer.carbonblack.com) along with reference documentation, video tutorials, and how-to guides.
* Use the [Developer Community Forum](https://community.carbonblack.com/community/resources/developer-relations) to discuss issues and get answers from other API developers in the Carbon Black Community.
* Report bugs and change requests to [Carbon Black Support](http://carbonblack.com/resources/support/).

### Reporting Problems

When you contact Carbon Black Support with an issue, please provide the following:

* Your name, company name, telephone number, and e-mail address
* Product name/version, CB EDR Server version, CB EDR Sensor version
* Hardware configuration of the EDR Server or computer (processor, memory, and RAM) 
* For documentation issues, specify the version of the manual you are using. 
* Action causing the problem, error message returned, and event log output (as appropriate) 
* Problem severity

## Building

To create a build for EL7, run:
```
FISH: ./gradlew build
BASH: ./gradlew build
```

To create a build for EL8, run:
```
FISH: env DOCKERIZED_BUILD_ENV=centos8 ./gradlew build
BASH: export DOCKERIZED_BUILD_ENV=centos8; ./gradlew build
```


Other common commands for ./gradlew:
* `runPyTest` - Runs the python test suite
* `generatePepperReport` - Generates a flake 8 based pepper report.
* `createVirtualEnv` - Creates the appropriate python virtual environment to build and execute the connector.  Can also be used for your IDE's virtual environment.
* `runSmokeTest` - Runs the smoke tests available.
