# VMware Carbon Black - ThreatConnect Connector (CentOS 6/7/8)

VMware Carbon Black EDR provides integration with ThreatConnect by retrieving Indicators of
Compromise (IOCs) from specified communities. To support this integration, Carbon
Black provides an out-of-band bridge that communicates with the ThreatConnect API.
Built with python3!

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
* `createVirtualEnv` - Creates the appropriate python virtual environement to build and execute the connector.  Can also be used for your IDE's virtual environment.
* `runSmokeTest` - Runs the smoke tests available.

## Installation Quickstart

As root on your EDR or other RPM based 64-bit Linux distribution server:
```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-threatconnect-connector
```

Once the software is installed via YUM, copy the 
`/etc/cb/integrations/threatconnect/connector.conf.example` file to 
`/etc/cb/integrations/threatconnect/connector.conf`.
 Edit this file and place your EDR API key into the 
`carbonblack_server_token` variable and your EDR server's base URL into the `carbonblack_server_url` variable.

Next, place the credentials for your ThreatConnect API account into the `api_key` and `secret_key` variables. The 
`api_key` variable is the numeric API identifier issued by ThreatConnect, and the `secret_key` is a long alphanumeric +
symbols secret key assigned to you. Any special characters in the secret key do not have to be escaped in the
configuration file.

To receive IOCs from your organization as a source, enter your organization's source name in `default_org`.

To specify which sources to pull from, enter your sources as a comma separated list in `sources` or `*` to pull from all
sources.

Once you have the connector configured for your API access, start the ThreatConnect service:
```
service cb-threatconnect-connector start
```

Any errors will be logged into `/var/log/cb/integrations/cb-threatconnect-connector/cb-threatconnect-connector.log`.

## Troubleshooting

If you suspect a problem, please first look at the ThreatConnect connector logs found here: 
`/var/log/cb/integrations/cb-threatconnect-connector/cb-threatconnect-connector.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

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
