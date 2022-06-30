# cb-taxii-connector (CentOS/RHEL 7/8)

VMware Carbon Black EDR connector for pulling and converting STIX information from TAXII Service Providers into EDR Feeds.

You can install the pre-built RPMs via YUM by using the CB Open Source repository.
*(See CbOpenSource.repo and put that in /etc/yum.repos.d/)*

The pre-built RPM is supported via our [User eXchange (Jive)](https://community.carbonblack.com/community/developer-relations) 
and via email to dev-support@carbonblack.com.  

## Support

1. View all API and integration offerings on the [Developer Network](https://developer.carbonblack.com/) along with reference documentation, video tutorials, and how-to guides.
2. Use the [Developer Community Forum](https://community.carbonblack.com/t5/Developer-Relations/bd-p/developer-relations) to discuss issues and get answers from other API developers in the Carbon Black Community.
3. Report bugs and change requests to [Carbon Black Support](http://carbonblack.com/resources/support/).

## Introduction

This document describes how to install and use the Cb Response TAXII Connector. This connector allows for the importing of STIX data by querying one or more TAXII services and retrieving that data and then converting it into CB feeds using the CB JSON format for IOCs. The job queries for available STIX/TAXII data that is newer than the last time it asked, and by default runs every hour.

For each TAXII service, available “collections” are enumerated and a Cb Response Feed is created. For example, if you have two TAXII services and each exposes two collections, you will have four CB feeds as a result of this connector.

The following IOC types are extracted from STIX data:

* MD5 Hashes
* SHA-256 Hashes
* Domain Names
* IP-Addresses
* IP-Address Ranges
	
## Requirements

This EDR TAXII Connector has the following requirements:

* *VMware Carbon Black EDR 5.0 (or greater)* – this integration leverages API calls and feed functionality available in Cb Response 5.0 and newer.  In order to check the version, you can run the following rpm command on your server:

```
[root@localhost ~]# rpm -qa | grep cb-enterprise
cb-enterprise-5.0.0.150122.1654-1.el6.x86_64
```

* *Access to TAXII Service Provider* – the purpose of this integration is to retrieve STIX threat information via a TAXII service, so if you do not have access to a TAXII service this integration will be of no value. Example services are SoltraEdge and HailATaxii.com

## Installation

Take the following steps to install the Cb Response Taxii Connector:

1. Install the CbOpenSource.repo file found in the root of this repository (place it in /etc/yum.repos.d/ on your head CB Server node.)
2. Install by issuing the following command as root (or sudo): yum install python-cbtaxii -y

## Upgrades

When an upgrade is available, it should be as easy as doing the following:

    yum install python-cbtaxii -y

* *Note* Upgrading from 1.0/1.1 to 1.2, you'll need to supply auth_token=(CB Server Admin API Token) in the config file under the cbconfig directive.

Please note that a new /etc/cb/integrations/cbtaxii/cbtaxii.conf.example might be made available in some cases, at which point any new settings should be studied, understood, and applied to the production configuration file if necessary.


## Configuration

You’ll need to place a configuration file in the following location:
`/etc/cb/integrations/cbtaxii/cbtaxii.conf`

A sample file is provided in `/etc/cb/integrations/cbtaxii/cbtaxii.conf.example`, so you can rename the file with the following command:
```
mv /etc/cb/integrations/cbtaxii/cbtaxii.conf.example /etc/cb/integrations/cbtaxii/cbtaxii.conf
```

From here, one or more TAXII services can be configured.
 

## Execution

By default the linux cron daemon will run this integration every day at 1:00 AM to check for new data from the TAXII services you 
have configured. When it runs it will use the current settings found in `/etc/cb/integrations/cbtaxii/cbtaxii.conf`, 
so make sure you are careful when changing any of those settings.

When you first install the connector, you might not want to wait until the hour mark for the job to run. In this case, 
you can force the connector to run manually. As either *root* or *cb* user on the Cb Response Server, execute the 
following command:

```
/usr/share/cb/integrations/cbtaxii/cbtaxii -c /etc/cb/integrations/cbtaxii/cbtaxii.conf
```

It is perfectly fine to do this because the script will only allow one copy of itself to run at a time, so you don’t 
have to worry about the cron daemon attempting to run this while your manual instance is still executing.

*Note #1: this script can take a long time to run depending on the amount of data available from the TAXII services you 
have configured.*

*Note #2: this script logs everything to /var/log/cb/integrations/cbtaxii/cbtaxii.log , so you will see very little 
output when you run it manually.*


You can also enable debug logging by executing:

```
/usr/share/cb/integrations/cbtaxii/cbtaxii -d 
```


## Troubleshooting

If you suspect a problem, please first look at the cbtaxii connector logs found here:

`/var/log/cb/integrations/cbtaxii/cbtaxii.log`

(There might be multiple files as the logger "rolls over" when the log file hits a certain size).


We've seen where Soltra Edge had a user account that wasn't returning data past a particular date for a specific username.  We don't know why this was the case.  The customer created a new SoltraEdge user account and used those credentials in our connector and everything went back to working.

Additionally, due to STIX being a particulary verbose format, sometimes IOCs are stored in fields that we don't expect.  This could result in some IOCs you see in your Taxii platform (such as SoltraEdge) but not show up in Cb Response.  For this and other issues, you can export the raw XML that our connector receives so we can see how information is represented.  To export, use the following command, then contact us and we'll setup a place for you to place the exported XML for our analysis.

```
/usr/share/cb/integrations/cbtaxii/cbtaxii -c /etc/cb/integrations/cbtaxii/cbtaxii.conf --export-dir
```

## Building

The easiest way to build the application is via PyInstaller and utilizing Carbon Black EDRs virtual Python3 enviornment (or a clone of it is actually best).
To do this:

1. Install PyInstaller: ```/usr/share/cb_clone/virtualenv/bin/python –m pip install PyInstaller```
2. Created symbolic links for /bin/python and /bin/pyinstaller via:
```
ln –s "$(which pyinstaller)" /bin/pyinstaller
ln –s /usr/share/cb_clone/virtualenv/bin/python /bin/python
```
3. Build and (re)install:
```
cd </path/to/source/code/directory/here>
rm -rf /home/user/rpm_build/
mkdir /home/user/rpm_build/
/usr/share/cb_clone/virtualenv/bin/python setup.py build_rpm --rpmbuild-dir=/home/user/rpm_build/
yum remove python-cbtaxii.x86_64
yum install /home/user/rpm_build/RPMS/x86_64/python-cbtaxii-1.6.7-4.el8.x86_64.rpm --nogpgcheck
```
4. Run the cbtaxii connector, after configuring it (see 'Configuration' above)
```
/usr/share/cb/integrations/cbtaxii/cbtaxii -c /etc/cb/integrations/cbtaxii/cbtaxii.conf
```
5. Fix errors as necessary (rinse & repeat)

If ImportError is reported upon execution, it's likely that one or more packages is missing from either the virtual Python3 enviornment used for building or the binary itself. To solve:
	   - Verify the package is installed in the virtual Python3 enviornment:
	   	```/usr/share/cb_clone/virtualenv/bin/python –m pip install <missing package>```
	   - Add the package to the cb-taxii-connector.spec PyInstaller file:
	   	```datas.extend([(get_package_paths('<package>')[1], '<package>')])```
		
6. When utilizing a custom build, it may be beneficial to exclude python-cbtaxii from the /etc/yum.conf to prevent accidental upgrades. To do this add the following:
```exclude=<any existing exclusions here> python-cbtaxii*```


If this connector is going to run on Centos 6 then you need to use the source package of lxml from pip.  
Use this command to grab python requirements:
```
pip insall --no-binary lxml -r requirements.txt
```
