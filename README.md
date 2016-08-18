# cb-taxii-connector

Connector for pulling and converting STIX information from TAXII Service Providers into CB Feeds.

You can install the pre-built RPMs via YUM by using the CB Open Source repository.
*(See CbOpenSource.repo and put that in /etc/yum.repos.d/)*

The pre-built RPM is supported via our [User eXchange (Jive)](https://community.carbonblack.com/community/developer-relations) 
and via email to dev-support@carbonblack.com.  

## Introduction

This document describes how to install and use the Cb Response TAXII Connector. This connector allows for the importing of STIX data by querying one or more TAXII services and retrieving that data and then converting it into CB feeds using the CB JSON format for IOCs. The job queries for available STIX/TAXII data that is newer than the last time it asked, and by default runs every hour.

For each TAXII service, available “collections” are enumerated and a Cb Response Feed is created. For example, if you have two TAXII services and each exposes two collections, you will have four CB feeds as a result of this connector.

The following IOC types are extracted from STIX data:

* MD5 Hashes
* Domain Names
* IP-Addresses
* IP-Address Ranges
	
## Requirements

This Cb Response TAXII Connector has the following requirements:

* *Carbon Black Enterprise Response Server 5.0 (or greater)* – this integration leverages API calls and feed functionality available in Cb Response 5.0 and newer.  In order to check the version, you can run the following rpm command on your server:

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

From here, one or more TAXII services can be configured. The example configuration file is placed here along with the comments it contains:

```
    # Imports taxii/stix feeds into Carbon Black feeds 
    
    # general cbconfig options
    [cbconfig]
    # change this if your API port is different
    #(API port is usually the same port that you login using for the UI) 
    server_port=443
    
    # You NEED to set this to a CB Server Admin API Token
    auth_token=
    
    #
    # Put each site into its own configuration section.
    # You might just have a single site, like soltra edge or a remote taxii server
    # Make sure each section like this has a unique name 
    #
    
    [soltraedge]
    # the address of the site (only server ip or dns; don't put https:// or a trailing slash) 
    # for example, site=analysis.fsisac.com
    site=192.168.230.205
    
    # change to true if you require https for your TAXII service connection 
    use_https=false
    
    # by default, we validate SSL certificates. Turn this off by setting sslverify=false
    sslverify=false
    
    # if you need SSL certificates for authentication, set the path of the 
    # certificate and key here. Please leave blank to ignore.
    cert_file=
    key_file=
    
    # username for auth 
    username=admin
    
    # password for auth 
    password=avalanche

    # you can optionally specify which collections to convert to feeds (comma-delimited)
    collections=*

    # the output path for the feeds, probably leave this alone 
    output_path=/usr/share/cb/integrations/cbtaxii/feeds/
    
    # the icon link, we come with soltra and taxii icons, but if you 
    # have your own, this will show up 
    icon_link=/usr/share/cb/integrations/cbtaxii/soltra-logo.png
    
    # automatically create CB feeds, probably leave this to true 
    feeds_enable=true
    
    # do you want feed hits in CB to generate alerts? Available options 
    # are syslog or cb, and you can do both by putting syslog,cb 
    feeds_alerting=syslog,cb
    
    # there have been a lot of indicators that are whole class Cs.
    # Set this to false if you do not want to include these indicators, 
    # otherwise set to true
    enable_ip_ranges=true

    # (optional) the start date for which to start requesting data. 
    # Defaults to 2015-01-01 00:00:00 if you supply nothing 
    start_date=2015-03-01 00:00:00

    # (optional) the minutes to advance for each request. This
    # defaults to 15. If you don't have a lot of data, you could
    # advance your requests to every 60 minutes or multiply 60 times 
    # number of hours, so 1440 to ask for data in daily chunks 
    minutes_to_advance=30
```    

## Execution

By default the linux cron daemon will run this integration every hour to check for new data from the TAXII services you 
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

If you want to check that your credentials work and list the available collections, execute the same command with -l (lowercase-L):

```
/usr/share/cb/integrations/cbtaxii/cbtaxii -c /etc/cb/integrations/cbtaxii/cbtaxii.conf -l
```

## Troubleshooting

If you suspect a problem, please first look at the cbtaxii connector logs found here:

`/var/log/cb/integrations/cbtaxii/cbtaxii.log`

(There might be multiple files as the logger "rolls over" when the log file hits a certain size).


We've seen where Soltra Edge had a user account that wasn't returning data past a particular date for a specific username.  We don't know why this was the case.  The customer created a new SoltraEdge user account and used those credentials in our connector and everything went back to working.

Additionally, due to STIX being a particulary verbose format, sometimes IOCs are stored in fields that we don't expect.  This could result in some IOCs you see in your Taxii platform (such as SoltraEdge) but not show up in Cb Response.  For this and other issues, you can export the raw XML that our connector receives so we can see how information is represented.  To export, use the following command, then contact us and we'll setup a place for you to place the exported XML for our analysis.

```
/usr/share/cb/integrations/cbtaxii/cbtaxii -c /etc/cb/integrations/cbtaxii/cbtaxii.conf --export
```
