#!/usr/bin/env python
# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.
################################################################################

import yaml

yaml.warnings({'YAMLLoadWarning': False})

from cbopensource.connectors.taxii import bridge

################################################################################
# Begin main
################################################################################

if __name__ == "__main__":
    name = "cb-taxii-connector"
    daemon = bridge.CarbonBlackTaxiiBridge(name, configfile="run/connector.conf", logfile="run/debug.log",
                                           debug=True)
    daemon.start()
