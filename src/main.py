import yaml
yaml.warnings({'YAMLLoadWarning': False})

from cbopensource.connectors.taxii import bridge

if __name__ == "__main__":
    name = "cb-taxii-connector"
    daemon = bridge.CarbonBlackTaxiiBridge(name, configfile="run/connector.conf", logfile="run/debug.log",
                                                   debug=True)
    daemon.start()
