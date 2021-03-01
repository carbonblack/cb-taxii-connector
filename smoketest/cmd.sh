#!/bin/bash

set -e

if [ -z "$1" ]; then
  echo Error: Missing rpm file location parameter.  Ex: ./run_smoketest.sh path/to/rpm
  exit 1
fi

RPM_FILE=$(find "$1" -name "*.rpm" -print -quit)

SYSTEM_CTL_PATCH="https://${ARTIFACTORY_SERVER}/artifactory/cb/gdraheim/docker-systemctl-replacement/1.4.3424/systemctl.py"
if [[ "$(cat /etc/redhat-release)" == *"release 8"* ]]; then
  SYSTEM_CTL_PATCH="https://${ARTIFACTORY_SERVER}/artifactory/cb/gdraheim/docker-systemctl-replacement/1.4.3424/systemctl3.py"
fi

echo Adding cb user
groupadd cb --gid 8300 && \
useradd --shell /sbin/nologin --gid cb --comment "Service account for VMware Carbon Black EDR" -M cb

echo Running smoke test on file: "$RPM_FILE"

rpm -ivh "$RPM_FILE"

echo 'Starting smoke test server'
cd $2/../test ; FLASK_APP=smoke_test_server.py python3.8 -m flask run --cert=adhoc &

echo Running connector...
cp $2/cbtaxii.conf /etc/cb/integrations/cbtaxii/cbtaxii.conf
/usr/share/cb/integrations/cbtaxii/bin/cb-taxii-connector -c /etc/cb/integrations/cbtaxii/cbtaxii.conf

#ensure the ioc has been written into the smoketest feed
sleep 3
grep "example-Observable-87c9a5bb-d005-4b3e-8081-99f720fad62b" /usr/share/cb/integrations/cbtaxii/feeds/*smoketest >/dev/null || (echo 'cbtaxii not working correctly' ; exit 1 )
echo 'cbtaxii connector working correctly!'

yum -y remove python-cbtaxii

# Uncomment the following line to leave the container running.
# sleep 9999999999
