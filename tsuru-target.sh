#!/bin/bash -ue

ip_address=$(hostname -i)

tsuru-admin target-remove default
tsuru-admin target-add default $ip_address:8080
tsuru-admin target-set default
service tsuru-server-api restart
/etc/init.d/tsuru-server-api restart

exit 0
