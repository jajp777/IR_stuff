#!/bin/bash

service elasticsearch start

echo '[*] Sleeping for 10 seconds'
sleep 10
echo '[*] Adding default mapping'
curl -XPUT http://127.0.0.1:9200/flurb -d @/mapping.json
echo '[*] Done, starting kibana'
/kibana/bin/kibana



