#!/bin/bash -x
if [ "$#" -ne "1" ]
then
    echo "$0 FILE"
    exit 1
fi
FILE=$1
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install $FILE
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start 
echo 'Done.'
